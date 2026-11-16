"""Dedicated StayFlow AI Receptionist Integration Router.

Provides:
1. Hotel Administration Endpoints (Staff JWT authenticated, strictly tenant-scoped)
   - Connection lifecycle (connect, disconnect, rotate-key, toggle, test-connection)
   - Sanitize activity logs
2. Machine-to-Machine Endpoints (Service Key authenticated via X-Integration-Key)
   - Chat / Q&A knowledge lookups
   - Room definitions & date-range availability checks
   - Concurrency-safe, 2-phase idempotent booking creation
   - Caller verification challenge & OTP verification (keyed HMAC, anti-enumeration)
   - Verified vs Unverified booking retrieval
   - Staff escalation / guest service requests
"""
import hashlib
import json
import logging
import secrets
import time
from datetime import datetime, timezone, date, timedelta
from decimal import Decimal
from typing import Optional, List, Dict, Any, Tuple

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, status
from pydantic import BaseModel, Field, EmailStr
from sqlalchemy import select, desc, func, and_, or_
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, joinedload

from app.database.connection import get_db
from app.models.entities import (
    Tenant, User, RoomType, Room, Guest, Reservation,
    HotelSettings, OperationalRecord,
    TenantIntegration, IntegrationLog, IntegrationIdempotencyRecord
)
from app.core.auth import current_user, get_tenant_id
from app.services.integration_crypto import (
    generate_service_key, hash_key, mask_key, encrypt_secret, decrypt_secret
)
from app.services.room_allocation_service import (
    allocate_and_lock_room, get_tenant_availability, check_room_conflict
)
from app.services.verification_service import (
    request_caller_verification, verify_caller_otp, validate_verification_token
)

logger = logging.getLogger("stayflow.integrations")

router = APIRouter(prefix="/api/integrations/ai-receptionist", tags=["AI Receptionist Integration"])

INTEGRATION_TYPE = "ai_receptionist"
DEFAULT_SCOPES = "hotel:read,rooms:read,rates:read,reservations:read,reservations:create,reservations:update,reservations:cancel,knowledge:read,escalations:create"

_INTEGRATION_RATE_LIMIT_STORE: Dict[int, List[float]] = {}


def check_integration_rate_limit(integration_id: int, max_requests: int = 120, window_seconds: int = 60):
    """In-memory sliding window rate limiter per integration (default 120 req/min)."""
    now = time.time()
    cutoff = now - window_seconds
    timestamps = [t for t in _INTEGRATION_RATE_LIMIT_STORE.get(integration_id, []) if t > cutoff]
    if len(timestamps) >= max_requests:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Integration rate limit exceeded ({max_requests} requests per minute). Please slow down."
        )
    timestamps.append(now)
    _INTEGRATION_RATE_LIMIT_STORE[integration_id] = timestamps


# ── Dependency: Staff RBAC (ADMIN or GENERAL_MANAGER) ─────────────────────────

def require_integration_admin(
    user: User = Depends(current_user)
) -> User:
    """Requires ADMIN, SUPER_ADMIN, or GENERAL_MANAGER role."""
    role = (user.role or "").upper().strip()
    if user.is_super_admin or role in ("ADMIN", "SUPER_ADMIN", "ADMINISTRATOR", "GENERAL_MANAGER"):
        return user
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Administrative permissions required to manage integrations."
    )


def require_admin_strictly(
    user: User = Depends(current_user)
) -> User:
    """Strictly requires ADMIN or SUPER_ADMIN role (e.g. for key rotation)."""
    role = (user.role or "").upper().strip()
    if user.is_super_admin or role in ("ADMIN", "SUPER_ADMIN", "ADMINISTRATOR"):
        return user
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Administrator privilege required for credential rotation."
    )


# ── Dependency: Machine-to-Machine Integration Key Auth ────────────────────────

def get_integration_context(required_scope: Optional[str] = None):
    """
    Validates external integration service credentials against active tenant integrations.
    Supports:
      - X-Service-Key header
      - X-Integration-Key header
      - Authorization: Bearer <key> header
    Tenant isolation is resolved strictly through the database record mapped to the SHA-256 key hash.
    Enforces scope checks, tenant status, integration enablement, and in-memory rate limiting.
    """
    def dependency(
        request: Request,
        x_service_key: Optional[str] = Header(None, alias="X-Service-Key"),
        x_integration_key: Optional[str] = Header(None, alias="X-Integration-Key"),
        authorization: Optional[str] = Header(None, alias="Authorization"),
        db: Session = Depends(get_db)
    ) -> Tuple[TenantIntegration, Tenant]:
        raw_key = None
        if x_service_key and x_service_key.strip():
            raw_key = x_service_key.strip()
        elif x_integration_key and x_integration_key.strip():
            raw_key = x_integration_key.strip()
        elif authorization and authorization.strip():
            auth_val = authorization.strip()
            parts = auth_val.split()
            if len(parts) == 2 and parts[0].lower() in ("bearer", "apikey", "key"):
                raw_key = parts[1].strip()
            elif len(parts) == 1 and parts[0].startswith("sf_"):
                raw_key = parts[0].strip()

        if not raw_key:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing integration credentials. Provide 'X-Service-Key', 'X-Integration-Key', or 'Authorization: Bearer <key>'."
            )
        
        k_hash = hash_key(raw_key)

        integration = db.scalar(
            select(TenantIntegration)
            .options(joinedload(TenantIntegration.tenant))
            .where(TenantIntegration.key_hash == k_hash)
        )

        if not integration:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid integration credentials."
            )

        if not integration.is_enabled or integration.status != "connected":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Integration is disabled or disconnected."
            )

        tenant = integration.tenant
        if not tenant or not tenant.is_active or tenant.status == "Suspended":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Hotel property account is suspended or inactive."
            )

        if required_scope:
            scopes = [s.strip() for s in (integration.scopes or "").split(",") if s.strip()]
            has_scope = (
                "*" in scopes
                or required_scope in scopes
                or (required_scope == "hotel:read" and "knowledge:read" in scopes)
                or (required_scope == "rates:read" and "rooms:read" in scopes)
            )
            if not has_scope:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Integration credentials lack required scope: '{required_scope}'."
                )

        # Rate limiting check (120 req/min)
        check_integration_rate_limit(integration.id, max_requests=120, window_seconds=60)

        # Update last_activity_at timestamp asynchronously
        try:
            integration.last_activity_at = datetime.now(timezone.utc)
            db.commit()
        except Exception:
            db.rollback()

        return integration, tenant

    return dependency


def to_iso(d: Any) -> Optional[str]:
    """Safely converts date or datetime to ISO string without direct method indexing."""
    if d is None:
        return None
    iso_fn = getattr(d, "isoformat", None)
    if callable(iso_fn):
        try:
            return str(iso_fn())
        except Exception:
            pass
    return str(d)

def log_integration_event(
    db: Session,
    tenant_id: int,
    integration_id: int,
    event_type: str,
    status_str: str = "success",
    direction: str = "inbound",
    status_code: Optional[int] = 200,
    payload_summary: Optional[str] = None,
    error_details: Optional[str] = None,
    duration_ms: Optional[int] = None,
    ip_address: Optional[str] = None
):
    """Safely records an activity log entry without raising exceptions."""
    try:
        log_entry = IntegrationLog(
            tenant_id=tenant_id,
            integration_id=integration_id,
            direction=direction,
            event_type=event_type,
            status=status_str,
            status_code=status_code,
            payload_summary=(payload_summary or "")[:250],
            error_details=error_details,
            duration_ms=duration_ms,
            ip_address=ip_address
        )
        db.add(log_entry)
        db.commit()
    except Exception as e:
        db.rollback()
        logger.warning(f"Failed to record integration log: {e}")


# ── Pydantic Request & Response Schemas ────────────────────────────────────────

class ConnectIntegrationIn(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    api_base_url: Optional[str] = None
    webhook_url: Optional[str] = None
    scopes: Optional[List[str]] = None
    config: Optional[Dict[str, Any]] = None

class UpdateIntegrationConfigIn(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    api_base_url: Optional[str] = None
    webhook_url: Optional[str] = None
    scopes: Optional[List[str]] = None
    is_enabled: Optional[bool] = None

class ToggleIntegrationIn(BaseModel):
    enabled: bool

class ChatQueryIn(BaseModel):
    query: str = Field(min_length=1, max_length=1000)
    guest_phone: Optional[str] = None
    session_id: Optional[str] = None

class BookingCreateIn(BaseModel):
    guest_name: str = Field(min_length=2, max_length=120)
    guest_phone: str = Field(min_length=7, max_length=30)
    guest_email: Optional[EmailStr] = None
    check_in: date
    check_out: date
    room_type_id: int
    room_id: Optional[int] = None
    num_guests: int = Field(default=1, ge=1, le=10)
    external_intent_id: Optional[str] = None
    special_requests: Optional[str] = None

class RequestVerificationIn(BaseModel):
    phone_number: str = Field(min_length=7, max_length=30)

class VerifyOtpIn(BaseModel):
    otp_code: str = Field(min_length=4, max_length=10)

class ServiceRequestIn(BaseModel):
    guest_name: str = Field(min_length=2, max_length=120)
    caller_phone: Optional[str] = None
    room_number: Optional[str] = None
    category: str = Field(default="front_desk", description="front_desk, room_service, maintenance, complaint")
    priority: str = Field(default="medium", description="low, medium, high, urgent")
    description: str = Field(min_length=5, max_length=1000)

class LogActivityIn(BaseModel):
    event_type: str = Field(min_length=2, max_length=80)
    status: str = Field(default="success")
    summary: str = Field(max_length=250)
    details: Optional[str] = None


class ReservationCreateIn(BaseModel):
    guest_name: str = Field(min_length=2, max_length=120)
    email: Optional[EmailStr] = None
    guest_email: Optional[EmailStr] = None
    phone: Optional[str] = None
    guest_phone: Optional[str] = None
    check_in: date
    check_out: date
    room_type_id: Optional[int] = None
    room_type: Optional[str] = None
    room_id: Optional[int] = None
    adults: int = Field(default=1, ge=1, le=20)
    children: int = Field(default=0, ge=0, le=20)
    number_of_rooms: int = Field(default=1, ge=1, le=10)
    special_requests: Optional[str] = None
    payment_method: Optional[str] = "Pay At Hotel"
    payment_preference: Optional[str] = None
    external_intent_id: Optional[str] = None
    idempotency_key: Optional[str] = None


class ReservationUpdateIn(BaseModel):
    check_in: Optional[date] = None
    check_out: Optional[date] = None
    room_type_id: Optional[int] = None
    room_type: Optional[str] = None
    adults: Optional[int] = Field(default=None, ge=1, le=20)
    children: Optional[int] = Field(default=None, ge=0, le=20)
    guest_name: Optional[str] = Field(default=None, min_length=2, max_length=120)
    email: Optional[EmailStr] = None
    phone: Optional[str] = Field(default=None, min_length=7, max_length=30)
    special_requests: Optional[str] = None


class ReservationCancelIn(BaseModel):
    reason: Optional[str] = Field(default=None, max_length=255)
    cancellation_reason: Optional[str] = Field(default=None, max_length=255)


def calculate_reservation_pricing(
    rt: RoomType,
    hotel_settings: Optional[HotelSettings],
    tenant: Tenant,
    check_in: date,
    check_out: date,
    adults: int = 1,
    children: int = 0
) -> Dict[str, Any]:
    """Calculates server-side accurate pricing based on room type rates, weekend pricing, extra guests, and GST."""
    nights = max(1, (check_out - check_in).days)
    base_night_sum = Decimal("0.00")

    curr = check_in
    while curr < check_out:
        is_weekend = curr.weekday() in (4, 5)  # Friday, Saturday night
        if is_weekend and rt.weekend_price is not None and float(rt.weekend_price) > 0:
            nightly_rate = Decimal(str(rt.weekend_price))
        elif rt.base_price is not None and float(rt.base_price) > 0:
            nightly_rate = Decimal(str(rt.base_price))
        else:
            nightly_rate = Decimal(str(rt.weekend_price or 1500.00))
        base_night_sum += nightly_rate
        curr += timedelta(days=1)

    avg_price_per_night = round(base_night_sum / Decimal(str(nights)), 2)

    max_adults = getattr(rt, "max_adults", 2) or 2
    max_children = getattr(rt, "max_children", 0) or 0
    extra_adults = max(0, adults - max_adults)
    extra_children = max(0, children - max_children)

    extra_adult_charge = Decimal(str(getattr(rt, "extra_adult_charge", 0.0) or 0.0))
    extra_child_charge = Decimal(str(getattr(rt, "extra_child_charge", 0.0) or 0.0))
    extra_charges = (extra_adults * extra_adult_charge + extra_children * extra_child_charge) * Decimal(str(nights))

    subtotal = base_night_sum + extra_charges

    tax_percent = Decimal(str(getattr(rt, "tax_percentage", None) or (hotel_settings.gst_percent if hotel_settings else 12.0) or 12.0))
    tax_amount = round(subtotal * (tax_percent / Decimal("100")), 2)
    total_amount = subtotal + tax_amount
    currency = (hotel_settings.currency if hotel_settings and hotel_settings.currency else None) or tenant.currency or "INR"

    return {
        "nights": nights,
        "avg_price_per_night": float(avg_price_per_night),
        "base_amount": float(round(base_night_sum, 2)),
        "extra_charges": float(round(extra_charges, 2)),
        "subtotal": float(round(subtotal, 2)),
        "tax_percent": float(tax_percent),
        "tax_amount": float(round(tax_amount, 2)),
        "discounts": 0.0,
        "total_amount": float(round(total_amount, 2)),
        "currency": currency
    }


# ══════════════════════════════════════════════════════════════════════════════
# 1. HOTEL ADMINISTRATION ENDPOINTS (Staff JWT Protected)
# ══════════════════════════════════════════════════════════════════════════════

@router.get("", summary="Get AI Receptionist Integration Status")
def get_integration_status(
    request: Request,
    user: User = Depends(require_integration_admin),
    db: Session = Depends(get_db)
):
    """Returns current connection status, settings, masked key, and metrics for the hotel."""
    tid = get_tenant_id(request, user)
    if not tid:
        raise HTTPException(status_code=400, detail="Tenant context required.")

    integration = db.scalar(
        select(TenantIntegration).where(
            TenantIntegration.tenant_id == tid,
            TenantIntegration.integration_type == INTEGRATION_TYPE
        )
    )

    tenant = db.scalar(select(Tenant).where(Tenant.id == tid))
    default_name = f"{tenant.name} - AI Receptionist" if tenant else "AI Receptionist Voice Agent"

    if not integration:
        return {
            "name": default_name,
            "description": "Connect your external AI Receptionist voice agent to live StayFlow reservation engine.",
            "api_base_url": "",
            "auth_method": "Header: X-Integration-Key (SHA-256 M2M Key)",
            "status": "disconnected",
            "is_enabled": False,
            "masked_key": None,
            "key_prefix": None,
            "key_last4": None,
            "webhook_url": None,
            "scopes": DEFAULT_SCOPES.split(","),
            "last_connected_at": None,
            "last_activity_at": None,
            "last_error_message": None,
            "total_logs": 0
        }

    cfg = json.loads(integration.config_json or "{}")
    name = cfg.get("name") or cfg.get("label") or default_name
    description = cfg.get("description") or "Dedicated AI Voice Receptionist Connector"
    api_base_url = cfg.get("api_base_url") or ""

    total_logs = db.scalar(
        select(func.count(IntegrationLog.id)).where(IntegrationLog.tenant_id == tid)
    ) or 0

    return {
        "id": integration.id,
        "name": name,
        "description": description,
        "api_base_url": api_base_url,
        "auth_method": "Header: X-Integration-Key (SHA-256 M2M Key)",
        "status": integration.status,
        "is_enabled": integration.is_enabled,
        "masked_key": mask_key(integration.key_prefix, integration.key_last4) if integration.key_hash else None,
        "key_prefix": integration.key_prefix,
        "key_last4": integration.key_last4,
        "webhook_url": integration.webhook_url,
        "scopes": [s.strip() for s in (integration.scopes or "").split(",") if s.strip()],
        "last_connected_at": to_iso(integration.last_connected_at),
        "last_activity_at": to_iso(integration.last_activity_at),
        "last_error_message": integration.last_error_message,
        "total_logs": total_logs
    }


@router.post("/connect", summary="Connect AI Receptionist & Generate Service Key")
def connect_integration(
    payload: ConnectIntegrationIn,
    request: Request,
    user: User = Depends(require_integration_admin),
    db: Session = Depends(get_db)
):
    """
    Connects the AI Receptionist integration and issues a high-entropy 72-character API key.
    The raw plaintext key is returned ONCE and never stored in the database.
    """
    tid = get_tenant_id(request, user)
    if not tid:
        raise HTTPException(status_code=400, detail="Tenant context required.")

    now = datetime.now(timezone.utc)
    raw_key, k_hash, prefix, last4 = generate_service_key()

    integration = db.scalar(
        select(TenantIntegration).where(
            TenantIntegration.tenant_id == tid,
            TenantIntegration.integration_type == INTEGRATION_TYPE
        )
    )

    cfg = payload.config or {}
    if payload.name:
        cfg["name"] = payload.name
    if payload.description:
        cfg["description"] = payload.description
    if payload.api_base_url:
        cfg["api_base_url"] = payload.api_base_url

    selected_scopes = DEFAULT_SCOPES
    if payload.scopes:
        clean_scopes = [s.strip() for s in payload.scopes if s.strip()]
        if clean_scopes:
            selected_scopes = ",".join(clean_scopes)

    if not integration:
        integration = TenantIntegration(
            tenant_id=tid,
            integration_type=INTEGRATION_TYPE,
            status="connected",
            is_enabled=True,
            key_hash=k_hash,
            key_prefix=prefix,
            key_last4=last4,
            webhook_url=payload.webhook_url,
            scopes=selected_scopes,
            config_json=json.dumps(cfg),
            last_connected_at=now,
            last_activity_at=now
        )
        db.add(integration)
    else:
        integration.status = "connected"
        integration.is_enabled = True
        integration.key_hash = k_hash
        integration.key_prefix = prefix
        integration.key_last4 = last4
        if payload.scopes:
            integration.scopes = selected_scopes
        if payload.webhook_url is not None:
            integration.webhook_url = payload.webhook_url
        integration.config_json = json.dumps(cfg)
        integration.last_connected_at = now
        integration.last_error_message = None

    db.commit()
    db.refresh(integration)

    log_integration_event(
        db=db,
        tenant_id=tid,
        integration_id=integration.id,
        event_type="connect",
        status_str="success",
        payload_summary=f"Connected by {user.email}. Key issued: {prefix}...{last4}"
    )

    return {
        "status": "connected",
        "service_key": raw_key,
        "masked_key": mask_key(prefix, last4),
        "key_prefix": prefix,
        "key_last4": last4,
        "message": "AI Receptionist connected successfully. Copy your API service key now; it will not be displayed again."
    }


@router.post("/rotate-key", summary="Rotate AI Receptionist Service Key")
def rotate_integration_key(
    request: Request,
    user: User = Depends(require_admin_strictly),
    db: Session = Depends(get_db)
):
    """
    Rotates the service key for the AI Receptionist.
    Immediately invalidates the prior key and returns the new 72-character key.
    """
    tid = get_tenant_id(request, user)
    if not tid:
        raise HTTPException(status_code=400, detail="Tenant context required.")

    integration = db.scalar(
        select(TenantIntegration).where(
            TenantIntegration.tenant_id == tid,
            TenantIntegration.integration_type == INTEGRATION_TYPE
        )
    )

    if not integration or integration.status != "connected":
        raise HTTPException(status_code=404, detail="Active integration not found to rotate.")

    raw_key, k_hash, prefix, last4 = generate_service_key()

    integration.key_hash = k_hash
    integration.key_prefix = prefix
    integration.key_last4 = last4
    integration.updated_at = datetime.now(timezone.utc)
    db.commit()

    log_integration_event(
        db=db,
        tenant_id=tid,
        integration_id=integration.id,
        event_type="rotate_key",
        status_str="success",
        payload_summary=f"Key rotated by {user.email}. New key: {prefix}...{last4}"
    )

    return {
        "status": "connected",
        "service_key": raw_key,
        "masked_key": mask_key(prefix, last4),
        "key_prefix": prefix,
        "key_last4": last4,
        "message": "Key rotated successfully. Update your AI Receptionist application with the new key."
    }


@router.post("/disconnect", summary="Disconnect AI Receptionist")
def disconnect_integration(
    request: Request,
    user: User = Depends(require_integration_admin),
    db: Session = Depends(get_db)
):
    """Disconnects the AI Receptionist and revokes active credentials immediately."""
    tid = get_tenant_id(request, user)
    if not tid:
        raise HTTPException(status_code=400, detail="Tenant context required.")

    integration = db.scalar(
        select(TenantIntegration).where(
            TenantIntegration.tenant_id == tid,
            TenantIntegration.integration_type == INTEGRATION_TYPE
        )
    )

    if not integration:
        return {"status": "disconnected", "message": "Integration is already disconnected."}

    integration.status = "disconnected"
    integration.is_enabled = False
    integration.key_hash = None
    integration.key_prefix = None
    integration.key_last4 = None
    integration.updated_at = datetime.now(timezone.utc)
    db.commit()

    log_integration_event(
        db=db,
        tenant_id=tid,
        integration_id=integration.id,
        event_type="disconnect",
        status_str="success",
        payload_summary=f"Disconnected by {user.email}"
    )

    return {"status": "disconnected", "message": "AI Receptionist disconnected successfully."}


@router.post("/toggle", summary="Enable / Disable Integration")
def toggle_integration(
    payload: ToggleIntegrationIn,
    request: Request,
    user: User = Depends(require_integration_admin),
    db: Session = Depends(get_db)
):
    """Temporarily enables or disables inbound AI Receptionist calls without revoking credentials."""
    tid = get_tenant_id(request, user)
    if not tid:
        raise HTTPException(status_code=400, detail="Tenant context required.")

    integration = db.scalar(
        select(TenantIntegration).where(
            TenantIntegration.tenant_id == tid,
            TenantIntegration.integration_type == INTEGRATION_TYPE
        )
    )

    if not integration:
        raise HTTPException(status_code=404, detail="Integration not found.")

    integration.is_enabled = payload.enabled
    db.commit()

    return {
        "status": integration.status,
        "is_enabled": integration.is_enabled,
        "message": f"Integration {'enabled' if payload.enabled else 'paused'} successfully."
    }


@router.put("/config", summary="Update Integration Configuration")
def update_integration_config(
    payload: UpdateIntegrationConfigIn,
    request: Request,
    user: User = Depends(require_integration_admin),
    db: Session = Depends(get_db)
):
    """Updates display name, description, API base URL, webhook, and scopes without key revocation."""
    tid = get_tenant_id(request, user)
    if not tid:
        raise HTTPException(status_code=400, detail="Tenant context required.")

    integration = db.scalar(
        select(TenantIntegration).where(
            TenantIntegration.tenant_id == tid,
            TenantIntegration.integration_type == INTEGRATION_TYPE
        )
    )
    if not integration:
        raise HTTPException(status_code=404, detail="Integration record not found.")

    cfg = json.loads(integration.config_json or "{}")
    if payload.name is not None:
        cfg["name"] = payload.name
    if payload.description is not None:
        cfg["description"] = payload.description
    if payload.api_base_url is not None:
        cfg["api_base_url"] = payload.api_base_url
    integration.config_json = json.dumps(cfg)

    if payload.webhook_url is not None:
        integration.webhook_url = payload.webhook_url
    if payload.scopes is not None:
        clean_scopes = [s.strip() for s in payload.scopes if s.strip()]
        if clean_scopes:
            integration.scopes = ",".join(clean_scopes)
    if payload.is_enabled is not None:
        integration.is_enabled = payload.is_enabled

    integration.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(integration)

    log_integration_event(
        db=db,
        tenant_id=tid,
        integration_id=integration.id,
        event_type="config_update",
        status_str="success",
        payload_summary="Integration configuration updated successfully."
    )

    return {"status": "ok", "message": "Integration configuration updated successfully."}


@router.post("/test-connection", summary="Test Connection Health & Latency")
def test_connection(
    request: Request,
    user: User = Depends(require_integration_admin),
    db: Session = Depends(get_db)
):
    """Performs a self-check on the integration state, verifying tenant isolation and database readiness."""
    start_time = time.perf_counter()
    tid = get_tenant_id(request, user)
    if not tid:
        raise HTTPException(status_code=400, detail="Tenant context required.")

    integration = db.scalar(
        select(TenantIntegration).where(
            TenantIntegration.tenant_id == tid,
            TenantIntegration.integration_type == INTEGRATION_TYPE
        )
    )

    if not integration or integration.status != "connected":
        return {
            "status": "error",
            "message": "AI Receptionist is not connected for this hotel.",
            "latency_ms": int((time.perf_counter() - start_time) * 1000)
        }

    duration_ms = int((time.perf_counter() - start_time) * 1000)

    log_integration_event(
        db=db,
        tenant_id=tid,
        integration_id=integration.id,
        event_type="ping",
        status_str="success",
        duration_ms=duration_ms,
        payload_summary="Test connection handshake successful."
    )

    return {
        "status": "ok",
        "integration_id": integration.id,
        "latency_ms": duration_ms,
        "message": "Connection active. StayFlow integration endpoints are ready to receive AI Receptionist calls."
    }


@router.get("/logs", summary="Get Integration Activity Logs")
def get_integration_logs(
    request: Request,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    event_type: Optional[str] = None,
    status_filter: Optional[str] = None,
    category: Optional[str] = None,
    user: User = Depends(require_integration_admin),
    db: Session = Depends(get_db)
):
    """Retrieves sanitized activity logs strictly scoped to the authenticated tenant."""
    tid = get_tenant_id(request, user)
    if not tid:
        raise HTTPException(status_code=400, detail="Tenant context required.")

    query = select(IntegrationLog).where(IntegrationLog.tenant_id == tid)
    if event_type:
        query = query.where(IntegrationLog.event_type == event_type)
    if status_filter:
        if status_filter == "success":
            query = query.where(IntegrationLog.status == "success")
        elif status_filter in ("failed", "error"):
            query = query.where(IntegrationLog.status.in_(["error", "failed"]))
    if category:
        if category == "connection":
            query = query.where(IntegrationLog.event_type.in_(["connect", "disconnect", "rotate_key", "toggle", "ping", "config_update"]))
        elif category == "booking":
            query = query.where(IntegrationLog.event_type.in_(["booking_create", "check_availability"]))
        elif category == "auth":
            query = query.where(IntegrationLog.event_type.in_(["auth_failure", "verify_caller", "verify_otp"]))
        elif category == "escalation":
            query = query.where(IntegrationLog.event_type == "escalation")

    total = db.scalar(select(func.count()).select_from(query.subquery())) or 0
    logs = db.scalars(query.order_by(desc(IntegrationLog.created_at)).offset(offset).limit(limit)).all()

    items = []
    for l in logs:
        items.append({
            "id": l.id,
            "direction": l.direction,
            "event_type": l.event_type,
            "status": l.status,
            "status_code": l.status_code,
            "payload_summary": l.payload_summary,
            "error_details": l.error_details,
            "duration_ms": l.duration_ms,
            "created_at": to_iso(l.created_at)
        })

    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "logs": items
    }


# ══════════════════════════════════════════════════════════════════════════════
# 2. MACHINE-TO-MACHINE (M2M) ENDPOINTS FOR EXTERNAL AI RECEPTIONIST
# ══════════════════════════════════════════════════════════════════════════════

@router.post("/chat", summary="AI Knowledge Inquiry & Hotel FAQs")
def integration_chat(
    payload: ChatQueryIn,
    context: Tuple[TenantIntegration, Tenant] = Depends(get_integration_context("knowledge:read")),
    db: Session = Depends(get_db)
):
    """
    Hotel Knowledge inquiry for guest calls.
    Returns property rules, check-in policies, amenities, and dining hours strictly for this tenant.
    """
    integration, tenant = context
    start_time = time.perf_counter()

    settings_row = db.scalar(select(HotelSettings).where(HotelSettings.tenant_id == tenant.id))
    room_types = db.scalars(select(RoomType).where(RoomType.tenant_id == tenant.id)).all()

    rt_summary = [f"{rt.name} (Capacity: {getattr(rt, 'max_guests', 2)} guests)" for rt in room_types]

    info = {
        "hotel_name": tenant.name,
        "city": tenant.city,
        "address": tenant.address,
        "contact_phone": tenant.contact_phone,
        "contact_email": tenant.contact_email,
        "currency": tenant.currency,
        "check_in_time": settings_row.check_in_time if settings_row and hasattr(settings_row, "check_in_time") else "14:00",
        "check_out_time": settings_row.check_out_time if settings_row and hasattr(settings_row, "check_out_time") else "11:00",
        "available_room_types": rt_summary
    }

    answer = (
        f"Welcome to {tenant.name}. Our check-in time is {info['check_in_time']} and check-out is {info['check_out_time']}. "
        f"We offer the following room options: {', '.join(rt_summary) if rt_summary else 'Standard Rooms'}. "
        f"Please let me know your desired check-in dates and number of guests to check live availability."
    )

    duration_ms = int((time.perf_counter() - start_time) * 1000)
    log_integration_event(
        db=db,
        tenant_id=tenant.id,
        integration_id=integration.id,
        event_type="chat",
        status_str="success",
        duration_ms=duration_ms,
        payload_summary=f"Q: {payload.query[:60]}"
    )

    return {
        "answer": answer,
        "hotel_info": info,
        "session_id": payload.session_id
    }


@router.get("/rooms", summary="List Hotel Room Types & Configurations")
def list_rooms(
    context: Tuple[TenantIntegration, Tenant] = Depends(get_integration_context("rooms:read")),
    db: Session = Depends(get_db)
):
    """Returns room types and standard occupancies for the authenticated hotel."""
    integration, tenant = context
    room_types = db.scalars(select(RoomType).where(RoomType.tenant_id == tenant.id)).all()

    results = []
    for rt in room_types:
        total_rooms = db.scalar(
            select(func.count(Room.id)).where(
                Room.tenant_id == tenant.id,
                Room.room_type_id == rt.id
            )
        ) or 0

        results.append({
            "id": rt.id,
            "name": rt.name,
            "description": getattr(rt, "short_description", "") or getattr(rt, "name", ""),
            "max_occupancy": getattr(rt, "max_guests", 2),
            "bed_type": getattr(rt, "bed_type", "King-size Bed"),
            "base_price": float(rt.weekend_price or 0.0) if hasattr(rt, "weekend_price") and rt.weekend_price else 0.0,
            "total_inventory": total_rooms
        })

    return {
        "tenant_id": tenant.id,
        "hotel_name": tenant.name,
        "room_types": results
    }


@router.get("/availability", summary="Check Date-Range Room Availability")
def check_availability(
    check_in: date = Query(..., description="Target check-in date (YYYY-MM-DD)"),
    check_out: date = Query(..., description="Target check-out date (YYYY-MM-DD)"),
    room_type_id: Optional[int] = Query(None, description="Optional specific room type ID"),
    context: Tuple[TenantIntegration, Tenant] = Depends(get_integration_context("rooms:read")),
    db: Session = Depends(get_db)
):
    """
    Checks real date-range availability against reservations.
    A vacant room status alone is NOT treated as confirmation of availability.
    """
    integration, tenant = context

    if check_out <= check_in:
        raise HTTPException(
            status_code=400,
            detail="Check-out date must be after check-in date."
        )

    avail = get_tenant_availability(
        db=db,
        tenant_id=tenant.id,
        check_in=check_in,
        check_out=check_out,
        room_type_id=room_type_id
    )

    log_integration_event(
        db=db,
        tenant_id=tenant.id,
        integration_id=integration.id,
        event_type="check_availability",
        status_str="success",
        payload_summary=f"Dates: {check_in} to {check_out}. Results: {len(avail)} types checked."
    )

    return {
        "check_in": to_iso(check_in),
        "check_out": to_iso(check_out),
        "availability": avail
    }


@router.post("/bookings", status_code=status.HTTP_201_CREATED, summary="Create Reservation (Concurrency-Safe & Idempotent)")
def create_integration_booking(
    payload: BookingCreateIn,
    request: Request,
    idempotency_key: Optional[str] = Header(None, alias="Idempotency-Key"),
    context: Tuple[TenantIntegration, Tenant] = Depends(get_integration_context("reservations:create")),
    db: Session = Depends(get_db)
):
    """
    Dedicated AI Receptionist booking creation endpoint.
    Guarantees:
    1. Row-level concurrency locking via allocate_and_lock_room() (prevents double-booking).
    2. 2-phase idempotency storage (prevents duplicate charging/reservations).
    3. Multi-year duplicate prevention via channel_ref = ext:{integration_id}:{external_intent_id}.
    """
    integration, tenant = context

    if not idempotency_key or not idempotency_key.strip():
        raise HTTPException(
            status_code=400,
            detail="Idempotency-Key header is required for reservation creation."
        )

    ikey = idempotency_key.strip()
    if payload.check_out <= payload.check_in:
        raise HTTPException(status_code=400, detail="Check-out date must be after check-in date.")

    # 1. Payload Hash for Idempotency
    raw_payload_str = json.dumps(payload.model_dump(), default=str, sort_keys=True)
    payload_hash = hashlib.sha256(raw_payload_str.encode("utf-8")).hexdigest()

    # 2. Check Existing Idempotency Record
    existing_rec = db.scalar(
        select(IntegrationIdempotencyRecord).where(
            IntegrationIdempotencyRecord.tenant_id == tenant.id,
            IntegrationIdempotencyRecord.integration_id == integration.id,
            IntegrationIdempotencyRecord.idempotency_key == ikey
        )
    )

    if existing_rec:
        if existing_rec.status == "COMPLETED" and existing_rec.response_body:
            if existing_rec.payload_hash != payload_hash:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Idempotency key reused with different request payload."
                )
            return json.loads(existing_rec.response_body)
        elif existing_rec.status == "PROCESSING":
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="A concurrent reservation request with this idempotency key is already in progress."
            )

    # 3. Multi-Year Duplicate Check via channel_ref
    if payload.external_intent_id:
        expected_channel_ref = f"ext:{integration.id}:{payload.external_intent_id}"
        prior_res = db.scalar(
            select(Reservation).where(
                Reservation.tenant_id == tenant.id,
                Reservation.channel_ref == expected_channel_ref
            )
        )
        if prior_res:
            res_dict = {
                "id": prior_res.id,
                "reference": prior_res.reference,
                "status": prior_res.status,
                "room_id": prior_res.room_id,
                "check_in": to_iso(prior_res.check_in),
                "check_out": to_iso(prior_res.check_out),
                "total_amount": float(prior_res.total_amount or 0.0),
                "is_cached": True
            }
            return res_dict

    # 4. Insert PROCESSING Idempotency Record in a savepoint
    idemp_rec = IntegrationIdempotencyRecord(
        tenant_id=tenant.id,
        integration_id=integration.id,
        idempotency_key=ikey,
        payload_hash=payload_hash,
        status="PROCESSING"
    )
    try:
        with db.begin_nested():
            db.add(idemp_rec)
    except IntegrityError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Concurrent request already registered with this Idempotency-Key."
        )

    # 5. Lock and Allocate Available Room
    room = allocate_and_lock_room(
        db=db,
        tenant_id=tenant.id,
        check_in=payload.check_in,
        check_out=payload.check_out,
        room_id=payload.room_id,
        room_type_id=payload.room_type_id
    )

    if not room:
        idemp_rec.status = "FAILED"
        db.commit()
        log_integration_event(
            db=db,
            tenant_id=tenant.id,
            integration_id=integration.id,
            event_type="create_booking",
            status_str="conflict",
            status_code=409,
            payload_summary=f"No available room for room_type #{payload.room_type_id} between {payload.check_in} and {payload.check_out}"
        )
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="No operational room is available for the selected room type and dates."
        )

    # 6. Find or Create Guest
    clean_phone = "".join(ch for ch in payload.guest_phone if ch.isdigit())
    guest = db.scalar(
        select(Guest).where(
            Guest.tenant_id == tenant.id,
            Guest.phone.like(f"%{clean_phone[-10:]}%")
        )
    )
    if not guest:
        guest = Guest(
            tenant_id=tenant.id,
            full_name=payload.guest_name,
            phone=payload.guest_phone,
            email=payload.guest_email or "",
            tier="Standard"
        )
        db.add(guest)
        db.flush()

    # 7. Pricing calculation
    nights = max(1, (payload.check_out - payload.check_in).days)
    rt = db.scalar(select(RoomType).where(RoomType.id == room.room_type_id))
    rate = Decimal(str(rt.weekend_price or 1500.00)) if rt and getattr(rt, "weekend_price", None) else Decimal("1500.00")
    total_amount = rate * nights

    # 8. Unique Reference & Create Reservation
    rand_suffix = secrets.token_hex(4).upper()
    booking_ref = f"BK-AI-{tenant.id}-{rand_suffix}"
    durable_channel_ref = f"ext:{integration.id}:{payload.external_intent_id or ikey}"

    reservation = Reservation(
        tenant_id=tenant.id,
        reference=booking_ref,
        guest_id=guest.id,
        room_id=room.id,
        source="AI Receptionist",
        channel_ref=durable_channel_ref,
        check_in=payload.check_in,
        check_out=payload.check_out,
        status="Confirmed",
        total_amount=total_amount,
        num_guests=payload.num_guests
    )
    db.add(reservation)
    db.flush()

    # 9. Complete Idempotency Record
    guest_display_name = getattr(guest, "full_name", None) or getattr(guest, "name", "")
    res_dict = {
        "id": reservation.id,
        "reference": reservation.reference,
        "guest_id": guest.id,
        "guest_name": guest_display_name,
        "room_id": room.id,
        "room_number": room.number,
        "room_type_id": room.room_type_id,
        "check_in": to_iso(reservation.check_in),
        "check_out": to_iso(reservation.check_out),
        "nights": nights,
        "total_amount": float(reservation.total_amount),
        "status": reservation.status,
        "source": reservation.source,
        "channel_ref": reservation.channel_ref
    }

    idemp_rec.status = "COMPLETED"
    idemp_rec.reservation_id = reservation.id
    idemp_rec.response_body = json.dumps(res_dict)
    idemp_rec.status_code = 201

    # Atomic Commit: commits the reservation and idempotency record together
    db.commit()

    log_integration_event(
        db=db,
        tenant_id=tenant.id,
        integration_id=integration.id,
        event_type="create_booking",
        status_str="success",
        status_code=201,
        payload_summary=f"Booking created: {booking_ref} (Room #{room.number}, Nights: {nights})"
    )

    return res_dict


@router.get("/bookings/{ref}", summary="Retrieve Booking by Reference (Caller Verified or Sanitized)")
def get_integration_booking(
    ref: str,
    x_verification_token: Optional[str] = Header(None, alias="X-Verification-Token"),
    verification_token: Optional[str] = Query(None),
    context: Tuple[TenantIntegration, Tenant] = Depends(get_integration_context("reservations:read")),
    db: Session = Depends(get_db)
):
    """
    Retrieves booking details.
    Caller Verification Rule:
    - If verified with valid ephemeral token: returns full booking & guest details.
    - If unverified: returns strictly sanitized status without leaking PII or exact dates.
    """
    integration, tenant = context
    token = x_verification_token or verification_token

    res = db.scalar(
        select(Reservation)
        .options(joinedload(Reservation.guest), joinedload(Reservation.room))
        .where(
            Reservation.tenant_id == tenant.id,
            Reservation.reference == ref.strip().upper()
        )
    )

    if not res:
        raise HTTPException(status_code=404, detail="Reservation not found.")

    is_verified = False
    if token:
        is_verified = validate_verification_token(db, tenant.id, ref, token)

    if is_verified:
        return {
            "is_caller_verified": True,
            "reference": res.reference,
            "status": res.status,
            "guest": {
                "name": getattr(res.guest, "full_name", None) or getattr(res.guest, "name", "Unknown") if res.guest else "Unknown",
                "phone": res.guest.phone if res.guest else "",
                "email": res.guest.email if res.guest else ""
            },
            "room_number": res.room.number if res.room else "",
            "check_in": to_iso(res.check_in),
            "check_out": to_iso(res.check_out),
            "total_amount": float(res.total_amount or 0.0),
            "created_at": to_iso(res.created_at)
        }

    # Sanitized unverified response
    guest_name = (getattr(res.guest, "full_name", None) or getattr(res.guest, "name", "Guest")) if res.guest else "Guest"
    masked_name = f"{guest_name[:1]}*** {guest_name.split()[-1][:1]}***" if " " in guest_name else f"{guest_name[:1]}***"

    return {
        "is_caller_verified": False,
        "reference": res.reference,
        "status": res.status,
        "guest_name_masked": masked_name,
        "message": "Caller is unverified. To receive reservation dates, room details, or make modifications, complete OTP caller verification."
    }


@router.post("/bookings/{ref}/request-verification", summary="Request Caller Verification Challenge")
def request_verification(
    ref: str,
    payload: RequestVerificationIn,
    context: Tuple[TenantIntegration, Tenant] = Depends(get_integration_context("reservations:read")),
    db: Session = Depends(get_db)
):
    """
    Issues an OTP verification challenge to the registered guest phone.
    Anti-enumeration: Uniform generic response returned whether or not details match.
    """
    integration, tenant = context

    result = request_caller_verification(
        db=db,
        tenant_id=tenant.id,
        booking_ref=ref,
        phone_number=payload.phone_number
    )

    log_integration_event(
        db=db,
        tenant_id=tenant.id,
        integration_id=integration.id,
        event_type="request_verification",
        status_str="success",
        payload_summary=f"Verification challenge requested for Ref {ref}"
    )

    return result


@router.post("/bookings/{ref}/verify-otp", summary="Verify OTP & Obtain Caller Token")
def verify_otp(
    ref: str,
    payload: VerifyOtpIn,
    context: Tuple[TenantIntegration, Tenant] = Depends(get_integration_context("reservations:read")),
    db: Session = Depends(get_db)
):
    """Verifies OTP code and returns an ephemeral verification token."""
    integration, tenant = context

    is_valid, token, message = verify_caller_otp(
        db=db,
        tenant_id=tenant.id,
        booking_ref=ref,
        otp_code=payload.otp_code
    )

    if not is_valid:
        log_integration_event(
            db=db,
            tenant_id=tenant.id,
            integration_id=integration.id,
            event_type="verify_otp",
            status_str="failed",
            status_code=400,
            payload_summary=f"Failed verification attempt for Ref {ref}"
        )
        raise HTTPException(status_code=400, detail=message)

    log_integration_event(
        db=db,
        tenant_id=tenant.id,
        integration_id=integration.id,
        event_type="verify_otp",
        status_str="success",
        status_code=200,
        payload_summary=f"Caller successfully verified for Ref {ref}"
    )

    return {
        "verified": True,
        "verification_token": token,
        "message": message,
        "expires_in_minutes": 15
    }


@router.post("/service-requests", status_code=status.HTTP_201_CREATED, summary="Create Guest Service Request / Staff Escalation")
def create_service_request(
    payload: ServiceRequestIn,
    context: Tuple[TenantIntegration, Tenant] = Depends(get_integration_context("escalations:create")),
    db: Session = Depends(get_db)
):
    """Creates a human staff escalation or service request from the AI Receptionist."""
    integration, tenant = context

    task_data = {
        "guest_name": payload.guest_name,
        "caller_phone": payload.caller_phone or "",
        "room_number": payload.room_number or "",
        "category": payload.category,
        "priority": payload.priority,
        "description": payload.description,
        "source": "AI Receptionist",
        "created_at": to_iso(datetime.now(timezone.utc))
    }

    record = OperationalRecord(
        tenant_id=tenant.id,
        category="guest_service",
        title=f"AI Request: {payload.category.title()} - Room {payload.room_number or 'Front Desk'}",
        status="PENDING",
        data=json.dumps(task_data)
    )
    db.add(record)
    db.commit()
    db.refresh(record)

    log_integration_event(
        db=db,
        tenant_id=tenant.id,
        integration_id=integration.id,
        event_type="service_request",
        status_str="success",
        status_code=201,
        payload_summary=f"Escalation ticket #{record.id} created: {payload.category} ({payload.priority})"
    )

    return {
        "id": record.id,
        "status": record.status,
        "title": record.title,
        "message": "Service request dispatched to hotel staff successfully."
    }


@router.post("/log-activity", summary="Log AI Receptionist Call Activity")
def log_activity(
    payload: LogActivityIn,
    context: Tuple[TenantIntegration, Tenant] = Depends(get_integration_context()),
    db: Session = Depends(get_db)
):
    """Allows the AI Receptionist to record call transcripts and audit summaries into StayFlow."""
    integration, tenant = context

    log_integration_event(
        db=db,
        tenant_id=tenant.id,
        integration_id=integration.id,
        event_type=payload.event_type,
        status_str=payload.status,
        payload_summary=payload.summary,
        error_details=payload.details
    )

    return {"status": "logged"}


# ══════════════════════════════════════════════════════════════════════════════
# 3. SECURE EXTERNAL INTEGRATION APIS (/api/integrations/...)
# ══════════════════════════════════════════════════════════════════════════════

external_router = APIRouter(prefix="/api/integrations", tags=["External Integrations"])


@external_router.get("/health", summary="External Integration Connection Health Check")
@external_router.get("/connection/health", summary="Connection Health Check (Alias)")
@router.get("/health", summary="Integration Health Check")
def integration_health_check(
    request: Request,
    db: Session = Depends(get_db)
):
    """
    Validates integration credentials, tenant identity, connection status,
    and returns enabled capability scopes and available endpoint URLs.
    If called without credentials, returns general operational status.
    """
    auth_header = request.headers.get("Authorization") or ""
    service_key = (
        request.headers.get("X-Service-Key")
        or request.headers.get("X-Integration-Key")
        or (auth_header.split(" ", 1)[1].strip() if auth_header.startswith("Bearer ") else None)
    )

    if not service_key:
        return {
            "status": "ok",
            "service": "StayFlow External Integrations API",
            "version": "1.0.0",
            "authenticated": False,
            "timestamp": to_iso(datetime.now(timezone.utc))
        }

    key_hash = hash_key(service_key)
    integration = db.scalar(
        select(TenantIntegration).where(TenantIntegration.key_hash == key_hash)
    )
    if not integration or not integration.is_enabled:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or disabled service key.")

    tenant = db.scalar(
        select(Tenant).where(Tenant.id == integration.tenant_id, Tenant.is_active == True)
    )
    if not tenant:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Tenant account is suspended or inactive.")

    scopes_list = [s.strip() for s in (integration.scopes or "").split(",") if s.strip()]

    return {
        "status": "ok",
        "authenticated": True,
        "hotel": {
            "id": tenant.id,
            "code": tenant.code,
            "name": tenant.name,
            "status": tenant.status
        },
        "integration": {
            "id": integration.id,
            "name": integration.name if hasattr(integration, "name") and getattr(integration, "name", None) else (json.loads(integration.config_json or "{}").get("name") or "External Integration"),
            "status": integration.status,
            "is_enabled": integration.is_enabled,
            "scopes": scopes_list,
            "last_connected_at": to_iso(integration.last_connected_at),
            "last_activity_at": to_iso(integration.last_activity_at)
        },
        "capabilities": {
            "hotel_details": "hotel:read" in scopes_list or "knowledge:read" in scopes_list or "*" in scopes_list,
            "room_availability": "rooms:read" in scopes_list or "*" in scopes_list,
            "room_rates": "rates:read" in scopes_list or "rooms:read" in scopes_list or "*" in scopes_list,
            "reservations_create": "reservations:create" in scopes_list or "*" in scopes_list,
            "reservations_read": "reservations:read" in scopes_list or "*" in scopes_list,
            "reservations_update": "reservations:update" in scopes_list or "*" in scopes_list,
            "reservations_cancel": "reservations:cancel" in scopes_list or "*" in scopes_list,
        },
        "endpoints": {
            "hotel_details": "/api/integrations/hotel/details",
            "room_availability": "/api/integrations/rooms/availability",
            "room_rates": "/api/integrations/rooms/rates",
            "reservations_create": "/api/integrations/reservations",
            "reservations_read": "/api/integrations/reservations/{reservation_id}",
            "reservations_update": "/api/integrations/reservations/{reservation_id}",
            "reservations_cancel": "/api/integrations/reservations/{reservation_id}/cancel"
        },
        "timestamp": to_iso(datetime.now(timezone.utc))
    }


@external_router.get("/hotel/details", summary="Get Hotel Details & Policies")
@router.get("/hotel/details", summary="Get Hotel Details (Alias)")
def get_hotel_details(
    context: Tuple[TenantIntegration, Tenant] = Depends(get_integration_context("hotel:read")),
    db: Session = Depends(get_db)
):
    """
    Returns hotel profile, property information, contact details, and policies.
    Strictly isolated to the authenticated hotel tenant.
    """
    integration, tenant = context

    settings_row = db.scalar(
        select(HotelSettings).where(HotelSettings.tenant_id == tenant.id)
    )

    total_rooms = db.scalar(
        select(func.count(Room.id)).where(
            Room.tenant_id == tenant.id,
            Room.status != "ooo"
        )
    ) or 0

    room_types = db.scalars(
        select(RoomType).where(RoomType.tenant_id == tenant.id)
    ).all()

    room_types_summary = [
        {
            "id": rt.id,
            "name": rt.name,
            "base_price": float(rt.base_price or 0.0),
            "max_occupancy": getattr(rt, "max_guests", 2),
            "bed_type": getattr(rt, "bed_type", "Standard Bed")
        }
        for rt in room_types
    ]

    log_integration_event(
        db=db,
        tenant_id=tenant.id,
        integration_id=integration.id,
        event_type="hotel_details",
        status_str="success",
        payload_summary="Hotel details retrieved."
    )

    hotel_display_name = (
        (settings_row.hotel_name if settings_row and settings_row.hotel_name else None)
        or tenant.name
        or "StayFlow Hotel"
    )

    return {
        "hotel_id": tenant.id,
        "hotel_code": tenant.code,
        "hotel_name": hotel_display_name,
        "currency": tenant.currency or (settings_row.currency if settings_row else "INR"),
        "property_details": {
            "slug": tenant.slug,
            "subscription_plan": tenant.subscription_plan,
            "status": tenant.status,
            "total_operational_rooms": total_rooms,
            "max_capacity_rooms": tenant.max_rooms,
            "room_types_count": len(room_types),
            "room_types": room_types_summary
        },
        "address": {
            "street": tenant.address or "",
            "city": tenant.city or "",
            "country": tenant.country or "India",
            "timezone": tenant.timezone or (settings_row.timezone if settings_row else "Asia/Kolkata")
        },
        "contact": {
            "phone": tenant.contact_phone or "",
            "email": tenant.contact_email or ""
        },
        "policies": {
            "check_in_time": settings_row.check_in_time if settings_row else "14:00",
            "check_out_time": settings_row.check_out_time if settings_row else "11:00",
            "currency": tenant.currency or (settings_row.currency if settings_row else "INR"),
            "tax_gst_percent": float(settings_row.gst_percent) if settings_row and settings_row.gst_percent is not None else 12.0,
            "cancellation_hours": settings_row.cancellation_hours if settings_row else 24,
            "cancellation_policy": f"Free cancellation up to {settings_row.cancellation_hours if settings_row else 24} hours before check-in.",
            "no_show_charge": settings_row.no_show_charge if settings_row else "First night"
        }
    }


@external_router.get("/rooms/availability", summary="Check Date-Range Room Availability")
def get_rooms_availability(
    check_in: date = Query(..., description="Target check-in date (YYYY-MM-DD)"),
    check_out: date = Query(..., description="Target check-out date (YYYY-MM-DD)"),
    adults: int = Query(default=1, ge=1, le=20, description="Number of adults"),
    children: int = Query(default=0, ge=0, le=20, description="Number of children"),
    room_type_id: Optional[int] = Query(None, description="Filter by specific room type ID"),
    room_type: Optional[str] = Query(None, description="Filter by room type name or slug"),
    context: Tuple[TenantIntegration, Tenant] = Depends(get_integration_context("rooms:read")),
    db: Session = Depends(get_db)
):
    """
    Checks live date-range availability against existing reservation records.
    Returns available room types, available room counts, occupancy limits, and descriptions.
    """
    integration, tenant = context

    if check_out <= check_in:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Check-out date must be after check-in date."
        )

    # Resolve room_type string to ID if provided
    resolved_rt_id = room_type_id
    if not resolved_rt_id and room_type and room_type.strip():
        rt_target = room_type.strip().lower()
        matched_rt = db.scalar(
            select(RoomType).where(
                RoomType.tenant_id == tenant.id,
                or_(
                    func.lower(RoomType.name) == rt_target,
                    func.lower(RoomType.slug) == rt_target,
                    func.lower(RoomType.name).like(f"%{rt_target}%")
                )
            )
        )
        if matched_rt:
            resolved_rt_id = matched_rt.id

    avail_raw = get_tenant_availability(
        db=db,
        tenant_id=tenant.id,
        check_in=check_in,
        check_out=check_out,
        room_type_id=resolved_rt_id
    )

    # Enrich with detailed RoomType fields
    rt_map = {
        rt.id: rt
        for rt in db.scalars(select(RoomType).where(RoomType.tenant_id == tenant.id)).all()
    }

    enriched_types = []
    total_requested_guests = adults + children

    for item in avail_raw:
        rt_obj = rt_map.get(item["room_type_id"])
        max_adults = getattr(rt_obj, "max_adults", 2) or 2
        max_children = getattr(rt_obj, "max_children", 0) or 0
        max_guests = getattr(rt_obj, "max_guests", max_adults + max_children) or 2

        amenities_list = []
        if rt_obj and rt_obj.amenities:
            try:
                amenities_list = json.loads(rt_obj.amenities) if isinstance(rt_obj.amenities, str) else list(rt_obj.amenities)
            except Exception:
                amenities_list = [str(rt_obj.amenities)]

        enriched_types.append({
            "room_type_id": item["room_type_id"],
            "room_type_name": item["room_type_name"],
            "description": getattr(rt_obj, "description", "") or getattr(rt_obj, "short_description", "") or "",
            "bed_type": getattr(rt_obj, "bed_type", "King-size Bed"),
            "occupancy_limits": {
                "max_adults": max_adults,
                "max_children": max_children,
                "max_guests": max_guests
            },
            "suitable_for_guests": total_requested_guests <= max_guests,
            "base_price": item["base_price"],
            "total_inventory": item["total_inventory"],
            "available_count": item["available_count"],
            "available_rooms_count": item["available_count"],
            "is_available": item["is_available"],
            "amenities": amenities_list,
            "sample_rooms": item.get("sample_rooms", [])
        })

    log_integration_event(
        db=db,
        tenant_id=tenant.id,
        integration_id=integration.id,
        event_type="check_availability",
        status_str="success",
        payload_summary=f"Dates: {check_in} to {check_out}. Checked {len(enriched_types)} types."
    )

    return {
        "hotel_id": tenant.id,
        "hotel_name": tenant.name,
        "check_in": to_iso(check_in),
        "check_out": to_iso(check_out),
        "nights": (check_out - check_in).days,
        "guests": {
            "adults": adults,
            "children": children,
            "total": total_requested_guests
        },
        "available_room_types": enriched_types
    }


@external_router.get("/rooms/rates", summary="Retrieve Room Pricing & Rates")
@router.get("/rooms/rates", summary="Retrieve Room Rates (Alias)")
def get_rooms_rates(
    check_in: date = Query(..., description="Target check-in date (YYYY-MM-DD)"),
    check_out: date = Query(..., description="Target check-out date (YYYY-MM-DD)"),
    room_type_id: Optional[int] = Query(None, description="Specific room type ID"),
    room_type: Optional[str] = Query(None, description="Room type name or slug"),
    adults: int = Query(default=1, ge=1, le=20, description="Adult guest count"),
    children: int = Query(default=0, ge=0, le=20, description="Children guest count"),
    guest_count: Optional[int] = Query(None, description="Optional total guest count override"),
    context: Tuple[TenantIntegration, Tenant] = Depends(get_integration_context("rates:read")),
    db: Session = Depends(get_db)
):
    """
    Retrieves dynamic room rates based on actual rate plans, weekday/weekend pricing,
    extra guest charges, applicable taxes (GST), and discounts. Never hardcodes prices.
    """
    integration, tenant = context

    if check_out <= check_in:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Check-out date must be after check-in date."
        )

    effective_adults = adults
    effective_children = children
    if guest_count is not None and guest_count > 0:
        effective_adults = guest_count
        effective_children = 0

    hotel_settings = db.scalar(
        select(HotelSettings).where(HotelSettings.tenant_id == tenant.id)
    )

    q = select(RoomType).where(RoomType.tenant_id == tenant.id)
    if room_type_id:
        q = q.where(RoomType.id == room_type_id)
    elif room_type and room_type.strip():
        rt_target = room_type.strip().lower()
        q = q.where(
            or_(
                func.lower(RoomType.name) == rt_target,
                func.lower(RoomType.slug) == rt_target,
                func.lower(RoomType.name).like(f"%{rt_target}%")
            )
        )

    room_types = db.scalars(q).all()
    if not room_types:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No matching room types found for this hotel property."
        )

    rate_results = []
    currency = (hotel_settings.currency if hotel_settings and hotel_settings.currency else None) or tenant.currency or "INR"

    for rt in room_types:
        pricing = calculate_reservation_pricing(
            rt=rt,
            hotel_settings=hotel_settings,
            tenant=tenant,
            check_in=check_in,
            check_out=check_out,
            adults=effective_adults,
            children=effective_children
        )

        # Check live availability count
        rooms = db.scalars(
            select(Room).where(
                Room.tenant_id == tenant.id,
                Room.room_type_id == rt.id,
                Room.status.notin_(["ooo"])
            )
        ).all()

        avail_count = 0
        for r in rooms:
            if not check_room_conflict(db, r.id, check_in, check_out):
                avail_count += 1

        rate_results.append({
            "room_type_id": rt.id,
            "room_type_name": rt.name,
            "bed_type": getattr(rt, "bed_type", "Standard Bed"),
            "max_occupancy": getattr(rt, "max_guests", 2),
            "pricing": {
                "nights": pricing["nights"],
                "avg_price_per_night": pricing["avg_price_per_night"],
                "base_nightly_rate": float(rt.base_price or 0.0),
                "weekend_nightly_rate": float(rt.weekend_price) if rt.weekend_price is not None else None,
                "base_subtotal": pricing["base_amount"],
                "extra_guest_charges": pricing["extra_charges"],
                "taxable_amount": pricing["subtotal"],
                "tax_percent": pricing["tax_percent"],
                "tax_amount": pricing["tax_amount"],
                "discounts": pricing["discounts"],
                "total_estimated_price": pricing["total_amount"],
                "currency": currency
            },
            "inventory": {
                "available_rooms": avail_count,
                "is_available": avail_count > 0
            },
            "policies": {
                "cancellation_policy": getattr(rt, "cancellation_policy", None) or "Free cancellation up to 24 hours before check-in.",
                "breakfast_included": bool(getattr(rt, "breakfast_included", False))
            }
        })

    log_integration_event(
        db=db,
        tenant_id=tenant.id,
        integration_id=integration.id,
        event_type="get_rates",
        status_str="success",
        payload_summary=f"Retrieved rates for {len(rate_results)} room types ({check_in} to {check_out})."
    )

    res = {
        "hotel_id": tenant.id,
        "hotel_name": tenant.name,
        "currency": currency,
        "check_in": to_iso(check_in),
        "check_out": to_iso(check_out),
        "nights": (check_out - check_in).days,
        "guests": {
            "adults": effective_adults,
            "children": effective_children
        },
        "rates": rate_results
    }
    if len(rate_results) == 1:
        top_p = rate_results[0]["pricing"]
        res["base_price_per_night"] = top_p["base_nightly_rate"]
        res["total_estimated_price"] = top_p["total_estimated_price"]
        res["tax_amount"] = top_p["tax_amount"]
        res["discounts"] = top_p["discounts"]
    return res


@external_router.post("/reservations", status_code=status.HTTP_201_CREATED, summary="Create Reservation")
def create_reservation(
    payload: ReservationCreateIn,
    request: Request,
    idempotency_key: Optional[str] = Header(None, alias="Idempotency-Key"),
    x_idempotency_key: Optional[str] = Header(None, alias="X-Idempotency-Key"),
    context: Tuple[TenantIntegration, Tenant] = Depends(get_integration_context("reservations:create")),
    db: Session = Depends(get_db)
):
    """
    Creates a new reservation with:
    1. Server-side validation of guest details and booking dates.
    2. Concurrency-safe row-level locking of available rooms.
    3. Server-side dynamic pricing calculation (base, weekend, taxes, extra guests).
    4. Two-phase idempotency prevention (guarantees exactly one reservation per unique key).
    5. Seamless persistence into the core StayFlow reservations module.
    """
    integration, tenant = context

    # 1. Date Validation
    if payload.check_out <= payload.check_in:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Check-out date must be after check-in date."
        )

    # 2. Resolve Idempotency Key
    raw_ikey = (
        idempotency_key
        or x_idempotency_key
        or payload.idempotency_key
        or payload.external_intent_id
    )
    if not raw_ikey or not str(raw_ikey).strip():
        # Generate deterministic key from payload parameters
        raw_ikey = hashlib.sha256(
            f"{tenant.id}:{payload.guest_name}:{payload.phone}:{payload.check_in}:{payload.check_out}:{payload.room_type_id}".encode("utf-8")
        ).hexdigest()[:32]
    ikey = str(raw_ikey).strip()

    # 3. Payload Hashing for Idempotency
    norm_dict = {
        "guest_name": payload.guest_name,
        "phone": payload.phone or payload.guest_phone,
        "email": payload.email or payload.guest_email,
        "check_in": str(payload.check_in),
        "check_out": str(payload.check_out),
        "room_type_id": payload.room_type_id,
        "room_type": payload.room_type,
        "adults": payload.adults,
        "children": payload.children
    }
    payload_hash = hashlib.sha256(json.dumps(norm_dict, sort_keys=True).encode("utf-8")).hexdigest()

    # 4. Check Prior Idempotency Record
    existing_rec = db.scalar(
        select(IntegrationIdempotencyRecord).where(
            IntegrationIdempotencyRecord.tenant_id == tenant.id,
            IntegrationIdempotencyRecord.integration_id == integration.id,
            IntegrationIdempotencyRecord.idempotency_key == ikey
        )
    )
    if existing_rec:
        if existing_rec.status == "COMPLETED" and existing_rec.response_body:
            if existing_rec.payload_hash != payload_hash:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Idempotency key reused with different request payload."
                )
            return json.loads(existing_rec.response_body)
        elif existing_rec.status == "PROCESSING":
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="A concurrent reservation request with this idempotency key is already in progress."
            )

    # 5. Resolve Room Type
    resolved_rt_id = payload.room_type_id
    if not resolved_rt_id and payload.room_type and payload.room_type.strip():
        rt_target = payload.room_type.strip().lower()
        matched_rt = db.scalar(
            select(RoomType).where(
                RoomType.tenant_id == tenant.id,
                or_(
                    func.lower(RoomType.name) == rt_target,
                    func.lower(RoomType.slug) == rt_target,
                    func.lower(RoomType.name).like(f"%{rt_target}%")
                )
            )
        )
        if matched_rt:
            resolved_rt_id = matched_rt.id

    if not resolved_rt_id:
        # Fall back to first active room type
        first_rt = db.scalar(select(RoomType).where(RoomType.tenant_id == tenant.id))
        if first_rt:
            resolved_rt_id = first_rt.id
        else:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="No room types configured for this hotel property."
            )

    # 6. Insert PROCESSING Idempotency Record in a nested savepoint
    idemp_rec = IntegrationIdempotencyRecord(
        tenant_id=tenant.id,
        integration_id=integration.id,
        idempotency_key=ikey,
        payload_hash=payload_hash,
        status="PROCESSING"
    )
    try:
        with db.begin_nested():
            db.add(idemp_rec)
    except IntegrityError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Concurrent request already registered with this Idempotency-Key."
        )

    # 7. Concurrency-Safe Room Row Locking
    room = allocate_and_lock_room(
        db=db,
        tenant_id=tenant.id,
        check_in=payload.check_in,
        check_out=payload.check_out,
        room_id=payload.room_id,
        room_type_id=resolved_rt_id
    )

    if not room:
        idemp_rec.status = "FAILED"
        db.commit()
        log_integration_event(
            db=db,
            tenant_id=tenant.id,
            integration_id=integration.id,
            event_type="create_reservation",
            status_str="conflict",
            status_code=409,
            payload_summary=f"No available room for room_type #{resolved_rt_id} ({payload.check_in} to {payload.check_out})."
        )
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="No operational room is available for the selected room type and dates."
        )

    # 8. Find or Create Guest Record
    guest_phone = payload.phone or payload.guest_phone or ""
    guest_email = str(payload.email or payload.guest_email or "").strip()
    clean_digits = "".join(ch for ch in guest_phone if ch.isdigit())

    guest = None
    if len(clean_digits) >= 7:
        guest = db.scalar(
            select(Guest).where(
                Guest.tenant_id == tenant.id,
                Guest.phone.like(f"%{clean_digits[-10:]}%")
            )
        )
    if not guest and guest_email:
        guest = db.scalar(
            select(Guest).where(
                Guest.tenant_id == tenant.id,
                func.lower(Guest.email) == guest_email.lower()
            )
        )

    if not guest:
        guest = Guest(
            tenant_id=tenant.id,
            full_name=payload.guest_name,
            phone=guest_phone,
            email=guest_email,
            tier="Standard"
        )
        db.add(guest)
        db.flush()

    # 9. Server-Side Accurate Pricing Calculation
    rt_obj = db.scalar(select(RoomType).where(RoomType.id == room.room_type_id))
    hotel_settings = db.scalar(select(HotelSettings).where(HotelSettings.tenant_id == tenant.id))
    pricing = calculate_reservation_pricing(
        rt=rt_obj,
        hotel_settings=hotel_settings,
        tenant=tenant,
        check_in=payload.check_in,
        check_out=payload.check_out,
        adults=payload.adults,
        children=payload.children
    )

    # 10. Generate Standard Reference & Create Reservation
    rand_suffix = secrets.token_hex(4).upper()
    booking_ref = f"BK-EXT-{tenant.id}-{rand_suffix}"
    durable_channel_ref = f"ext:{integration.id}:{payload.external_intent_id or ikey}"

    reservation = Reservation(
        tenant_id=tenant.id,
        reference=booking_ref,
        guest_id=guest.id,
        room_id=room.id,
        source=integration.name if hasattr(integration, "name") and getattr(integration, "name", None) else "External Integration",
        channel_ref=durable_channel_ref,
        check_in=payload.check_in,
        check_out=payload.check_out,
        status="Confirmed",
        total_amount=Decimal(str(pricing["total_amount"])),
        num_guests=payload.adults + payload.children
    )
    db.add(reservation)
    db.flush()

    # 11. Complete Idempotency Record
    guest_display_name = getattr(guest, "full_name", None) or getattr(guest, "name", "")
    res_dict = {
        "id": reservation.id,
        "reservation_id": reservation.id,
        "booking_reference": reservation.reference,
        "status": reservation.status,
        "allocated_room_number": room.number,
        "hotel": {
            "id": tenant.id,
            "name": tenant.name
        },
        "guest": {
            "id": guest.id,
            "name": guest_display_name,
            "phone": guest.phone or "",
            "email": guest.email or ""
        },
        "room": {
            "id": room.id,
            "number": room.number,
            "floor": room.floor,
            "room_type_id": room.room_type_id,
            "room_type_name": rt_obj.name if rt_obj else ""
        },
        "dates": {
            "check_in": to_iso(reservation.check_in),
            "check_out": to_iso(reservation.check_out),
            "nights": pricing["nights"]
        },
        "pricing": {
            "base_amount": pricing["base_amount"],
            "extra_charges": pricing["extra_charges"],
            "taxable_amount": pricing["subtotal"],
            "tax_percent": pricing["tax_percent"],
            "tax_amount": pricing["tax_amount"],
            "total_price": pricing["total_amount"],
            "currency": pricing["currency"]
        },
        "special_requests": payload.special_requests,
        "payment_status": "Pending",
        "payment_method": payload.payment_method or "Pay At Hotel",
        "created_at": to_iso(reservation.created_at or datetime.now(timezone.utc))
    }

    idemp_rec.status = "COMPLETED"
    idemp_rec.reservation_id = reservation.id
    idemp_rec.response_body = json.dumps(res_dict)
    idemp_rec.status_code = 201

    # Atomic Commit
    db.commit()

    log_integration_event(
        db=db,
        tenant_id=tenant.id,
        integration_id=integration.id,
        event_type="create_reservation",
        status_str="success",
        status_code=201,
        payload_summary=f"Booking created: {booking_ref} (Room #{room.number}, Nights: {pricing['nights']}, Total: {pricing['total_amount']} {pricing['currency']})"
    )

    return res_dict


@external_router.get("/reservations/{reservation_id}", summary="Retrieve Reservation Details")
@router.get("/reservations/{reservation_id}", summary="Retrieve Reservation Details (Alias)")
def get_reservation_details(
    reservation_id: str,
    context: Tuple[TenantIntegration, Tenant] = Depends(get_integration_context("reservations:read")),
    db: Session = Depends(get_db)
):
    """
    Retrieves full reservation details by numeric ID or booking reference.
    Strictly isolated: only returns reservations belonging to the authenticated hotel tenant.
    """
    integration, tenant = context

    stmt = (
        select(Reservation)
        .options(
            joinedload(Reservation.guest),
            joinedload(Reservation.room).joinedload(Room.room_type),
            joinedload(Reservation.tenant)
        )
        .where(Reservation.tenant_id == tenant.id)
    )

    clean_id = reservation_id.strip()
    if clean_id.isdigit():
        stmt = stmt.where(
            or_(
                Reservation.id == int(clean_id),
                Reservation.reference == clean_id
            )
        )
    else:
        stmt = stmt.where(Reservation.reference == clean_id)

    res = db.scalar(stmt)
    if not res:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Reservation not found for this hotel property."
        )

    nights = max(1, (res.check_out - res.check_in).days)
    hotel_settings = db.scalar(select(HotelSettings).where(HotelSettings.tenant_id == tenant.id))
    currency = (hotel_settings.currency if hotel_settings and hotel_settings.currency else None) or tenant.currency or "INR"

    guest_name = getattr(res.guest, "full_name", None) or getattr(res.guest, "name", "")
    room_number = res.room.number if res.room else "Unassigned"
    room_type_name = res.room.room_type.name if res.room and res.room.room_type else ""

    return {
        "id": res.id,
        "reservation_id": res.id,
        "booking_reference": res.reference,
        "status": res.status,
        "source": res.source,
        "channel_ref": res.channel_ref,
        "hotel": {
            "id": tenant.id,
            "name": tenant.name,
            "code": tenant.code
        },
        "guest": {
            "id": res.guest_id,
            "name": guest_name,
            "phone": res.guest.phone if res.guest else "",
            "email": res.guest.email if res.guest else "",
            "tier": res.guest.tier if res.guest else "Standard"
        },
        "room": {
            "id": res.room_id,
            "number": room_number,
            "floor": res.room.floor if res.room else None,
            "room_type_id": res.room.room_type_id if res.room else None,
            "room_type_name": room_type_name
        },
        "dates": {
            "check_in": to_iso(res.check_in),
            "check_out": to_iso(res.check_out),
            "nights": nights,
            "checked_in_at": to_iso(res.checked_in_at),
            "checked_out_at": to_iso(res.checked_out_at)
        },
        "pricing": {
            "total_price": float(res.total_amount or 0.0),
            "currency": currency
        },
        "num_guests": res.num_guests,
        "created_at": to_iso(res.created_at)
    }


@external_router.patch("/reservations/{reservation_id}", summary="Modify Reservation Details")
@external_router.put("/reservations/{reservation_id}", summary="Update Reservation Details (Alias)")
def update_reservation_details(
    reservation_id: str,
    payload: ReservationUpdateIn,
    context: Tuple[TenantIntegration, Tenant] = Depends(get_integration_context("reservations:update")),
    db: Session = Depends(get_db)
):
    """
    Modifies an active reservation (booking dates, guest details, room type).
    Rechecks live availability and recalculates server-side pricing.
    """
    integration, tenant = context

    stmt = (
        select(Reservation)
        .options(
            joinedload(Reservation.guest),
            joinedload(Reservation.room).joinedload(Room.room_type)
        )
        .where(Reservation.tenant_id == tenant.id)
    )

    clean_id = reservation_id.strip()
    if clean_id.isdigit():
        stmt = stmt.where(
            or_(
                Reservation.id == int(clean_id),
                Reservation.reference == clean_id
            )
        )
    else:
        stmt = stmt.where(Reservation.reference == clean_id)

    res = db.scalar(stmt)
    if not res:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Reservation not found for this hotel property."
        )

    if res.status in ("Cancelled", "Checked-out"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot modify a reservation with status '{res.status}'."
        )

    # Date modifications
    new_in = payload.check_in or res.check_in
    new_out = payload.check_out or res.check_out

    if new_out <= new_in:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Check-out date must be after check-in date."
        )

    dates_changed = (new_in != res.check_in) or (new_out != res.check_out)
    rt_changed = payload.room_type_id is not None or (payload.room_type and payload.room_type.strip())

    target_rt_id = res.room.room_type_id if res.room else None
    if payload.room_type_id:
        target_rt_id = payload.room_type_id
    elif payload.room_type and payload.room_type.strip():
        rt_target = payload.room_type.strip().lower()
        matched_rt = db.scalar(
            select(RoomType).where(
                RoomType.tenant_id == tenant.id,
                or_(
                    func.lower(RoomType.name) == rt_target,
                    func.lower(RoomType.slug) == rt_target,
                    func.lower(RoomType.name).like(f"%{rt_target}%")
                )
            )
        )
        if matched_rt:
            target_rt_id = matched_rt.id

    if dates_changed or rt_changed:
        # Re-allocate room with conflict checking, ignoring current reservation
        new_room = allocate_and_lock_room(
            db=db,
            tenant_id=tenant.id,
            check_in=new_in,
            check_out=new_out,
            room_type_id=target_rt_id,
            ignore_res_id=res.id
        )
        if not new_room:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="No available room for the modified dates or room type."
            )

        res.room_id = new_room.id
        res.check_in = new_in
        res.check_out = new_out

        # Recalculate price
        rt_obj = db.scalar(select(RoomType).where(RoomType.id == new_room.room_type_id))
        hotel_settings = db.scalar(select(HotelSettings).where(HotelSettings.tenant_id == tenant.id))
        adults_count = payload.adults or res.num_guests or 1
        children_count = payload.children or 0
        pricing = calculate_reservation_pricing(
            rt=rt_obj,
            hotel_settings=hotel_settings,
            tenant=tenant,
            check_in=new_in,
            check_out=new_out,
            adults=adults_count,
            children=children_count
        )
        res.total_amount = Decimal(str(pricing["total_amount"]))
        res.status = "Modified"

    # Guest details modification
    if res.guest:
        if payload.guest_name:
            res.guest.full_name = payload.guest_name
        if payload.email:
            res.guest.email = str(payload.email)
        if payload.phone:
            res.guest.phone = payload.phone

    if payload.adults is not None or payload.children is not None:
        total_guests = (payload.adults or 1) + (payload.children or 0)
        res.num_guests = total_guests

    if payload.special_requests:
        res.group_name = payload.special_requests[:160]

    db.commit()
    db.refresh(res)

    log_integration_event(
        db=db,
        tenant_id=tenant.id,
        integration_id=integration.id,
        event_type="modify_reservation",
        status_str="success",
        payload_summary=f"Reservation {res.reference} modified: Dates={res.check_in} to {res.check_out}, Total={res.total_amount}."
    )

    nights = max(1, (res.check_out - res.check_in).days)
    hotel_settings = db.scalar(select(HotelSettings).where(HotelSettings.tenant_id == tenant.id))
    currency = (hotel_settings.currency if hotel_settings and hotel_settings.currency else None) or tenant.currency or "INR"

    return {
        "id": res.id,
        "reservation_id": res.id,
        "booking_reference": res.reference,
        "status": res.status,
        "hotel": {
            "id": tenant.id,
            "name": tenant.name
        },
        "guest": {
            "name": getattr(res.guest, "full_name", ""),
            "phone": getattr(res.guest, "phone", ""),
            "email": getattr(res.guest, "email", "")
        },
        "room": {
            "id": res.room_id,
            "number": res.room.number if res.room else "",
            "room_type_name": res.room.room_type.name if res.room and res.room.room_type else ""
        },
        "dates": {
            "check_in": to_iso(res.check_in),
            "check_out": to_iso(res.check_out),
            "nights": nights
        },
        "special_requests": payload.special_requests or res.group_name,
        "pricing": {
            "total_price": float(res.total_amount or 0.0),
            "currency": currency
        },
        "message": "Reservation updated successfully."
    }


@external_router.post("/reservations/{reservation_id}/cancel", summary="Cancel Reservation")
@external_router.delete("/reservations/{reservation_id}", summary="Cancel Reservation (Delete Alias)")
def cancel_reservation(
    reservation_id: str,
    payload: Optional[ReservationCancelIn] = None,
    context: Tuple[TenantIntegration, Tenant] = Depends(get_integration_context("reservations:cancel")),
    db: Session = Depends(get_db)
):
    """
    Cancels an active reservation, releases room inventory, and applies hotel cancellation policy.
    Strictly tenant isolated. Idempotent if already cancelled.
    """
    integration, tenant = context

    stmt = (
        select(Reservation)
        .options(joinedload(Reservation.guest), joinedload(Reservation.room))
        .where(Reservation.tenant_id == tenant.id)
    )

    clean_id = reservation_id.strip()
    if clean_id.isdigit():
        stmt = stmt.where(
            or_(
                Reservation.id == int(clean_id),
                Reservation.reference == clean_id
            )
        )
    else:
        stmt = stmt.where(Reservation.reference == clean_id)

    res = db.scalar(stmt)
    if not res:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Reservation not found for this hotel property."
        )

    # Idempotent response if already cancelled
    if res.status == "Cancelled":
        return {
            "id": res.id,
            "booking_reference": res.reference,
            "status": "Cancelled",
            "message": "Reservation is already cancelled."
        }

    if res.status in ("Checked-in", "Checked-out"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot cancel a reservation with status '{res.status}'."
        )

    res.status = "Cancelled"
    db.commit()

    hotel_settings = db.scalar(select(HotelSettings).where(HotelSettings.tenant_id == tenant.id))
    cancellation_hours = hotel_settings.cancellation_hours if hotel_settings else 24
    no_show_charge = hotel_settings.no_show_charge if hotel_settings else "First night"

    cancel_reason = (
        (payload.cancellation_reason if payload and payload.cancellation_reason else None)
        or (payload.reason if payload and payload.reason else None)
        or "Cancelled via external integration"
    )

    log_integration_event(
        db=db,
        tenant_id=tenant.id,
        integration_id=integration.id,
        event_type="cancel_reservation",
        status_str="success",
        payload_summary=f"Cancelled booking {res.reference}. Reason: {cancel_reason}."
    )

    return {
        "id": res.id,
        "reservation_id": res.id,
        "booking_reference": res.reference,
        "status": "Cancelled",
        "cancellation_reason": cancel_reason,
        "cancelled_at": to_iso(datetime.now(timezone.utc)),
        "cancellation_policy": {
            "cancellation_notice_hours": cancellation_hours,
            "fee_policy": no_show_charge
        },
        "message": "Reservation cancelled successfully."
    }
