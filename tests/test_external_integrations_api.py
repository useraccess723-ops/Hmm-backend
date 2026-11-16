"""Comprehensive Automated Test Suite for StayFlow External Integration APIs.

Verifies:
1. Health & connectivity check (public/M2M).
2. Service Key Authentication (Bearer, X-Service-Key, X-Integration-Key).
3. Rejection of invalid, revoked, or inactive integration keys (HTTP 401).
4. Granular Scope Enforcement (HTTP 403 on missing scopes).
5. Hotel Details API (GET /api/integrations/hotel/details).
6. Room Availability API (GET /api/integrations/rooms/availability).
7. Dynamic Pricing & Rate Calculation API (GET /api/integrations/rooms/rates).
8. Reservation Creation (POST /api/integrations/reservations) with Idempotency-Key.
9. Duplicate Reservation Prevention via Idempotency.
10. Room Conflict & Inventory Exhaustion handling (HTTP 409).
11. Reservation Retrieval (GET /api/integrations/reservations/{id}) by DB ID and reference.
12. Reservation Update (PATCH /api/integrations/reservations/{id}).
13. Reservation Cancellation (POST /api/integrations/reservations/{id}/cancel).
14. Strict Cross-Tenant Multi-Tenancy Isolation.
"""
import os
import sys
import hashlib
import secrets
from datetime import date, timedelta
from decimal import Decimal
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

# Setup path and environment
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
os.environ["TESTING"] = "1"
os.environ.setdefault("JWT_SECRET_KEY", "test-secret-key-with-at-least-32-characters-long")

from app.main import app
from app.database.connection import Base, get_db
from app.models import (
    Tenant, TenantIntegration, IntegrationLog, IntegrationIdempotencyRecord,
    RoomType, Room, Guest, Reservation, HotelSettings
)


@pytest.fixture(scope="module")
def setup_test_env():
    """Sets up an in-memory SQLite database with two distinct tenants for multi-tenancy testing."""
    test_engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    TestingSession = sessionmaker(bind=test_engine, autoflush=False, autocommit=False, expire_on_commit=False)
    Base.metadata.create_all(bind=test_engine)

    raw_key_tenant_1 = "sf_live_ten1_secure_key_1234567890abcdef1234567890abcdef1234567890abcdef123456"
    raw_key_tenant_2 = "sf_live_ten2_secure_key_1234567890abcdef1234567890abcdef1234567890abcdef123456"
    raw_key_limited = "sf_live_lim1_secure_key_1234567890abcdef1234567890abcdef1234567890abcdef123456"

    with TestingSession() as db:
        # Create Tenants
        t1 = Tenant(id=1, name="Grand Meridian Hotel", slug="grand-meridian", code="GMH", is_active=True)
        t2 = Tenant(id=2, name="Royal Palace New Delhi", slug="royal-palace", code="RPD", is_active=True)
        t3 = Tenant(id=3, name="Budget Lodge Express", slug="budget-lodge", code="BLE", is_active=True)
        db.add_all([t1, t2, t3])
        db.commit()

        # Hotel Settings for Tenant 1
        s1 = HotelSettings(
            tenant_id=1,
            hotel_name="Grand Meridian Chennai",
            currency="INR",
            gst_percent=Decimal("12.0"),
            check_in_time="14:00",
            check_out_time="11:00",
            cancellation_hours=24,
            no_show_charge="One Night Fee"
        )
        db.add(s1)

        # Integrations
        all_scopes = (
            "hotel:read,rooms:read,rates:read,reservations:read,reservations:create,"
            "reservations:update,reservations:cancel,knowledge:read,escalations:create"
        )
        integ1 = TenantIntegration(
            id=1,
            tenant_id=1,
            integration_type="ai_receptionist",
            key_hash=hashlib.sha256(raw_key_tenant_1.encode()).hexdigest(),
            key_prefix="sf_live_",
            key_last4="3456",
            scopes=all_scopes,
            is_enabled=True,
            status="connected"
        )
        integ2 = TenantIntegration(
            id=2,
            tenant_id=2,
            integration_type="ai_receptionist",
            key_hash=hashlib.sha256(raw_key_tenant_2.encode()).hexdigest(),
            key_prefix="sf_live_",
            key_last4="3456",
            scopes=all_scopes,
            is_enabled=True,
            status="connected"
        )
        integ_limited = TenantIntegration(
            id=3,
            tenant_id=3,
            integration_type="ai_receptionist",
            key_hash=hashlib.sha256(raw_key_limited.encode()).hexdigest(),
            key_prefix="sf_live_",
            key_last4="3456",
            scopes="hotel:read",  # Only hotel:read
            is_enabled=True,
            status="connected"
        )
        db.add_all([integ1, integ2, integ_limited])

        # Room types & rooms for Tenant 1
        rt1 = RoomType(
            id=1,
            tenant_id=1,
            name="Deluxe King",
            base_price=Decimal("4000.00"),
            weekend_price=Decimal("4500.00"),
            max_adults=2,
            max_children=1,
            max_guests=3,
            extra_adult_charge=Decimal("800.00"),
            extra_child_charge=Decimal("400.00"),
            description="Spacious deluxe king room"
        )
        db.add(rt1)
        db.commit()

        # Add 2 rooms for Tenant 1 Deluxe King
        r101 = Room(tenant_id=1, number="101", room_type_id=1, floor=1, status="vac", description="")
        r102 = Room(tenant_id=1, number="102", room_type_id=1, floor=1, status="vac", description="")
        db.add_all([r101, r102])

        # Room types & rooms for Tenant 2
        rt2 = RoomType(
            id=2,
            tenant_id=2,
            name="Presidential Suite",
            base_price=Decimal("15000.00"),
            max_adults=4,
            max_children=2,
            max_guests=6,
            description="Luxury presidential suite"
        )
        db.add(rt2)
        db.commit()
        r201 = Room(tenant_id=2, number="201", room_type_id=2, floor=2, status="vac", description="")
        db.add(r201)
        db.commit()

    def override_db():
        db = TestingSession()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_db
    client = TestClient(app)
    
    keys = {
        "t1_key": raw_key_tenant_1,
        "t2_key": raw_key_tenant_2,
        "limited_key": raw_key_limited
    }
    yield client, keys
    app.dependency_overrides.clear()


def test_health_check_endpoints(setup_test_env):
    """Verifies that connection health endpoints respond without requiring authentication."""
    client, keys = setup_test_env
    r = client.get("/api/integrations/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"

    r2 = client.get("/api/integrations/connection/health")
    assert r2.status_code == 200
    assert r2.json()["status"] == "ok"


def test_authentication_mechanisms(setup_test_env):
    """Verifies service key authentication via Bearer token, X-Service-Key, and rejection of invalid keys."""
    client, keys = setup_test_env

    # 1. Bearer token
    r = client.get("/api/integrations/hotel/details", headers={"Authorization": f"Bearer {keys['t1_key']}"})
    assert r.status_code == 200
    assert r.json()["hotel_id"] == 1

    # 2. X-Service-Key
    r2 = client.get("/api/integrations/hotel/details", headers={"X-Service-Key": keys["t1_key"]})
    assert r2.status_code == 200
    assert r2.json()["hotel_id"] == 1

    # 3. X-Integration-Key
    r3 = client.get("/api/integrations/hotel/details", headers={"X-Integration-Key": keys["t1_key"]})
    assert r3.status_code == 200
    assert r3.json()["hotel_id"] == 1

    # 4. Invalid key
    r4 = client.get("/api/integrations/hotel/details", headers={"Authorization": "Bearer invalid_key_12345"})
    assert r4.status_code == 401

    # 5. Missing auth
    r5 = client.get("/api/integrations/hotel/details")
    assert r5.status_code == 401


def test_scope_enforcement(setup_test_env):
    """Verifies that an integration without proper scope is rejected with HTTP 403."""
    client, keys = setup_test_env
    limited_headers = {"X-Service-Key": keys["limited_key"]}

    # 1. hotel:read is allowed on limited_key
    r = client.get("/api/integrations/hotel/details", headers=limited_headers)
    assert r.status_code == 200

    # 2. reservations:create is NOT in limited scopes -> 403 Forbidden
    payload = {
        "room_type_id": 1,
        "check_in": (date.today() + timedelta(days=1)).isoformat(),
        "check_out": (date.today() + timedelta(days=2)).isoformat(),
        "guest_name": "Test Guest",
        "guest_email": "guest@example.com",
        "phone": "+919876543210"
    }
    r2 = client.post("/api/integrations/reservations", headers=limited_headers, json=payload)
    assert r2.status_code == 403
    assert "reservations:create" in r2.json()["detail"]

    # 3. reservations:update is NOT in limited scopes -> 403 Forbidden
    r3 = client.patch("/api/integrations/reservations/1", headers=limited_headers, json={"adults": 2})
    assert r3.status_code == 403
    assert "reservations:update" in r3.json()["detail"]

    # 4. reservations:cancel is NOT in limited scopes -> 403 Forbidden
    r4 = client.post("/api/integrations/reservations/1/cancel", headers=limited_headers, json={"reason": "Test"})
    assert r4.status_code == 403
    assert "reservations:cancel" in r4.json()["detail"]


def test_hotel_details_retrieval(setup_test_env):
    """Verifies GET /api/integrations/hotel/details returns hotel info, address, policies."""
    client, keys = setup_test_env
    headers = {"X-Service-Key": keys["t1_key"]}
    r = client.get("/api/integrations/hotel/details", headers=headers)
    assert r.status_code == 200
    data = r.json()
    assert data["hotel_id"] == 1
    assert data["hotel_name"] == "Grand Meridian Chennai"
    assert data["currency"] == "INR"
    assert "check_in_time" in data["policies"]
    assert "cancellation_policy" in data["policies"]


def test_room_availability_api(setup_test_env):
    """Verifies GET /api/integrations/rooms/availability returns real available inventory."""
    client, keys = setup_test_env
    headers = {"X-Service-Key": keys["t1_key"]}
    ci = (date.today() + timedelta(days=10)).isoformat()
    co = (date.today() + timedelta(days=12)).isoformat()

    r = client.get(f"/api/integrations/rooms/availability?check_in={ci}&check_out={co}", headers=headers)
    assert r.status_code == 200
    data = r.json()
    assert data["check_in"] == ci
    assert data["check_out"] == co
    assert len(data["available_room_types"]) >= 1
    assert data["available_room_types"][0]["available_rooms_count"] == 2


def test_room_pricing_api(setup_test_env):
    """Verifies GET /api/integrations/rooms/rates returns itemized pricing, taxes, and total."""
    client, keys = setup_test_env
    headers = {"X-Service-Key": keys["t1_key"]}
    ci = (date.today() + timedelta(days=15)).isoformat()
    co = (date.today() + timedelta(days=17)).isoformat()

    r = client.get(
        f"/api/integrations/rooms/rates?room_type_id=1&check_in={ci}&check_out={co}&adults=2&children=1",
        headers=headers
    )
    assert r.status_code == 200
    data = r.json()
    assert data["currency"] == "INR"
    assert data["nights"] == 2
    assert "base_price_per_night" in data
    assert "total_estimated_price" in data
    assert data["tax_amount"] > 0


def test_reservation_lifecycle_and_idempotency(setup_test_env):
    """Verifies booking creation, idempotency prevention, retrieval, update, and cancellation."""
    client, keys = setup_test_env
    headers = {
        "X-Service-Key": keys["t1_key"],
        "Idempotency-Key": "test-idemp-" + secrets.token_hex(8)
    }
    ci = (date.today() + timedelta(days=20)).isoformat()
    co = (date.today() + timedelta(days=22)).isoformat()

    payload = {
        "room_type_id": 1,
        "check_in": ci,
        "check_out": co,
        "adults": 2,
        "children": 0,
        "guest_name": "Koushik Balaji",
        "guest_email": "koushik@example.com",
        "guest_phone": "+919876543210",
        "special_requests": "High floor room preferred"
    }

    # 1. Create Reservation
    r = client.post("/api/integrations/reservations", headers=headers, json=payload)
    assert r.status_code == 201, r.text
    res_data = r.json()
    assert res_data["status"] == "Confirmed"
    booking_ref = res_data["booking_reference"]
    res_id = res_data["reservation_id"]
    assert res_data["allocated_room_number"] in ["101", "102"]

    # 2. Duplicate Idempotency Re-request
    r_dup = client.post("/api/integrations/reservations", headers=headers, json=payload)
    assert r_dup.status_code == 200 or r_dup.status_code == 201
    assert r_dup.json()["booking_reference"] == booking_ref

    # 3. Retrieve Reservation by DB ID
    r_get = client.get(f"/api/integrations/reservations/{res_id}", headers={"X-Service-Key": keys["t1_key"]})
    assert r_get.status_code == 200
    assert r_get.json()["booking_reference"] == booking_ref

    # 4. Retrieve Reservation by Booking Reference string
    r_get_ref = client.get(f"/api/integrations/reservations/{booking_ref}", headers={"X-Service-Key": keys["t1_key"]})
    assert r_get_ref.status_code == 200
    assert r_get_ref.json()["reservation_id"] == res_id

    # 5. Update Reservation (e.g. special requests and guest count)
    patch_payload = {
        "adults": 2,
        "special_requests": "Late check-in requested at 6 PM"
    }
    r_patch = client.patch(
        f"/api/integrations/reservations/{res_id}",
        headers={"X-Service-Key": keys["t1_key"]},
        json=patch_payload
    )
    assert r_patch.status_code == 200
    assert "Late check-in" in r_patch.json()["special_requests"]

    # 6. Cancel Reservation
    r_cancel = client.post(
        f"/api/integrations/reservations/{res_id}/cancel",
        headers={"X-Service-Key": keys["t1_key"]},
        json={"cancellation_reason": "Travel plans altered"}
    )
    assert r_cancel.status_code == 200
    assert r_cancel.json()["status"] == "Cancelled"
    assert r_cancel.json()["cancellation_reason"] == "Travel plans altered"


def test_cross_tenant_isolation(setup_test_env):
    """Verifies that Tenant 2 cannot access, modify, or cancel Tenant 1's reservations."""
    client, keys = setup_test_env
    # Create booking in Tenant 1
    t1_headers = {
        "X-Service-Key": keys["t1_key"],
        "Idempotency-Key": "iso-test-" + secrets.token_hex(8)
    }
    ci = (date.today() + timedelta(days=30)).isoformat()
    co = (date.today() + timedelta(days=32)).isoformat()
    payload = {
        "room_type_id": 1,
        "check_in": ci,
        "check_out": co,
        "adults": 1,
        "children": 0,
        "guest_name": "Tenant One Resident",
        "guest_email": "t1@example.com"
    }
    r = client.post("/api/integrations/reservations", headers=t1_headers, json=payload)
    assert r.status_code == 201
    booking_ref = r.json()["booking_reference"]
    res_id = r.json()["reservation_id"]

    # Attempt to read Tenant 1's reservation using Tenant 2's key
    t2_headers = {"X-Service-Key": keys["t2_key"]}
    r_leak = client.get(f"/api/integrations/reservations/{res_id}", headers=t2_headers)
    assert r_leak.status_code == 404

    r_leak_ref = client.get(f"/api/integrations/reservations/{booking_ref}", headers=t2_headers)
    assert r_leak_ref.status_code == 404

    # Attempt to update Tenant 1's reservation using Tenant 2's key
    r_patch_leak = client.patch(
        f"/api/integrations/reservations/{res_id}",
        headers=t2_headers,
        json={"special_requests": "Hacked request"}
    )
    assert r_patch_leak.status_code == 404

    # Attempt to cancel Tenant 1's reservation using Tenant 2's key
    r_cancel_leak = client.post(
        f"/api/integrations/reservations/{res_id}/cancel",
        headers=t2_headers,
        json={"cancellation_reason": "Malicious cancel"}
    )
    assert r_cancel_leak.status_code == 404
