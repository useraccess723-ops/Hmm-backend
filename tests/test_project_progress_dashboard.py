import os
import sys
import json
from decimal import Decimal
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
os.environ["TESTING"] = "1"
os.environ["JWT_SECRET_KEY"] = "test-secret-key-with-at-least-32-characters-long"

from app.main import app
from app.database.connection import Base, get_db
from app.core.config import settings
from app.core.security import hash_password
from app.models import User, RoomType, Room, OperationalRecord

@pytest.fixture()
def client():
    settings.JWT_SECRET_KEY = "test-secret-key-with-at-least-32-characters-long"
    test_engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    TestingSession = sessionmaker(bind=test_engine, autoflush=False, autocommit=False, expire_on_commit=False)
    Base.metadata.create_all(bind=test_engine)
    with TestingSession() as db:
        # Super admin (platform-level)
        super_admin = User(
            email="superadmin@stayflow.com",
            full_name="Super Admin",
            password_hash=hash_password("SuperSecret@123"),
            role="SUPER_ADMIN",
            is_super_admin=True,
            hotel_id=None,
            tenant_id=None
        )
        # Tenant 1 Admin
        admin_t1 = User(
            email="admin@hotel1.com",
            full_name="Hotel 1 Admin",
            password_hash=hash_password("Password@123"),
            role="ADMIN",
            hotel_id=1,
            tenant_id=1
        )
        # Tenant 2 Admin
        admin_t2 = User(
            email="admin@hotel2.com",
            full_name="Hotel 2 Admin",
            password_hash=hash_password("Password@123"),
            role="ADMIN",
            hotel_id=2,
            tenant_id=2
        )
        # Tenant 1 Front Desk (read-only for progress)
        front_desk_t1 = User(
            email="frontdesk@hotel1.com",
            full_name="Front Desk Staff",
            password_hash=hash_password("Password@123"),
            role="FRONT_DESK",
            hotel_id=1,
            tenant_id=1
        )
        # Customer
        customer = User(
            email="guest@example.com",
            full_name="Guest Customer",
            password_hash=hash_password("Password@123"),
            role="CUSTOMER",
            hotel_id=1,
            tenant_id=1
        )
        db.add_all([super_admin, admin_t1, admin_t2, front_desk_t1, customer])
        db.commit()

    def override_db():
        db = TestingSession()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_db
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()

def auth_header(client, email, password="Password@123", tenant_id="1"):
    res = client.post("/api/auth/token", data={"username": email, "password": password})
    assert res.status_code == 200, res.text
    token = res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    if tenant_id is not None:
        headers["X-Tenant-Id"] = str(tenant_id)
    return headers

# ==============================================================================
# 1. EXACT 9 PHASES VERIFICATION
# ==============================================================================
def test_dashboard_displays_exactly_nine_phases_in_order(client):
    """Verify that exactly 9 phases are returned in sequential order from Phase 1 to Phase 9."""
    headers = auth_header(client, "admin@hotel1.com", tenant_id="1")
    res = client.get("/api/project-progress", headers=headers)
    assert res.status_code == 200, res.text
    data = res.json()

    assert data["total_phases"] == 9, "Must contain exactly 9 phases"
    phases = data["phases"]
    assert len(phases) == 9

    expected_phases = [
        (1, "Requirements & Project Planning", 100, 0, "Completed"),
        (2, "Architecture, Database & Multi-Tenancy", 100, 0, "Completed"),
        (3, "Authentication, RBAC & User Management", 100, 0, "Completed"),
        (4, "Front Office & Reservations", 100, 0, "Completed"),
        (5, "Rooms, Housekeeping & Guests", 100, 0, "Completed"),
        (6, "F&B, POS & KOT", 100, 0, "Completed"),
        (7, "Operations, Procurement, Security & Engineering", 100, 0, "Completed"),
        (8, "Finance, HR & Administration", 100, 0, "Completed"),
        (9, "Reports & Analytics", 100, 0, "Completed"),
    ]

    for i, exp in enumerate(expected_phases):
        p = phases[i]
        assert p["phase_number"] == exp[0], f"Expected phase_number {exp[0]}, got {p['phase_number']}"
        assert p["name"] == exp[1], f"Expected name {exp[1]}, got {p['name']}"
        assert p["completed"] == exp[2], f"Phase {exp[0]} completed expected {exp[2]}, got {p['completed']}"
        assert p["pending"] == exp[3], f"Phase {exp[0]} pending expected {exp[3]}, got {p['pending']}"
        assert p["status"] == exp[4], f"Phase {exp[0]} status expected {exp[4]}, got {p['status']}"
        assert p["completed"] + p["pending"] == 100, f"Phase {exp[0]} sum must be 100"

    # Confirm Phase 9 is the final phase
    assert phases[-1]["phase_number"] == 9
    assert phases[-1]["name"] == "Reports & Analytics"

# ==============================================================================
# 2. PHASE 10 EXCLUSION VERIFICATION
# ==============================================================================
def test_phase_10_strictly_excluded_from_dashboard(client):
    """Verify Phase 10 is completely excluded from list, total, and counts."""
    headers = auth_header(client, "admin@hotel1.com", tenant_id="1")
    res = client.get("/api/project-progress", headers=headers)
    assert res.status_code == 200
    data = res.json()

    for p in data["phases"]:
        assert p["phase_number"] != 10, "Phase 10 must not be present"
        assert "ai receptionist" not in p["name"].lower()

def test_phase_10_update_rejected_with_422(client):
    """Verify attempting to inject or update Phase 10 returns HTTP 422 error."""
    headers = auth_header(client, "admin@hotel1.com", tenant_id="1")
    res = client.put(
        "/api/project-progress",
        json={"phases": [{"phase_number": 10, "name": "AI Receptionist Integration", "completed": 95}]},
        headers=headers
    )
    assert res.status_code == 422, f"Expected 422 for Phase 10, got {res.status_code}: {res.text}"
    assert "Phase 10" in res.json()["detail"] or "excluded" in res.json()["detail"]

def test_operational_records_rejects_phase_10(client):
    """Verify generic /api/records also rejects category=project_progress Phase 10."""
    headers = auth_header(client, "admin@hotel1.com", tenant_id="1")
    res = client.post(
        "/api/records",
        json={
            "category": "project_progress",
            "title": "Phase 10: AI Receptionist",
            "data": {"phase_number": 10, "completed": 95},
            "status": "In Progress"
        },
        headers=headers
    )
    assert res.status_code == 422
    assert "Phase 10" in res.json()["detail"]

# ==============================================================================
# 3. OVERALL CALCULATION VERIFICATION
# ==============================================================================
def test_baseline_calculation_values(client):
    """Verify exact 100% completion calculation results: 100% (100%), 0% (0%), 9 completed, 0 in-progress, 0 not-started."""
    headers = auth_header(client, "admin@hotel1.com", tenant_id="1")
    res = client.get("/api/project-progress", headers=headers)
    assert res.status_code == 200
    data = res.json()

    assert data["overall_completed"] == 100.0, f"Expected 100.0, got {data['overall_completed']}"
    assert data["overall_completed_rounded"] == 100, f"Expected 100, got {data['overall_completed_rounded']}"
    assert data["overall_pending"] == 0.0, f"Expected 0.0, got {data['overall_pending']}"
    assert data["overall_pending_rounded"] == 0, f"Expected 0, got {data['overall_pending_rounded']}"
    assert data["completed_phases"] == 9, f"Expected 9 completed, got {data['completed_phases']}"
    assert data["in_progress_phases"] == 0, f"Expected 0 in-progress, got {data['in_progress_phases']}"
    assert data["not_started_phases"] == 0, f"Expected 0 not-started, got {data['not_started_phases']}"
    assert data["total_phases"] == 9

# ==============================================================================
# 4. DYNAMIC UPDATE, SINGLE SOURCE OF TRUTH & PERSISTENCE
# ==============================================================================
def test_update_phase_and_dynamic_recalculation_and_persistence(client):
    """Update Phase 7 from 100% to 90%, verify summary recalculates dynamically and persists."""
    headers = auth_header(client, "admin@hotel1.com", tenant_id="1")

    # Update Phase 7 to 90%
    update_res = client.put(
        "/api/project-progress",
        json={"phases": [{"phase_number": 7, "completed": 90}]},
        headers=headers
    )
    assert update_res.status_code == 200, update_res.text
    updated_data = update_res.json()

    # Sum now: 100 * 8 + 90 = 890. 890 / 9 = 98.89%
    assert updated_data["overall_completed"] == 98.89
    assert updated_data["overall_completed_rounded"] == 99
    assert updated_data["overall_pending"] == 1.11
    assert updated_data["overall_pending_rounded"] == 1
    p7 = next(p for p in updated_data["phases"] if p["phase_number"] == 7)
    assert p7["completed"] == 90
    assert p7["pending"] == 10

    # Persistence verification: Fetch fresh from GET
    get_res = client.get("/api/project-progress", headers=headers)
    assert get_res.status_code == 200
    fresh_data = get_res.json()
    fresh_p7 = next(p for p in fresh_data["phases"] if p["phase_number"] == 7)
    assert fresh_p7["completed"] == 90
    assert fresh_p7["pending"] == 10
    assert fresh_data["overall_completed"] == 98.89

# ==============================================================================
# 5. STRICT MULTI-TENANT ISOLATION
# ==============================================================================
def test_multi_tenant_isolation_between_hotels(client):
    """Tenant 1 modifications must not be visible to Tenant 2."""
    h1_headers = auth_header(client, "admin@hotel1.com", tenant_id="1")
    h2_headers = auth_header(client, "admin@hotel2.com", tenant_id="2")

    # Tenant 1 updates Phase 2 to 95%
    u1 = client.put(
        "/api/project-progress",
        json={"phases": [{"phase_number": 2, "completed": 95}]},
        headers=h1_headers
    )
    assert u1.status_code == 200
    t1_p2 = next(p for p in u1.json()["phases"] if p["phase_number"] == 2)
    assert t1_p2["completed"] == 95
    assert t1_p2["status"] == "In Progress"
    assert u1.json()["completed_phases"] == 8  # All except Phase 2

    # Tenant 2 checks progress: Must still see default 100% for Phase 2
    res_t2 = client.get("/api/project-progress", headers=h2_headers)
    assert res_t2.status_code == 200
    t2_p2 = next(p for p in res_t2.json()["phases"] if p["phase_number"] == 2)
    assert t2_p2["completed"] == 100
    assert t2_p2["status"] == "Completed"
    assert res_t2.json()["completed_phases"] == 9  # All 9 completed

def test_super_admin_can_inspect_tenants_with_header(client):
    """Super Admin passes X-Tenant-Id to inspect specific tenant data."""
    sa_h1 = auth_header(client, "superadmin@stayflow.com", password="SuperSecret@123", tenant_id="1")
    sa_h2 = auth_header(client, "superadmin@stayflow.com", password="SuperSecret@123", tenant_id="2")

    res1 = client.get("/api/project-progress", headers=sa_h1)
    assert res1.status_code == 200
    assert res1.json()["tenant_id"] == 1

    res2 = client.get("/api/project-progress", headers=sa_h2)
    assert res2.status_code == 200
    assert res2.json()["tenant_id"] == 2

# ==============================================================================
# 6. RBAC PERMISSIONS VERIFICATION
# ==============================================================================
def test_customer_role_forbidden_from_project_progress(client):
    """Customer accounts cannot access project progress (returns 403)."""
    headers = auth_header(client, "guest@example.com", tenant_id="1")
    res = client.get("/api/project-progress", headers=headers)
    assert res.status_code == 403, f"Expected 403 for Customer, got {res.status_code}"

def test_unauthorized_staff_cannot_update_progress(client):
    """Front Desk staff cannot update project progress (returns 403)."""
    headers = auth_header(client, "frontdesk@hotel1.com", tenant_id="1")
    # Can view
    v_res = client.get("/api/project-progress", headers=headers)
    assert v_res.status_code == 200

    # Cannot update
    u_res = client.put(
        "/api/project-progress",
        json={"phases": [{"phase_number": 3, "completed": 99}]},
        headers=headers
    )
    assert u_res.status_code == 403, f"Expected 403 for Front Desk PUT, got {u_res.status_code}"

# ==============================================================================
# 7. INPUT VALIDATION EDGE CASES
# ==============================================================================
def test_invalid_completed_percentage_rejected(client):
    """Rejects completed > 100, < 0, or alphabetic input with HTTP 422."""
    headers = auth_header(client, "admin@hotel1.com", tenant_id="1")

    # > 100
    r1 = client.put("/api/project-progress", json={"phase_number": 1, "completed": 105}, headers=headers)
    assert r1.status_code == 422

    # < 0
    r2 = client.put("/api/project-progress", json={"phase_number": 1, "completed": -5}, headers=headers)
    assert r2.status_code == 422

    # Alphabetic
    r3 = client.put("/api/project-progress", json={"phase_number": 1, "completed": "one_hundred"}, headers=headers)
    assert r3.status_code == 422

