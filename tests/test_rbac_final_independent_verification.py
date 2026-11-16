import os
import sys
import json
from decimal import Decimal
from datetime import date, timedelta

os.environ["TESTING"] = "1"
os.environ.setdefault("JWT_SECRET_KEY", "test-secret-key-with-at-least-32-characters-long")
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.main import app
from app.database.connection import Base, get_db
from app.core.config import settings
from app.core.security import hash_password
from app.models import User, RoomType, Room, Guest, Reservation, Role, Tenant, Amenity, OperationalRecord


@pytest.fixture(scope="module")
def client():
    settings.JWT_SECRET_KEY = "test-secret-key-with-at-least-32-characters-long"
    test_engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    TestingSession = sessionmaker(bind=test_engine, autoflush=False, autocommit=False, expire_on_commit=False)
    Base.metadata.create_all(bind=test_engine)

    with TestingSession() as db:
        # Seed Separate Test Tenants
        t1 = Tenant(id=1, name="Grand Hotel Alpha", slug="grand-hotel-alpha", code="HOTEL-001", is_active=True, status="Active")
        t2 = Tenant(id=2, name="Resort Beta", slug="resort-beta", code="HOTEL-002", is_active=True, status="Active")
        db.add_all([t1, t2])
        db.commit()

        # Seed Users
        superadmin = User(
            email="superadmin@stayflow.com",
            full_name="Global Super Administrator",
            password_hash=hash_password("Password@123"),
            role="SUPER_ADMIN",
            hotel_id=None,
            tenant_id=None,
            is_super_admin=True
        )
        hotel1_admin = User(
            email="admin@hotel.com",
            full_name="Hotel 1 Admin",
            password_hash=hash_password("Password@123"),
            role="ADMIN",
            hotel_id=1,
            tenant_id=1,
            is_super_admin=False
        )
        hotel2_admin = User(
            email="admin2@resortbeta.com",
            full_name="Hotel 2 Admin",
            password_hash=hash_password("Password@123"),
            role="ADMIN",
            hotel_id=2,
            tenant_id=2,
            is_super_admin=False
        )
        fd_user = User(
            email="frontdesk@hotel.com",
            full_name="Priya Front Desk",
            password_hash=hash_password("Password@123"),
            role="FRONT_DESK",
            hotel_id=1,
            tenant_id=1
        )
        hk_user = User(
            email="housekeeping@hotel.com",
            full_name="Ramesh Housekeeping",
            password_hash=hash_password("Password@123"),
            role="HOUSEKEEPING",
            hotel_id=1,
            tenant_id=1
        )
        hr_user = User(
            email="hr@hotel.com",
            full_name="Ananya HR",
            password_hash=hash_password("Password@123"),
            role="HUMAN_RESOURCES",
            hotel_id=1,
            tenant_id=1
        )
        hotel2_fd = User(
            email="frontdesk2@hotel.com",
            full_name="Hotel 2 Front Desk",
            password_hash=hash_password("Password@123"),
            role="FRONT_DESK",
            hotel_id=2,
            tenant_id=2
        )
        db.add_all([superadmin, hotel1_admin, hotel2_admin, fd_user, hk_user, hr_user, hotel2_fd])

        # Seed Roles with default permissions
        fd_initial_perms = {
            "/": {"view": True, "create": False, "edit": False, "delete": False},
            "/front-desk": {"view": True, "create": True, "edit": True, "delete": False},
            "/front-desk/amenities-booking": {"view": True, "create": True, "edit": True, "delete": False},
            "/bookings": {"view": True, "create": True, "edit": True, "delete": False},
            "/guests": {"view": True, "create": True, "edit": True, "delete": False},
            "/rooms": {"view": True, "create": False, "edit": False, "delete": False},
        }
        hk_initial_perms = {
            "/": {"view": True, "create": False, "edit": False, "delete": False},
            "/housekeeping": {"view": True, "create": True, "edit": True, "delete": False},
            "/housekeeping/amenities-booking": {"view": True, "create": True, "edit": True, "delete": False},
            "/rooms": {"view": True, "create": False, "edit": True, "delete": False},
        }
        hr_initial_perms = {
            "/": {"view": True, "create": False, "edit": False, "delete": False},
            "/human-resources": {"view": True, "create": True, "edit": True, "delete": False},
            "/human-resources/employee-directory": {"view": True, "create": True, "edit": True, "delete": False},
        }
        db.add_all([
            Role(id=1, tenant_id=1, name="Front Desk", code="FRONT_DESK", description="Front Desk Staff", is_system=True, permissions=json.dumps(fd_initial_perms)),
            Role(id=2, tenant_id=1, name="Housekeeping", code="HOUSEKEEPING", description="Housekeeping Staff", is_system=True, permissions=json.dumps(hk_initial_perms)),
            Role(id=3, tenant_id=1, name="Human Resources", code="HUMAN_RESOURCES", description="HR Staff", is_system=True, permissions=json.dumps(hr_initial_perms)),
            Role(id=4, tenant_id=2, name="Front Desk", code="FRONT_DESK", description="Hotel 2 Front Desk", is_system=True, permissions=json.dumps(fd_initial_perms)),
        ])

        # Seed Operational Entities
        rt = RoomType(tenant_id=1, name="Standard Deluxe", base_price=Decimal("4000.00"), max_occupancy=2, description="", amenities="[]")
        db.add(rt)
        db.commit()

        rm = Room(tenant_id=1, number="201", floor=2, room_type_id=rt.id, status="vac", description="")
        db.add(rm)
        db.commit()

        gst = Guest(tenant_id=1, full_name="Arjun Nair", email="arjun@stayflow.test", phone="+919876543219")
        db.add(gst)
        db.commit()

        res = Reservation(
            tenant_id=1,
            reference="BK-VERIFY-001",
            guest_id=gst.id,
            room_id=rm.id,
            check_in=date.today(),
            check_out=date.today() + timedelta(days=2),
            num_guests=2,
            total_amount=Decimal("8000.00"),
            status="Confirmed",
            source="Direct"
        )
        db.add(res)

        amenity = Amenity(
            hotel_id=1,
            name="Spa Retreat",
            amenity_type="spa",
            pricing_type="paid",
            price=Decimal("1200.00"),
            status="available",
            details=json.dumps({"service": "Full body massage"})
        )
        db.add(amenity)
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


def auth_header(client, email, password="Password@123"):
    res = client.post("/api/auth/token", data={"username": email, "password": password})
    assert res.status_code == 200, res.text
    return {"Authorization": f"Bearer {res.json()['access_token']}"}


# ==============================================================================
# 1. VERIFY ALL ROLES & METADATA PERMISSIONS
# ==============================================================================
def test_verify_roles_and_module_metadata(client):
    admin_headers = auth_header(client, "admin@hotel.com")
    res = client.get("/api/rbac/permissions-meta", headers=admin_headers)
    assert res.status_code == 200
    meta = res.json()
    paths = [m["path"] for m in meta]
    assert "/" in paths
    assert "/front-desk" in paths
    assert "/housekeeping" in paths
    assert "/rooms" in paths
    assert "/bookings" in paths

    # Check Guest Amenities Booking submodule in Front Desk and Housekeeping
    fd_mod = next(m for m in meta if m["path"] == "/front-desk")
    fd_sub_paths = [s["path"] for s in fd_mod["submodules"]]
    assert "/front-desk/amenities-booking" in fd_sub_paths

    hk_mod = next(m for m in meta if m["path"] == "/housekeeping")
    hk_sub_paths = [s["path"] for s in hk_mod["submodules"]]
    assert "/housekeeping/amenities-booking" in hk_sub_paths


# ==============================================================================
# 2. VERIFY PROTECTED READ AND WRITE APIS ENFORCE HTTP 403 ON DENIAL
# ==============================================================================
def test_verify_protected_read_and_write_apis_return_403(client):
    admin_headers = auth_header(client, "admin@hotel.com")
    fd_headers = auth_header(client, "frontdesk@hotel.com")

    # Disable write operations (create/edit/delete) for front desk
    client.put("/api/rbac/roles/1", json={"permissions": {
        "/": {"view": True, "create": False, "edit": False, "delete": False},
        "/front-desk": {"view": True, "create": False, "edit": False, "delete": False},
        "/bookings": {"view": True, "create": False, "edit": False, "delete": False},
    }}, headers=admin_headers)

    # 1. Read operations succeed
    assert client.get("/api/bookings", headers=fd_headers).status_code == 200

    # 2. Write operations return HTTP 403
    # 2a. POST /api/bookings -> 403
    r_post = client.post("/api/bookings", json={"guest_name": "Test Guest", "room_id": 1, "check_in": str(date.today()), "check_out": str(date.today() + timedelta(days=1))}, headers=fd_headers)
    assert r_post.status_code == 403, f"Expected 403 for unauthorized booking creation, got {r_post.status_code}"

    # 2b. PUT /api/bookings/{ref} -> 403
    r_put = client.put("/api/bookings/BK-VERIFY-001", json={"notes": "Updated note"}, headers=fd_headers)
    assert r_put.status_code == 403

    # 2c. DELETE /api/bookings/{ref} -> 403
    r_del = client.delete("/api/bookings/BK-VERIFY-001", headers=fd_headers)
    assert r_del.status_code == 403

    # 2d. Check-in action (edit) -> 403
    r_ci = client.post("/api/bookings/BK-VERIFY-001/check-in", headers=fd_headers)
    assert r_ci.status_code == 403


# ==============================================================================
# 3. VERIFY FRONT DESK & HOUSEKEEPING GUEST AMENITIES BOOKING INDEPENDENTLY
# ==============================================================================
def test_verify_amenities_booking_independent_controls(client):
    admin_headers = auth_header(client, "admin@hotel.com")
    fd_headers = auth_header(client, "frontdesk@hotel.com")
    hk_headers = auth_header(client, "housekeeping@hotel.com")

    # Front Desk has amenities ENABLED, Housekeeping has amenities DISABLED
    client.put("/api/rbac/roles/1", json={"permissions": {
        "/front-desk": {"view": True, "create": True, "edit": True, "delete": False},
        "/front-desk/amenities-booking": {"view": True, "create": True, "edit": True, "delete": False},
        "/bookings": {"view": True, "create": True, "edit": True, "delete": False},
    }}, headers=admin_headers)

    client.put("/api/rbac/roles/2", json={"permissions": {
        "/housekeeping": {"view": True, "create": True, "edit": True, "delete": False},
        "/housekeeping/amenities-booking": {"view": False, "create": False, "edit": False, "delete": False},
        "/rooms": {"view": True, "create": False, "edit": True, "delete": False},
    }}, headers=admin_headers)

    # FD can view and query amenities
    assert client.get("/api/amenities", headers=fd_headers).status_code == 200
    assert client.get("/api/service-requests", headers=fd_headers).status_code == 200

    # HK is blocked from amenities with 403
    assert client.get("/api/amenities", headers=hk_headers).status_code == 403
    assert client.get("/api/service-requests", headers=hk_headers).status_code == 403

    # HK can still view rooms
    assert client.get("/api/rooms", headers=hk_headers).status_code == 200


# ==============================================================================
# 4. VERIFY DASHBOARD ACCESS IS INDEPENDENTLY CONTROLLED
# ==============================================================================
def test_verify_dashboard_access_independent_control(client):
    admin_headers = auth_header(client, "admin@hotel.com")
    fd_headers = auth_header(client, "frontdesk@hotel.com")

    # Set Dashboard (/) to False, keep /front-desk True
    client.put("/api/rbac/roles/1", json={"permissions": {
        "/": {"view": False, "create": False, "edit": False, "delete": False},
        "/front-desk": {"view": True, "create": True, "edit": True, "delete": False},
        "/bookings": {"view": True, "create": True, "edit": True, "delete": False}
    }}, headers=admin_headers)

    # Dashboard is blocked
    assert client.get("/api/dashboard", headers=fd_headers).status_code == 403
    # Front Desk bookings accessible
    assert client.get("/api/bookings", headers=fd_headers).status_code == 200


# ==============================================================================
# 5. VERIFY PERMISSION REVOCATION DURING ACTIVE SESSION
# ==============================================================================
def test_verify_permission_revocation_during_active_session(client):
    admin_headers = auth_header(client, "admin@hotel.com")
    fd_headers = auth_header(client, "frontdesk@hotel.com")

    # Grant permissions
    client.put("/api/rbac/roles/1", json={"permissions": {
        "/bookings": {"view": True, "create": True, "edit": True, "delete": False}
    }}, headers=admin_headers)

    # First request with active token succeeds
    assert client.get("/api/bookings", headers=fd_headers).status_code == 200

    # Revoke permissions while token is active
    client.put("/api/rbac/roles/1", json={"permissions": {}}, headers=admin_headers)

    # Immediate next request with the same token is denied (HTTP 403)
    assert client.get("/api/bookings", headers=fd_headers).status_code == 403


# ==============================================================================
# 6. VERIFY PERMISSION PERSISTENCE AFTER LOGOUT, LOGIN, AND REFRESH
# ==============================================================================
def test_verify_permission_persistence_across_login_sessions(client):
    admin_headers = auth_header(client, "admin@hotel.com")

    # Save distinct custom permissions
    custom_perms = {
        "/": {"view": True, "create": False, "edit": False, "delete": False},
        "/front-desk": {"view": True, "create": True, "edit": True, "delete": False},
        "/front-desk/amenities-booking": {"view": False, "create": False, "edit": False, "delete": False},
        "/bookings": {"view": True, "create": True, "edit": True, "delete": False},
    }
    client.put("/api/rbac/roles/1", json={"permissions": custom_perms}, headers=admin_headers)

    # Simulate fresh login
    login_res = client.post("/api/auth/token", data={"username": "frontdesk@hotel.com", "password": "Password@123"})
    assert login_res.status_code == 200
    token_headers = {"Authorization": f"Bearer {login_res.json()['access_token']}"}

    # Verify /api/rbac/my-permissions reflects the saved database permissions
    my_perms_res = client.get("/api/rbac/my-permissions", headers=token_headers)
    assert my_perms_res.status_code == 200
    my_perms = my_perms_res.json()["permissions"]
    assert my_perms["/front-desk/amenities-booking"]["view"] is False
    assert my_perms["/bookings"]["view"] is True


# ==============================================================================
# 7. VERIFY PARENT-CHILD BEHAVIOR AND MISSING PERMISSIONS (DEFAULT-DENY)
# ==============================================================================
def test_verify_parent_child_and_missing_permissions_behavior(client):
    admin_headers = auth_header(client, "admin@hotel.com")
    fd_headers = auth_header(client, "frontdesk@hotel.com")

    # Parent disabled: /front-desk = False, child amenities = True
    client.put("/api/rbac/roles/1", json={"permissions": {
        "/front-desk": {"view": False, "create": False, "edit": False, "delete": False},
        "/front-desk/amenities-booking": {"view": True, "create": True, "edit": True, "delete": False},
    }}, headers=admin_headers)

    # Child feature under disabled parent is blocked
    assert client.get("/api/amenities", headers=fd_headers).status_code == 403

    # Missing permission: /reports, /finance, /human-resources not in dict
    assert client.get("/api/reports/revenue-by-room", headers=fd_headers).status_code == 403
    assert client.get("/api/hr/leave", headers=fd_headers).status_code == 403


# ==============================================================================
# 8. VERIFY CROSS-TENANT ROLE AND PERMISSION ISOLATION (TENANT 1 VS TENANT 2)
# ==============================================================================
def test_verify_cross_tenant_role_and_permission_isolation(client):
    admin1_headers = auth_header(client, "admin@hotel.com")
    admin2_headers = auth_header(client, "admin2@resortbeta.com")
    fd2_headers = auth_header(client, "frontdesk2@hotel.com")
    fd1_headers = auth_header(client, "frontdesk@hotel.com")

    # 1. Modify Hotel 1's Front Desk role to have NO permissions
    client.put("/api/rbac/roles/1", json={"permissions": {}}, headers=admin1_headers)

    # Hotel 1 Front Desk is blocked
    assert client.get("/api/bookings", headers=fd1_headers).status_code == 403

    # Hotel 2 Front Desk still retains full default permissions in Tenant 2
    res_t2 = client.get("/api/bookings", headers=fd2_headers)
    assert res_t2.status_code == 200

    # 2. Hotel 1 Admin cannot modify Hotel 2 Role (id=4)
    res_unauth = client.put("/api/rbac/roles/4", json={"permissions": {}}, headers=admin1_headers)
    assert res_unauth.status_code in (403, 404), f"Expected 403 or 404 cross-tenant role update, got {res_unauth.status_code}"


# ==============================================================================
# 9. VERIFY HOTEL ADMIN AND SUPER ADMIN ACCESS BOUNDARIES
# ==============================================================================
def test_verify_hotel_admin_and_super_admin_boundaries(client):
    super_headers = auth_header(client, "superadmin@stayflow.com")
    admin1_headers = auth_header(client, "admin@hotel.com")

    # Super Admin can view all roles and permissions
    roles_super = client.get("/api/rbac/roles", headers=super_headers)
    assert roles_super.status_code == 200
    assert len(roles_super.json()) > 0

    # Hotel 1 Admin cannot access Tenant 2's specific role (id=4)
    roles_hotel1 = client.get("/api/rbac/roles", headers=admin1_headers)
    assert roles_hotel1.status_code == 200
    hotel1_role_ids = {r.get("id") for r in roles_hotel1.json()}
    assert 4 not in hotel1_role_ids


# ==============================================================================
# 10. VERIFY PHASE 10 AI RECEPTIONIST FUNCTIONALITY REMAINS INTACT
# ==============================================================================
def test_verify_phase_10_ai_receptionist_endpoints(client):
    admin_headers = auth_header(client, "admin@hotel.com")

    # Verify AI Receptionist status endpoint
    status_res = client.get("/api/integrations/ai-receptionist", headers=admin_headers)
    assert status_res.status_code == 200
    status_data = status_res.json()
    assert "status" in status_data
    assert "name" in status_data
    assert "auth_method" in status_data

    # Verify health endpoint
    health_res = client.get("/api/integrations/ai-receptionist/health")
    assert health_res.status_code == 200
    health_data = health_res.json()
    assert health_data.get("status") in ("operational", "healthy", "ok", "degraded")
