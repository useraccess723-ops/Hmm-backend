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
from app.models import User, RoomType, Room, Guest, Reservation, Role, Tenant, Amenity


@pytest.fixture()
def client():
    settings.JWT_SECRET_KEY = "test-secret-key-with-at-least-32-characters-long"
    test_engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    TestingSession = sessionmaker(bind=test_engine, autoflush=False, autocommit=False, expire_on_commit=False)
    Base.metadata.create_all(bind=test_engine)

    with TestingSession() as db:
        # Seed Tenants
        t1 = Tenant(id=1, name="Grand Hotel Alpha", slug="grand-hotel-alpha", code="HOTEL-001", is_active=True, status="Active")
        t2 = Tenant(id=2, name="Resort Beta", slug="resort-beta", code="HOTEL-002", is_active=True, status="Active")
        db.add_all([t1, t2])
        db.commit()

        # Seed Users
        admin_user = User(
            email="admin@hotel.com",
            full_name="Hotel Administrator",
            password_hash=hash_password("Password@123"),
            role="ADMIN",
            hotel_id=1,
            tenant_id=1,
            is_super_admin=False
        )
        fd_user = User(
            email="frontdesk@hotel.com",
            full_name="Priya Sharma",
            password_hash=hash_password("Password@123"),
            role="FRONT_DESK",
            hotel_id=1,
            tenant_id=1
        )
        fd2_user = User(
            email="frontdesk2@hotel.com",
            full_name="Hotel 2 Front Desk",
            password_hash=hash_password("Password@123"),
            role="FRONT_DESK",
            hotel_id=2,
            tenant_id=2
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
        hotel2_user = User(
            email="manager2@hotel.com",
            full_name="Hotel 2 Manager",
            password_hash=hash_password("Password@123"),
            role="GENERAL_MANAGER",
            hotel_id=2,
            tenant_id=2
        )
        db.add_all([admin_user, fd_user, fd2_user, hk_user, hr_user, hotel2_user])

        # Seed System Roles with initial permissions
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
        gm_perms = {
            "/": {"view": True, "create": False, "edit": False, "delete": False},
            "/front-desk": {"view": True, "create": True, "edit": True, "delete": False},
            "/bookings": {"view": True, "create": True, "edit": True, "delete": False},
            "/guests": {"view": True, "create": True, "edit": True, "delete": False},
            "/rooms": {"view": True, "create": True, "edit": True, "delete": False},
            "/reports": {"view": True, "create": False, "edit": False, "delete": False},
        }
        db.add_all([
            Role(tenant_id=1, name="Front Desk", code="FRONT_DESK", description="Front Desk Staff", is_system=True, permissions=json.dumps(fd_initial_perms)),
            Role(tenant_id=1, name="Housekeeping", code="HOUSEKEEPING", description="Housekeeping Staff", is_system=True, permissions=json.dumps(hk_initial_perms)),
            Role(tenant_id=1, name="Human Resources", code="HUMAN_RESOURCES", description="HR Staff", is_system=True, permissions=json.dumps(hr_initial_perms)),
            Role(tenant_id=2, name="Front Desk", code="FRONT_DESK", description="Hotel 2 Front Desk", is_system=True, permissions=json.dumps(fd_initial_perms)),
            Role(tenant_id=2, name="General Manager", code="GENERAL_MANAGER", description="Hotel 2 GM", is_system=True, permissions=json.dumps(gm_perms)),
        ])

        # Seed Room Type, Room, Guest & Reservation
        rt = RoomType(tenant_id=1, name="Deluxe Suite", base_price=Decimal("3500.00"), max_occupancy=2, description="", amenities="[]")
        db.add(rt)
        db.commit()

        rm = Room(tenant_id=1, number="101", floor=1, room_type_id=rt.id, status="vac", description="")
        db.add(rm)
        db.commit()

        gst = Guest(tenant_id=1, full_name="Rahul Verma", email="rahul@example.com", phone="+919876543210")
        db.add(gst)
        db.commit()

        res = Reservation(
            tenant_id=1,
            reference="BK-RBAC-001",
            guest_id=gst.id,
            room_id=rm.id,
            check_in=date.today(),
            check_out=date.today() + timedelta(days=2),
            num_guests=2,
            total_amount=Decimal("7000.00"),
            status="Confirmed",
            source="Direct"
        )
        db.add(res)
        db.commit()

        # Seed Amenity
        amenity = Amenity(
            hotel_id=1,
            name="Infinity Pool",
            amenity_type="pool",
            pricing_type="paid",
            price=Decimal("500.00"),
            status="available",
            details=json.dumps({"hours": "06:00 - 22:00"})
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
# TEST CASE 1: Front Desk permission disabled -> Front Desk portal blocked
# ==============================================================================
def test_case_01_front_desk_permission_disabled(client):
    admin_headers = auth_header(client, "admin@hotel.com")
    fd_headers = auth_header(client, "frontdesk@hotel.com")

    roles_res = client.get("/api/rbac/roles", headers=admin_headers)
    assert roles_res.status_code == 200
    fd_role = next(r for r in roles_res.json() if r["code"] == "FRONT_DESK" and r.get("tenant_id") == 1)

    # Disable Front Desk portal permissions
    perms = {
        "/": {"view": False, "create": False, "edit": False, "delete": False},
        "/front-desk": {"view": False, "create": False, "edit": False, "delete": False},
        "/bookings": {"view": False, "create": False, "edit": False, "delete": False},
    }
    update_res = client.put(f"/api/rbac/roles/{fd_role['id']}", json={"permissions": perms}, headers=admin_headers)
    assert update_res.status_code == 200

    # Front Desk APIs must return HTTP 403
    r_dash = client.get("/api/dashboard", headers=fd_headers)
    assert r_dash.status_code == 403
    r_bk = client.get("/api/bookings", headers=fd_headers)
    assert r_bk.status_code == 403
    r_ci = client.post("/api/bookings/BK-RBAC-001/check-in", headers=fd_headers)
    assert r_ci.status_code == 403


# ==============================================================================
# TEST CASE 2: Housekeeping permission disabled -> Housekeeping portal blocked
# ==============================================================================
def test_case_02_housekeeping_permission_disabled(client):
    admin_headers = auth_header(client, "admin@hotel.com")
    hk_headers = auth_header(client, "housekeeping@hotel.com")

    roles_res = client.get("/api/rbac/roles", headers=admin_headers)
    hk_role = next(r for r in roles_res.json() if r["code"] == "HOUSEKEEPING" and r.get("tenant_id") == 1)

    # Disable Housekeeping portal permissions
    perms = {
        "/": {"view": False, "create": False, "edit": False, "delete": False},
        "/housekeeping": {"view": False, "create": False, "edit": False, "delete": False},
        "/rooms": {"view": False, "create": False, "edit": False, "delete": False},
    }
    client.put(f"/api/rbac/roles/{hk_role['id']}", json={"permissions": perms}, headers=admin_headers)

    # Housekeeping portal APIs must return HTTP 403
    r_dash = client.get("/api/dashboard", headers=hk_headers)
    assert r_dash.status_code == 403
    r_rm = client.get("/api/rooms", headers=hk_headers)
    assert r_rm.status_code == 403
    r_hk = client.get("/api/records?category=housekeeping_tasks", headers=hk_headers)
    assert r_hk.status_code == 403


# ==============================================================================
# TEST CASE 3: Human Resources permission disabled -> HR portal blocked
# ==============================================================================
def test_case_03_hr_permission_disabled(client):
    admin_headers = auth_header(client, "admin@hotel.com")
    hr_headers = auth_header(client, "hr@hotel.com")

    roles_res = client.get("/api/rbac/roles", headers=admin_headers)
    hr_role = next(r for r in roles_res.json() if r["code"] == "HUMAN_RESOURCES" and r.get("tenant_id") == 1)

    # Disable HR portal permissions
    perms = {
        "/": {"view": False, "create": False, "edit": False, "delete": False},
        "/human-resources": {"view": False, "create": False, "edit": False, "delete": False},
    }
    client.put(f"/api/rbac/roles/{hr_role['id']}", json={"permissions": perms}, headers=admin_headers)

    # HR portal APIs must return HTTP 403
    r_dash = client.get("/api/dashboard", headers=hr_headers)
    assert r_dash.status_code == 403
    r_hr = client.get("/api/records?category=employees", headers=hr_headers)
    assert r_hr.status_code == 403
    r_leave = client.get("/api/hr/leave", headers=hr_headers)
    assert r_leave.status_code == 403


# ==============================================================================
# TEST CASE 4: Dashboard permission disabled -> Dashboard blocked
# ==============================================================================
def test_case_04_dashboard_permission_disabled(client):
    admin_headers = auth_header(client, "admin@hotel.com")
    fd_headers = auth_header(client, "frontdesk@hotel.com")

    roles_res = client.get("/api/rbac/roles", headers=admin_headers)
    fd_role = next(r for r in roles_res.json() if r["code"] == "FRONT_DESK" and r.get("tenant_id") == 1)

    # Enable front desk but explicitly DISABLE dashboard (/)
    perms = {
        "/": {"view": False, "create": False, "edit": False, "delete": False},
        "/front-desk": {"view": True, "create": True, "edit": True, "delete": False},
        "/bookings": {"view": True, "create": True, "edit": True, "delete": False},
    }
    client.put(f"/api/rbac/roles/{fd_role['id']}", json={"permissions": perms}, headers=admin_headers)

    # Dashboard is blocked (403)
    r_dash = client.get("/api/dashboard", headers=fd_headers)
    assert r_dash.status_code == 403
    # Front desk bookings still accessible
    r_bk = client.get("/api/bookings", headers=fd_headers)
    assert r_bk.status_code == 200


# ==============================================================================
# TEST CASE 5: Front Desk Guest Amenities Booking disabled -> Only that feature blocked
# ==============================================================================
def test_case_05_front_desk_amenities_booking_disabled(client):
    admin_headers = auth_header(client, "admin@hotel.com")
    fd_headers = auth_header(client, "frontdesk@hotel.com")

    roles_res = client.get("/api/rbac/roles", headers=admin_headers)
    fd_role = next(r for r in roles_res.json() if r["code"] == "FRONT_DESK" and r.get("tenant_id") == 1)

    # Front Desk enabled, but Guest Amenities Booking explicitly disabled
    perms = {
        "/": {"view": True, "create": False, "edit": False, "delete": False},
        "/front-desk": {"view": True, "create": True, "edit": True, "delete": False},
        "/front-desk/amenities-booking": {"view": False, "create": False, "edit": False, "delete": False},
        "/bookings": {"view": True, "create": True, "edit": True, "delete": False},
    }
    client.put(f"/api/rbac/roles/{fd_role['id']}", json={"permissions": perms}, headers=admin_headers)

    # Front Desk amenities endpoints return HTTP 403
    r_amen = client.get("/api/amenities", headers=fd_headers)
    assert r_amen.status_code == 403
    r_cust_amen = client.get("/api/customer/amenities", headers=fd_headers)
    assert r_cust_amen.status_code == 403
    r_sr = client.get("/api/service-requests", headers=fd_headers)
    assert r_sr.status_code == 403

    # Other Front Desk features must remain fully accessible
    r_bk = client.get("/api/bookings", headers=fd_headers)
    assert r_bk.status_code == 200


# ==============================================================================
# TEST CASE 6: Housekeeping Guest Amenities Booking disabled -> Only HK feature blocked
# ==============================================================================
def test_case_06_housekeeping_amenities_booking_disabled(client):
    admin_headers = auth_header(client, "admin@hotel.com")
    hk_headers = auth_header(client, "housekeeping@hotel.com")

    roles_res = client.get("/api/rbac/roles", headers=admin_headers)
    hk_role = next(r for r in roles_res.json() if r["code"] == "HOUSEKEEPING" and r.get("tenant_id") == 1)

    # Housekeeping enabled, but Housekeeping Guest Amenities Booking disabled
    perms = {
        "/": {"view": True, "create": False, "edit": False, "delete": False},
        "/housekeeping": {"view": True, "create": True, "edit": True, "delete": False},
        "/housekeeping/amenities-booking": {"view": False, "create": False, "edit": False, "delete": False},
        "/rooms": {"view": True, "create": False, "edit": True, "delete": False},
    }
    client.put(f"/api/rbac/roles/{hk_role['id']}", json={"permissions": perms}, headers=admin_headers)

    # Housekeeping amenities endpoints return HTTP 403
    r_amen = client.get("/api/amenities", headers=hk_headers)
    assert r_amen.status_code == 403
    r_sr = client.get("/api/service-requests", headers=hk_headers)
    assert r_sr.status_code == 403

    # Housekeeping rooms list remains accessible
    r_rm = client.get("/api/rooms", headers=hk_headers)
    assert r_rm.status_code == 200


# ==============================================================================
# TEST CASE 7: Guest Amenities Booking enabled for one role -> Available only to permitted role
# ==============================================================================
def test_case_07_amenities_booking_enabled_for_one_role_only(client):
    admin_headers = auth_header(client, "admin@hotel.com")
    fd_headers = auth_header(client, "frontdesk@hotel.com")
    hk_headers = auth_header(client, "housekeeping@hotel.com")

    roles_res = client.get("/api/rbac/roles", headers=admin_headers)
    fd_role = next(r for r in roles_res.json() if r["code"] == "FRONT_DESK" and r.get("tenant_id") == 1)
    hk_role = next(r for r in roles_res.json() if r["code"] == "HOUSEKEEPING" and r.get("tenant_id") == 1)

    # Enable for Front Desk
    client.put(f"/api/rbac/roles/{fd_role['id']}", json={"permissions": {
        "/front-desk": {"view": True, "create": True, "edit": True, "delete": False},
        "/front-desk/amenities-booking": {"view": True, "create": True, "edit": True, "delete": False}
    }}, headers=admin_headers)

    # Disable for Housekeeping
    client.put(f"/api/rbac/roles/{hk_role['id']}", json={"permissions": {
        "/housekeeping": {"view": True, "create": True, "edit": True, "delete": False},
        "/housekeeping/amenities-booking": {"view": False, "create": False, "edit": False, "delete": False},
        "/rooms": {"view": True, "create": False, "edit": True, "delete": False}
    }}, headers=admin_headers)

    # Front Desk CAN access amenities
    r_fd = client.get("/api/amenities", headers=fd_headers)
    assert r_fd.status_code == 200

    # Housekeeping CANNOT access amenities
    r_hk = client.get("/api/amenities", headers=hk_headers)
    assert r_hk.status_code == 403


# ==============================================================================
# TEST CASE 8: All permissions disabled -> No protected modules accessible
# ==============================================================================
def test_case_08_all_permissions_disabled(client):
    admin_headers = auth_header(client, "admin@hotel.com")
    fd_headers = auth_header(client, "frontdesk@hotel.com")

    roles_res = client.get("/api/rbac/roles", headers=admin_headers)
    fd_role = next(r for r in roles_res.json() if r["code"] == "FRONT_DESK" and r.get("tenant_id") == 1)

    # Disable everything
    client.put(f"/api/rbac/roles/{fd_role['id']}", json={"permissions": {}}, headers=admin_headers)

    endpoints = [
        "/api/dashboard",
        "/api/bookings",
        "/api/rooms",
        "/api/guests",
        "/api/amenities",
        "/api/service-requests",
        "/api/reports/revenue-by-room"
    ]
    for ep in endpoints:
        r = client.get(ep, headers=fd_headers)
        assert r.status_code == 403, f"Expected 403 for {ep}, got {r.status_code}"


# ==============================================================================
# TEST CASE 9: Live permission revocation on active session
# ==============================================================================
def test_case_09_live_permission_revocation(client):
    admin_headers = auth_header(client, "admin@hotel.com")
    fd_headers = auth_header(client, "frontdesk@hotel.com")

    roles_res = client.get("/api/rbac/roles", headers=admin_headers)
    fd_role = next(r for r in roles_res.json() if r["code"] == "FRONT_DESK" and r.get("tenant_id") == 1)

    # Initially enabled
    client.put(f"/api/rbac/roles/{fd_role['id']}", json={"permissions": {
        "/front-desk": {"view": True, "create": True, "edit": True, "delete": False},
        "/bookings": {"view": True, "create": True, "edit": True, "delete": False}
    }}, headers=admin_headers)

    # Request succeeds
    assert client.get("/api/bookings", headers=fd_headers).status_code == 200

    # Administrator revokes live
    client.put(f"/api/rbac/roles/{fd_role['id']}", json={"permissions": {}}, headers=admin_headers)

    # Next request using same active session token is immediately denied
    assert client.get("/api/bookings", headers=fd_headers).status_code == 403


# ==============================================================================
# TEST CASE 10: Direct URL access to a disabled feature (API rejection verification)
# ==============================================================================
def test_case_10_direct_access_to_disabled_feature(client):
    admin_headers = auth_header(client, "admin@hotel.com")
    fd_headers = auth_header(client, "frontdesk@hotel.com")

    roles_res = client.get("/api/rbac/roles", headers=admin_headers)
    fd_role = next(r for r in roles_res.json() if r["code"] == "FRONT_DESK" and r.get("tenant_id") == 1)

    # Disable rooms
    client.put(f"/api/rbac/roles/{fd_role['id']}", json={"permissions": {
        "/front-desk": {"view": True, "create": True, "edit": True, "delete": False},
        "/rooms": {"view": False, "create": False, "edit": False, "delete": False}
    }}, headers=admin_headers)

    # Attempting to fetch room details directly
    r = client.get("/api/rooms", headers=fd_headers)
    assert r.status_code == 403


# ==============================================================================
# TEST CASE 11: Direct API request without permission -> HTTP 403
# ==============================================================================
def test_case_11_direct_api_request_without_permission(client):
    admin_headers = auth_header(client, "admin@hotel.com")
    hk_headers = auth_header(client, "housekeeping@hotel.com")

    roles_res = client.get("/api/rbac/roles", headers=admin_headers)
    hk_role = next(r for r in roles_res.json() if r["code"] == "HOUSEKEEPING" and r.get("tenant_id") == 1)

    # HK without bookings permission
    client.put(f"/api/rbac/roles/{hk_role['id']}", json={"permissions": {
        "/housekeeping": {"view": True, "create": True, "edit": True, "delete": False},
    }}, headers=admin_headers)

    # Attempting to mutate bookings directly returns 403
    r = client.post("/api/bookings/BK-RBAC-001/check-in", headers=hk_headers)
    assert r.status_code == 403


# ==============================================================================
# TEST CASE 12: Other roles' permissions unaffected
# ==============================================================================
def test_case_12_other_roles_unaffected(client):
    admin_headers = auth_header(client, "admin@hotel.com")
    fd_headers = auth_header(client, "frontdesk@hotel.com")
    hk_headers = auth_header(client, "housekeeping@hotel.com")

    roles_res = client.get("/api/rbac/roles", headers=admin_headers)
    fd_role = next(r for r in roles_res.json() if r["code"] == "FRONT_DESK" and r.get("tenant_id") == 1)
    hk_role = next(r for r in roles_res.json() if r["code"] == "HOUSEKEEPING" and r.get("tenant_id") == 1)

    # Strip Front Desk
    client.put(f"/api/rbac/roles/{fd_role['id']}", json={"permissions": {}}, headers=admin_headers)

    # Ensure Housekeeping has rooms permission
    client.put(f"/api/rbac/roles/{hk_role['id']}", json={"permissions": {
        "/housekeeping": {"view": True, "create": True, "edit": True, "delete": False},
        "/rooms": {"view": True, "create": False, "edit": True, "delete": False}
    }}, headers=admin_headers)

    # Front Desk is blocked from rooms
    assert client.get("/api/rooms", headers=fd_headers).status_code == 403
    # Housekeeping still succeeds
    assert client.get("/api/rooms", headers=hk_headers).status_code == 200


# ==============================================================================
# TEST CASE 13: Parent module disabled -> All child features blocked
# ==============================================================================
def test_case_13_parent_module_disabled_blocks_all_children(client):
    admin_headers = auth_header(client, "admin@hotel.com")
    fd_headers = auth_header(client, "frontdesk@hotel.com")

    roles_res = client.get("/api/rbac/roles", headers=admin_headers)
    fd_role = next(r for r in roles_res.json() if r["code"] == "FRONT_DESK" and r.get("tenant_id") == 1)

    # Explicitly set parent /front-desk to False, even if a child was set to True
    client.put(f"/api/rbac/roles/{fd_role['id']}", json={"permissions": {
        "/front-desk": {"view": False, "create": False, "edit": False, "delete": False},
        "/front-desk/amenities-booking": {"view": True, "create": True, "edit": True, "delete": False}
    }}, headers=admin_headers)

    # Child amenities booking under front desk is blocked because parent is disabled
    r = client.get("/api/amenities", headers=fd_headers)
    assert r.status_code == 403


# ==============================================================================
# TEST CASE 14: Parent enabled, one child disabled -> Other child features work
# ==============================================================================
def test_case_14_parent_enabled_one_child_disabled(client):
    admin_headers = auth_header(client, "admin@hotel.com")
    fd_headers = auth_header(client, "frontdesk@hotel.com")

    roles_res = client.get("/api/rbac/roles", headers=admin_headers)
    fd_role = next(r for r in roles_res.json() if r["code"] == "FRONT_DESK" and r.get("tenant_id") == 1)

    # Parent /front-desk enabled, child amenities disabled, bookings enabled
    client.put(f"/api/rbac/roles/{fd_role['id']}", json={"permissions": {
        "/front-desk": {"view": True, "create": True, "edit": True, "delete": False},
        "/front-desk/amenities-booking": {"view": False, "create": False, "edit": False, "delete": False},
        "/bookings": {"view": True, "create": True, "edit": True, "delete": False}
    }}, headers=admin_headers)

    # Child amenities booking returns 403
    assert client.get("/api/amenities", headers=fd_headers).status_code == 403

    # Other child / related front desk features work
    assert client.get("/api/bookings", headers=fd_headers).status_code == 200


# ==============================================================================
# TEST CASE 15: Page refreshed after update -> Saved permission state persisted
# ==============================================================================
def test_case_15_saved_permission_state_persisted(client):
    admin_headers = auth_header(client, "admin@hotel.com")

    roles_res = client.get("/api/rbac/roles", headers=admin_headers)
    fd_role = next(r for r in roles_res.json() if r["code"] == "FRONT_DESK" and r.get("tenant_id") == 1)

    custom_perms = {
        "/": {"view": True, "create": False, "edit": False, "delete": False},
        "/front-desk": {"view": True, "create": True, "edit": False, "delete": False},
        "/front-desk/amenities-booking": {"view": True, "create": False, "edit": False, "delete": False}
    }
    client.put(f"/api/rbac/roles/{fd_role['id']}", json={"permissions": custom_perms}, headers=admin_headers)

    # Simulate fresh fetch (page reload)
    refreshed_roles = client.get("/api/rbac/roles", headers=admin_headers).json()
    saved_fd_role = next(r for r in refreshed_roles if r["id"] == fd_role["id"])
    assert saved_fd_role["permissions"]["/front-desk/amenities-booking"]["view"] is True
    assert saved_fd_role["permissions"]["/front-desk/amenities-booking"]["create"] is False


# ==============================================================================
# TEST CASE 16: Missing permission configuration -> Default deny
# ==============================================================================
def test_case_16_missing_permission_default_deny(client):
    admin_headers = auth_header(client, "admin@hotel.com")
    fd_headers = auth_header(client, "frontdesk@hotel.com")

    roles_res = client.get("/api/rbac/roles", headers=admin_headers)
    fd_role = next(r for r in roles_res.json() if r["code"] == "FRONT_DESK" and r.get("tenant_id") == 1)

    # Configure only front-desk, leaving finance, hr, inventory, reports completely missing
    client.put(f"/api/rbac/roles/{fd_role['id']}", json={"permissions": {
        "/front-desk": {"view": True, "create": True, "edit": True, "delete": False}
    }}, headers=admin_headers)

    # Unconfigured endpoints must default deny (403)
    assert client.get("/api/reports/revenue-by-room", headers=fd_headers).status_code == 403
    assert client.get("/api/hr/leave", headers=fd_headers).status_code == 403
    assert client.get("/api/dashboard", headers=fd_headers).status_code == 403
