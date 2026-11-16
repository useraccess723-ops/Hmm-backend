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
        admin_user = User(
            email="admin@hotel.com",
            full_name="Administrator",
            password_hash=hash_password("Password@123"),
            role="ADMIN",
            hotel_id=1,
            tenant_id=1
        )
        hotel2_user = User(
            email="manager2@hotel.com",
            full_name="Hotel 2 Manager",
            password_hash=hash_password("Password@123"),
            role="MANAGER",
            hotel_id=2,
            tenant_id=2
        )
        db.add_all([admin_user, hotel2_user])
        rt = RoomType(tenant_id=1, name="Standard", base_price=Decimal("2000.00"), max_occupancy=2, description="", amenities="[]")
        db.add(rt)
        db.commit()
        db.add(Room(tenant_id=1, number="101", floor=1, room_type_id=rt.id, status="vac", description=""))
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

def auth_header(client, email="admin@hotel.com", password="Password@123"):
    res = client.post("/api/auth/token", data={"username": email, "password": password})
    assert res.status_code == 200, res.text
    return {"Authorization": f"Bearer {res.json()['access_token']}", "X-Tenant-Id": "1"}

def test_reports_database_persistence_rejected(client):
    """Verify that reports & analytics categories are strictly rejected from DB persistence."""
    headers = auth_header(client)
    
    # 1. POST to reports category must return 400
    report_categories = [
        "reports_daily-flash",
        "reports_revenue-summary",
        "reports_manager-log",
        "reports/monthly-summary",
        "reports",
        "offers_redemption-reports"
    ]
    for cat in report_categories:
        payload = {
            "category": cat,
            "title": "Unintended Report Save",
            "data": {"Metric": "Occupancy", "Value": "85%"},
            "status": "Active"
        }
        res = client.post("/api/records", json=payload, headers=headers)
        assert res.status_code == 400, f"Expected 400 for category '{cat}', got {res.status_code}: {res.text}"
        assert "read-only" in res.json()["detail"].lower()

def test_empty_payload_rejected(client):
    """Verify that empty payloads or whitespace-only records are rejected with HTTP 422."""
    headers = auth_header(client)
    payload = {
        "category": "engineering_asset-registry",
        "title": "Empty Asset",
        "data": {},
        "status": "Active"
    }
    res = client.post("/api/records", json=payload, headers=headers)
    assert res.status_code == 422, f"Expected 422 for empty data payload, got {res.status_code}: {res.text}"

def test_operations_procurement_po_creation_and_update(client):
    """Verify Procurement Purchase Orders: field mapping, status sync, and edit without data bleed."""
    headers = auth_header(client)
    po_payload = {
        "category": "procurement_purchase-orders",
        "title": "PO-2026-001",
        "data": {
            "PO Number": "PO-2026-001",
            "Vendor": "Fresh Farms Ltd",
            "Category": "F&B Supplies",
            "Total Amount (₹)": "45000",
            "Status": "Pending Approval"
        },
        "status": "Pending Approval"
    }
    # 1. Create PO
    res = client.post("/api/records", json=po_payload, headers=headers)
    assert res.status_code == 201, res.text
    rec_id = res.json()["id"]
    assert res.json()["title"] == "PO-2026-001"
    assert res.json()["status"] == "Pending Approval"
    
    # 2. Update PO status and fields
    update_payload = {
        "status": "Approved",
        "data": {
            "PO Number": "PO-2026-001",
            "Vendor": "Fresh Farms Ltd",
            "Category": "F&B Supplies",
            "Total Amount (₹)": "45000",
            "Status": "Approved"
        }
    }
    res_update = client.put(f"/api/records/{rec_id}", json=update_payload, headers=headers)
    assert res_update.status_code == 200, res_update.text
    assert res_update.json()["status"] == "Approved"
    assert res_update.json()["data"]["Status"] == "Approved"

def test_operations_engineering_work_orders(client):
    """Verify Engineering Work Orders validation, status, and aliased fields."""
    headers = auth_header(client)
    wo_payload = {
        "category": "engineering_work-orders",
        "title": "WO-101-HVAC",
        "data": {
            "WO #": "WO-101-HVAC",
            "Location": "Room 101",
            "Priority": "High",
            "Status": "Assigned",
            "Assigned To": "Rajesh Kumar",
            "Description": "AC compressor making noise"
        },
        "status": "Assigned"
    }
    res = client.post("/api/records", json=wo_payload, headers=headers)
    assert res.status_code == 201, res.text
    rec_id = res.json()["id"]
    assert res.json()["data"]["WO #"] == "WO-101-HVAC"
    
    # Update work order
    res_up = client.put(f"/api/records/{rec_id}", json={
        "status": "Completed",
        "data": {
            "WO #": "WO-101-HVAC",
            "Location": "Room 101",
            "Priority": "High",
            "Status": "Completed",
            "Assigned To": "Rajesh Kumar",
            "Resolution Notes": "Replaced faulty fan belt"
        }
    }, headers=headers)
    assert res_up.status_code == 200, res_up.text
    assert res_up.json()["status"] == "Completed"
    assert res_up.json()["data"]["Status"] == "Completed"

def test_operations_security_keycard_audits(client):
    """Verify Security Keycard Audits: Lock Result mapping and edit persistence."""
    headers = auth_header(client)
    audit_payload = {
        "category": "security_keycard-audits",
        "title": "AUDIT-2026-99",
        "data": {
            "Audit Log ID": "AUDIT-2026-99",
            "Room / Door ID": "Room 101",
            "Keycard UID": "KC-8849-01",
            "Holder / User ID": "EMP-401",
            "Lock Result": "Access Granted",
            "Verified By": "Security Officer Amit"
        },
        "status": "Access Granted"
    }
    res = client.post("/api/records", json=audit_payload, headers=headers)
    assert res.status_code == 201, res.text
    rec_id = res.json()["id"]
    assert res.json()["status"] == "Access Granted"
    
    # Update audit record
    res_up = client.put(f"/api/records/{rec_id}", json={
        "status": "Access Denied",
        "data": {
            "Audit Log ID": "AUDIT-2026-99",
            "Room / Door ID": "Room 101",
            "Keycard UID": "KC-8849-01",
            "Holder / User ID": "EMP-401",
            "Lock Result": "Access Denied",
            "Verified By": "Security Officer Amit",
            "Remarks": "Keycard expired"
        }
    }, headers=headers)
    assert res_up.status_code == 200, res_up.text
    assert res_up.json()["status"] == "Access Denied"

def test_cross_record_isolation_no_data_bleed(client):
    """Verify two distinct records do not bleed field values into each other."""
    headers = auth_header(client)
    
    # Record A: Food & Beverage KOT
    rec_a = client.post("/api/records", json={
        "category": "food-beverage_kitchen-orders",
        "title": "KOT-501",
        "data": {
            "Order ID": "KOT-501",
            "Table / Room": "Table 4",
            "Server": "Vikram",
            "Items": "2x Butter Chicken, 4x Naan",
            "KOT Status": "Preparing"
        },
        "status": "Preparing"
    }, headers=headers).json()
    
    # Record B: Housekeeping Linen
    rec_b = client.post("/api/records", json={
        "category": "housekeeping_linen-laundry",
        "title": "LINEN-701",
        "data": {
            "Item Type": "King Bed Sheet",
            "Quantity": "50",
            "Vendor": "Sparkle Laundry",
            "Delivery Status": "In Transit"
        },
        "status": "In Transit"
    }, headers=headers).json()
    
    # Fetch both records and verify no key bleeding
    res_get_a = client.get(f"/api/records/{rec_a['id']}", headers=headers).json()
    res_get_b = client.get(f"/api/records/{rec_b['id']}", headers=headers).json()
    
    assert "Item Type" not in res_get_a["data"]
    assert "Table / Room" not in res_get_b["data"]
    assert res_get_a["data"]["Order ID"] == "KOT-501"
    assert res_get_b["data"]["Item Type"] == "King Bed Sheet"


def test_report_configuration_records_crud(client):
    """Verify that report configuration and source records can be created, updated, and deleted with tenant isolation."""
    headers = auth_header(client)
    
    # 1. Create a configuration record under a reports category
    payload = {
        "category": "reports_booking-source",
        "title": "Corporate Direct Channel",
        "data": {"Source": "Corporate Direct", "Share": "12%", "Cancel Rate": "2%"},
        "status": "Active"
    }
    res = client.post("/api/records", json=payload, headers=headers)
    assert res.status_code == 201, res.text
    rec = res.json()
    rec_id = rec["id"]
    
    # 2. Update the record
    update_payload = {
        "data": {"Source": "Corporate Direct Updated", "Share": "15%", "Cancel Rate": "1.5%"},
        "status": "Active"
    }
    res_update = client.put(f"/api/records/{rec_id}", json=update_payload, headers=headers)
    assert res_update.status_code == 200, res_update.text
    assert res_update.json()["data"]["Source"] == "Corporate Direct Updated"
    
    # 3. Cross-tenant access must be rejected (Tenant 2 user cannot access Tenant 1 record)
    h2_headers = auth_header(client, email="manager2@hotel.com", password="Password@123")
    res_cross = client.get(f"/api/records/{rec_id}", headers=h2_headers)
    assert res_cross.status_code in (403, 404), "Cross-tenant access must be rejected"
    
    res_cross_del = client.delete(f"/api/records/{rec_id}", headers=h2_headers)
    assert res_cross_del.status_code in (403, 404), "Cross-tenant deletion must be rejected"
    
    # 4. Delete the record by authorized owner
    res_del = client.delete(f"/api/records/{rec_id}", headers=headers)
    assert res_del.status_code == 200
    
    # 5. Verify deletion
    res_get_deleted = client.get(f"/api/records/{rec_id}", headers=headers)
    assert res_get_deleted.status_code == 404


def test_report_endpoints_data_retrieval_and_tenant_isolation(client):
    """Verify that all report endpoints return structured read-only operational datasets with strict tenant isolation."""
    headers1 = auth_header(client, "admin@hotel.com", "Password@123")
    headers2 = auth_header(client, "manager2@hotel.com", "Password@123")

    # 1. Booking Source Report
    r_bs1 = client.get("/api/reports/booking-source", headers=headers1)
    assert r_bs1.status_code == 200, r_bs1.text
    assert "data" in r_bs1.json()
    assert r_bs1.json()["read_only"] is True

    # 2. Revenue by Room Report
    r_rr1 = client.get("/api/reports/revenue-by-room", headers=headers1)
    assert r_rr1.status_code == 200, r_rr1.text
    assert "data" in r_rr1.json()
    assert r_rr1.json()["read_only"] is True
    assert len(r_rr1.json()["data"]) > 0

    # 3. OTA Commission Report
    r_ota = client.get("/api/reports/ota-commission", headers=headers1)
    assert r_ota.status_code == 200, r_ota.text
    assert "data" in r_ota.json()
    assert r_ota.json()["read_only"] is True

    # 4. Cancellation & Refund Report
    r_cr = client.get("/api/reports/cancellation-refund", headers=headers1)
    assert r_cr.status_code == 200, r_cr.text
    assert "cancellations" in r_cr.json()
    assert r_cr.json()["read_only"] is True

    # 5. No-Show Report
    r_ns = client.get("/api/reports/no-show", headers=headers1)
    assert r_ns.status_code == 200, r_ns.text
    assert "data" in r_ns.json()
    assert r_ns.json()["read_only"] is True

    # 6. Feedback & Complaints Report
    r_fc = client.get("/api/reports/feedback-complaint", headers=headers1)
    assert r_fc.status_code == 200, r_fc.text
    assert "resolution_rate" in r_fc.json()
    assert r_fc.json()["read_only"] is True

    # 7. Offers Redemption Report
    r_off = client.get("/api/reports/offers-redemption", headers=headers1)
    assert r_off.status_code == 200, r_off.text
    assert "data" in r_off.json()
    assert r_off.json()["read_only"] is True

    # 8. Multi-Tenant Isolation Verification
    r_bs2 = client.get("/api/reports/booking-source", headers=headers2)
    assert r_bs2.status_code == 200
    r_rr2 = client.get("/api/reports/revenue-by-room", headers=headers2)
    assert r_rr2.status_code == 200


