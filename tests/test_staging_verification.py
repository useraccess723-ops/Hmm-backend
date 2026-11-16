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
            full_name="Hotel 1 Admin",
            password_hash=hash_password("Password@123"),
            role="ADMIN",
            hotel_id=1,
            tenant_id=1
        )
        staff_user = User(
            email="staff1@hotel.com",
            full_name="Hotel 1 Staff",
            password_hash=hash_password("Password@123"),
            role="STAFF",
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
        db.add_all([admin_user, staff_user, hotel2_user])
        rt = RoomType(tenant_id=1, name="Standard Deluxe", base_price=Decimal("2500.00"), max_occupancy=2, description="", amenities="[]")
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

def auth_header(client, email="admin@hotel.com", password="Password@123", tenant_id="1"):
    res = client.post("/api/auth/token", data={"username": email, "password": password})
    assert res.status_code == 200, res.text
    return {"Authorization": f"Bearer {res.json()['access_token']}", "X-Tenant-Id": str(tenant_id)}

# ==============================================================================
# 1. VERIFY REPORTS READ-ONLY PROTECTION
# ==============================================================================
def test_reports_read_only_protection_all_endpoints(client):
    """Verify that reports & analytics categories are strictly protected from write operations."""
    headers = auth_header(client, "admin@hotel.com", "Password@123", tenant_id="1")
    
    report_categories = [
        "reports_daily-flash",
        "reports_revenue-summary",
        "reports_manager-log",
        "reports_channel-performance",
        "reports_tax-summary",
        "reports/monthly-pnl",
        "reports",
        "offers_redemption-reports"
    ]
    
    for cat in report_categories:
        # POST /api/records
        post_res = client.post("/api/records", json={
            "category": cat,
            "title": f"Report Entry for {cat}",
            "data": {"Total Revenue": "150000", "ADR": "4500"},
            "status": "Final"
        }, headers=headers)
        assert post_res.status_code == 400, f"Expected 400 for POST to '{cat}', got {post_res.status_code}: {post_res.text}"
        assert "read-only" in post_res.json()["detail"].lower()

# ==============================================================================
# 2. VERIFY OPERATIONS EDIT -> SAVE -> REOPEN WORKFLOWS
# ==============================================================================
def test_operations_food_and_beverage_workflow(client):
    """F&B Banquet BEO: Create -> Save -> Reopen/Edit -> Update -> Verify integrity."""
    headers = auth_header(client)
    
    # 1. Create Banquet BEO
    beo_payload = {
        "category": "food-beverage_banquets",
        "title": "BEO-880",
        "data": {
            "BEO #": "BEO-880",
            "Event Title": "Annual Tech Gala",
            "Client Name": "Apex Corp",
            "Banquet Venue": "Grand Ballroom",
            "Pax Count": "150",
            "Meal Format": "Buffet Dinner",
            "BEO Coordinator": "Siddharth Rao",
            "Total Amount (₹)": "350000",
            "Advance Paid (₹)": "100000",
            "Status": "Draft"
        },
        "status": "Draft"
    }
    create_res = client.post("/api/records", json=beo_payload, headers=headers)
    assert create_res.status_code == 201, create_res.text
    rec_id = create_res.json()["id"]
    
    # 2. Reopen (Fetch by ID for Edit)
    get_res = client.get(f"/api/records/{rec_id}", headers=headers)
    assert get_res.status_code == 200
    saved_data = get_res.json()["data"]
    assert saved_data["BEO #"] == "BEO-880"
    assert saved_data["Event Title"] == "Annual Tech Gala"
    assert saved_data["Pax Count"] == "150"
    assert saved_data["Status"] == "Draft"
    
    # 3. Edit & Save (Update)
    updated_data = {**saved_data, "Pax Count": "180", "Status": "Confirmed", "Advance Paid (₹)": "200000"}
    update_res = client.put(f"/api/records/{rec_id}", json={
        "status": "Confirmed",
        "data": updated_data
    }, headers=headers)
    assert update_res.status_code == 200, update_res.text
    assert update_res.json()["status"] == "Confirmed"
    
    # 4. Reopen again and verify all values persist accurately
    reopen_res = client.get(f"/api/records/{rec_id}", headers=headers)
    assert reopen_res.status_code == 200
    final_data = reopen_res.json()["data"]
    assert final_data["Pax Count"] == "180"
    assert final_data["Status"] == "Confirmed"
    assert final_data["Advance Paid (₹)"] == "200000"
    assert final_data["BEO #"] == "BEO-880"
    assert final_data["Event Title"] == "Annual Tech Gala"

def test_operations_housekeeping_workflow(client):
    """Housekeeping Linen: Create -> Save -> Reopen/Edit -> Update -> Verify integrity."""
    headers = auth_header(client)
    
    # 1. Create Linen record
    linen_payload = {
        "category": "housekeeping_linen-laundry",
        "title": "LINEN-BATCH-402",
        "data": {
            "Item Type": "Bath Towels",
            "Quantity": "120",
            "Vendor": "PureWhite Laundry",
            "Delivery Status": "Dispatched",
            "Assigned Staff": "Ravi Kumar"
        },
        "status": "Dispatched"
    }
    create_res = client.post("/api/records", json=linen_payload, headers=headers)
    assert create_res.status_code == 201, create_res.text
    rec_id = create_res.json()["id"]
    
    # 2. Reopen (Fetch by ID)
    get_res = client.get(f"/api/records/{rec_id}", headers=headers)
    assert get_res.status_code == 200
    data = get_res.json()["data"]
    assert data["Item Type"] == "Bath Towels"
    assert data["Quantity"] == "120"
    assert data["Delivery Status"] == "Dispatched"
    
    # 3. Update status & quantity
    update_res = client.put(f"/api/records/{rec_id}", json={
        "status": "Delivered",
        "data": {**data, "Delivery Status": "Delivered", "Quantity": "118", "Remarks": "2 damaged in wash"}
    }, headers=headers)
    assert update_res.status_code == 200
    
    # 4. Reopen again
    reopen_res = client.get(f"/api/records/{rec_id}", headers=headers)
    final_data = reopen_res.json()["data"]
    assert final_data["Delivery Status"] == "Delivered"
    assert final_data["Quantity"] == "118"
    assert final_data["Remarks"] == "2 damaged in wash"
    assert final_data["Vendor"] == "PureWhite Laundry"

def test_operations_engineering_workflow(client):
    """Engineering Asset Registry: Create -> Save -> Reopen/Edit -> Update -> Verify integrity."""
    headers = auth_header(client)
    
    asset_payload = {
        "category": "engineering_asset-registry",
        "title": "HVAC-CHILLER-01",
        "data": {
            "Asset Tag": "HVAC-CHILLER-01",
            "Asset Tag #": "HVAC-CHILLER-01",
            "Asset Name": "Central Water Chiller 50TR",
            "Equipment Description": "Central Water Chiller 50TR",
            "Location": "Basement Plant Room",
            "Asset / Location": "Basement Plant Room",
            "Manufacturer": "Carrier",
            "Model Number": "30XA-050",
            "Warranty Status": "Valid until 2028",
            "Warranty Details": "Valid until 2028",
            "Status": "Operational"
        },
        "status": "Operational"
    }
    create_res = client.post("/api/records", json=asset_payload, headers=headers)
    assert create_res.status_code == 201, create_res.text
    rec_id = create_res.json()["id"]
    
    # Reopen for edit
    get_res = client.get(f"/api/records/{rec_id}", headers=headers)
    data = get_res.json()["data"]
    assert data["Asset Tag"] == "HVAC-CHILLER-01"
    assert data["Equipment Description"] == "Central Water Chiller 50TR"
    assert data["Manufacturer"] == "Carrier"
    
    # Update warranty & status
    update_res = client.put(f"/api/records/{rec_id}", json={
        "status": "Under Maintenance",
        "data": {
            **data,
            "Status": "Under Maintenance",
            "Warranty Status": "Extended to 2029",
            "Maintenance Notes": "Quarterly overhaul scheduled"
        }
    }, headers=headers)
    assert update_res.status_code == 200
    
    # Reopen again and check all fields
    reopen_res = client.get(f"/api/records/{rec_id}", headers=headers)
    final_data = reopen_res.json()["data"]
    assert final_data["Status"] == "Under Maintenance"
    assert final_data["Warranty Status"] == "Extended to 2029"
    assert final_data["Manufacturer"] == "Carrier"
    assert final_data["Location"] == "Basement Plant Room"

def test_operations_procurement_workflow(client):
    """Procurement Purchase Orders: Create -> Save -> Reopen/Edit -> Update -> Verify integrity."""
    headers = auth_header(client)
    
    po_payload = {
        "category": "procurement_purchase-orders",
        "title": "PO-2026-901",
        "data": {
            "PO Number": "PO-2026-901",
            "PO #": "PO-2026-901",
            "Vendor": "Green Produce Co.",
            "Category": "Fresh Vegetables",
            "Total Amount (₹)": "32000",
            "Status": "Pending Approval",
            "PO Status": "Pending Approval",
            "Ordered By": "Chef Anand"
        },
        "status": "Pending Approval"
    }
    create_res = client.post("/api/records", json=po_payload, headers=headers)
    assert create_res.status_code == 201
    rec_id = create_res.json()["id"]
    
    # Edit / Update
    update_res = client.put(f"/api/records/{rec_id}", json={
        "status": "Approved",
        "data": {
            **po_payload["data"],
            "Status": "Approved",
            "PO Status": "Approved",
            "Approved By": "General Manager"
        }
    }, headers=headers)
    assert update_res.status_code == 200
    
    # Reopen and verify
    reopen_res = client.get(f"/api/records/{rec_id}", headers=headers)
    final_data = reopen_res.json()["data"]
    assert final_data["PO Status"] == "Approved"
    assert final_data["Status"] == "Approved"
    assert final_data["Approved By"] == "General Manager"
    assert final_data["Total Amount (₹)"] == "32000"

def test_operations_security_workflow(client):
    """Security Incident Logs: Create -> Save -> Reopen/Edit -> Update -> Verify integrity."""
    headers = auth_header(client)
    
    incident_payload = {
        "category": "security_incident-logs",
        "title": "INC-2026-044",
        "data": {
            "Incident ID": "INC-2026-044",
            "Incident Type": "Unattended Baggage",
            "Location": "North Lobby",
            "Reported By": "Concierge Vikram",
            "Resolution Status": "Investigating",
            "Status": "Investigating"
        },
        "status": "Investigating"
    }
    create_res = client.post("/api/records", json=incident_payload, headers=headers)
    assert create_res.status_code == 201
    rec_id = create_res.json()["id"]
    
    # Update resolution
    update_res = client.put(f"/api/records/{rec_id}", json={
        "status": "Resolved",
        "data": {
            **incident_payload["data"],
            "Resolution Status": "Resolved",
            "Status": "Resolved",
            "Resolution Notes": "Owner retrieved bag after ID verification"
        }
    }, headers=headers)
    assert update_res.status_code == 200
    
    # Reopen and verify
    reopen_res = client.get(f"/api/records/{rec_id}", headers=headers)
    final_data = reopen_res.json()["data"]
    assert final_data["Resolution Status"] == "Resolved"
    assert final_data["Status"] == "Resolved"
    assert final_data["Incident ID"] == "INC-2026-044"

# ==============================================================================
# 3. VERIFY STATUS SYNCHRONIZATION WITHOUT OVERWRITING UNRELATED FIELDS
# ==============================================================================
def test_status_sync_preserves_all_unrelated_fields(client):
    """Verify that updating only the status preserves all nested data fields intact."""
    headers = auth_header(client)
    
    rec_payload = {
        "category": "engineering_preventive-maintenance",
        "title": "PPM-ELEC-01",
        "data": {
            "PPM Task ID": "PPM-ELEC-01",
            "Asset / Location": "Main Electrical Panel - Basement",
            "Frequency": "Monthly",
            "Last Serviced": "2026-10-01",
            "Next Due Date": "2026-11-30",
            "Checklist Items": ["Inspect main breaker", "Check voltage calibration"],
            "Technician": "Suresh Raina",
            "Status": "Scheduled",
            "Special Instructions": "Ensure main breaker is locked and tagged out."
        },
        "status": "Scheduled"
    }
    create_res = client.post("/api/records", json=rec_payload, headers=headers)
    assert create_res.status_code == 201
    rec_id = create_res.json()["id"]
    
    # Update ONLY status
    patch_res = client.put(f"/api/records/{rec_id}", json={"status": "Completed"}, headers=headers)
    assert patch_res.status_code == 200
    assert patch_res.json()["status"] == "Completed"
    
    # Re-fetch and verify all fields remained intact
    get_res = client.get(f"/api/records/{rec_id}", headers=headers)
    data = get_res.json()["data"]
    assert data["Status"] == "Completed"
    assert data["PPM Task ID"] == "PPM-ELEC-01"
    assert data["Frequency"] == "Monthly"
    assert data["Technician"] == "Suresh Raina"
    assert data["Special Instructions"] == "Ensure main breaker is locked and tagged out."

# ==============================================================================
# 4. VERIFY MULTI-TENANCY ISOLATION AND RBAC
# ==============================================================================
def test_strict_multi_tenant_isolation_and_rbac(client):
    """Verify cross-tenant data isolation and role boundaries between Hotel 1 and Hotel 2."""
    h1_headers = auth_header(client, "admin@hotel.com", "Password@123", tenant_id="1")
    h2_headers = auth_header(client, "manager2@hotel.com", "Password@123", tenant_id="2")
    
    # 1. Hotel 1 creates a sensitive procurement PO
    po_res = client.post("/api/records", json={
        "category": "procurement_purchase-orders",
        "title": "PO-H1-SECRET",
        "data": {
            "PO Number": "PO-H1-SECRET",
            "Vendor": "H1 Exclusive Vendor",
            "Total Amount (₹)": "999999",
            "Status": "Approved"
        },
        "status": "Approved"
    }, headers=h1_headers)
    assert po_res.status_code == 201
    h1_po_id = po_res.json()["id"]
    
    # 2. Hotel 2 attempts to read Hotel 1's PO -> Must be 403 or 404
    h2_get = client.get(f"/api/records/{h1_po_id}", headers=h2_headers)
    assert h2_get.status_code in [403, 404], f"Cross-tenant read should fail, got {h2_get.status_code}"
    
    # 3. Hotel 2 attempts to update Hotel 1's PO -> Must be 403 or 404
    h2_put = client.put(f"/api/records/{h1_po_id}", json={
        "status": "Cancelled",
        "data": {"PO Number": "PO-H1-SECRET", "Status": "Cancelled"}
    }, headers=h2_headers)
    assert h2_put.status_code in [403, 404], f"Cross-tenant update should fail, got {h2_put.status_code}"
    
    # 4. Hotel 2 attempts to delete Hotel 1's PO -> Must be 403 or 404
    h2_del = client.delete(f"/api/records/{h1_po_id}", headers=h2_headers)
    assert h2_del.status_code in [403, 404], f"Cross-tenant delete should fail, got {h2_del.status_code}"
    
    # 5. List records for Hotel 2 -> Hotel 1 records must NEVER appear
    h2_list = client.get("/api/records?category=procurement_purchase-orders", headers=h2_headers)
    assert h2_list.status_code == 200
    ids_in_h2 = [item["id"] for item in h2_list.json()]
    assert h1_po_id not in ids_in_h2, "Hotel 1 record leaked into Hotel 2 listing!"
