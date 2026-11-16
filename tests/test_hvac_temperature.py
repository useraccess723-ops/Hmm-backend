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

def base_hvac_payload(set_temp="22", actual_temp="22.2", unit="AHU-LOBBY-01", zone="Ground Floor Main Lobby"):
    return {
        "category": "engineering_hvac-controls",
        "title": unit,
        "data": {
            "AHU / Chiller Unit": unit,
            "Zone Monitored": zone,
            "Set Temperature": set_temp,
            "Actual Temp": actual_temp,
            "Chilled Water In/Out": "In: 7.5°C / Out: 11.8°C",
            "VFD Fan Speed": "75% Speed",
            "Status": "Auto Mode"
        },
        "status": "Auto Mode"
    }

# ==============================================================================
# 1. POSITIVE NUMERIC TEMPERATURE TESTS
# ==============================================================================
def test_hvac_integer_temperature_accepted_and_stored_numeric(client):
    """Test integer temperature 22 is accepted and stored as clean numeric value without °C."""
    headers = auth_header(client)
    payload = base_hvac_payload(set_temp="22")
    res = client.post("/api/records", json=payload, headers=headers)
    assert res.status_code == 201, res.text
    rec = res.json()
    assert rec["data"]["Set Temperature"] == "22", "Stored temperature must be clean numeric '22' without °C"
    assert "°C" not in rec["data"]["Set Temperature"], "Database must not store unit suffix"

def test_hvac_decimal_temperature_18_5_accepted(client):
    """Test decimal temperature 18.5 is accepted and stored numeric."""
    headers = auth_header(client)
    payload = base_hvac_payload(set_temp="18.5", unit="CHILLER-PRIMARY-01")
    res = client.post("/api/records", json=payload, headers=headers)
    assert res.status_code == 201, res.text
    rec = res.json()
    assert rec["data"]["Set Temperature"] == "18.5"
    assert "°C" not in rec["data"]["Set Temperature"]

def test_hvac_decimal_temperature_22_5_accepted(client):
    """Test decimal temperature 22.5 is accepted and stored numeric."""
    headers = auth_header(client)
    payload = base_hvac_payload(set_temp="22.5", unit="AHU-BANQ-02")
    res = client.post("/api/records", json=payload, headers=headers)
    assert res.status_code == 201, res.text
    rec = res.json()
    assert rec["data"]["Set Temperature"] == "22.5"
    assert "°C" not in rec["data"]["Set Temperature"]

# ==============================================================================
# 2. NEGATIVE VALIDATION TESTS (REJECT INVALID FORMATS)
# ==============================================================================
def test_hvac_alphabetic_input_rejected(client):
    """Test alphabetic characters such as 'AA' are rejected with 422 validation message."""
    headers = auth_header(client)
    payload = base_hvac_payload(set_temp="AA")
    res = client.post("/api/records", json=payload, headers=headers)
    assert res.status_code == 422, f"Expected 422 for 'AA', got {res.status_code}: {res.text}"
    detail = res.json()["detail"]
    assert "Set Temperature" in detail
    assert "numeric" in detail.lower() or "rejected" in detail.lower()

def test_hvac_alphanumeric_input_rejected(client):
    """Test mixed alphanumeric values such as '22AB' are rejected with 422."""
    headers = auth_header(client)
    payload = base_hvac_payload(set_temp="22AB")
    res = client.post("/api/records", json=payload, headers=headers)
    assert res.status_code == 422, f"Expected 422 for '22AB', got {res.status_code}: {res.text}"
    assert "numeric" in res.json()["detail"].lower()

def test_hvac_invalid_format_rejected(client):
    """Test malformed formats such as '--' are rejected with 422."""
    headers = auth_header(client)
    payload = base_hvac_payload(set_temp="--")
    res = client.post("/api/records", json=payload, headers=headers)
    assert res.status_code == 422, f"Expected 422 for '--', got {res.status_code}: {res.text}"

def test_hvac_empty_temperature_rejected(client):
    """Test empty temperature is rejected as mandatory field with 422."""
    headers = auth_header(client)
    payload = base_hvac_payload(set_temp="")
    res = client.post("/api/records", json=payload, headers=headers)
    assert res.status_code == 422, f"Expected 422 for empty, got {res.status_code}: {res.text}"
    assert "Set Temperature" in res.json()["detail"]

def test_hvac_actual_temp_alphabetic_rejected(client):
    """Test actual temperature field also validates numeric format."""
    headers = auth_header(client)
    payload = base_hvac_payload(set_temp="22", actual_temp="BAD_TEMP")
    res = client.post("/api/records", json=payload, headers=headers)
    assert res.status_code == 422
    assert "Actual Temp" in res.json()["detail"]

# ==============================================================================
# 3. UNIT CLEANING AND BACKWARD COMPATIBILITY
# ==============================================================================
def test_hvac_backward_compatibility_unit_cleaning(client):
    """Test that input with unit '22°C' is safely normalized to '22' in DB without duplicate units."""
    headers = auth_header(client)
    payload = base_hvac_payload(set_temp="22°C", actual_temp="22.4°C", unit="AHU-SUITE-10")
    res = client.post("/api/records", json=payload, headers=headers)
    assert res.status_code == 201, res.text
    rec = res.json()
    assert rec["data"]["Set Temperature"] == "22", "Must strip °C unit suffix before storing"
    assert rec["data"]["Actual Temp"] == "22.4"
    assert "°C" not in rec["data"]["Set Temperature"]

# ==============================================================================
# 4. EDIT, UPDATE, REOPEN AND PERSISTENCE WORKFLOW
# ==============================================================================
def test_hvac_edit_update_reopen_persistence_workflow(client):
    """End-to-End Workflow: Create (22) -> Reopen -> Update (22.5) -> Reopen -> Update (18.5) -> Verify."""
    headers = auth_header(client)
    
    # 1. Create with integer 22
    create_res = client.post("/api/records", json=base_hvac_payload(set_temp="22", unit="AHU-BALLROOM-01"), headers=headers)
    assert create_res.status_code == 201, create_res.text
    rec_id = create_res.json()["id"]
    
    # 2. Reopen (Fetch by ID)
    get_res1 = client.get(f"/api/records/{rec_id}", headers=headers)
    assert get_res1.status_code == 200
    data1 = get_res1.json()["data"]
    assert data1["Set Temperature"] == "22"
    assert data1["AHU / Chiller Unit"] == "AHU-BALLROOM-01"
    
    # 3. Update with decimal 22.5
    update_res1 = client.put(f"/api/records/{rec_id}", json={
        "status": "Running Optimal",
        "data": {
            **data1,
            "Set Temperature": "22.5",
            "Actual Temp": "22.6",
            "Status": "Running Optimal"
        }
    }, headers=headers)
    assert update_res1.status_code == 200, update_res1.text
    
    # 4. Reopen and verify 22.5 persisted
    get_res2 = client.get(f"/api/records/{rec_id}", headers=headers)
    assert get_res2.status_code == 200
    data2 = get_res2.json()["data"]
    assert data2["Set Temperature"] == "22.5"
    assert data2["Actual Temp"] == "22.6"
    
    # 5. Update with 18.5
    update_res2 = client.put(f"/api/records/{rec_id}", json={
        "status": "Running Optimal",
        "data": {
            **data2,
            "Set Temperature": "18.5",
            "Actual Temp": "18.7"
        }
    }, headers=headers)
    assert update_res2.status_code == 200
    
    # 6. Final Reopen and check persistence
    get_res3 = client.get(f"/api/records/{rec_id}", headers=headers)
    assert get_res3.status_code == 200
    data3 = get_res3.json()["data"]
    assert data3["Set Temperature"] == "18.5"
    assert data3["Actual Temp"] == "18.7"
    assert data3["Zone Monitored"] == "Ground Floor Main Lobby"
    assert data3["Chilled Water In/Out"] == "In: 7.5°C / Out: 11.8°C"

