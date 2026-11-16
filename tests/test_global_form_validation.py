import os
import sys
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
from app.models import User

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
        db.add(admin_user)
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

def test_cancellation_rule_missing_mandatory_fields(client):
    """Verify that submitting only 1 field for cancellation rules is rejected with HTTP 422."""
    headers = auth_header(client)
    payload = {
        "category": "reports_cancellation_rules",
        "title": "Direct Web Rule",
        "data": {
            "Policy Tier / Channel": "Direct Website Bookings"
            # Missing: Notice Window, Refund Eligibility, Admin Fee
        }
    }
    response = client.post("/api/records", json=payload, headers=headers)
    assert response.status_code == 422
    data = response.json()
    assert "mandatory" in data["detail"].lower() or "required" in data["detail"].lower()
    assert "Notice Window" in data["detail"]

def test_cancellation_rule_valid_all_mandatory_fields(client):
    """Verify that submitting all required fields for cancellation rules succeeds."""
    headers = auth_header(client)
    payload = {
        "category": "reports_cancellation_rules",
        "title": "Direct Web Rule",
        "data": {
            "Policy Tier / Channel": "Direct Website Bookings",
            "Notice Window": "24 Hours Before Check-in",
            "Refund Eligibility": "100%",
            "Admin Fee": "₹0",
            "Status": "Active"
        }
    }
    response = client.post("/api/records", json=payload, headers=headers)
    assert response.status_code == 201
    res_data = response.json()
    assert res_data["category"] == "reports_cancellation_rules"
    assert res_data["data"]["Policy Tier / Channel"] == "Direct Website Bookings"

def test_procurement_rejects_alphabetic_spend(client):
    """Verify that financial/spend fields reject alphabetic strings like 'abc', 'bbw'."""
    headers = auth_header(client)
    payload = {
        "category": "procurement",
        "title": "F&B Procurement Spend",
        "data": {
            "Department Indenting": "Food & Beverage",
            "Monthly Spend (₹)": "abc",
            "Budget Allocation (₹)": "150000"
        }
    }
    response = client.post("/api/records", json=payload, headers=headers)
    assert response.status_code == 422
    data = response.json()
    assert "numeric" in data["detail"].lower()
    assert "Monthly Spend (₹)" in data["detail"]

def test_procurement_rejects_alphabetic_budget(client):
    """Verify that budget fields reject alphabetic strings like 'bbw'."""
    headers = auth_header(client)
    payload = {
        "category": "procurement",
        "title": "Housekeeping Budget",
        "data": {
            "Department Indenting": "Housekeeping",
            "Monthly Spend (₹)": "45000",
            "Budget Allocation (₹)": "bbw"
        }
    }
    response = client.post("/api/records", json=payload, headers=headers)
    assert response.status_code == 422
    data = response.json()
    assert "numeric" in data["detail"].lower()
    assert "Budget Allocation (₹)" in data["detail"]

def test_procurement_accepts_valid_numeric_values(client):
    """Verify that valid numeric/currency values are accepted."""
    headers = auth_header(client)
    payload = {
        "category": "procurement",
        "title": "Front Office Spend",
        "data": {
            "Department Indenting": "Front Office",
            "Open POs": "5",
            "Pending Approvals": "2",
            "Monthly Spend (₹)": "35000.50",
            "Budget Allocation (₹)": "₹50,000",
            "Budget Utilization": "70%"
        }
    }
    response = client.post("/api/records", json=payload, headers=headers)
    assert response.status_code == 201
    res_data = response.json()
    assert res_data["category"] == "procurement"
    assert res_data["data"]["Department Indenting"] == "Front Office"

def test_percentage_bounds_validation(client):
    """Verify percentage fields must be between 0% and 100%."""
    headers = auth_header(client)
    payload = {
        "category": "reports_room_benchmarks",
        "title": "Deluxe Room Benchmark",
        "data": {
            "Room Type": "Deluxe Room",
            "Target Occupancy": "150%", # Invalid: > 100%
            "Base ADR Target": "₹2,500",
            "Min RevPAR Benchmark": "₹1,875"
        }
    }
    response = client.post("/api/records", json=payload, headers=headers)
    assert response.status_code == 422
    data = response.json()
    assert "percentage between 0% and 100%" in data["detail"].lower()
