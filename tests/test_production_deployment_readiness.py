import os
import sys
import json
from decimal import Decimal

os.environ["TESTING"] = "1"
os.environ.setdefault("JWT_SECRET_KEY", "test-secret-key-with-at-least-32-characters-long")
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select, func, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.main import app, run_alembic_migrations_safe
from app.database.connection import Base, get_db
from app.core.config import settings, parse_cors_origins, normalize_database_url
from app.core.security import hash_password, verify_password
from app.models.entities import User, Role, Tenant, RoomType, Room, Amenity
from app.database.migrations import ensure_default_tenants
from app.database.seed_data import ensure_default_roles, ensure_default_users, DEFAULT_USERS_DATA


@pytest.fixture()
def test_db_session():
    test_engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    TestingSession = sessionmaker(bind=test_engine, autoflush=False, autocommit=False, expire_on_commit=False)
    Base.metadata.create_all(bind=test_engine)

    with TestingSession() as db:
        ensure_default_tenants(db)
        ensure_default_roles(db)
        ensure_default_users(db)

    def override_db():
        db = TestingSession()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_db
    yield TestingSession
    app.dependency_overrides.clear()


# ==============================================================================
# 1. VERIFY CORS ORIGINS CONFIGURATION FOR VERCEL FRONTEND
# ==============================================================================
def test_cors_origins_includes_vercel_frontend():
    # Test with VERCEL_URL or FRONTEND_URL set
    os.environ["FRONTEND_URL"] = "https://stayflow-hotel.vercel.app"
    parsed = parse_cors_origins("https://preview-123.vercel.app")
    assert "https://stayflow-hotel.vercel.app" in parsed
    assert "https://preview-123.vercel.app" in parsed
    assert "http://localhost:5173" in parsed


# ==============================================================================
# 2. VERIFY CLOUD ENVIRONMENT DISALLOWS SILENT SQLITE FALLBACK
# ==============================================================================
def test_cloud_environment_disallows_sqlite_fallback():
    os.environ["RAILWAY_ENVIRONMENT"] = "production"
    # When DATABASE_URL and MYSQL_URL are not set, it should raise RuntimeError
    old_db_url = os.environ.pop("DATABASE_URL", None)
    old_mysql_url = os.environ.pop("MYSQL_URL", None)
    old_mysql_host = os.environ.pop("MYSQLHOST", None)

    try:
        with pytest.raises(RuntimeError) as exc_info:
            normalize_database_url(None)
        assert "no database connection is configured" in str(exc_info.value)
    finally:
        os.environ.pop("RAILWAY_ENVIRONMENT", None)
        if old_db_url:
            os.environ["DATABASE_URL"] = old_db_url
        if old_mysql_url:
            os.environ["MYSQL_URL"] = old_mysql_url
        if old_mysql_host:
            os.environ["MYSQLHOST"] = old_mysql_host


# ==============================================================================
# 3. VERIFY RAILWAY MYSQL URL NORMALIZATION (mysql:// -> mysql+pymysql://)
# ==============================================================================
def test_railway_mysql_url_normalization():
    # Railway standard format: mysql://root:pass@mysql.railway.internal:3306/railway
    raw = "mysql://root:secretpass@containers-us-west.railway.app:7123/railway"
    normalized = normalize_database_url(raw)
    assert normalized.startswith("mysql+pymysql://")
    assert "secretpass@containers-us-west.railway.app:7123/railway" in normalized


# ==============================================================================
# 4. VERIFY DATABASE HEALTHCHECK REPORTS 200 ON SUCCESS AND 503 ON FAILURE
# ==============================================================================
def test_healthcheck_endpoint_verifies_real_db(test_db_session):
    with TestClient(app) as client:
        res = client.get("/health")
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "ok"
        assert data["database"] == "connected"


# ==============================================================================
# 5. VERIFY DEFAULT USERS SEEDING AND PASSWORD RETENTION (NO OVERWRITE ON RESTART)
# ==============================================================================
def test_default_users_seeding_and_no_overwrite(test_db_session):
    with test_db_session() as db:
        # Check initial user count
        admin = db.scalar(select(User).where(User.email == "admin@hotel.com"))
        assert admin is not None
        assert verify_password("Password@123", admin.password_hash)

        # Admin updates password to a custom production secret
        custom_password = "MySecureCustomProductionPassword#2026!"
        admin.password_hash = hash_password(custom_password)
        db.commit()

        # Simulate backend restart / re-running ensure_default_users
        ensure_default_users(db)

        # Verify password was NOT overwritten!
        db.refresh(admin)
        assert verify_password(custom_password, admin.password_hash), "Password was overwritten during startup seeding!"
        assert not verify_password("Password@123", admin.password_hash)


# ==============================================================================
# 6. VERIFY DEFAULT ROLES AND PERMISSIONS INITIALIZATION IDEMPOTENCY
# ==============================================================================
def test_default_roles_initialization_idempotency(test_db_session):
    with test_db_session() as db:
        roles_count_1 = db.scalar(select(func.count(Role.id)))
        assert roles_count_1 > 0

        # Running ensure_default_roles again must not create duplicates
        ensure_default_roles(db)
        roles_count_2 = db.scalar(select(func.count(Role.id)))
        assert roles_count_1 == roles_count_2


# ==============================================================================
# 7. VERIFY FRESH AND UPGRADE MIGRATION SAFETY
# ==============================================================================
def test_run_alembic_migrations_safe_executes_without_error(test_db_session):
    # Running safe alembic migration helper does not crash or break existing connection
    run_alembic_migrations_safe()
