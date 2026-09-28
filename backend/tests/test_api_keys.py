"""Tests for hashed, scoped API keys and the legacy environment-token fallback."""
import os
import tempfile
from pathlib import Path

database_path = Path(tempfile.gettempdir()) / "evonids-api-keys-test.db"
database_path.unlink(missing_ok=True)
dataset_root = Path(tempfile.gettempdir()) / "evonids-dataset-apikeys"
dataset_root.mkdir(exist_ok=True)
os.environ["EVONIDS_DATABASE_URL"] = f"sqlite:///{database_path.as_posix()}"
os.environ["EVONIDS_AUTO_CREATE_DB"] = "true"
os.environ["EVONIDS_ADMIN_API_TOKEN"] = "test-admin-token"
os.environ["EVONIDS_ENVIRONMENT"] = "development"

from fastapi.testclient import TestClient  # noqa: E402

from app.db.base import Base  # noqa: E402
from app.db.session import SessionLocal, engine  # noqa: E402
from app.main import app  # noqa: E402
from app.schemas.api import ApiKeyCreate  # noqa: E402
from app.services import api_keys as keys_service  # noqa: E402

Base.metadata.create_all(bind=engine)

ADMIN_HEADER = {"x-evonids-admin-token": "test-admin-token"}


def test_secret_hashing_roundtrip():
    secret = keys_service.generate_secret()
    stored = keys_service.hash_secret(secret)
    assert stored.startswith("sha256$")
    assert keys_service.verify_secret(secret, stored)
    assert not keys_service.verify_secret(secret + "x", stored)
    assert not keys_service.verify_secret(secret, "garbage")
    assert keys_service.public_prefix(secret).startswith("evn_")


def test_create_list_and_authenticate_sensor_key():
    with SessionLocal() as db:
        payload = ApiKeyCreate(name="integration sensor", scope="sensor")
        row, secret = keys_service.create_api_key(
            db, payload, actor="test", request_id="req-1"
        )
        assert row.id.startswith("AK-")
        assert row.enabled is True
        assert keys_service.authenticate_api_key(db, secret, scope="sensor") is not None
        assert keys_service.authenticate_api_key(db, secret, scope="admin") is None
        assert keys_service.authenticate_api_key(db, "not-the-secret", scope="sensor") is None
        listed = {item.id for item in keys_service.list_api_keys(db)}
        assert row.id in listed


def test_env_admin_token_can_manage_keys_over_http():
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/admin/api-keys",
            json={"name": "env-created", "scope": "sensor"},
            headers=ADMIN_HEADER,
        )
        assert response.status_code == 201
        body = response.json()
        assert body["id"].startswith("AK-")
        assert body["secret"]
        assert body["prefix"].startswith("evn_")
        assert body["scope"] == "sensor"

        listed = client.get("/api/v1/admin/api-keys", headers=ADMIN_HEADER)
        assert listed.status_code == 200
        assert any(item["id"] == body["id"] for item in listed.json()["items"])


def test_created_db_admin_key_can_authenticate_and_wrong_secret_is_rejected():
    with TestClient(app) as client:
        created = client.post(
            "/api/v1/admin/api-keys",
            json={"name": "db admin", "scope": "admin"},
            headers=ADMIN_HEADER,
        ).json()
        db_header = {"x-evonids-admin-token": created["secret"]}
        second = client.post(
            "/api/v1/admin/api-keys",
            json={"name": "another", "scope": "sensor"},
            headers=db_header,
        )
        assert second.status_code == 201

        denied = client.post(
            "/api/v1/admin/api-keys",
            json={"name": "x", "scope": "sensor"},
            headers={"x-evonids-admin-token": "wrong-secret"},
        )
        assert denied.status_code == 401
        assert denied.json()["error"] == "unauthorized"


def test_scope_is_enforced_for_analyst_keys():
    with TestClient(app) as client:
        created = client.post(
            "/api/v1/admin/api-keys",
            json={"name": "analyst key", "scope": "analyst"},
            headers=ADMIN_HEADER,
        ).json()
        denied = client.post(
            "/api/v1/admin/api-keys",
            json={"name": "should fail", "scope": "sensor"},
            headers={"x-evonids-analyst-token": created["secret"]},
        )
        assert denied.status_code in (401, 503)
        assert denied.json()["error"] in ("unauthorized", "service_unavailable")


def test_revoked_key_no_longer_authenticates():
    with TestClient(app) as client:
        created = client.post(
            "/api/v1/admin/api-keys",
            json={"name": "to revoke", "scope": "admin"},
            headers=ADMIN_HEADER,
        ).json()
        revoked = client.post(
            f"/api/v1/admin/api-keys/{created['id']}/revoke",
            headers=ADMIN_HEADER,
        )
        assert revoked.status_code == 200
        assert revoked.json()["enabled"] is False

        denied = client.post(
            "/api/v1/admin/api-keys",
            json={"name": "x", "scope": "sensor"},
            headers={"x-evonids-admin-token": created["secret"]},
        )
        assert denied.status_code == 401


def test_revoke_missing_key_returns_404_envelope():
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/admin/api-keys/AK-NOT-A-REAL-KEY/revoke",
            headers=ADMIN_HEADER,
        )
        assert response.status_code == 404
        assert response.json()["error"] == "not_found"


def test_key_operations_are_audited():
    with TestClient(app) as client:
        client.post(
            "/api/v1/admin/api-keys",
            json={"name": "audited key", "scope": "sensor"},
            headers=ADMIN_HEADER,
        )
        audit = client.get("/api/v1/audit?objectType=api_key", headers=ADMIN_HEADER)
        assert audit.status_code == 200
        items = audit.json()["items"]
        assert any(item["objectType"] == "api_key" for item in items)
        assert any(item["action"] == "apikey.created" for item in items)
