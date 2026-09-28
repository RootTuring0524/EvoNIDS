"""End-to-end sensor-identity tests: ingestion must accept a scoped DB sensor
API key exactly like the legacy environment token (and reject everything else)."""
import os
import tempfile
from pathlib import Path

database_path = Path(tempfile.gettempdir()) / "evonids-sensor-identity-test.db"
database_path.unlink(missing_ok=True)
os.environ["EVONIDS_DATABASE_URL"] = f"sqlite:///{database_path.as_posix()}"
os.environ["EVONIDS_AUTO_CREATE_DB"] = "true"
os.environ["EVONIDS_ADMIN_API_TOKEN"] = "test-admin-token"
os.environ["EVONIDS_SENSOR_INGEST_TOKEN"] = "test-sensor-token"
os.environ["EVONIDS_ENVIRONMENT"] = "development"

from fastapi.testclient import TestClient  # noqa: E402
from pydantic import SecretStr  # noqa: E402
import pytest  # noqa: E402

from app.core.config import get_settings  # noqa: E402
from app.main import app  # noqa: E402

ADMIN_HEADER = {"x-evonids-admin-token": "test-admin-token"}
ENV_SENSOR_HEADER = {"x-evonids-sensor-token": "test-sensor-token"}


@pytest.fixture(autouse=True)
def disable_sensor_dev_bypass(monkeypatch):
    # get_settings() is cached process-wide at the first app import, so the
    # development sensor bypass may already be active depending on test order.
    # Force the sensor token for the duration of these tests so the
    # authentication paths are actually exercised.
    settings = get_settings()
    if settings.sensor_ingest_token is None or not settings.sensor_ingest_token.get_secret_value():
        monkeypatch.setattr(settings, "sensor_ingest_token", SecretStr("test-sensor-token"))

EVE_FLOW = (
    '{"timestamp":"2026-09-07T10:00:00+08:00","flow_id":7001,"event_type":"flow",'
    '"src_ip":"192.0.2.10","src_port":51000,"dest_ip":"10.0.0.8","dest_port":445,'
    '"proto":"TCP","app_proto":"smb","flow":{"pkts_toserver":5,"pkts_toclient":2,'
    '"bytes_toserver":300,"bytes_toclient":100,"age":1}}\n'
)


def _create_sensor_key(client) -> str:
    created = client.post(
        "/api/v1/admin/api-keys",
        json={"name": "e2e sensor", "scope": "sensor"},
        headers=ADMIN_HEADER,
    )
    assert created.status_code == 201
    return created.json()["secret"]


def test_ingestion_rejects_missing_sensor_credential():
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/ingestion/eve?sensorId=lab-core-01",
            content=EVE_FLOW,
            headers={"content-type": "application/x-ndjson"},
        )
        assert response.status_code == 401
        assert response.json()["error"] == "unauthorized"


def test_ingestion_accepts_environment_sensor_token():
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/ingestion/eve?sensorId=lab-core-01",
            content=EVE_FLOW,
            headers={"content-type": "application/x-ndjson", **ENV_SENSOR_HEADER},
        )
        assert response.status_code == 200
        assert response.json()["acceptedEvents"] == 1


def test_ingestion_rejects_wrong_sensor_secret():
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/ingestion/eve?sensorId=lab-core-01",
            content=EVE_FLOW,
            headers={"content-type": "application/x-ndjson", "x-evonids-sensor-token": "wrong"},
        )
        assert response.status_code == 401


def test_ingestion_accepts_db_sensor_api_key():
    with TestClient(app) as client:
        secret = _create_sensor_key(client)
        response = client.post(
            "/api/v1/ingestion/eve?sensorId=lab-core-01",
            content=EVE_FLOW,
            headers={"content-type": "application/x-ndjson", "x-evonids-sensor-token": secret},
        )
        assert response.status_code == 200
        assert response.json()["acceptedEvents"] == 1


def test_revoked_sensor_key_is_rejected_by_ingestion():
    with TestClient(app) as client:
        secret = _create_sensor_key(client)
        created = client.post(
            "/api/v1/ingestion/eve?sensorId=lab-core-01",
            content=EVE_FLOW,
            headers={"content-type": "application/x-ndjson", "x-evonids-sensor-token": secret},
        )
        assert created.status_code == 200
        key_id = next(
            item["id"]
            for item in client.get("/api/v1/admin/api-keys", headers=ADMIN_HEADER).json()["items"]
            if item["name"] == "e2e sensor"
        )
        revoked = client.post(f"/api/v1/admin/api-keys/{key_id}/revoke", headers=ADMIN_HEADER)
        assert revoked.status_code == 200
        after = client.post(
            "/api/v1/ingestion/eve?sensorId=lab-core-01",
            content=EVE_FLOW,
            headers={"content-type": "application/x-ndjson", "x-evonids-sensor-token": secret},
        )
        assert after.status_code == 401
