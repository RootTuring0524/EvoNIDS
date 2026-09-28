"""Tests for the uniform API error envelope and production configuration baseline."""
import os
import tempfile
from pathlib import Path

import pytest

database_path = Path(tempfile.gettempdir()) / "evonids-errors-test.db"
database_path.unlink(missing_ok=True)
os.environ["EVONIDS_DATABASE_URL"] = f"sqlite:///{database_path.as_posix()}"
os.environ["EVONIDS_AUTO_CREATE_DB"] = "true"
os.environ["EVONIDS_ADMIN_API_TOKEN"] = "test-admin-token"
os.environ["EVONIDS_ENVIRONMENT"] = "development"

from fastapi.testclient import TestClient  # noqa: E402

from app.core.config import Settings, validate_production_settings  # noqa: E402
from app.core.errors import code_for_status, message_for_status  # noqa: E402
from app.main import app  # noqa: E402


def assert_envelope(response, *, allow_details: bool = False):
    assert response.headers.get("x-request-id"), "error responses must carry X-Request-ID"
    body = response.json()
    assert body["error"] and isinstance(body["error"], str)
    assert body["message"] and isinstance(body["message"], str)
    assert body["requestId"] and isinstance(body["requestId"], str)
    if allow_details:
        assert "details" in body
    else:
        assert set(body.keys()) == {"error", "message", "requestId"}
    return body


def test_error_registry_mapping():
    assert code_for_status(404) == "not_found"
    assert code_for_status(422) == "validation_error"
    assert code_for_status(500) == "internal_error"
    assert code_for_status(599) == "internal_error"
    assert message_for_status(503).strip()


def test_missing_route_returns_envelope():
    with TestClient(app) as client:
        response = client.get("/api/v1/definitely-not-a-route")
        assert response.status_code == 404
        assert_envelope(response)


def test_missing_resource_returns_envelope():
    with TestClient(app) as client:
        response = client.get("/api/v1/alerts/no-such-alert-xyz")
        assert response.status_code == 404
        body = assert_envelope(response)
        assert body["error"] == "not_found"


def test_unauthorized_admin_write_returns_envelope():
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/datasets",
            json={},
            headers={"x-evonids-admin-token": "definitely-wrong"},
        )
        assert response.status_code == 401
        body = assert_envelope(response)
        assert body["error"] == "unauthorized"


def test_validation_error_returns_envelope_with_details():
    with TestClient(app) as client:
        response = client.get("/api/v1/rag?topK=99999")
        assert response.status_code == 422
        body = assert_envelope(response, allow_details=True)
        assert body["error"] == "validation_error"
        assert isinstance(body["details"], list) and len(body["details"]) >= 1


def test_production_validation_rejects_missing_secrets_and_sqlite():
    settings = Settings(
        _env_file=None,
        environment="production",
        admin_api_token=None,
        sensor_ingest_token="sensor-secret",
        database_url="sqlite:///./local.db",
    )
    with pytest.raises(RuntimeError) as excinfo:
        validate_production_settings(settings)
    message = str(excinfo.value)
    assert "EVONIDS_ADMIN_API_TOKEN" in message
    assert "PostgreSQL" in message


def test_production_validation_rejects_missing_sensor_token():
    settings = Settings(
        _env_file=None,
        environment="production",
        admin_api_token="admin-secret",
        sensor_ingest_token=None,
        database_url="postgresql+psycopg://u:p@host:5432/evonids",
    )
    with pytest.raises(RuntimeError) as excinfo:
        validate_production_settings(settings)
    assert "EVONIDS_SENSOR_INGEST_TOKEN" in str(excinfo.value)


def test_production_validation_accepts_complete_configuration():
    settings = Settings(
        _env_file=None,
        environment="production",
        admin_api_token="admin-secret",
        sensor_ingest_token="sensor-secret",
        database_url="postgresql+psycopg://u:p@host:5432/evonids",
    )
    validate_production_settings(settings)  # must not raise


def test_environment_whitelist_rejects_unknown_values():
    with pytest.raises(ValueError, match="EVONIDS_ENVIRONMENT"):
        Settings(_env_file=None, environment="prod")
