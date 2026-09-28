"""Tests for the console authentication audit endpoint."""
import os
import tempfile
from pathlib import Path

database_path = Path(tempfile.gettempdir()) / "evonids-console-audit-test.db"
database_path.unlink(missing_ok=True)
os.environ["EVONIDS_DATABASE_URL"] = f"sqlite:///{database_path.as_posix()}"
os.environ["EVONIDS_AUTO_CREATE_DB"] = "true"
os.environ["EVONIDS_ADMIN_API_TOKEN"] = "test-admin-token"
os.environ["EVONIDS_ENVIRONMENT"] = "development"

from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402

ADMIN_HEADER = {"x-evonids-admin-token": "test-admin-token"}


def test_console_event_requires_admin():
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/audit/console",
            json={"action": "console.login.failure", "note": "x"},
        )
        assert response.status_code == 401
        assert response.json()["error"] == "unauthorized"


def test_console_event_is_persisted_and_searchable():
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/audit/console",
            json={"action": "console.login.success", "note": "test login"},
            headers=ADMIN_HEADER,
        )
        assert response.status_code == 201

        listing = client.get("/api/v1/audit?objectType=console_session", headers=ADMIN_HEADER)
        assert listing.status_code == 200
        items = listing.json()["items"]
        assert any(item["action"] == "console.login.success" for item in items)
        assert any(item["actor"] == "console" for item in items)


def test_console_event_rejects_unknown_action():
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/audit/console",
            json={"action": "console.hax"},
            headers=ADMIN_HEADER,
        )
        assert response.status_code == 422
        assert response.json()["error"] == "validation_error"
