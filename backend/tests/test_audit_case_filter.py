"""Audit log case-scope filter integration tests.

Covers the ``caseId`` query filter added to ``GET /api/v1/audit``: unfiltered
behaviour stays byte-for-byte, a valid case id restricts results to that case's
events (including case-scoped state records and attached-alert events), and a
well-formed but unknown case id answers 404 with the uniform error envelope.
"""
import os
import tempfile
import uuid
from pathlib import Path

database_path = Path(tempfile.gettempdir()) / "evonids-audit-case-filter-test.db"
database_path.unlink(missing_ok=True)
os.environ["EVONIDS_DATABASE_URL"] = f"sqlite:///{database_path.as_posix()}"
os.environ["EVONIDS_AUTO_CREATE_DB"] = "true"
os.environ["EVONIDS_ADMIN_API_TOKEN"] = "test-admin-token"
os.environ["EVONIDS_ENVIRONMENT"] = "development"

from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import func, select  # noqa: E402

from app.db.base import utc_now  # noqa: E402
from app.db.models import AuditEvent  # noqa: E402
from app.db.session import SessionLocal  # noqa: E402
from app.main import app  # noqa: E402

ADMIN_HEADER = {"x-evonids-admin-token": "test-admin-token"}

AUDIT_ITEM_KEYS = {
    "id",
    "createdAt",
    "actor",
    "action",
    "objectType",
    "objectId",
    "outcome",
    "requestId",
    "note",
}

EVE_ALERTS = "\n".join(
    [
        '{"timestamp":"2026-09-07T10:00:01+08:00","flow_id":9201,"event_type":"alert",'
        '"src_ip":"192.0.2.20","src_port":51000,"dest_ip":"10.0.0.9","dest_port":445,'
        '"proto":"TCP","alert":{"signature_id":2200451,"signature":"ET SCAN port scan","severity":1}}',
        '{"timestamp":"2026-09-07T10:00:02+08:00","flow_id":9202,"event_type":"alert",'
        '"src_ip":"192.0.2.21","src_port":51001,"dest_ip":"10.0.0.9","dest_port":22,'
        '"proto":"TCP","alert":{"signature_id":2200451,"signature":"ET SCAN port scan","severity":2}}',
        '{"timestamp":"2026-09-07T10:00:03+08:00","flow_id":9203,"event_type":"alert",'
        '"src_ip":"192.0.2.22","src_port":51002,"dest_ip":"10.0.0.9","dest_port":3389,'
        '"proto":"TCP","alert":{"signature_id":2200451,"signature":"ET SCAN port scan","severity":3}}',
    ]
)


def _import_alerts(client) -> list[str]:
    imported = client.post(
        "/api/v1/ingestion/eve?sensorId=lab-core-01",
        content=EVE_ALERTS,
        headers={"content-type": "application/x-ndjson"},
    )
    assert imported.status_code == 200
    return [item["id"] for item in client.get("/api/v1/alerts").json()["items"]]


def _create_case(client, title="Suspicious scanning campaign") -> dict:
    response = client.post(
        "/api/v1/cases",
        json={"title": title, "summary": "Repeated scan attempts from 192.0.2.20.", "severity": "high"},
        headers=ADMIN_HEADER,
    )
    assert response.status_code == 201
    return response.json()


def _insert_state_event(*, object_type: str, case_id: str, note: str = "state record") -> str:
    """Insert a case-scoped audit record whose state JSON references the case."""
    event_id = f"AUD-{uuid.uuid4().hex.upper()}"
    with SessionLocal() as db:
        db.add(
            AuditEvent(
                id=event_id,
                created_at=utc_now(),
                actor="analyst",
                action=f"{object_type}.added",
                object_type=object_type,
                object_id=f"TLN-{uuid.uuid4().hex.upper()[:12]}",
                outcome="completed",
                request_id=None,
                before_state=None,
                after_state={"caseId": case_id, "note": note},
                note="Case-scoped state record",
            )
        )
        db.commit()
    return event_id


def _audit_count() -> int:
    with SessionLocal() as db:
        return int(db.scalar(select(func.count()).select_from(AuditEvent)) or 0)


def test_unfiltered_audit_request_returns_everything_unchanged():
    """(a) Without caseId the response keeps the pre-existing contract."""
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/audit/console",
            json={"action": "console.login.success", "note": "unfiltered probe"},
            headers=ADMIN_HEADER,
        )
        assert response.status_code == 201

        listing = client.get("/api/v1/audit", headers=ADMIN_HEADER)
        assert listing.status_code == 200
        body = listing.json()
        assert set(body) == {"items", "total", "page", "pageSize"}
        assert body["page"] == 1
        assert body["pageSize"] == 50
        assert body["total"] == _audit_count()
        assert any(item["action"] == "console.login.success" for item in body["items"])
        for item in body["items"]:
            assert set(item) == AUDIT_ITEM_KEYS
        # Ordering is unchanged: newest events surface first.
        created_at = [item["createdAt"] for item in body["items"]]
        assert created_at == sorted(created_at, reverse=True)


def test_case_filter_returns_only_that_cases_events():
    """(b) A case id restricts results to events belonging to that case."""
    with TestClient(app) as client:
        first = _create_case(client, title="Filtered case one")
        second = _create_case(client, title="Filtered case two")
        # Case-scoped state records for both cases (never produced through the
        # public API yet) prove the before/after-state JSON path filters both ways.
        first_note = _insert_state_event(object_type="case_note", case_id=first["id"])
        first_link = _insert_state_event(object_type="case_alert", case_id=first["id"])
        second_timeline = _insert_state_event(object_type="case_timeline", case_id=second["id"])

        listing = client.get(f"/api/v1/audit?caseId={first['id']}", headers=ADMIN_HEADER)
        assert listing.status_code == 200
        body = listing.json()
        assert set(body) == {"items", "total", "page", "pageSize"}
        ids = {item["id"] for item in body["items"]}
        object_ids = {item["objectId"] for item in body["items"]}
        # Every event returned belongs to the requested case: the case events
        # carry the case id in object_id, and state records reference it in JSON.
        assert all(
            (item["objectType"] == "case" and item["objectId"] == first["id"])
            or item["id"] in {first_note, first_link}
            for item in body["items"]
        )
        assert first_note in ids
        assert first_link in ids
        # No event from the other case leaks through — not its case events and
        # not its case-scoped state records.
        assert second["id"] not in object_ids
        assert second_timeline not in ids
        assert body["total"] == len(body["items"])


def test_case_filter_unknown_case_returns_404_envelope():
    """(c) A well-formed but nonexistent case id answers 404 with the error envelope."""
    with TestClient(app) as client:
        missing = "CASE-" + "0" * 12
        response = client.get(f"/api/v1/audit?caseId={missing}", headers=ADMIN_HEADER)
        assert response.status_code == 404
        body = response.json()
        assert set(body) == {"error", "message", "requestId"}
        assert body["error"] == "not_found"
        assert missing in body["message"]
        assert "requestId" in body


def test_case_filter_includes_attached_alert_events():
    """(d) Alert events for alerts attached to the case are included."""
    with TestClient(app) as client:
        alert_ids = _import_alerts(client)
        case = _create_case(client, title="Attached alerts case")
        attached = client.post(
            f"/api/v1/cases/{case['id']}/alerts",
            json={"alertId": alert_ids[0]},
            headers=ADMIN_HEADER,
        )
        assert attached.status_code == 200

        # Update the attached alert and an unrelated unattached alert so both
        # produce object_type="alert" audit events.
        for alert_id in (alert_ids[0], alert_ids[2]):
            patched = client.patch(
                f"/api/v1/alerts/{alert_id}",
                json={"owner": "audit-case-filter-test", "note": "case scope probe"},
                headers=ADMIN_HEADER,
            )
            assert patched.status_code == 200

        listing = client.get(f"/api/v1/audit?caseId={case['id']}", headers=ADMIN_HEADER)
        assert listing.status_code == 200
        body = listing.json()
        alert_events = [item for item in body["items"] if item["objectType"] == "alert"]
        assert any(item["objectId"] == alert_ids[0] and item["action"] == "alert.update" for item in alert_events)
        # The attached alert's events belong to the case; the unattached one's do not.
        assert all(item["objectId"] == alert_ids[0] for item in alert_events)
        assert any(item["action"] == "case.alert_attached" for item in body["items"])


def test_case_filter_rejects_malformed_case_id():
    """A malformed case id is rejected by request validation (422 envelope)."""
    with TestClient(app) as client:
        for malformed in ("CASE-ABC123", "case-ABCDEF123456", "CASE-ABCDEF12345G", "CASE"):
            response = client.get(f"/api/v1/audit?caseId={malformed}", headers=ADMIN_HEADER)
            assert response.status_code == 422
            body = response.json()
            assert body["error"] == "validation_error"
            assert "requestId" in body
