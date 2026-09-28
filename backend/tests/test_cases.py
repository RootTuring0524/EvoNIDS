"""Case management API integration tests (create/list/detail/attach/detach/status)."""
import os
import tempfile
from pathlib import Path

database_path = Path(tempfile.gettempdir()) / "evonids-cases-test.db"
database_path.unlink(missing_ok=True)
os.environ["EVONIDS_DATABASE_URL"] = f"sqlite:///{database_path.as_posix()}"
os.environ["EVONIDS_AUTO_CREATE_DB"] = "true"
os.environ["EVONIDS_ADMIN_API_TOKEN"] = "test-admin-token"
os.environ["EVONIDS_ENVIRONMENT"] = "development"

from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402

ADMIN_HEADER = {"x-evonids-admin-token": "test-admin-token"}

EVE_ALERTS = "\n".join(
    [
        '{"timestamp":"2026-09-07T10:00:01+08:00","flow_id":9101,"event_type":"alert",'
        '"src_ip":"192.0.2.10","src_port":51000,"dest_ip":"10.0.0.8","dest_port":445,'
        '"proto":"TCP","alert":{"signature_id":2200451,"signature":"ET SCAN port scan","severity":1}}',
        '{"timestamp":"2026-09-07T10:00:02+08:00","flow_id":9102,"event_type":"alert",'
        '"src_ip":"192.0.2.10","src_port":51001,"dest_ip":"10.0.0.8","dest_port":22,'
        '"proto":"TCP","alert":{"signature_id":2200451,"signature":"ET SCAN port scan","severity":2}}',
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
        json={"title": title, "summary": "Repeated scan attempts from 192.0.2.10.", "severity": "high"},
        headers=ADMIN_HEADER,
    )
    assert response.status_code == 201
    return response.json()


def test_create_list_and_detail_case():
    with TestClient(app) as client:
        _import_alerts(client)
        case = _create_case(client)
        assert case["status"] == "open"
        assert case["severity"] == "high"
        assert case["createdBy"] == "env:admin"

        listed = client.get("/api/v1/cases").json()
        assert listed["total"] >= 1
        assert any(item["id"] == case["id"] for item in listed["items"])

        detail = client.get(f"/api/v1/cases/{case['id']}").json()
        assert detail["case"]["id"] == case["id"]
        assert detail["alerts"] == []
        assert any(event["eventType"] == "case.created" for event in detail["timeline"])


def test_attach_and_detach_alerts_updates_counts_and_timeline():
    with TestClient(app) as client:
        alert_ids = _import_alerts(client)
        case = _create_case(client)
        attached = client.post(
            f"/api/v1/cases/{case['id']}/alerts",
            json={"alertId": alert_ids[0]},
            headers=ADMIN_HEADER,
        )
        assert attached.status_code == 200
        assert attached.json()["alertCount"] == 1

        duplicate = client.post(
            f"/api/v1/cases/{case['id']}/alerts",
            json={"alertId": alert_ids[0]},
            headers=ADMIN_HEADER,
        )
        assert duplicate.status_code == 409

        second = client.post(
            f"/api/v1/cases/{case['id']}/alerts",
            json={"alertId": alert_ids[1]},
            headers=ADMIN_HEADER,
        )
        assert second.status_code == 200
        assert second.json()["alertCount"] == 2
        assert second.json()["highestRiskScore"] > 0

        detail = client.get(f"/api/v1/cases/{case['id']}").json()
        assert len(detail["alerts"]) == 2
        events = [event["eventType"] for event in detail["timeline"]]
        assert events.count("case.alert_attached") == 2

        detached = client.delete(
            f"/api/v1/cases/{case['id']}/alerts/{alert_ids[0]}",
            headers=ADMIN_HEADER,
        )
        assert detached.status_code == 200
        assert detached.json()["alertCount"] == 1

        missing = client.delete(
            f"/api/v1/cases/{case['id']}/alerts/{alert_ids[0]}",
            headers=ADMIN_HEADER,
        )
        assert missing.status_code == 404


def test_case_status_transitions_require_note_for_closure():
    with TestClient(app) as client:
        case = _create_case(client, title="Lifecycle case")
        case_id = case["id"]

        invalid = client.patch(
            f"/api/v1/cases/{case_id}",
            json={"status": "archived"},  # archived is only reachable from closed
            headers=ADMIN_HEADER,
        )
        assert invalid.status_code == 409

        investigating = client.patch(
            f"/api/v1/cases/{case_id}",
            json={"status": "investigating"},
            headers=ADMIN_HEADER,
        )
        assert investigating.status_code == 200
        assert investigating.json()["status"] == "investigating"

        no_note = client.patch(
            f"/api/v1/cases/{case_id}",
            json={"status": "contained"},
            headers=ADMIN_HEADER,
        )
        assert no_note.status_code == 400

        contained = client.patch(
            f"/api/v1/cases/{case_id}",
            json={"status": "contained", "note": "Evidence reviewed, no action needed."},
            headers=ADMIN_HEADER,
        )
        assert contained.status_code == 200
        assert contained.json()["status"] == "contained"

        closed = client.patch(
            f"/api/v1/cases/{case_id}",
            json={"status": "closed", "note": "Investigation complete; case closed."},
            headers=ADMIN_HEADER,
        )
        assert closed.status_code == 200
        assert closed.json()["status"] == "closed"

        archived = client.patch(
            f"/api/v1/cases/{case_id}",
            json={"status": "archived", "note": "Campaign closed by analyst; archived."},
            headers=ADMIN_HEADER,
        )
        assert archived.status_code == 200
        assert archived.json()["status"] == "archived"

        detail = client.get(f"/api/v1/cases/{case_id}").json()
        events = [event["eventType"] for event in detail["timeline"]]
        assert events.count("case.contained") == 1
        assert events.count("case.archived") == 1


def test_case_operations_are_audited():
    with TestClient(app) as client:
        case = _create_case(client, title="Audited case")
        audit = client.get("/api/v1/audit?objectType=case", headers=ADMIN_HEADER)
        assert audit.status_code == 200
        items = audit.json()["items"]
        assert any(item["action"] == "case.created" for item in items)
        assert any(item["objectId"] == case["id"] for item in items)
