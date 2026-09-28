"""Entity discovery + case suggestion tests."""
import os
import tempfile
from pathlib import Path

database_path = Path(tempfile.gettempdir()) / "evonids-entities-test.db"
database_path.unlink(missing_ok=True)
os.environ["EVONIDS_DATABASE_URL"] = f"sqlite:///{database_path.as_posix()}"
os.environ["EVONIDS_AUTO_CREATE_DB"] = "true"
os.environ["EVONIDS_ADMIN_API_TOKEN"] = "test-admin-token"
os.environ["EVONIDS_ENVIRONMENT"] = "development"

from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402

ADMIN_HEADER = {"x-evonids-admin-token": "test-admin-token"}
SENSOR = "ent-core"


def _alert_body(src_ip: str, dst_ip: str, flow_id: int, signature_id: int, signature: str) -> str:
    return (
        f'{{"timestamp":"2026-09-09T10:00:0{flow_id % 10}+08:00","flow_id":{flow_id},'
        f'"event_type":"alert","src_ip":"{src_ip}","src_port":51000,'
        f'"dest_ip":{dst_ip},"dest_port":443,"proto":"TCP",'
        f'"alert":{{"signature_id":{signature_id},"signature":"{signature}","severity":2}}}}'
    )


def _import_alerts(client, lines: list[str], title: str) -> list[str]:
    response = client.post(
        f"/api/v1/ingestion/eve?sensorId={SENSOR}",
        content="\n".join(lines),
        headers={"content-type": "application/x-ndjson"},
    )
    assert response.status_code == 200
    # The test database is shared across modules/files in a full run, so select
    # only this test's alerts by their unique signature title.
    all_alerts = client.get("/api/v1/alerts").json()["items"]
    return [item["id"] for item in all_alerts if item["title"] == title]


def test_ingestion_discovers_entities_and_relations():
    with TestClient(app) as client:
        _import_alerts(
            client,
            [
                _alert_body("192.0.2.1", '"10.0.0.5"', 20001, 900001, "ET ENT SCAN A"),
                _alert_body("192.0.2.1", '"10.0.0.6"', 20002, 900001, "ET ENT SCAN A"),
            ],
            title="ET ENT SCAN A",
        )
        listing = client.get("/api/v1/entities")
        assert listing.status_code == 200
        entities = {item["value"]: item for item in listing.json()["items"]}
        # entities are IP values discovered from accepted events
        assert "192.0.2.1" in entities and "10.0.0.5" in entities and "10.0.0.6" in entities
        assert entities["192.0.2.1"]["eventCount"] == 2

        attacker = client.get(f"/api/v1/entities/{entities['192.0.2.1']['id']}").json()
        assert attacker["value"] == "192.0.2.1"
        assert len(attacker["relations"]) == 2
        related_values = {item["otherEntityValue"] for item in attacker["relations"]}
        assert related_values == {"10.0.0.5", "10.0.0.6"}
        for item in attacker["relations"]:
            assert item["relationType"] == "communicates_with"


def test_case_suggestions_share_endpoints_with_existing_case():
    with TestClient(app) as client:
        first_alert_ids = _import_alerts(
            client,
            [_alert_body("192.0.2.77", '"10.9.9.9"', 30001, 900101, "ET ENT SCAN B")],
            title="ET ENT SCAN B",
        )
        case = client.post(
            "/api/v1/cases",
            json={"title": "Campaign from 192.0.2.77", "severity": "high"},
            headers=ADMIN_HEADER,
        ).json()
        attached = client.post(
            f"/api/v1/cases/{case['id']}/alerts",
            json={"alertId": first_alert_ids[0]},
            headers=ADMIN_HEADER,
        )
        assert attached.status_code == 200

        new_alert_ids = _import_alerts(
            client,
            [_alert_body("192.0.2.77", '"10.9.9.10"', 30002, 900102, "ET ENT SCAN B")],
            title="ET ENT SCAN B",
        )
        suggestions = client.get(
            f"/api/v1/cases/suggestions?alertId={new_alert_ids[-1]}"
        ).json()["items"]
        assert any(item["caseId"] == case["id"] for item in suggestions)
        hit = next(item for item in suggestions if item["caseId"] == case["id"])
        assert "192.0.2.77" in hit["sharedIps"]
        assert first_alert_ids[0] in hit["matchingAlertIds"]

        unrelated_alert_ids = _import_alerts(
            client,
            [_alert_body("203.0.113.50", '"10.9.9.10"', 30003, 900103, "ET ENT SCAN C")],
            title="ET ENT SCAN C",
        )
        unrelated = client.get(
            f"/api/v1/cases/suggestions?alertId={unrelated_alert_ids[0]}"
        ).json()["items"]
        assert not any(item["caseId"] == case["id"] for item in unrelated)

        missing = client.get("/api/v1/cases/suggestions?alertId=ALT-NOT-REAL")
        assert missing.status_code == 404
