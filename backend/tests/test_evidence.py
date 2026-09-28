"""Evidence registry integration tests: ingestion hashing, idempotency, API."""
import os
import tempfile
from pathlib import Path

database_path = Path(tempfile.gettempdir()) / "evonids-evidence-test.db"
database_path.unlink(missing_ok=True)
os.environ["EVONIDS_DATABASE_URL"] = f"sqlite:///{database_path.as_posix()}"
os.environ["EVONIDS_AUTO_CREATE_DB"] = "true"
os.environ["EVONIDS_ADMIN_API_TOKEN"] = "test-admin-token"
os.environ["EVONIDS_ENVIRONMENT"] = "development"

from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402

ADMIN_HEADER = {"x-evonids-admin-token": "test-admin-token"}
SENSOR = "evd-core"  # per-file sensor keeps assertions independent of test order

EVE_BODY = "\n".join(
    [
        '{"timestamp":"2026-09-07T10:00:00+08:00","flow_id":10001,"event_type":"flow",'
        '"src_ip":"192.0.2.10","src_port":51000,"dest_ip":"10.0.0.8","dest_port":445,'
        '"proto":"TCP","app_proto":"smb","flow":{"pkts_toserver":5,"pkts_toclient":2,'
        '"bytes_toserver":300,"bytes_toclient":100,"age":1}}',
        '{"timestamp":"2026-09-07T10:00:01+08:00","flow_id":10001,"event_type":"alert",'
        '"src_ip":"192.0.2.10","src_port":51000,"dest_ip":"10.0.0.8","dest_port":445,'
        '"proto":"TCP","alert":{"signature_id":2200451,"signature":"ET SCAN port scan","severity":1}}',
    ]
)


def _sensor_count(client, sensor_id: str) -> int:
    return client.get(f"/api/v1/evidence?sensorId={sensor_id}").json()["total"]


def _import(client, sensor_id: str):
    return client.post(
        f"/api/v1/ingestion/eve?sensorId={sensor_id}",
        content=EVE_BODY,
        headers={"content-type": "application/x-ndjson"},
    )


def test_ingestion_creates_hashed_evidence_with_raw_artifacts():
    with TestClient(app) as client:
        imported = _import(client, SENSOR)
        assert imported.status_code == 200
        assert _sensor_count(client, SENSOR) == 2

        listing = client.get(f"/api/v1/evidence?sensorId={SENSOR}").json()
        assert listing["total"] == 2
        by_type = {item["eventType"]: item for item in listing["items"]}
        assert set(by_type) == {"flow", "alert"}
        for item in listing["items"]:
            assert len(item["contentSha256"]) == 64
            assert item["integrity"] == "complete"
            assert item["dataMissing"] == "none"
            assert item["parserVersion"] == "evonids-eve-v1"
            assert item["redacted"] is False
            assert item["artifactSizeBytes"] > 0
        assert by_type["flow"]["sourceRefType"] == "flow"
        assert by_type["alert"]["sourceRefType"] == "alert"

        detail = client.get(f"/api/v1/evidence/{by_type['alert']['id']}", headers=ADMIN_HEADER)
        assert detail.status_code == 200
        assert detail.json()["artifactText"].startswith('{"timestamp"')
        assert detail.json()["fields"]["alert"]["signature_id"] == 2200451


def test_reingesting_same_events_does_not_duplicate_evidence():
    with TestClient(app) as client:
        # Dedicated sensor so earlier tests in this module (same database)
        # cannot pre-seed these events.
        sensor = "evd-reingest"
        first = _import(client, sensor)
        assert first.json()["duplicateEvents"] == 0
        count_after_first = _sensor_count(client, sensor)

        second = _import(client, sensor)
        assert second.status_code == 200
        assert second.json()["duplicateEvents"] == 2
        assert _sensor_count(client, sensor) == count_after_first


def test_evidence_detail_requires_admin_and_list_is_filterable_by_hash():
    with TestClient(app) as client:
        _import(client, SENSOR)
        item = client.get(f"/api/v1/evidence?sensorId={SENSOR}").json()["items"][0]

        denied = client.get(f"/api/v1/evidence/{item['id']}")
        assert denied.status_code == 401

        by_hash = client.get(
            f"/api/v1/evidence?contentSha256={item['contentSha256']}&sensorId={SENSOR}"
        ).json()
        assert by_hash["total"] == 1
        assert by_hash["items"][0]["id"] == item["id"]

        missing = client.get("/api/v1/evidence/EVD-DOES-NOT-EXIST", headers=ADMIN_HEADER)
        assert missing.status_code == 404
        assert missing.json()["error"] == "not_found"


def test_evidence_is_registered_per_sensor():
    with TestClient(app) as client:
        _import(client, SENSOR)
        _import(client, "evd-second")
        alpha = _sensor_count(client, SENSOR)
        beta = _sensor_count(client, "evd-second")
        assert alpha == 2
        assert beta == 2
        alpha_ids = {item["id"] for item in client.get(f"/api/v1/evidence?sensorId={SENSOR}").json()["items"]}
        beta_ids = {item["id"] for item in client.get("/api/v1/evidence?sensorId=evd-second").json()["items"]}
        assert not alpha_ids & beta_ids
