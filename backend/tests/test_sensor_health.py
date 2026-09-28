"""Sensor data-quality metrics: measured vs unmeasured, gaps, skew, heartbeat."""
import json
import os
import tempfile
import uuid
from pathlib import Path

database_path = Path(tempfile.gettempdir()) / "evonids-sensor-health-test.db"
database_path.unlink(missing_ok=True)
os.environ["EVONIDS_DATABASE_URL"] = f"sqlite:///{database_path.as_posix()}"
os.environ["EVONIDS_AUTO_CREATE_DB"] = "true"
os.environ["EVONIDS_ADMIN_API_TOKEN"] = "test-admin-token"
os.environ["EVONIDS_SENSOR_INGEST_TOKEN"] = "test-sensor-token"
os.environ["EVONIDS_ENVIRONMENT"] = "development"

from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402

SENSOR_HEADER = {"x-evonids-sensor-token": "test-sensor-token"}


def _flow_line(flow_id: int, timestamp: str) -> str:
    return json.dumps(
        {
            "timestamp": timestamp,
            "flow_id": flow_id,
            "event_type": "flow",
            "src_ip": "192.0.2.10",
            "src_port": 45000,
            "dest_ip": "10.0.0.8",
            "dest_port": 80,
            "proto": "TCP",
            "flow": {"pkts_toserver": 3, "pkts_toclient": 1, "bytes_toserver": 200, "bytes_toclient": 60, "age": 1},
        }
    )


def _batch(client, sensor: str, batch_id: str, lines: list[str], **headers):
    return client.post(
        f"/api/v1/ingestion/eve/batch?sensorId={sensor}",
        content="\n".join(lines) + "\n",
        headers={
            **SENSOR_HEADER,
            "content-type": "application/x-ndjson",
            "x-evonids-batch-id": batch_id,
            "x-evonids-event-count": str(len(lines)),
            **headers,
        },
    )


def _health(client, sensor: str) -> dict:
    payload = client.get(f"/api/v1/sensors/health?sensorId={sensor}").json()
    assert len(payload["items"]) == 1
    return payload["items"][0]


def test_sensor_without_batches_reports_unmeasured_metrics():
    sensor = f"hq-empty-{uuid.uuid4().hex[:6]}"
    with TestClient(app) as client:
        client.post(
            f"/api/v1/sensors/{sensor}/heartbeat",
            json={"agentVersion": "0.1.1", "spoolDepth": 4, "capabilities": ["suricata-eve"]},
            headers=SENSOR_HEADER,
        )
        health = _health(client, sensor)
        assert health["batches"] == 0
        assert health["rejectRate"]["measured"] is False
        assert health["rejectRate"]["value"] is None
        assert health["ingestLatencyP50Ms"]["measured"] is False
        assert health["gapCount"]["measured"] is False
        assert health["spoolDepth"] == 4
        assert health["lastHeartbeatAt"] is not None


def test_batch_metrics_reject_rate_latency_and_duplicates_are_measured():
    sensor = f"hq-metrics-{uuid.uuid4().hex[:6]}"
    with TestClient(app) as client:
        good = _batch(client, sensor, f"b1-{uuid.uuid4().hex[:8]}", [_flow_line(7001, "2026-09-09T10:00:00+00:00")])
        assert good.status_code == 200
        assert good.json()["rejectedEvents"] == 0

        mixed = _batch(
            client,
            sensor,
            f"b2-{uuid.uuid4().hex[:8]}",
            [_flow_line(7002, "2026-09-09T10:01:00+00:00"), "{not json}"],
        )
        assert mixed.status_code == 200
        assert mixed.json()["rejectedEvents"] == 1

        duplicate = _batch(client, sensor, f"b3-{uuid.uuid4().hex[:8]}", [_flow_line(7001, "2026-09-09T10:02:00+00:00")])
        assert duplicate.json()["duplicateEvents"] == 1

        health = _health(client, sensor)
        assert health["batches"] == 3
        # Accepted counts every event the parser understood, including the one
        # that later turned out to be a duplicate; duplicates are reported apart.
        assert health["eventsAccepted"] == 3
        assert health["eventsRejected"] == 1
        assert health["eventsDuplicate"] == 1
        assert health["rejectRate"]["measured"] is True
        assert health["rejectRate"]["value"] > 0
        assert health["duplicateRate"]["measured"] is True
        assert health["ingestLatencyP50Ms"]["measured"] is True
        assert health["ingestLatencyP50Ms"]["value"] >= 0
        assert health["ingestLatencyP95Ms"]["value"] >= health["ingestLatencyP50Ms"]["value"]


def test_gap_detection_counts_missing_intervals():
    sensor = f"hq-gap-{uuid.uuid4().hex[:6]}"
    with TestClient(app) as client:
        _batch(client, sensor, f"g1-{uuid.uuid4().hex[:8]}", [_flow_line(8001, "2026-09-09T10:00:00+00:00")])
        _batch(client, sensor, f"g2-{uuid.uuid4().hex[:8]}", [_flow_line(8002, "2026-09-09T11:00:00+00:00")])
        health = _health(client, sensor)
        assert health["gapCount"]["measured"] is True
        assert health["gapCount"]["value"] >= 1
        assert health["estimatedMissingSeconds"]["value"] > 3000
        assert health["expectedIntervalSeconds"] == 60


def test_heartbeat_persists_agent_identity_and_clock_skew():
    sensor = f"hq-heart-{uuid.uuid4().hex[:6]}"
    with TestClient(app) as client:
        response = client.post(
            f"/api/v1/sensors/{sensor}/heartbeat",
            json={
                "agentVersion": "0.1.1",
                "capabilities": ["suricata-eve", "zeek-json", "suricata-eve"],
                "spoolDepth": 12,
                "droppedEvents": 3,
                "clockSkewSeconds": -41.5,
                "expectedIntervalSeconds": 30,
                "metadata": {"host": "sensor-a"},
            },
            headers=SENSOR_HEADER,
        )
        assert response.status_code == 200
        payload = response.json()
        assert payload["agentVersion"] == "0.1.1"
        assert payload["capabilities"] == ["suricata-eve", "zeek-json"]
        assert payload["spoolDepth"] == 12
        assert payload["droppedEvents"] == 3
        assert payload["clockSkewSeconds"] == -41.5
        assert payload["expectedIntervalSeconds"] == 30
        assert payload["lastHeartbeatAt"] is not None

        health = _health(client, sensor)
        assert health["clockSkewSeconds"]["measured"] is True
        assert health["clockSkewSeconds"]["value"] == -41.5
        assert health["droppedEvents"] == 3


def test_batch_ledger_is_queryable_per_sensor():
    sensor = f"hq-ledger-{uuid.uuid4().hex[:6]}"
    batch_id = f"ledger-{uuid.uuid4().hex[:8]}"
    with TestClient(app) as client:
        _batch(client, sensor, batch_id, [_flow_line(9001, "2026-09-09T10:00:00+00:00")])
        listing = client.get(f"/api/v1/sensors/{sensor}/batches?pageSize=10").json()
        assert listing["total"] == 1
        item = listing["items"][0]
        assert item["batchId"] == batch_id
        assert item["status"] == "accepted"
        assert item["acceptedCount"] == 1
        assert len(item["contentSha256"]) == 64

        missing = client.get("/api/v1/sensors/does-not-exist/batches")
        assert missing.status_code == 404
        assert missing.json()["error"] == "not_found"
