"""Online dual-channel detection: fusion, provenance, shadow/enabled policy, batch API."""
import gzip
import json
import os
import tempfile
import uuid
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

database_path = Path(tempfile.gettempdir()) / "evonids-detection-test.db"
database_path.unlink(missing_ok=True)
os.environ["EVONIDS_DATABASE_URL"] = f"sqlite:///{database_path.as_posix()}"
os.environ["EVONIDS_AUTO_CREATE_DB"] = "true"
os.environ["EVONIDS_ADMIN_API_TOKEN"] = "test-admin-token"
os.environ["EVONIDS_SENSOR_INGEST_TOKEN"] = "test-sensor-token"
os.environ["EVONIDS_ENVIRONMENT"] = "development"

from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import select  # noqa: E402

from app.core.config import get_settings  # noqa: E402
from app.db.base import utc_now  # noqa: E402
from app.db.models import (  # noqa: E402
    Alert,
    DatasetAsset,
    DetectionSignal,
    Flow,
    ModelVersion,
    RiskAssessment,
    TrainingRun,
)
from app.db.session import SessionLocal  # noqa: E402
from app.main import app  # noqa: E402
from app.services.online_detection import (  # noqa: E402
    ChannelSignal,
    fuse_signals,
    parse_mode,
    project_model_row,
)

SENSOR_HEADER = {"x-evonids-sensor-token": "test-sensor-token"}
CONTRACT_FEATURES = (
    "source_port",
    "destination_port",
    "protocol_number",
    "flow_duration_seconds",
    "forward_packet_count",
    "backward_packet_count",
    "forward_bytes",
    "backward_bytes",
    "packets_per_second",
    "bytes_per_second",
    "average_packet_size",
    "packet_ratio",
)
ARTIFACT_DIR = Path(tempfile.gettempdir()) / "evonids-detection-artifacts"
_SEEDED: list[tuple[str, str, str]] = []


@pytest.fixture(autouse=True)
def _cleanup_seeded_registry_rows():
    """Remove synthetic registry rows so later test modules see a clean registry."""
    yield
    if not _SEEDED:
        return
    from sqlalchemy import delete

    with SessionLocal() as db:
        for run_id, model_id, dataset_id in _SEEDED:
            db.execute(delete(DetectionSignal).where(DetectionSignal.model_id == model_id))
            db.execute(delete(TrainingRun).where(TrainingRun.id == run_id))
            db.execute(delete(ModelVersion).where(ModelVersion.id == model_id))
            db.execute(delete(DatasetAsset).where(DatasetAsset.id == dataset_id))
        db.commit()
    _SEEDED.clear()


def _synthetic_baseline(artifact_path: Path) -> dict:
    import joblib
    from sklearn.ensemble import HistGradientBoostingClassifier
    from sklearn.impute import SimpleImputer
    from sklearn.pipeline import Pipeline

    rng = np.random.RandomState(7)
    attack = {
        "source_port": rng.randint(40000, 50000, 200),
        "destination_port": rng.randint(1, 1024, 200),
        "protocol_number": np.full(200, 6),
        "flow_duration_seconds": rng.uniform(0.0, 0.2, 200),
        "forward_packet_count": np.ones(200, dtype=int),
        "backward_packet_count": np.zeros(200, dtype=int),
        "forward_bytes": rng.randint(40, 60, 200),
        "backward_bytes": np.zeros(200, dtype=int),
        "packets_per_second": rng.uniform(0, 50, 200),
        "bytes_per_second": rng.uniform(0, 3000, 200),
        "average_packet_size": rng.uniform(40, 60, 200),
        "packet_ratio": np.ones(200),
    }
    benign = {
        "source_port": rng.randint(30000, 40000, 200),
        "destination_port": np.full(200, 445),
        "protocol_number": np.full(200, 6),
        "flow_duration_seconds": rng.uniform(5.0, 60.0, 200),
        "forward_packet_count": rng.randint(80, 120, 200),
        "backward_packet_count": rng.randint(60, 100, 200),
        "forward_bytes": rng.randint(8000, 12000, 200),
        "backward_bytes": rng.randint(4000, 9000, 200),
        "packets_per_second": rng.uniform(2, 20, 200),
        "bytes_per_second": rng.uniform(200, 2000, 200),
        "average_packet_size": rng.uniform(90, 140, 200),
        "packet_ratio": rng.uniform(0.4, 0.6, 200),
    }
    frame = pd.DataFrame({**{key: np.concatenate([attack[key], benign[key]]) for key in CONTRACT_FEATURES}})
    labels = ["PortScan"] * 200 + ["BENIGN"] * 200
    pipeline = Pipeline(
        [
            ("imputer", SimpleImputer(strategy="median")),
            ("model", HistGradientBoostingClassifier(random_state=0, max_iter=30)),
        ]
    )
    pipeline.fit(frame, labels)
    artifact = {
        "formatVersion": 1,
        "task": "known_attack_classification_baseline",
        "featureVersion": "flow-online-v1",
        "pipeline": pipeline,
        "metrics": {"numeric_features": list(CONTRACT_FEATURES)},
    }
    artifact_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(artifact, artifact_path)
    return artifact


def _seed_model(task: str, artifact_path: Path, *, contract: str = "flow-online-v1") -> str:
    _synthetic_baseline(artifact_path)
    suffix = uuid.uuid4().hex[:10].upper()
    from app.db.base import Base
    from app.db.session import engine

    Base.metadata.create_all(engine)
    with SessionLocal() as db:
        dataset_id = f"DS-TEST-{suffix}"
        db.add(
            DatasetAsset(
                id=dataset_id,
                name="synthetic contract dataset",
                version="v1",
                relative_path=f"synthetic/{suffix}.csv",
                format="csv",
                sha256="0" * 64,
            )
        )
        model_id = f"MODEL-TEST-{suffix}"
        db.add(
            ModelVersion(
                id=model_id,
                name=f"synthetic {task}",
                role=task,
                version=f"test-{suffix.lower()}",
                state="healthy",
                feature_version=contract,
                parameters={"featureContract": contract},
            )
        )
        db.add(
            TrainingRun(
                id=f"TRN-TEST-{suffix}",
                dataset_id=dataset_id,
                model_id=model_id,
                task=task,
                algorithm="hgb",
                state="succeeded",
                requested_by="test",
                dataset_sha256="0" * 64,
                feature_version=contract,
                completed_at=utc_now(),
                artifact_uri=str(artifact_path),
            )
        )
        db.commit()
    _SEEDED.append((f"TRN-TEST-{suffix}", model_id, dataset_id))
    return model_id


def _eve_line(flow_id: int, *, packets: int = 1, duration: int = 0) -> str:
    return json.dumps(
        {
            "timestamp": "2026-09-09T10:00:00+00:00",
            "flow_id": flow_id,
            "event_type": "flow",
            "src_ip": "192.0.2.10",
            "src_port": 45000,
            "dest_ip": "10.0.0.8",
            "dest_port": 80,
            "proto": "TCP",
            "flow": {
                "pkts_toserver": packets,
                "pkts_toclient": 0,
                "bytes_toserver": 50,
                "bytes_toclient": 0,
                "age": duration,
            },
        }
    )


def _signal(channel: str, *, score: float, decision: str, degraded: bool = False, reason=None) -> ChannelSignal:
    return ChannelSignal(
        channel=channel,
        channel_version=f"{channel}-v1",
        model_id=None,
        raw_score=score,
        calibrated_score=score,
        threshold=0.65,
        decision=decision,
        uncertainty=0.0,
        latency_ms=0.0,
        imputed_features=(),
        degraded=degraded,
        degraded_reason=reason,
    )


# --------------------------------------------------------------------- fusion
def test_fusion_dual_confirmed_weighs_both_channels():
    fused = fuse_signals(
        [_signal("baseline", score=0.9, decision="alert"), _signal("autoencoder", score=0.8, decision="alert")]
    )
    assert fused.decision == "malicious"
    assert fused.lean == "dual_confirmed"
    assert fused.agreement == "consistent"
    assert fused.weights["baseline"] == 0.65
    assert fused.final_score == pytest.approx(0.65 * 90 + 0.35 * 80, abs=0.01)


def test_fusion_single_channel_is_marked_insufficient_evidence():
    fused = fuse_signals([_signal("baseline", score=0.9, decision="alert"), _signal("autoencoder", score=0.0, decision="abstain", degraded=True, reason="artifact_unavailable")])
    assert fused.lean == "single_channel"
    assert fused.agreement == "insufficient"
    assert "证据不足" in fused.explanation
    assert fused.uncertainty > 0.5
    assert any("artifact_unavailable" in reason for reason in fused.degraded_reasons)


def test_fusion_conflict_and_unknown_anomaly():
    fused = fuse_signals(
        [_signal("baseline", score=0.1, decision="benign"), _signal("autoencoder", score=0.95, decision="alert")]
    )
    assert fused.lean == "unknown_anomaly"
    assert fused.agreement == "conflicting"
    assert fused.decision == "malicious"


def test_fusion_rule_floor_prevents_model_dilution():
    fused = fuse_signals(
        [_signal("baseline", score=0.02, decision="benign"), _signal("autoencoder", score=0.02, decision="benign")],
        rule_risk=0.95,
    )
    assert fused.final_score == pytest.approx(95.0)
    assert fused.weights["ruleFloorApplied"] == 1.0
    assert "签名下限" in fused.explanation


def test_fusion_without_any_channel_abstains():
    fused = fuse_signals([])
    assert fused.decision == "abstain"
    assert fused.lean == "insufficient_evidence"
    assert fused.degraded_reasons == ("no_channel_available",)


def test_project_model_row_maps_transforms_and_reports_imputation():
    values = {
        "source_port": 1234,
        "protocol_number": 6,
        "flow_duration_seconds": 2.0,
        "forward_packet_count": 10,
    }
    row, imputed = project_model_row(
        values, ["source_port", "protocol", "duration_us", "flow_iat_mean", "total_fwd_packets"]
    )
    assert row["source_port"] == 1234
    assert row["protocol"] == 6
    assert row["duration_us"] == 2_000_000
    assert row["total_fwd_packets"] == 10
    assert np.isnan(row["flow_iat_mean"])
    assert imputed == ("flow_iat_mean",)


def test_parse_mode_rejects_unknown_values():
    assert parse_mode(None) == "shadow"
    assert parse_mode("ENABLED") == "enabled"
    with pytest.raises(ValueError):
        parse_mode("aggressive")


# ------------------------------------------------------------------ API paths
def test_shadow_mode_records_signals_and_assessments_without_alerting(monkeypatch):
    monkeypatch.setattr(get_settings(), "detection_mode", "shadow")
    model_id = _seed_model("known_attack_classification_baseline", ARTIFACT_DIR / "baseline.joblib")
    sensor = f"det-shadow-{uuid.uuid4().hex[:6]}"
    flow_id = abs(hash(sensor)) % 10**9
    with TestClient(app) as client:
        response = client.post(
            f"/api/v1/ingestion/eve?sensorId={sensor}",
            content=_eve_line(flow_id),
            headers={**SENSOR_HEADER, "content-type": "application/x-ndjson"},
        )
        assert response.status_code == 200
        body = response.json()
        assert body["detection"]["mode"] == "shadow"
        assert body["detection"]["flowsScored"] == 1
        assert body["detection"]["signals"] == 2
        assert body["detection"]["alertsCreated"] == 0

        with SessionLocal() as db:
            flow = db.scalar(select(Flow).where(Flow.sensor_id == sensor))
            assert flow is not None
            assert flow.verdict == "benign"
            signals = db.scalars(select(DetectionSignal).where(DetectionSignal.flow_id == flow.id)).all()
            assert {signal.channel for signal in signals} == {"baseline", "autoencoder"}
            baseline = next(signal for signal in signals if signal.channel == "baseline")
            assert baseline.model_id == model_id
            assert baseline.feature_version == "flow-online-v1"
            assert baseline.detail["missingFields"] == []
            assert baseline.detail["contextFeatures"]["flow_count_60s"] >= 1
            autoencoder = next(signal for signal in signals if signal.channel == "autoencoder")
            assert autoencoder.decision == "abstain"
            assert autoencoder.degraded is True
            assert autoencoder.degraded_reason == "artifact_unavailable"
            assessment = db.scalar(select(RiskAssessment).where(RiskAssessment.flow_id == flow.id))
            assert assessment is not None
            assert assessment.mode == "shadow"
            assert assessment.alert_id is None
            assert len(assessment.inputs) == 2
            assert assessment.signal_ids
            assert db.scalars(select(Alert).where(Alert.sensor == sensor)).all() == []
            flow_pk = flow.id

        detail = client.get(f"/api/v1/detections/flows/{flow_pk}")
        assert detail.status_code == 200
        payload = detail.json()
        assert len(payload["signals"]) == 2
        assert payload["assessments"][0]["mode"] == "shadow"
        assert payload["assessments"][0]["explanation"]


def test_enabled_mode_creates_alert_with_full_provenance(monkeypatch):
    monkeypatch.setattr(get_settings(), "detection_mode", "enabled")
    _seed_model("known_attack_classification_baseline", ARTIFACT_DIR / "baseline-enabled.joblib")
    sensor = f"det-enabled-{uuid.uuid4().hex[:6]}"
    flow_id = abs(hash(sensor)) % 10**9
    with TestClient(app) as client:
        response = client.post(
            f"/api/v1/ingestion/eve?sensorId={sensor}",
            content=_eve_line(flow_id),
            headers={**SENSOR_HEADER, "content-type": "application/x-ndjson"},
        )
        assert response.status_code == 200
        assert response.json()["detection"]["mode"] == "enabled"
        assert response.json()["detection"]["alertsCreated"] == 1

        with SessionLocal() as db:
            flow = db.scalar(select(Flow).where(Flow.sensor_id == sensor))
            assert flow is not None and flow.verdict in {"malicious", "suspicious"}
            alert = db.scalar(select(Alert).where(Alert.sensor == sensor))
            assert alert is not None
            assert alert.flow_id == flow.id
            assert alert.risk_score > 0
            assert any("风险融合评估" in item for item in alert.evidence)
            signals = db.scalars(select(DetectionSignal).where(DetectionSignal.flow_id == flow.id)).all()
            assert all(signal.alert_id == alert.id for signal in signals)
            assessment = db.scalar(select(RiskAssessment).where(RiskAssessment.flow_id == flow.id))
            assert assessment is not None and assessment.alert_id == alert.id


def test_scoring_failure_degrades_to_abstain_without_failing_ingestion(monkeypatch):
    monkeypatch.setattr(get_settings(), "detection_mode", "shadow")
    _seed_model("known_attack_classification_baseline", ARTIFACT_DIR / "baseline-degraded.joblib")

    def _explode(*args, **kwargs):
        raise RuntimeError("simulated model runtime failure")

    monkeypatch.setattr("app.services.online_detection.score_baseline", _explode)
    sensor = f"det-degraded-{uuid.uuid4().hex[:6]}"
    flow_id = abs(hash(sensor)) % 10**9
    with TestClient(app) as client:
        response = client.post(
            f"/api/v1/ingestion/eve?sensorId={sensor}",
            content=_eve_line(flow_id),
            headers={**SENSOR_HEADER, "content-type": "application/x-ndjson"},
        )
        assert response.status_code == 200
        detection = response.json()["detection"]
        assert detection["degraded"] is True
        assert any("scoring_failed" in reason for reason in detection["degradedReasons"])
        with SessionLocal() as db:
            flow = db.scalar(select(Flow).where(Flow.sensor_id == sensor))
            assert flow is not None
            signals = db.scalars(select(DetectionSignal).where(DetectionSignal.flow_id == flow.id)).all()
            assert {signal.decision for signal in signals} == {"abstain"}
            assessment = db.scalar(select(RiskAssessment).where(RiskAssessment.flow_id == flow.id))
            assert assessment is not None
            assert assessment.decision == "abstain"
            assert "scoring_failed" in " ".join(assessment.degraded_reasons)


def test_batch_endpoint_is_idempotent_and_conflicts_on_content_change():
    sensor = f"det-batch-{uuid.uuid4().hex[:6]}"
    batch_id = f"batch-{uuid.uuid4().hex[:10]}"
    flow_id = abs(hash(sensor)) % 10**9
    body = _eve_line(flow_id) + "\n"
    headers = {
        **SENSOR_HEADER,
        "content-type": "application/x-ndjson",
        "x-evonids-batch-id": batch_id,
        "x-evonids-encoding": "identity",
        "x-evonids-event-count": "1",
        "x-evonids-clock-skew-seconds": "12.5",
    }
    with TestClient(app) as client:
        first = client.post(f"/api/v1/ingestion/eve/batch?sensorId={sensor}", content=body, headers=headers)
        assert first.status_code == 200
        assert first.json()["replayed"] is False
        assert first.json()["createdFlows"] == 1

        replay = client.post(f"/api/v1/ingestion/eve/batch?sensorId={sensor}", content=body, headers=headers)
        assert replay.status_code == 200
        assert replay.json()["replayed"] is True
        assert replay.json()["createdFlows"] == 1

        conflict = client.post(
            f"/api/v1/ingestion/eve/batch?sensorId={sensor}",
            content=_eve_line(flow_id + 1) + "\n",
            headers=headers,
        )
        assert conflict.status_code == 409
        assert conflict.json()["error"] == "conflict"

        with SessionLocal() as db:
            flows = db.scalars(select(Flow).where(Flow.sensor_id == sensor)).all()
            assert len(flows) == 1
            sensor_row = client.get(f"/api/v1/sensors?search={sensor}").json()["items"][0]
            assert sensor_row["clockSkewSeconds"] == 12.5


def test_batch_endpoint_accepts_gzip_and_rejects_oversized_declared_count():
    sensor = f"det-gzip-{uuid.uuid4().hex[:6]}"
    flow_id = abs(hash(sensor)) % 10**9
    compressed = gzip.compress((_eve_line(flow_id) + "\n").encode("utf-8"))
    with TestClient(app) as client:
        accepted = client.post(
            f"/api/v1/ingestion/eve/batch?sensorId={sensor}",
            content=compressed,
            headers={
                **SENSOR_HEADER,
                "content-type": "application/x-ndjson",
                "content-encoding": "identity",
                "x-evonids-batch-id": f"gzip-{uuid.uuid4().hex[:10]}",
                "x-evonids-encoding": "gzip",
            },
        )
        assert accepted.status_code == 200
        assert accepted.json()["createdFlows"] == 1

        bad = client.post(
            f"/api/v1/ingestion/eve/batch?sensorId={sensor}",
            content=(_eve_line(flow_id + 1) + "\n"),
            headers={
                **SENSOR_HEADER,
                "x-evonids-batch-id": f"bad-{uuid.uuid4().hex[:10]}",
                "x-evonids-event-count": "0",
            },
        )
        assert bad.status_code == 400

        missing_id = client.post(
            f"/api/v1/ingestion/eve/batch?sensorId={sensor}",
            content=(_eve_line(flow_id + 2) + "\n"),
            headers=SENSOR_HEADER,
        )
        assert missing_id.status_code == 422


def test_detection_status_and_signal_listing_endpoints():
    sensor = f"det-api-{uuid.uuid4().hex[:6]}"
    with TestClient(app) as client:
        status = client.get("/api/v1/detections/status")
        assert status.status_code == 200
        payload = status.json()
        assert payload["featureVersion"] == "flow-online-v1"
        assert set(payload["channels"]) == {"baseline", "autoencoder"}
        assert isinstance(payload["notes"], list)

        listing = client.get("/api/v1/detections/signals?pageSize=5")
        assert listing.status_code == 200
        assert set(listing.json()).issuperset({"items", "total", "page", "pageSize"})

        filtered = client.get(f"/api/v1/detections/signals?sensorId={sensor}")
        assert filtered.status_code == 200
        assert filtered.json()["total"] == 0

        missing = client.get("/api/v1/detections/flows/FLOW-DOES-NOT-EXIST")
        assert missing.status_code == 404
        assert missing.json()["error"] == "not_found"
