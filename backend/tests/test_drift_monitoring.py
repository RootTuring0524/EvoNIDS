"""Drift monitoring: PSI/KS against the artifact reference distribution, honest gaps."""
import os
import tempfile
import uuid
from datetime import timedelta
from pathlib import Path

database_path = Path(tempfile.gettempdir()) / "evonids-drift-test.db"
database_path.unlink(missing_ok=True)
os.environ["EVONIDS_DATABASE_URL"] = f"sqlite:///{database_path.as_posix()}"
os.environ["EVONIDS_AUTO_CREATE_DB"] = "true"
os.environ["EVONIDS_ADMIN_API_TOKEN"] = "test-admin-token"
os.environ["EVONIDS_ENVIRONMENT"] = "development"

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.db.base import Base, utc_now  # noqa: E402
from app.db.models import DatasetAsset, Flow, ModelVersion, Sensor, TrainingRun  # noqa: E402
from app.db.session import SessionLocal, engine  # noqa: E402
from app.main import app  # noqa: E402
from app.services.drift_monitoring import (  # noqa: E402
    build_histogram,
    _ks,
    _psi,
    _status,
    feature_drift_report,
    prediction_drift,
)

ADMIN_HEADER = {"x-evonids-admin-token": "test-admin-token"}
ARTIFACT_DIR = Path(tempfile.gettempdir()) / "evonids-drift-artifacts"


@pytest.fixture(scope="module", autouse=True)
def _create_schema():
    Base.metadata.create_all(engine)
    yield


@pytest.fixture(autouse=True)
def _cleanup_seeded_rows():
    """Remove synthetic registry/flow rows so other modules see a clean registry."""
    from sqlalchemy import delete

    yield
    with SessionLocal() as db:
        db.execute(delete(Flow).where(Flow.id.like("FLOW-DRIFT-%")))
        db.execute(delete(TrainingRun).where(TrainingRun.id.like("TRN-DRIFT-%")))
        db.execute(delete(ModelVersion).where(ModelVersion.id.like("MODEL-DRIFT-%")))
        db.execute(delete(DatasetAsset).where(DatasetAsset.id.like("DS-DRIFT-%")))
        db.execute(delete(Sensor).where(Sensor.id.like("drift-sensor-%")))
        db.commit()


def _reference(mean: float, spread: float) -> dict:
    values = [mean - spread + (2 * spread) * index / 99 for index in range(100)]
    return {
        "mean": mean,
        "std": spread / 2,
        "min": min(values),
        "max": max(values),
        "quantiles": {"0.1": mean - spread / 2, "0.5": mean, "0.9": mean + spread / 2},
        "histogram": build_histogram(values),
    }


def _seed_contract_model() -> str:
    import joblib
    import pandas as pd  # noqa: F401

    ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
    path = ARTIFACT_DIR / f"baseline-{uuid.uuid4().hex[:8]}.joblib"
    reference = {
        "flow_duration_seconds": _reference(1.0, 2.0),
        "forward_packet_count": _reference(10.0, 8.0),
    }
    joblib.dump(
        {
            "formatVersion": 1,
            "task": "known_attack_classification_baseline",
            "featureVersion": "flow-online-v1",
            "referenceDistribution": reference,
            "metrics": {"numeric_features": list(reference)},
        },
        path,
    )
    suffix = uuid.uuid4().hex[:10].upper()
    with SessionLocal() as db:
        dataset_id = f"DS-DRIFT-{suffix}"
        model_id = f"MODEL-DRIFT-{suffix}"
        db.add(
            DatasetAsset(
                id=dataset_id,
                name="drift test",
                version="v1",
                relative_path=f"drift/{suffix}.csv",
                format="csv",
                sha256="0" * 64,
            )
        )
        db.add(
            ModelVersion(
                id=model_id,
                name="drift baseline",
                role="known_attack_classification_baseline",
                version=f"drift-{suffix.lower()}",
                state="healthy",
                feature_version="flow-online-v1",
                parameters={"featureContract": "flow-online-v1"},
            )
        )
        db.add(
            TrainingRun(
                id=f"TRN-DRIFT-{suffix}",
                dataset_id=dataset_id,
                model_id=model_id,
                task="known_attack_classification_baseline",
                algorithm="hgb",
                state="succeeded",
                requested_by="test",
                dataset_sha256="0" * 64,
                feature_version="flow-online-v1",
                completed_at=utc_now(),
                artifact_uri=str(path),
            )
        )
        db.commit()
    return model_id


def _seed_flows(
    *,
    values: dict[str, float] | None = None,
    spread: dict[str, tuple[float, float]] | None = None,
    count: int = 40,
    verdict: str = "benign",
) -> str:
    with SessionLocal() as db:
        sensor_id = f"drift-sensor-{uuid.uuid4().hex[:6]}"
        db.add(Sensor(id=sensor_id, name=sensor_id, state="online", metadata_json={}))
        db.flush()
        now = utc_now().replace(tzinfo=None)
        for index in range(count):
            if spread:
                payload: dict[str, float] = {
                    name: low + (high - low) * index / max(count - 1, 1)
                    for name, (low, high) in spread.items()
                }
            else:
                payload = dict(values or {})
            db.add(
                Flow(
                    id=f"FLOW-DRIFT-{uuid.uuid4().hex[:16]}",
                    external_id=f"drift-{uuid.uuid4().hex[:10]}",
                    sensor_id=sensor_id,
                    time=now - timedelta(minutes=index),
                    source="192.0.2.1",
                    destination="10.0.0.1",
                    source_port=1000 + index,
                    destination_port=80,
                    protocol="TCP",
                    service="HTTP",
                    activity="test",
                    packets=1,
                    bytes=100,
                    duration_ms=1000,
                    verdict=verdict,
                    anomaly_score=0.0,
                    feature_version="flow-online-v1",
                    features={"onlineContract": {"modelFeatures": payload}},
                    raw_reference={},
                )
            )
        db.commit()
    return sensor_id


def test_psi_ks_and_status_thresholds():
    reference = _reference(1.0, 2.0)
    identical = [reference["min"] + (reference["max"] - reference["min"]) * index / 99 for index in range(100)]
    shifted = [value + 500 for value in identical]
    assert _psi(reference, identical) == pytest.approx(0.0, abs=0.05)
    assert _psi(reference, shifted) > 0.25
    assert _psi({"mean": 1.0}, identical) is None
    assert _ks(reference, identical) == pytest.approx(0.0, abs=0.05)
    assert _ks(reference, shifted) == 1.0
    assert _status(None, None) == "not_measured"
    assert _status(0.01, 0.01) == "ok"
    assert _status(0.15, 0.01) == "warn"
    assert _status(0.30, 0.01) == "drift"


def test_drift_report_is_ok_when_traffic_matches_the_reference():
    _seed_contract_model()
    # Traffic spread across the reference range, matching the reference shape.
    sensor = _seed_flows(
        spread={"flow_duration_seconds": (-1.0, 3.0), "forward_packet_count": (2.0, 18.0)},
        count=40,
    )
    with SessionLocal() as db:
        report = feature_drift_report(db, channel="baseline", window_hours=24, sensor_id=sensor)
    by_feature = {item["feature"]: item for item in report["items"]}
    assert by_feature["flow_duration_seconds"]["measured"] is True
    assert by_feature["flow_duration_seconds"]["status"] == "ok"
    # A feature with neither reference data nor observed values stays unmeasured.
    assert by_feature["average_packet_size"]["status"] == "not_measured"
    assert by_feature["average_packet_size"]["psi"] is None


def test_drift_report_detects_a_real_shift():
    _seed_contract_model()
    sensor = _seed_flows(
        values={"flow_duration_seconds": 900.0, "forward_packet_count": 5000.0}, count=40
    )
    with SessionLocal() as db:
        report = feature_drift_report(db, channel="baseline", window_hours=24, sensor_id=sensor)
    by_feature = {item["feature"]: item for item in report["items"]}
    assert by_feature["flow_duration_seconds"]["status"] == "drift"
    assert by_feature["forward_packet_count"]["status"] == "drift"
    assert report["status"] == "drift"
    assert "flow_duration_seconds" in report["driftedFeatures"]


def test_drift_is_not_measured_on_a_database_without_traffic():
    """A dedicated empty database proves the not_measured path deterministically."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session

    empty_engine = create_engine("sqlite://")
    Base.metadata.create_all(empty_engine)
    with Session(empty_engine) as db:
        report = feature_drift_report(db, channel="baseline", window_hours=24)
        assert all(item["status"] == "not_measured" for item in report["items"])
        assert report["status"] == "not_measured"
        assert report["flowsScanned"] == 0
        assert prediction_drift(db, window_hours=24)["measured"] is False


def test_prediction_drift_counts_verdicts():
    _seed_flows(values={"flow_duration_seconds": 1.0}, count=10, verdict="suspicious")
    with SessionLocal() as db:
        measured = prediction_drift(db, window_hours=24)
    assert measured["measured"] is True
    assert measured["counts"].get("suspicious", 0) >= 10


def test_drift_api_endpoint_shape():
    _seed_contract_model()
    with TestClient(app) as client:
        response = client.get("/api/v1/models/drift?channel=baseline&windowHours=24")
        assert response.status_code == 200
        payload = response.json()
        assert payload["featureContract"] == "flow-online-v1"
        assert "predictionDrift" in payload
        assert payload["thresholds"]["psiDrift"] == 0.25
        assert isinstance(payload["items"], list)

        health = client.get("/api/v1/models/health")
        assert health.status_code == 200
        assert "items" in health.json()
