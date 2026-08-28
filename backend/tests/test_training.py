from pathlib import Path
from tempfile import gettempdir

import joblib
import pandas as pd
import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlalchemy import select

from app.db.models import TrainingRun
from app.db.session import SessionLocal
from app.main import app
from app.schemas.api import TrainingMetrics
from app.services.training import (
    _class_sample_quotas,
    _is_identifier_or_target_proxy,
    recover_interrupted_training_runs,
)


def test_real_baseline_training_persists_metrics_and_loadable_artifact():
    dataset_root = Path(gettempdir()) / "evonids-dataset-test"
    dataset_path = dataset_root / "training-real-fixture.csv"
    lines = ["duration,packets,bytes,syn_ratio,protocol,Label"]
    labels = ("BENIGN", "PortScan", "DDoS")
    for index in range(150):
        label = labels[index % len(labels)]
        if label == "BENIGN":
            values = (5 + index / 100, 8 + index % 4, 1_200 + index, 0.08, "TCP")
        elif label == "PortScan":
            values = (0.2 + index / 10_000, 70 + index % 10, 4_000 + index, 0.86, "TCP")
        else:
            values = (0.8 + index / 10_000, 800 + index % 20, 90_000 + index * 10, 0.74, "UDP")
        lines.append(",".join(str(value) for value in (*values, label)))
    dataset_path.write_text("\n".join(lines), encoding="utf-8")

    with TestClient(app) as client:
        registered = client.post(
            "/api/v1/datasets",
            headers={"x-evonids-admin-token": "test-admin-token"},
            json={
                "id": "DS-TRAINING-REAL",
                "name": "Training integration fixture",
                "version": "test-only-v1",
                "relativePath": dataset_path.name,
                "labelColumn": "Label",
                "normalLabels": ["BENIGN"],
                "split": {"train": 70, "validation": 15, "test": 15},
            },
        )
        assert registered.status_code == 202
        assert client.get("/api/v1/datasets").json()["items"][0]["state"] == "ready"

        denied = client.post(
            "/api/v1/training/runs",
            json={"datasetId": "DS-TRAINING-REAL", "maxRows": 150},
        )
        assert denied.status_code == 401
        queued = client.post(
            "/api/v1/training/runs",
            headers={"x-evonids-admin-token": "test-admin-token"},
            json={
                "datasetId": "DS-TRAINING-REAL",
                "maxRows": 150,
                "maxIter": 40,
                "randomSeed": 7,
                "actor": "integration-test",
            },
        )
        assert queued.status_code == 202
        run_id = queued.json()["id"]
        completed = client.get(f"/api/v1/training/runs/{run_id}")
        assert completed.status_code == 200
        payload = completed.json()
        assert payload["state"] == "succeeded"
        assert payload["samplesSeen"] == 150
        assert payload["samplesUsed"] == 150
        assert payload["artifactState"] == "available"
        assert len(payload["artifactSha256"]) == 64
        assert payload["metrics"]["testSamples"] > 0
        assert set(payload["metrics"]["labels"]) == {"BENIGN", "PortScan", "DDoS"}
        assert payload["metrics"]["featureCount"] == 4
        assert payload["metrics"]["droppedFeatures"] == ["protocol"]
        assert 0 <= payload["metrics"]["macroF1"] <= 1

        models = client.get("/api/v1/models").json()["items"]
        trained = next(item for item in models if item["trainingRunId"] == run_id)
        assert trained["artifactState"] == "available"
        assert trained["datasetId"] == "DS-TRAINING-REAL"
        assert trained["algorithm"] == "hist_gradient_boosting"

        protected_dataset = client.delete(
            "/api/v1/datasets/DS-TRAINING-REAL",
            headers={"x-evonids-admin-token": "test-admin-token"},
        )
        assert protected_dataset.status_code == 409
        assert run_id in protected_dataset.json()["detail"]

        dataset_path.write_text(
            dataset_path.read_text(encoding="utf-8") + "\n1,1,1,0,TCP,BENIGN",
            encoding="utf-8",
        )
        reprofile = client.post(
            "/api/v1/datasets/DS-TRAINING-REAL/reprofile?actor=integration-test",
            headers={"x-evonids-admin-token": "test-admin-token"},
        )
        assert reprofile.status_code == 202
        protected_profile = next(
            item
            for item in client.get("/api/v1/datasets").json()["items"]
            if item["id"] == "DS-TRAINING-REAL"
        )
        assert protected_profile["state"] == "error"
        assert "immutable lineage" in protected_profile["inspectionError"]

    with SessionLocal() as db:
        row = db.get(TrainingRun, run_id)
        assert row is not None and row.artifact_uri
        artifact = joblib.load(row.artifact_uri)
    assert artifact["task"] == "known_attack_classification_baseline"
    assert set(artifact["runtimeVersions"]) == {
        "python",
        "numpy",
        "pandas",
        "scikitLearn",
        "joblib",
    }
    prediction = artifact["pipeline"].predict(
        pd.DataFrame(
            [{"duration": 0.3, "packets": 76, "bytes": 4_050, "syn_ratio": 0.84}]
        )
    )
    assert prediction[0] in {"BENIGN", "PortScan", "DDoS"}


def test_interrupted_in_process_training_is_failed_on_recovery():
    with SessionLocal() as db:
        completed = db.scalar(
            select(TrainingRun).where(TrainingRun.state == "succeeded").limit(1)
        )
        assert completed is not None
        interrupted = TrainingRun(
            id="TRN-INTERRUPTED-TEST",
            dataset_id=completed.dataset_id,
            model_id=None,
            task="known_attack_classification_baseline",
            algorithm="hist_gradient_boosting",
            state="running",
            requested_by="integration-test",
            dataset_sha256=completed.dataset_sha256,
            feature_version="tabular-baseline-v1",
            config={},
            samples_seen=0,
            samples_used=0,
            metrics={},
        )
        db.add(interrupted)
        db.commit()

        assert recover_interrupted_training_runs(db) == 1
        db.refresh(interrupted)
        assert interrupted.state == "failed"
        assert interrupted.completed_at is not None
        assert "API restart" in (interrupted.error_message or "")


def test_stratified_quota_preserves_rare_classes_and_blocks_obvious_leakage():
    quotas = _class_sample_quotas(
        {"BENIGN": 994, "Infiltration": 3, "DDoS": 3},
        max_rows=30,
    )
    assert sum(quotas.values()) == 30
    assert quotas["Infiltration"] == 3
    assert quotas["DDoS"] == 3
    assert _is_identifier_or_target_proxy("Flow ID", label_column="Label") is True
    assert _is_identifier_or_target_proxy("Timestamp", label_column="Label") is True
    assert _is_identifier_or_target_proxy("attack_cat", label_column="label") is True
    assert _is_identifier_or_target_proxy("Flow Duration", label_column="Label") is False


def test_training_metrics_reject_a_misaligned_confusion_matrix():
    with pytest.raises(ValidationError, match="confusion_matrix"):
        TrainingMetrics(
            accuracy=0.9,
            macro_precision=0.9,
            macro_recall=0.9,
            macro_f1=0.9,
            weighted_f1=0.9,
            validation_macro_f1=0.88,
            train_samples=70,
            validation_samples=15,
            test_samples=15,
            dropped_target_rows=0,
            feature_count=2,
            labels=["BENIGN", "DDoS"],
            class_metrics=[
                {"label": "BENIGN", "support": 8, "precision": 1, "recall": 0.8, "f1": 0.89},
                {"label": "DDoS", "support": 7, "precision": 0.8, "recall": 1, "f1": 0.89},
            ],
            confusion_matrix=[[8]],
            numeric_features=["duration", "packets"],
            dropped_features=["Flow ID"],
            train_seconds=1.2,
            test_predict_ms=3.5,
            throughput_fps=4200,
        )
