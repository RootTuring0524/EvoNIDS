from __future__ import annotations

import csv
import gzip
import hashlib
import importlib.util
import json
import math
import os
import platform
import re
import time
import uuid
from pathlib import Path
from typing import Any

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.db.base import utc_now
from app.db.models import AuditEvent, DatasetAsset, ModelVersion, TrainingRun
from app.db.session import SessionLocal
from app.schemas.api import (
    AutoEncoderTrainingMetrics,
    TrainingMetrics,
    TrainingRunCreate,
    TrainingRunRead,
    TrainingRunsResponse,
)
from app.services.dataset_catalog import resolve_dataset_path
from app.services.model_registry import artifact_state


ML_MODULES = ("joblib", "numpy", "pandas", "sklearn")
FEATURE_VERSION = "tabular-baseline-v1"
TASK = "known_attack_classification_baseline"


def ml_runtime_available() -> bool:
    return all(importlib.util.find_spec(name) is not None for name in ML_MODULES)


def recover_interrupted_training_runs(db: Session) -> int:
    """Fail non-durable jobs left active by a previous process.

    Training currently runs inside the API process. An API restart therefore means that any
    previously queued/running job has lost its worker and must not remain operationally ambiguous.
    """
    rows = db.scalars(
        select(TrainingRun).where(TrainingRun.state.in_(("queued", "running")))
    ).all()
    if not rows:
        return 0
    now = utc_now()
    message = "Training worker was interrupted by an API restart; start a new run to retry"
    for run in rows:
        previous_state = run.state
        run.state = "failed"
        run.completed_at = now
        run.updated_at = now
        run.error_message = message
        db.add(
            _audit_event(
                actor="training-recovery",
                action="training.interrupted",
                object_id=run.id,
                outcome="failed",
                request_id=None,
                after_state={"state": "failed", "previousState": previous_state},
                note=message,
            )
        )
    db.commit()
    return len(rows)


def queue_training_run(
    db: Session,
    payload: TrainingRunCreate,
    *,
    settings: Settings,
    request_id: str | None,
) -> TrainingRun:
    if not ml_runtime_available():
        raise HTTPException(status_code=503, detail="ML dependencies are not installed; install the backend ml extra")
    dataset = db.get(DatasetAsset, payload.dataset_id)
    if dataset is None:
        raise HTTPException(status_code=404, detail=f"Dataset {payload.dataset_id} not found")
    if dataset.state != "ready" or not dataset.sha256 or not dataset.label_column:
        raise HTTPException(status_code=409, detail="Dataset must finish profiling and have a label column before training")
    resolve_dataset_path(settings, dataset.relative_path)
    active = db.scalar(
        select(TrainingRun).where(
            TrainingRun.dataset_id == dataset.id,
            TrainingRun.state.in_(("queued", "running")),
        )
    )
    if active is not None:
        raise HTTPException(status_code=409, detail=f"Dataset already has active training run {active.id}")
    now = utc_now()
    run = TrainingRun(
        id=f"TRN-{uuid.uuid4().hex.upper()}",
        dataset_id=dataset.id,
        model_id=None,
        task=TASK,
        algorithm=payload.algorithm,
        state="queued",
        requested_by=payload.actor,
        dataset_sha256=dataset.sha256,
        feature_version=FEATURE_VERSION,
        config={
            "maxRows": payload.max_rows,
            "randomSeed": payload.random_seed,
            "maxIter": payload.max_iter,
            "learningRate": payload.learning_rate,
            "maxLeafNodes": payload.max_leaf_nodes,
            "l2Regularization": payload.l2_regularization,
            "split": dataset.split,
            "sampling": "deterministic_stratified_priority_reservoir_over_full_file",
            "numericFeatureThreshold": 0.8,
            "datasetRelativePath": dataset.relative_path,
            "cpuThreads": settings.training_cpu_threads,
        },
        samples_seen=0,
        samples_used=0,
        metrics={},
        created_at=now,
        updated_at=now,
    )
    db.add(run)
    db.add(
        _audit_event(
            actor=payload.actor,
            action="training.queued",
            object_id=run.id,
            outcome="accepted",
            request_id=request_id,
            after_state={
                "datasetId": dataset.id,
                "datasetSha256": dataset.sha256,
                "algorithm": payload.algorithm,
                "maxRows": payload.max_rows,
            },
            note="A real CPU baseline training run was queued; this is not a Flow Transformer run.",
        )
    )
    db.commit()
    db.refresh(run)
    return run


def list_training_runs(db: Session) -> TrainingRunsResponse:
    rows = db.scalars(select(TrainingRun).order_by(TrainingRun.created_at.desc())).all()
    return TrainingRunsResponse(items=[to_training_run_read(db, row) for row in rows])


def get_training_run(db: Session, run_id: str) -> TrainingRunRead:
    row = db.get(TrainingRun, run_id)
    if row is None:
        raise HTTPException(status_code=404, detail=f"Training run {run_id} not found")
    return to_training_run_read(db, row)


def to_training_run_read(db: Session, row: TrainingRun) -> TrainingRunRead:
    dataset = db.get(DatasetAsset, row.dataset_id)
    metrics = None
    if row.metrics:
        metrics = (
            AutoEncoderTrainingMetrics.model_validate(row.metrics)
            if row.task == "unknown_anomaly_detection"
            else TrainingMetrics.model_validate(row.metrics)
        )
    return TrainingRunRead(
        id=row.id,
        dataset_id=row.dataset_id,
        dataset_name=dataset.name if dataset is not None else row.dataset_id,
        model_id=row.model_id,
        task=row.task,
        algorithm=row.algorithm,
        state=row.state,
        requested_by=row.requested_by,
        dataset_sha256=row.dataset_sha256,
        feature_version=row.feature_version,
        config=row.config,
        samples_seen=row.samples_seen,
        samples_used=row.samples_used,
        started_at=row.started_at,
        completed_at=row.completed_at,
        metrics=metrics,
        artifact_state=artifact_state(row.artifact_uri),
        artifact_sha256=row.artifact_sha256,
        error_message=row.error_message,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


def execute_training_run(run_id: str) -> None:
    settings = get_settings()
    with SessionLocal() as db:
        run = db.get(TrainingRun, run_id)
        if run is None or run.state != "queued":
            return
        dataset = db.get(DatasetAsset, run.dataset_id)
        if dataset is None:
            _fail_run(db, run, "Registered dataset no longer exists")
            return
        run.state = "running"
        run.started_at = utc_now()
        run.updated_at = run.started_at
        run.error_message = None
        db.add(
            _audit_event(
                actor="baseline-trainer",
                action="training.started",
                object_id=run.id,
                outcome="running",
                request_id=None,
                after_state={"datasetId": dataset.id, "algorithm": run.algorithm},
                note="Dataset identity verification and real model fitting started.",
            )
        )
        db.commit()

        try:
            path = resolve_dataset_path(settings, dataset.relative_path)
            actual_sha256 = _sha256(path)
            if actual_sha256 != run.dataset_sha256:
                raise ValueError(
                    "Dataset SHA-256 changed after profiling; re-profile the dataset before training"
                )
            result = _train_classifier(path, dataset=dataset, config=run.config)
            artifact_path, artifact_sha256, metadata_path = _write_artifact(
                settings,
                run=run,
                dataset=dataset,
                result=result,
            )
            model = ModelVersion(
                id=f"MODEL-{run.id}",
                name="Known Attack CPU Baseline",
                role="Known attack classification baseline; not Flow Transformer",
                version=f"baseline-{run.id[-12:].lower()}",
                state="healthy",
                artifact_uri=str(artifact_path),
                feature_version=FEATURE_VERSION,
                metrics={
                    "latency_ms": result["metrics"]["test_predict_ms"],
                    "throughput_fps": result["metrics"]["throughput_fps"],
                    "quality_label": "Test macro F1",
                    "quality_value": result["metrics"]["macro_f1"] * 100,
                    "training_run_id": run.id,
                    "dataset_id": dataset.id,
                    "evaluated_at": utc_now().isoformat(),
                },
                parameters={
                    "algorithm": run.algorithm,
                    "trainingRunId": run.id,
                    "datasetId": dataset.id,
                    "datasetSha256": run.dataset_sha256,
                    "artifactSha256": artifact_sha256,
                    "metadataUri": str(metadata_path),
                    "runtimeVersions": result["runtime_versions"],
                    **run.config,
                },
            )
            db.add(model)
            now = utc_now()
            run.config = {**run.config, "runtimeVersions": result["runtime_versions"]}
            run.model_id = model.id
            run.state = "succeeded"
            run.samples_seen = result["samples_seen"]
            run.samples_used = result["samples_used"]
            run.metrics = result["metrics"]
            run.artifact_uri = str(artifact_path)
            run.artifact_sha256 = artifact_sha256
            run.completed_at = now
            run.updated_at = now
            db.add(
                _audit_event(
                    actor="baseline-trainer",
                    action="training.completed",
                    object_id=run.id,
                    outcome="completed",
                    request_id=None,
                    after_state={
                        "modelId": model.id,
                        "samplesUsed": run.samples_used,
                        "macroF1": run.metrics["macro_f1"],
                        "artifactSha256": artifact_sha256,
                    },
                    note="Real test-set metrics and a verified local model artifact were persisted.",
                )
            )
            db.commit()
        except Exception as exc:  # job failures must become visible operational state
            db.rollback()
            refreshed = db.get(TrainingRun, run_id)
            if refreshed is not None:
                _fail_run(db, refreshed, f"{type(exc).__name__}: {exc}"[:2000])


def _train_classifier(path: Path, *, dataset: DatasetAsset, config: dict[str, Any]) -> dict[str, Any]:
    cpu_threads = int(config.get("cpuThreads", 0))
    if cpu_threads > 0:
        os.environ["OMP_NUM_THREADS"] = str(cpu_threads)
        os.environ["LOKY_MAX_CPU_COUNT"] = str(cpu_threads)
    import joblib
    import numpy as np
    import pandas as pd
    import sklearn
    from sklearn.compose import ColumnTransformer
    from sklearn.ensemble import HistGradientBoostingClassifier
    from sklearn.impute import SimpleImputer
    from sklearn.metrics import (
        accuracy_score,
        confusion_matrix,
        f1_score,
        precision_recall_fscore_support,
        precision_score,
        recall_score,
    )
    from sklearn.model_selection import train_test_split
    from sklearn.pipeline import Pipeline

    encoding, delimiter = _detect_csv_format(path)
    max_rows = int(config["maxRows"])
    seed = int(config["randomSeed"])
    quotas = _class_sample_quotas(dataset.label_distribution, max_rows=max_rows)
    rng = np.random.default_rng(seed)
    reservoirs: dict[str, Any] = {}
    samples_seen = 0
    for chunk in pd.read_csv(
        path,
        encoding=encoding,
        sep=delimiter,
        compression="infer",
        chunksize=100_000,
        low_memory=False,
    ):
        chunk.columns = [str(value).strip() for value in chunk.columns]
        samples_seen += len(chunk)
        if dataset.label_column not in chunk.columns:
            raise ValueError(f"Label column disappeared from dataset: {dataset.label_column}")
        chunk = chunk.copy()
        chunk["__evonids_sample_priority"] = rng.random(len(chunk))
        normalized_labels = chunk[dataset.label_column].astype("string").str.strip()
        for label, indices in normalized_labels.groupby(normalized_labels, dropna=True).groups.items():
            label_text = str(label)
            quota = quotas.get(label_text, 0)
            if quota <= 0:
                continue
            candidate = chunk.loc[indices].nsmallest(quota, "__evonids_sample_priority")
            existing = reservoirs.get(label_text)
            if existing is not None:
                candidate = pd.concat([existing, candidate], ignore_index=True).nsmallest(
                    quota,
                    "__evonids_sample_priority",
                )
            reservoirs[label_text] = candidate
    if not reservoirs:
        raise ValueError("Stratified sampling selected no labeled rows; increase maxRows")
    frame = pd.concat(reservoirs.values(), ignore_index=True).drop(
        columns=["__evonids_sample_priority"]
    )
    target = frame[dataset.label_column].astype("string").str.strip()
    valid_target = target.notna() & target.ne("") & target.ne("<missing>")
    dropped_target_rows = int((~valid_target).sum())
    frame = frame.loc[valid_target].reset_index(drop=True)
    target = target.loc[valid_target].astype(str).reset_index(drop=True)
    if len(frame) < 30:
        raise ValueError("At least 30 labeled sampled rows are required for a train/validation/test split")
    class_counts = target.value_counts()
    if len(class_counts) < 2:
        raise ValueError("Known-attack classification requires at least two labels")
    if int(class_counts.min()) < 3:
        rare = ", ".join(f"{label}={count}" for label, count in class_counts.items() if count < 3)
        raise ValueError(f"Every sampled class needs at least three rows; increase maxRows. Rare classes: {rare}")

    raw_features = frame.drop(columns=[dataset.label_column])
    numeric_features: list[str] = []
    numeric_frame: dict[str, Any] = {}
    dropped_features: list[str] = []
    for column in raw_features.columns:
        if _is_identifier_or_target_proxy(str(column), label_column=dataset.label_column):
            dropped_features.append(str(column))
            continue
        values = pd.to_numeric(raw_features[column], errors="coerce").replace([np.inf, -np.inf], np.nan)
        numeric_ratio = float(values.notna().mean())
        if numeric_ratio >= 0.8 and values.nunique(dropna=True) > 1:
            numeric_features.append(str(column))
            numeric_frame[str(column)] = values
        else:
            dropped_features.append(str(column))
    if not numeric_features:
        raise ValueError("No usable numeric features were found (requires at least 80% numeric values)")
    features = pd.DataFrame(numeric_frame)
    split = dataset.split
    test_fraction = float(split["test"]) / 100
    validation_fraction = float(split["validation"]) / 100
    if test_fraction <= 0 or validation_fraction <= 0 or float(split["train"]) <= 0:
        raise ValueError("Training requires non-zero train, validation and test percentages")
    class_count = len(class_counts)
    if math.floor(len(features) * test_fraction) < class_count:
        raise ValueError("Test split is too small to contain every class; increase maxRows or test percentage")
    train_validation_x, test_x, train_validation_y, test_y = train_test_split(
        features,
        target,
        test_size=test_fraction,
        random_state=seed,
        stratify=target,
    )
    relative_validation = validation_fraction / (1 - test_fraction)
    if math.floor(len(train_validation_x) * relative_validation) < class_count:
        raise ValueError("Validation split is too small to contain every class; increase maxRows or validation percentage")
    train_x, validation_x, train_y, validation_y = train_test_split(
        train_validation_x,
        train_validation_y,
        test_size=relative_validation,
        random_state=seed + 1,
        stratify=train_validation_y,
    )
    pipeline = Pipeline(
        steps=[
            (
                "features",
                ColumnTransformer(
                    [("numeric", SimpleImputer(strategy="median"), numeric_features)],
                    remainder="drop",
                ),
            ),
            (
                "classifier",
                HistGradientBoostingClassifier(
                    learning_rate=float(config["learningRate"]),
                    max_iter=int(config["maxIter"]),
                    max_leaf_nodes=int(config["maxLeafNodes"]),
                    l2_regularization=float(config["l2Regularization"]),
                    class_weight="balanced",
                    early_stopping=True,
                    random_state=seed,
                ),
            ),
        ]
    )
    train_started = time.perf_counter()
    pipeline.fit(train_x, train_y)
    train_seconds = time.perf_counter() - train_started
    validation_prediction = pipeline.predict(validation_x)
    prediction_started = time.perf_counter()
    test_prediction = pipeline.predict(test_x)
    prediction_seconds = time.perf_counter() - prediction_started
    labels = sorted(str(value) for value in class_counts.index)
    precision, recall, f1, support = precision_recall_fscore_support(
        test_y,
        test_prediction,
        labels=labels,
        zero_division=0,
    )
    metrics = {
        "accuracy": float(accuracy_score(test_y, test_prediction)),
        "macro_precision": float(precision_score(test_y, test_prediction, average="macro", zero_division=0)),
        "macro_recall": float(recall_score(test_y, test_prediction, average="macro", zero_division=0)),
        "macro_f1": float(f1_score(test_y, test_prediction, average="macro", zero_division=0)),
        "weighted_f1": float(f1_score(test_y, test_prediction, average="weighted", zero_division=0)),
        "validation_macro_f1": float(
            f1_score(validation_y, validation_prediction, average="macro", zero_division=0)
        ),
        "train_samples": int(len(train_x)),
        "validation_samples": int(len(validation_x)),
        "test_samples": int(len(test_x)),
        "dropped_target_rows": dropped_target_rows,
        "feature_count": len(numeric_features),
        "labels": labels,
        "class_metrics": [
            {
                "label": label,
                "support": int(support[index]),
                "precision": float(precision[index]),
                "recall": float(recall[index]),
                "f1": float(f1[index]),
            }
            for index, label in enumerate(labels)
        ],
        "confusion_matrix": confusion_matrix(test_y, test_prediction, labels=labels).astype(int).tolist(),
        "numeric_features": numeric_features,
        "dropped_features": dropped_features,
        "train_seconds": train_seconds,
        "test_predict_ms": prediction_seconds * 1000,
        "throughput_fps": float(len(test_x) / prediction_seconds) if prediction_seconds > 0 else 0.0,
    }
    return {
        "pipeline": pipeline,
        "metrics": metrics,
        "samples_seen": int(samples_seen),
        "samples_used": int(len(frame)),
        "encoding": encoding,
        "delimiter": delimiter,
        "runtime_versions": {
            "python": platform.python_version(),
            "numpy": np.__version__,
            "pandas": pd.__version__,
            "scikitLearn": sklearn.__version__,
            "joblib": joblib.__version__,
        },
    }


def _class_sample_quotas(label_distribution: dict[str, int], *, max_rows: int) -> dict[str, int]:
    counts = {
        str(label).strip(): int(count)
        for label, count in label_distribution.items()
        if str(label).strip() not in {"", "<missing>"} and int(count) > 0
    }
    if len(counts) < 2:
        raise ValueError("Known-attack classification requires at least two profiled labels")
    rare = {label: count for label, count in counts.items() if count < 3}
    if rare:
        detail = ", ".join(f"{label}={count}" for label, count in sorted(rare.items()))
        raise ValueError(f"Every profiled class needs at least three rows. Rare classes: {detail}")
    minimum = 3 * len(counts)
    if max_rows < minimum:
        raise ValueError(
            f"maxRows must be at least {minimum} to preserve three rows for each of {len(counts)} classes"
        )
    total = sum(counts.values())
    if total <= max_rows:
        return counts

    quotas = {label: 3 for label in counts}
    remaining = max_rows - sum(quotas.values())
    capacities = {label: counts[label] - quotas[label] for label in counts}
    while remaining > 0:
        total_capacity = sum(capacities.values())
        if total_capacity <= 0:
            break
        additions = {
            label: min(capacity, int(remaining * capacity / total_capacity))
            for label, capacity in capacities.items()
        }
        allocated = sum(additions.values())
        if allocated == 0:
            label = max(capacities, key=capacities.get)
            additions[label] = 1
            allocated = 1
        for label, addition in additions.items():
            quotas[label] += addition
            capacities[label] -= addition
        remaining -= allocated
    return quotas


def _is_identifier_or_target_proxy(column: str, *, label_column: str) -> bool:
    normalized = re.sub(r"[^a-z0-9]", "", column.casefold())
    normalized_label = re.sub(r"[^a-z0-9]", "", label_column.casefold())
    identifiers = {
        "id",
        "flowid",
        "recordid",
        "rowid",
        "srcip",
        "sourceip",
        "dstip",
        "destinationip",
        "timestamp",
        "starttime",
        "endtime",
        "stime",
        "ltime",
    }
    target_aliases = {"label", "labels", "class", "target", "attackcat", "attackcategory", "groundtruth"}
    return normalized in identifiers or (normalized != normalized_label and normalized in target_aliases)


def _write_artifact(
    settings: Settings,
    *,
    run: TrainingRun,
    dataset: DatasetAsset,
    result: dict[str, Any],
) -> tuple[Path, str, Path]:
    import joblib

    root = Path(settings.model_artifact_root).expanduser().resolve()
    run_dir = (root / "known-attack-baseline" / run.id).resolve()
    if not run_dir.is_relative_to(root):
        raise ValueError("Resolved model artifact path escaped EVONIDS_MODEL_ARTIFACT_ROOT")
    run_dir.mkdir(parents=True, exist_ok=True)
    artifact = run_dir / "model.joblib"
    temporary = run_dir / "model.joblib.tmp"
    metadata = run_dir / "metadata.json"
    payload = {
        "formatVersion": 1,
        "task": TASK,
        "algorithm": run.algorithm,
        "featureVersion": FEATURE_VERSION,
        "pipeline": result["pipeline"],
        "dataset": {
            "id": dataset.id,
            "name": dataset.name,
            "version": dataset.version,
            "sha256": run.dataset_sha256,
            "labelColumn": dataset.label_column,
        },
        "config": run.config,
        "runtimeVersions": result["runtime_versions"],
        "metrics": result["metrics"],
    }
    joblib.dump(payload, temporary, compress=3)
    temporary.replace(artifact)
    artifact_sha256 = _sha256(artifact)
    metadata_payload = {
        key: value for key, value in payload.items() if key != "pipeline"
    } | {
        "trainingRunId": run.id,
        "artifactSha256": artifact_sha256,
        "createdAt": utc_now().isoformat(),
    }
    metadata.write_text(json.dumps(metadata_payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return artifact, artifact_sha256, metadata


def _detect_csv_format(path: Path) -> tuple[str, str]:
    opener = gzip.open if path.name.lower().endswith(".gz") else open
    last_error: UnicodeDecodeError | None = None
    for encoding in ("utf-8-sig", "latin-1"):
        try:
            with opener(path, "rt", encoding=encoding, newline="") as handle:
                sample = handle.read(65_536)
            try:
                dialect = csv.Sniffer().sniff(sample, delimiters=",;\t|")
                return encoding, dialect.delimiter
            except csv.Error:
                return encoding, ","
        except UnicodeDecodeError as exc:
            last_error = exc
    raise ValueError(f"Dataset encoding is not supported: {last_error}")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _fail_run(db: Session, run: TrainingRun, message: str) -> None:
    now = utc_now()
    run.state = "failed"
    run.error_message = message
    run.completed_at = now
    run.updated_at = now
    db.add(
        _audit_event(
            actor="baseline-trainer",
            action="training.failed",
            object_id=run.id,
            outcome="failed",
            request_id=None,
            after_state={"state": "failed"},
            note=message,
        )
    )
    db.commit()


def _audit_event(
    *,
    actor: str,
    action: str,
    object_id: str,
    outcome: str,
    request_id: str | None,
    note: str,
    after_state: dict[str, object] | None = None,
) -> AuditEvent:
    return AuditEvent(
        id=f"AUD-{uuid.uuid4().hex.upper()}",
        created_at=utc_now(),
        actor=actor,
        action=action,
        object_type="training_run",
        object_id=object_id,
        outcome=outcome,
        request_id=request_id,
        before_state=None,
        after_state=after_state,
        note=note,
    )
