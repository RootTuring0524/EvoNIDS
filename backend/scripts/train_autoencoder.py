from __future__ import annotations

import argparse
import sys
import uuid
from pathlib import Path
from typing import Any

from app.core.config import get_settings
from app.db.base import utc_now
from app.db.models import AuditEvent, DatasetAsset, ModelVersion, TrainingRun
from app.db.session import SessionLocal
from app.services.autoencoder import (
    ALGORITHM,
    FEATURE_VERSION,
    TASK,
    sha256_file,
    train_autoencoder,
    write_artifact,
)
from app.services.dataset_catalog import resolve_dataset_path


DATASET_ID = "DS-CIC-2017-PCAP-V1"
IDENTIFIER_FEATURES = {"capture_day", "source_ip", "destination_ip", "start_time"}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Train the EvoNIDS PyTorch CPU AutoEncoder on normal CICIDS2017 flows."
    )
    parser.add_argument("--dataset-id", default=DATASET_ID)
    parser.add_argument("--run-id")
    parser.add_argument("--max-normal-rows", type=int, default=46_000)
    parser.add_argument("--max-attack-rows", type=int, default=120_000)
    parser.add_argument("--epochs", type=int, default=40)
    parser.add_argument("--patience", type=int, default=6)
    parser.add_argument("--batch-size", type=int, default=512)
    parser.add_argument("--learning-rate", type=float, default=0.001)
    parser.add_argument("--bottleneck-size", type=int, default=8)
    parser.add_argument("--threshold-quantile", type=float, default=0.95)
    parser.add_argument("--target-fpr", type=float, default=None)
    parser.add_argument("--random-seed", type=int, default=20260728)
    parser.add_argument("--smoke", action="store_true")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.smoke:
        args.max_normal_rows = min(args.max_normal_rows, 5_000)
        args.max_attack_rows = min(args.max_attack_rows, 10_000)
        args.epochs = min(args.epochs, 3)
        args.patience = min(args.patience, 2)
    settings = get_settings()
    run_id = args.run_id or f"TRN-AE-{uuid.uuid4().hex.upper()}"
    with SessionLocal() as db:
        dataset = db.get(DatasetAsset, args.dataset_id)
        if dataset is None:
            raise RuntimeError(f"Dataset registry entry is missing: {args.dataset_id}")
        if dataset.state != "ready" or not dataset.sha256 or not dataset.label_column:
            raise RuntimeError("Dataset must be ready and profiled before AutoEncoder training")
        if db.get(TrainingRun, run_id) is not None:
            raise RuntimeError(f"Training run already exists: {run_id}")
        numeric_features = [
            feature for feature in dataset.feature_columns if feature not in IDENTIFIER_FEATURES
        ]
        if len(numeric_features) < 2:
            raise RuntimeError("Dataset registry does not expose enough numeric features")
        dataset_path = resolve_dataset_path(settings, dataset.relative_path)
        config = {
            "framework": "pytorch-cpu",
            "maxNormalRows": args.max_normal_rows,
            "maxAttackRows": args.max_attack_rows,
            "maxEpochs": args.epochs,
            "patience": args.patience,
            "batchSize": args.batch_size,
            "learningRate": args.learning_rate,
            "bottleneckSize": args.bottleneck_size,
            "thresholdQuantile": args.threshold_quantile,
            "targetFpr": args.target_fpr,
            "randomSeed": args.random_seed,
            "split": dataset.split,
            "normalLabels": dataset.normal_labels,
            "datasetRelativePath": dataset.relative_path,
            "progress": {"stage": "queued", "percent": 0},
        }
        now = utc_now()
        run = TrainingRun(
            id=run_id,
            dataset_id=dataset.id,
            model_id=None,
            task=TASK,
            algorithm=ALGORITHM,
            state="running",
            requested_by="local-pytorch-cpu-trainer",
            dataset_sha256=dataset.sha256,
            feature_version=FEATURE_VERSION,
            config=config,
            samples_seen=0,
            samples_used=0,
            started_at=now,
            completed_at=None,
            metrics={},
            artifact_uri=None,
            artifact_sha256=None,
            error_message=None,
            created_at=now,
            updated_at=now,
        )
        db.add(run)
        db.add(
            audit_event(
                action="training.autoencoder.started",
                object_id=run_id,
                outcome="running",
                after_state={
                    "datasetId": dataset.id,
                    "framework": "pytorch-cpu",
                    "normalLabels": dataset.normal_labels,
                    "featureCount": len(numeric_features),
                },
                note="PyTorch CPU AutoEncoder training started on normal traffic only.",
            )
        )
        db.commit()
        dataset_info = {
            "id": dataset.id,
            "name": dataset.name,
            "version": dataset.version,
            "sha256": dataset.sha256,
            "labelColumn": dataset.label_column,
            "normalLabels": dataset.normal_labels,
        }
        label_column = dataset.label_column
        normal_labels = list(dataset.normal_labels)
        split = dict(dataset.split)
        expected_sha256 = dataset.sha256

    print("=" * 78, flush=True)
    print("EvoNIDS PyTorch CPU AutoEncoder Training", flush=True)
    print(f"run_id          : {run_id}", flush=True)
    print(f"dataset         : {dataset_path}", flush=True)
    print(f"normal labels   : {', '.join(normal_labels)}", flush=True)
    print(f"features        : {len(numeric_features)}", flush=True)
    print(
        f"network         : {len(numeric_features)} -> "
        f"{max(args.bottleneck_size * 3, min(32, len(numeric_features)))} -> "
        f"{args.bottleneck_size} -> "
        f"{max(args.bottleneck_size * 3, min(32, len(numeric_features)))} -> "
        f"{len(numeric_features)}",
        flush=True,
    )
    print(
        f"epochs/batch    : {args.epochs} / {args.batch_size} "
        f"(early-stop patience={args.patience})",
        flush=True,
    )
    print("=" * 78, flush=True)

    try:
        print("[verify] calculating dataset SHA-256 ...", flush=True)
        actual_sha256 = sha256_file(dataset_path)
        if actual_sha256 != expected_sha256:
            raise RuntimeError(
                "Dataset SHA-256 changed after profiling; re-profile before training"
            )
        print(f"[verify] dataset identity OK: {actual_sha256}", flush=True)

        def report(event: dict[str, Any]) -> None:
            if event["stage"] == "loading":
                print(
                    f"[load] chunk={event['chunk']:02d} "
                    f"rows={event['samplesSeen']:,} "
                    f"normal_seen={event['normalSeen']:,} "
                    f"attack_classes={event['attackLabelsSeen']}",
                    flush=True,
                )
            elif event["stage"] == "training":
                eta = format_seconds(float(event["etaSeconds"]))
                print(
                    f"[epoch {event['epoch']:02d}/{event['maxEpochs']:02d}] "
                    f"train_mse={event['trainLoss']:.6f} "
                    f"val_mse={event['validationLoss']:.6f} "
                    f"best={event['bestValidationLoss']:.6f} "
                    f"stale={event['staleEpochs']} eta={eta}",
                    flush=True,
                )
            update_progress(run_id, event)

        result = train_autoencoder(
            dataset_path,
            label_column=label_column,
            normal_labels=normal_labels,
            numeric_features=numeric_features,
            split=split,
            random_seed=args.random_seed,
            max_normal_rows=args.max_normal_rows,
            max_attack_rows=args.max_attack_rows,
            max_epochs=args.epochs,
            patience=args.patience,
            batch_size=args.batch_size,
            learning_rate=args.learning_rate,
            bottleneck_size=args.bottleneck_size,
            threshold_quantile=args.threshold_quantile,
            target_fpr=args.target_fpr,
            progress=report,
        )

        artifact_root = Path(settings.model_artifact_root).expanduser().resolve()
        artifact_path = artifact_root / "autoencoder" / run_id / "model.joblib"
        artifact_sha256, metadata_path = write_artifact(
            artifact_path,
            run_id=run_id,
            dataset=dataset_info,
            config=config,
            result=result,
        )
        model_id = f"MODEL-{run_id}"
        metrics = result["metrics"]
        with SessionLocal() as db:
            run = db.get(TrainingRun, run_id)
            if run is None:
                raise RuntimeError("Training run disappeared before completion")
            model = ModelVersion(
                id=model_id,
                name="Normal Traffic AutoEncoder",
                role="Unknown anomaly detection trained only on normal CICIDS2017 flows",
                version=f"ae-{run_id[-12:].lower()}",
                state="healthy",
                artifact_uri=str(artifact_path),
                feature_version=FEATURE_VERSION,
                metrics={
                    "latency_ms": metrics["test_predict_ms"]
                    / max(1, metrics["attack_test_samples"]),
                    "throughput_fps": metrics["throughput_fps"],
                    "quality_label": (
                        f"Attack recall @ normal q{args.threshold_quantile * 100:g}"
                    ),
                    "quality_value": metrics["recall"] * 100,
                    "training_run_id": run_id,
                    "dataset_id": args.dataset_id,
                    "evaluated_at": utc_now().isoformat(),
                },
                parameters={
                    "algorithm": ALGORITHM,
                    "framework": "pytorch-cpu",
                    "trainingRunId": run_id,
                    "datasetId": args.dataset_id,
                    "datasetSha256": expected_sha256,
                    "artifactSha256": artifact_sha256,
                    "metadataUri": str(metadata_path),
                    "runtimeVersions": result["runtime_versions"],
                    **config,
                },
            )
            db.merge(model)
            now = utc_now()
            run.model_id = model_id
            run.state = "succeeded"
            run.samples_seen = result["samples_seen"]
            run.samples_used = result["samples_used"]
            run.metrics = metrics
            run.config = {
                **run.config,
                "runtimeVersions": result["runtime_versions"],
                "progress": {"stage": "completed", "percent": 100},
            }
            run.artifact_uri = str(artifact_path)
            run.artifact_sha256 = artifact_sha256
            run.completed_at = now
            run.updated_at = now
            db.add(
                audit_event(
                    action="training.autoencoder.completed",
                    object_id=run_id,
                    outcome="completed",
                    after_state={
                        "modelId": model_id,
                        "threshold": metrics["threshold"],
                        "attackRecall": metrics["recall"],
                        "normalFalsePositiveRate": metrics["normal_false_positive_rate"],
                        "artifactSha256": artifact_sha256,
                    },
                    note="PyTorch CPU AutoEncoder artifact and independent attack evaluation were persisted.",
                )
            )
            db.commit()

        print("-" * 78, flush=True)
        print(
            f"[result] threshold={metrics['threshold']:.6f} "
            f"attack_recall={metrics['recall']:.4%} "
            f"normal_fpr={metrics['normal_false_positive_rate']:.4%} "
            f"AUROC={metrics['roc_auc']:.4f} "
            f"AUPRC={metrics['average_precision']:.4f}",
            flush=True,
        )
        print(f"[artifact] {artifact_path}", flush=True)
        print(f"[sha256]   {artifact_sha256}", flush=True)
        print(f"[complete] training run {run_id} succeeded", flush=True)
    except Exception as exc:
        fail_run(run_id, exc)
        print(f"[failed] {type(exc).__name__}: {exc}", file=sys.stderr, flush=True)
        raise


def update_progress(run_id: str, event: dict[str, Any]) -> None:
    with SessionLocal() as db:
        run = db.get(TrainingRun, run_id)
        if run is None or run.state != "running":
            return
        if event["stage"] == "loading":
            run.samples_seen = int(event["samplesSeen"])
        run.config = {**run.config, "progress": event}
        run.updated_at = utc_now()
        db.commit()


def fail_run(run_id: str, exc: Exception) -> None:
    with SessionLocal() as db:
        run = db.get(TrainingRun, run_id)
        if run is None:
            return
        now = utc_now()
        run.state = "failed"
        run.completed_at = now
        run.updated_at = now
        run.error_message = f"{type(exc).__name__}: {exc}"[:2_000]
        run.config = {
            **run.config,
            "progress": {"stage": "failed", "message": run.error_message},
        }
        db.add(
            audit_event(
                action="training.autoencoder.failed",
                object_id=run_id,
                outcome="failed",
                after_state={"state": "failed"},
                note=run.error_message,
            )
        )
        db.commit()


def audit_event(
    *,
    action: str,
    object_id: str,
    outcome: str,
    after_state: dict[str, object],
    note: str,
) -> AuditEvent:
    return AuditEvent(
        id=f"AUD-{uuid.uuid4().hex.upper()}",
        created_at=utc_now(),
        actor="pytorch-cpu-autoencoder",
        action=action,
        object_type="training_run",
        object_id=object_id,
        outcome=outcome,
        request_id="local-autoencoder-training",
        before_state=None,
        after_state=after_state,
        note=note,
    )


def format_seconds(value: float) -> str:
    seconds = max(0, int(value))
    if seconds < 60:
        return f"{seconds}s"
    return f"{seconds // 60}m{seconds % 60:02d}s"


if __name__ == "__main__":
    main()
