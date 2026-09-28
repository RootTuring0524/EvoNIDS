"""Train the HGB baseline and AutoEncoder on the ONLINE feature contract.

Why this script exists: the shipped models were trained on 41-42 CICIDS2017
columns (IAT statistics, TCP flag counts, packet length min/max/std) that a
Suricata EVE ``flow`` event does not contain, so online inference had to impute
~2/3 of the input space and online alerting stayed in ``shadow`` mode.

This script projects the dataset onto exactly the features
``app.domain.flow_features.project_cicids_row`` produces - the same function the
online builder is parity-tested against - so the resulting artifacts have
``featureContract = flow-online-v1`` and require **zero** imputation online.

Split protocol (ADR-0009): time-ordered, never random. Metrics are reported for
the held-out last window; class quotas cap the majority class so training is not
dominated by BENIGN. Calibration is fitted on the validation window and stored in
the artifact so ``online_detection`` can apply it.

Usage:
    python scripts/train_online_contract_models.py --max-rows 300000 --register
"""
from __future__ import annotations

import argparse
import json
import math
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.domain.flow_features import (  # noqa: E402
    ONLINE_FEATURE_VERSION,
    ONLINE_MODEL_FEATURES,
    project_cicids_row,
)
from app.services.drift_monitoring import build_histogram  # noqa: E402

DEFAULT_DATASET = Path("datasets/CICIDS2017/cicids2017_pcap_flow_full_v1.csv.gz")
BENIGN_LABEL = "BENIGN"
SOURCE_COLUMNS = (
    "capture_day",
    "start_time",
    "source_port",
    "destination_port",
    "protocol",
    "duration_us",
    "total_fwd_packets",
    "total_bwd_packets",
    "total_fwd_bytes",
    "total_bwd_bytes",
    "Label",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    parser.add_argument("--output-root", type=Path, default=Path("model-artifacts"))
    parser.add_argument("--max-rows", type=int, default=300_000, help="0 = every row (slow)")
    parser.add_argument("--validation-fraction", type=float, default=0.15)
    parser.add_argument("--test-fraction", type=float, default=0.15)
    parser.add_argument("--seed", type=int, default=20260909)
    parser.add_argument("--max-majority", type=int, default=120_000, help="cap for the BENIGN class")
    parser.add_argument("--cpu-threads", type=int, default=0)
    parser.add_argument("--register", action="store_true", help="register artifacts in the DB registry")
    parser.add_argument("--artifact-sha256", action="store_true", help="print artifact hashes")
    return parser.parse_args()


def log(message: str) -> None:
    print(f"[{datetime.now(timezone.utc).strftime('%H:%M:%S')}] {message}", flush=True)


def project_frame(frame: pd.DataFrame) -> pd.DataFrame:
    """Vectorised projection that must equal project_cicids_row row by row."""
    duration_seconds = frame["duration_us"].astype(float) / 1_000_000
    forward_packets = frame["total_fwd_packets"].astype(float)
    backward_packets = frame["total_bwd_packets"].astype(float)
    forward_bytes = frame["total_fwd_bytes"].astype(float)
    backward_bytes = frame["total_bwd_bytes"].astype(float)
    total_packets = forward_packets + backward_packets
    total_bytes = forward_bytes + backward_bytes
    forward_mean = np.where(forward_packets > 0, forward_bytes / forward_packets, 0.0)
    backward_mean = np.where(backward_packets > 0, backward_bytes / backward_packets, 0.0)
    largest = np.maximum(forward_mean, backward_mean)
    projected = pd.DataFrame(
        {
            "source_port": frame["source_port"].astype(float),
            "destination_port": frame["destination_port"].astype(float),
            "protocol_number": frame["protocol"].astype(float),
            "flow_duration_seconds": np.round(duration_seconds, 6),
            "forward_packet_count": forward_packets,
            "backward_packet_count": backward_packets,
            "forward_bytes": forward_bytes,
            "backward_bytes": backward_bytes,
            "packets_per_second": _ratio(total_packets, duration_seconds),
            "bytes_per_second": _ratio(total_bytes, duration_seconds),
            "average_packet_size": _ratio(total_bytes, total_packets),
            "forward_mean_packet_size": np.round(forward_mean, 6),
            "backward_mean_packet_size": np.round(backward_mean, 6),
            "packet_size_asymmetry": np.round(
                np.where(largest > 0, np.abs(forward_mean - backward_mean) / largest, 0.0), 6
            ),
            "byte_ratio": _ratio(forward_bytes, total_bytes),
            "packet_ratio": _ratio(forward_packets, total_packets),
        }
    )
    return projected[list(ONLINE_MODEL_FEATURES)]


def _ratio(numerator: pd.Series, denominator: pd.Series) -> pd.Series:
    safe = np.where(denominator > 0, denominator, np.nan)
    values = np.where(denominator > 0, numerator / safe, 0.0)
    return np.round(values, 6)


def verify_projection(frame: pd.DataFrame, projected: pd.DataFrame, *, sample: int = 200) -> None:
    """Guard the parity guarantee with a row-by-row check on a sample."""
    step = max(len(frame) // sample, 1)
    for position in range(0, len(frame), step):
        expected = project_cicids_row(frame.iloc[position].to_dict())
        for name in ONLINE_MODEL_FEATURES:
            if not math.isclose(
                float(expected[name]), float(projected.iloc[position][name]), rel_tol=0, abs_tol=1e-6
            ):
                raise SystemExit(
                    f"projection mismatch at row {position} for {name}: "
                    f"{expected[name]} != {projected.iloc[position][name]}"
                )
    log(f"projection parity verified on {len(range(0, len(frame), step))} sampled rows")


def load_dataset(path: Path, *, max_rows: int, chunk_rows: int = 250_000) -> pd.DataFrame:
    """Read the dataset with a spread over the WHOLE capture, not just the head.

    The CICIDS2017 file is ordered by capture day, so ``nrows`` would return only
    Monday BENIGN traffic and every metric computed on it would be meaningless.
    Instead each chunk contributes a bounded number of rows per label, which keeps
    every attack family and every day represented while staying fast.
    """
    log(f"reading {path} (max_rows={max_rows or 'all'}, chunk_rows={chunk_rows})")
    if max_rows <= 0:
        frame = pd.read_csv(path, usecols=list(SOURCE_COLUMNS))
        frame["start_time"] = pd.to_datetime(frame["start_time"], utc=True, errors="coerce")
        frame["Label"] = frame["Label"].astype(str).str.strip()
        frame = frame.dropna(subset=["start_time"])
        log(f"loaded {len(frame):,} rows, {frame['Label'].nunique()} labels")
        return frame.sort_values("start_time").reset_index(drop=True)

    per_label_budget = max(max_rows // 16, 2_000)
    chunks: list[pd.DataFrame] = []
    scanned = 0
    for chunk in pd.read_csv(path, usecols=list(SOURCE_COLUMNS), chunksize=chunk_rows):
        scanned += len(chunk)
        chunk["start_time"] = pd.to_datetime(chunk["start_time"], utc=True, errors="coerce")
        chunk["Label"] = chunk["Label"].astype(str).str.strip()
        chunk = chunk.dropna(subset=["start_time"])
        pieces = []
        for _, group in chunk.groupby("Label", sort=False):
            take = min(len(group), per_label_budget)
            pieces.append(group.sample(n=take, random_state=7) if len(group) > take else group)
        if pieces:
            chunks.append(pd.concat(pieces))
    frame = pd.concat(chunks).sort_values("start_time").reset_index(drop=True)
    log(
        f"loaded {len(frame):,} rows from {scanned:,} scanned, {frame['Label'].nunique()} labels, "
        f"{frame['capture_day'].nunique()} capture days"
    )
    return frame


def split_time_ordered(
    frame: pd.DataFrame, *, validation_fraction: float, test_fraction: float
) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    total = len(frame)
    test_size = int(total * test_fraction)
    validation_size = int(total * validation_fraction)
    train_end = total - test_size - validation_size
    train = frame.iloc[:train_end]
    validation = frame.iloc[train_end : train_end + validation_size]
    test = frame.iloc[train_end + validation_size :]
    return train, validation, test


def cap_majority(frame: pd.DataFrame, *, label_column: str, cap: int, seed: int) -> pd.DataFrame:
    if cap <= 0:
        return frame
    counts = frame[label_column].value_counts()
    if counts.empty:
        return frame
    majority_label = counts.idxmax()
    majority = frame[frame[label_column] == majority_label]
    if len(majority) <= cap:
        return frame
    sampled = majority.sample(n=cap, random_state=seed)
    rest = frame[frame[label_column] != majority_label]
    return pd.concat([sampled, rest]).sort_values("start_time").reset_index(drop=True)


def fit_baseline(
    train: pd.DataFrame, validation: pd.DataFrame, test: pd.DataFrame, *, seed: int
) -> dict[str, Any]:
    from sklearn.ensemble import HistGradientBoostingClassifier
    from sklearn.impute import SimpleImputer
    from sklearn.isotonic import IsotonicRegression
    from sklearn.metrics import (
        accuracy_score,
        average_precision_score,
        balanced_accuracy_score,
        confusion_matrix,
        f1_score,
        precision_recall_fscore_support,
        roc_auc_score,
    )
    from sklearn.pipeline import Pipeline

    features = list(ONLINE_MODEL_FEATURES)
    train_x, train_y = train[features], train["Label"].to_numpy()
    validation_x, validation_y = validation[features], validation["Label"].to_numpy()
    test_x, test_y = test[features], test["Label"].to_numpy()
    pipeline = Pipeline(
        [
            ("imputer", SimpleImputer(strategy="median")),
            (
                "model",
                HistGradientBoostingClassifier(
                    random_state=seed, max_iter=200, learning_rate=0.1, early_stopping=True
                ),
            ),
        ]
    )
    started = time.perf_counter()
    pipeline.fit(train_x, train_y)
    fit_seconds = time.perf_counter() - started
    classes = [str(value) for value in pipeline.classes_]
    benign_index = classes.index(BENIGN_LABEL) if BENIGN_LABEL in classes else None

    test_probabilities = pipeline.predict_proba(test_x)
    test_prediction = pipeline.predict(test_x)
    risk = (
        1 - test_probabilities[:, benign_index] if benign_index is not None else test_probabilities.max(axis=1)
    )
    binary_true = (test_y != BENIGN_LABEL).astype(int)
    single_class_test = bool(binary_true.min() == binary_true.max())
    metrics: dict[str, Any] = {
        # A single-class test window makes accuracy/F1 meaningless; report them
        # as null instead of a perfect 1.0 that would be a fabricated result.
        "accuracy": None
        if single_class_test
        else round(float(accuracy_score(test_y, test_prediction)), 6),
        "balanced_accuracy": None
        if single_class_test
        else round(float(balanced_accuracy_score(test_y, test_prediction)), 6),
        "macro_f1": None
        if single_class_test
        else round(float(f1_score(test_y, test_prediction, average="macro", zero_division=0)), 6),
        "weighted_f1": None
        if single_class_test
        else round(float(f1_score(test_y, test_prediction, average="weighted", zero_division=0)), 6),
        "train_rows": int(len(train)),
        "validation_rows": int(len(validation)),
        "test_rows": int(len(test)),
        "fit_seconds": round(fit_seconds, 3),
        "numeric_features": features,
        "singleClassTestSet": single_class_test,
    }
    if not single_class_test:
        metrics["ovr_roc_auc"] = round(float(roc_auc_score(binary_true, risk)), 6)
        metrics["ovr_pr_auc"] = round(float(average_precision_score(binary_true, risk)), 6)
    precision, recall, f1, support = precision_recall_fscore_support(
        test_y, test_prediction, labels=classes, zero_division=0
    )
    metrics["per_class"] = {
        classes[index]: {
            "precision": round(float(precision[index]), 6),
            "recall": round(float(recall[index]), 6),
            "f1": round(float(f1[index]), 6),
            "support": int(support[index]),
        }
        for index in range(len(classes))
    }
    metrics["confusion_matrix"] = confusion_matrix(test_y, test_prediction, labels=classes).tolist()
    metrics["classes"] = classes

    # Calibration on the validation window: map the raw risk onto observed
    # attack frequency. IsotonicRegression.predict is what online_detection calls.
    validation_risk = (
        1 - pipeline.predict_proba(validation_x)[:, benign_index]
        if benign_index is not None
        else pipeline.predict_proba(validation_x).max(axis=1)
    )
    validation_binary = (validation_y != BENIGN_LABEL).astype(int)
    calibrator = IsotonicRegression(out_of_bounds="clip", y_min=0.0, y_max=1.0)
    if validation_binary.min() != validation_binary.max():
        calibrator.fit(validation_risk, validation_binary)
    else:
        calibrator = None  # type: ignore[assignment]
    reference = reference_distribution(train[features])
    return {
        "pipeline": pipeline,
        "calibrator": calibrator,
        "metrics": metrics,
        "reference": reference,
        "classes": classes,
    }


def reference_distribution(frame: pd.DataFrame) -> dict[str, Any]:
    """Per-feature summary used by drift monitoring (no raw rows are stored).

    The histogram (10 equal-width bins with their observed shares) is what PSI is
    computed against online; without it drift would be unmeasurable.
    """
    summary: dict[str, Any] = {}
    for column in frame.columns:
        series = pd.to_numeric(frame[column], errors="coerce").dropna()
        if series.empty:
            continue
        summary[column] = {
            "mean": float(series.mean()),
            "std": float(series.std(ddof=0)),
            "min": float(series.min()),
            "max": float(series.max()),
            "quantiles": {str(q): float(series.quantile(q)) for q in (0.1, 0.25, 0.5, 0.75, 0.9)},
            "histogram": build_histogram([float(value) for value in series]),
        }
    return summary





def train_autoencoder(
    train: pd.DataFrame, validation: pd.DataFrame, test: pd.DataFrame, *, seed: int
) -> dict[str, Any]:
    import torch
    from sklearn.preprocessing import StandardScaler

    from app.services.autoencoder import (
        TabularAutoEncoder,
        reconstruction_errors,
    )

    torch.manual_seed(seed)
    features = list(ONLINE_MODEL_FEATURES)
    normal_train = train[train["Label"] == BENIGN_LABEL][features]
    normal_validation = validation[validation["Label"] == BENIGN_LABEL][features]
    scaler = StandardScaler().fit(normal_train.to_numpy(dtype=float))
    train_values = np.clip(scaler.transform(normal_train.to_numpy(dtype=float)), -8, 8).astype(np.float32)
    validation_values = np.clip(
        scaler.transform(normal_validation.to_numpy(dtype=float)), -8, 8
    ).astype(np.float32)
    model = TabularAutoEncoder(
        input_size=len(features), shoulder_size=32, bottleneck_size=8
    )
    optimizer = torch.optim.Adam(model.parameters(), lr=1e-3)
    loss_function = torch.nn.MSELoss()
    tensor = torch.from_numpy(train_values)
    batch_size = 1024
    epochs = 8
    started = time.perf_counter()
    for epoch in range(epochs):
        permutation = torch.randperm(len(tensor))
        total_loss = 0.0
        for start in range(0, len(tensor), batch_size):
            batch = tensor[permutation[start : start + batch_size]]
            optimizer.zero_grad()
            output = model(batch)
            loss = loss_function(output, batch)
            loss.backward()
            optimizer.step()
            total_loss += float(loss.item()) * len(batch)
        log(f"  AE epoch {epoch + 1}/{epochs} loss={total_loss / max(len(tensor), 1):.6f}")
    fit_seconds = time.perf_counter() - started
    with torch.inference_mode():
        validation_errors, _ = reconstruction_errors(model, validation_values, np=np)
    threshold = float(np.quantile(validation_errors, 0.95)) if len(validation_errors) else 1.0
    test_values = np.clip(scaler.transform(test[features].to_numpy(dtype=float)), -8, 8).astype(np.float32)
    with torch.inference_mode():
        test_errors, _ = reconstruction_errors(model, test_values, np=np)
    scores = 1 - np.exp(-math.log(2) * test_errors / max(threshold, 1e-9))
    binary_true = (test["Label"] != BENIGN_LABEL).astype(int).to_numpy()
    from sklearn.metrics import average_precision_score, roc_auc_score

    metrics: dict[str, Any] = {
        "threshold": threshold,
        "threshold_quantile": 0.95,
        "normal_validation_error_mean": float(validation_errors.mean()) if len(validation_errors) else None,
        "normal_test_error_mean": float(test_errors[binary_true == 0].mean())
        if (binary_true == 0).any()
        else None,
        "attack_test_error_mean": float(test_errors[binary_true == 1].mean())
        if (binary_true == 1).any()
        else None,
        "fit_seconds": round(fit_seconds, 3),
        "numeric_features": features,
        "train_samples": int(len(train_values)),
        "validation_samples": int(len(validation_values)),
        "test_samples": int(len(test_values)),
    }
    if binary_true.min() != binary_true.max():
        metrics["roc_auc"] = round(float(roc_auc_score(binary_true, scores)), 6)
        metrics["average_precision"] = round(float(average_precision_score(binary_true, scores)), 6)
        exceeds = test_errors > threshold
        metrics["recall_at_threshold"] = round(float((exceeds & (binary_true == 1)).sum() / binary_true.sum()), 6)
        normal_mask = binary_true == 0
        metrics["normal_false_positive_rate"] = (
            round(float(exceeds[normal_mask].mean()), 6) if normal_mask.any() else None
        )
    reference = reference_distribution(train[features])
    return {
        "model": model,
        "scaler": scaler,
        "threshold": threshold,
        "metrics": metrics,
        "reference": reference,
    }


def write_baseline_artifact(
    root: Path, run_id: str, result: dict[str, Any], *, dataset: dict[str, Any]
) -> tuple[str, Path]:
    import joblib

    path = root / "online-baseline" / run_id / "model.joblib"
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "formatVersion": 1,
        "task": "known_attack_classification_baseline",
        "algorithm": "hist_gradient_boosting",
        "featureVersion": ONLINE_FEATURE_VERSION,
        "trainingRunId": run_id,
        "dataset": dataset,
        "runtimeVersions": runtime_versions(),
        "pipeline": result["pipeline"],
        "calibration": result["calibrator"],
        "metrics": result["metrics"],
        "referenceDistribution": result["reference"],
    }
    joblib.dump(payload, path)
    metadata = {key: value for key, value in payload.items() if key != "pipeline"}
    metadata.pop("calibration", None)
    (path.parent / "metadata.json").write_text(
        json.dumps(metadata, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    return sha256(path), path


def write_autoencoder_artifact(
    root: Path, run_id: str, result: dict[str, Any], *, dataset: dict[str, Any]
) -> tuple[str, Path]:
    import joblib

    path = root / "online-autoencoder" / run_id / "model.joblib"
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "formatVersion": 1,
        "task": "unknown_anomaly_detection",
        "algorithm": "mlp_autoencoder",
        "featureVersion": ONLINE_FEATURE_VERSION,
        "trainingRunId": run_id,
        "dataset": dataset,
        "runtimeVersions": runtime_versions(),
        "numericFeatures": list(ONLINE_MODEL_FEATURES),
        "featureBaseline": {
            name: float(value["mean"])
            for name, value in result["reference"].items()
            if isinstance(value, dict)
        },
        "threshold": result["threshold"],
        "metrics": result["metrics"],
        "preprocessor": result["scaler"],
        "architecture": {
            "inputSize": len(ONLINE_MODEL_FEATURES),
            "shoulderSize": 32,
            "bottleneckSize": 8,
        },
        "modelState": result["model"].state_dict(),
        "referenceDistribution": result["reference"],
    }
    joblib.dump(payload, path)
    metadata = {key: value for key, value in payload.items() if key not in {"modelState", "preprocessor"}}
    (path.parent / "metadata.json").write_text(
        json.dumps(metadata, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    return sha256(path), path


def runtime_versions() -> dict[str, str]:
    import sklearn
    import torch

    return {
        "python": sys.version.split()[0],
        "numpy": np.__version__,
        "pandas": pd.__version__,
        "scikit-learn": sklearn.__version__,
        "torch": torch.__version__,
    }


def sha256(path: Path) -> str:
    import hashlib

    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def register_artifacts(
    *,
    dataset_id: str,
    dataset_sha256: str,
    baseline: tuple[str, Path, dict[str, Any]],
    autoencoder: tuple[str, Path, dict[str, Any]],
) -> dict[str, str]:

    from app.db.base import Base
    from app.db.models import DatasetAsset, ModelVersion, TrainingRun
    from app.db.session import SessionLocal, engine

    Base.metadata.create_all(engine)
    registered: dict[str, str] = {}
    with SessionLocal() as db:
        dataset = db.get(DatasetAsset, dataset_id)
        if dataset is None:
            dataset = DatasetAsset(
                id=dataset_id,
                name="CICIDS2017 (online contract projection)",
                version="online-v1",
                relative_path="CICIDS2017/cicids2017_pcap_flow_full_v1.csv.gz",
                format="csv.gz",
                state="ready",
                sha256=dataset_sha256,
            )
            db.add(dataset)
        for task, (artifact_sha, path, metrics) in (
            ("known_attack_classification_baseline", baseline),
            ("unknown_anomaly_detection", autoencoder),
        ):
            run_id = f"TRN-ONLINE-{task.split('_')[0].upper()}-{artifact_sha[:12].upper()}"
            model_id = f"MODEL-{run_id}"
            if db.get(TrainingRun, run_id) is None:
                db.add(
                    TrainingRun(
                        id=run_id,
                        dataset_id=dataset_id,
                        model_id=model_id,
                        task=task,
                        algorithm="hist_gradient_boosting"
                        if task == "known_attack_classification_baseline"
                        else "mlp_autoencoder",
                        state="succeeded",
                        requested_by="online-contract-training",
                        dataset_sha256=dataset_sha256,
                        feature_version=ONLINE_FEATURE_VERSION,
                        completed_at=datetime.now(timezone.utc),
                        artifact_uri=str(path),
                        artifact_sha256=artifact_sha,
                        metrics=metrics,
                    )
                )
            if db.get(ModelVersion, model_id) is None:
                db.add(
                    ModelVersion(
                        id=model_id,
                        name="Known Attack CPU Baseline (online contract)"
                        if task == "known_attack_classification_baseline"
                        else "Normal Traffic AutoEncoder (online contract)",
                        role=task,
                        version=f"online-{artifact_sha[:8]}",
                        state="healthy",
                        artifact_uri=str(path),
                        feature_version=ONLINE_FEATURE_VERSION,
                        metrics=metrics,
                        parameters={
                            "featureContract": ONLINE_FEATURE_VERSION,
                            "artifactSha256": artifact_sha,
                            "trainingRunId": run_id,
                        },
                    )
                )
            registered[task] = model_id
        db.commit()
    return registered


def main() -> int:
    args = parse_args()
    if args.cpu_threads > 0:
        import torch

        torch.set_num_threads(args.cpu_threads)
    dataset_path = args.dataset.resolve()
    if not dataset_path.is_file():
        raise SystemExit(f"dataset not found: {dataset_path}")
    dataset_sha = sha256(dataset_path)
    log(f"dataset sha256={dataset_sha}")

    frame = load_dataset(dataset_path, max_rows=args.max_rows)
    projected = project_frame(frame)
    verify_projection(frame, projected)
    projected = projected.assign(Label=frame["Label"].to_numpy(), start_time=frame["start_time"].to_numpy())
    log(f"label distribution: {dict(Counter(frame['Label']).most_common(8))}")

    train, validation, test = split_time_ordered(
        projected,
        validation_fraction=args.validation_fraction,
        test_fraction=args.test_fraction,
    )
    train = cap_majority(train, label_column="Label", cap=args.max_majority, seed=args.seed)
    log(
        f"split: train={len(train):,} validation={len(validation):,} test={len(test):,} "
        f"(time-ordered; train ends {train['start_time'].max()}, test starts {test['start_time'].min()})"
    )

    log("training HGB baseline on the online contract")
    baseline_result = fit_baseline(train, validation, test, seed=args.seed)
    log(f"baseline metrics: {json.dumps({k: v for k, v in baseline_result['metrics'].items() if not isinstance(v, (dict, list))}, ensure_ascii=False)}")

    log("training AutoEncoder on normal traffic")
    autoencoder_result = train_autoencoder(train, validation, test, seed=args.seed)
    log(f"autoencoder metrics: {json.dumps({k: v for k, v in autoencoder_result['metrics'].items() if not isinstance(v, (dict, list))}, ensure_ascii=False)}")

    dataset_info: dict[str, Any] = {
        "id": "DS-CIC-2017-PCAP-FULL",
        "sha256": dataset_sha,
        "rows": int(len(frame)),
        "featureContract": ONLINE_FEATURE_VERSION,
        "split": "time_ordered",
    }
    run_suffix = dataset_sha[:12].upper()
    baseline_sha, baseline_path = write_baseline_artifact(
        args.output_root, f"TRN-ONLINE-BASE-{run_suffix}", baseline_result, dataset=dataset_info
    )
    autoencoder_sha, autoencoder_path = write_autoencoder_artifact(
        args.output_root, f"TRN-ONLINE-AE-{run_suffix}", autoencoder_result, dataset=dataset_info
    )
    log(f"baseline artifact {baseline_path} sha256={baseline_sha}")
    log(f"autoencoder artifact {autoencoder_path} sha256={autoencoder_sha}")

    if args.register:
        registered = register_artifacts(
            dataset_id=dataset_info["id"],
            dataset_sha256=dataset_sha,
            baseline=(baseline_sha, baseline_path, baseline_result["metrics"]),
            autoencoder=(autoencoder_sha, autoencoder_path, autoencoder_result["metrics"]),
        )
        log(f"registered: {json.dumps(registered, ensure_ascii=False)}")
    else:
        log("not registered (pass --register to write the model registry)")

    summary = {
        "dataset": dataset_info,
        "split": {
            "strategy": "time_ordered",
            "trainRows": int(len(train)),
            "validationRows": int(len(validation)),
            "testRows": int(len(test)),
            "trainEnd": str(train["start_time"].max()),
            "testStart": str(test["start_time"].min()),
        },
        "baseline": baseline_result["metrics"],
        "autoencoder": autoencoder_result["metrics"],
        "artifacts": {
            "baseline": {"path": str(baseline_path), "sha256": baseline_sha},
            "autoencoder": {"path": str(autoencoder_path), "sha256": autoencoder_sha},
        },
        "featureContract": ONLINE_FEATURE_VERSION,
        "generatedAt": datetime.now(timezone.utc).isoformat(),
    }
    summary_path = args.output_root / "online-contract-latest-summary.json"
    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    log(f"summary written to {summary_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
