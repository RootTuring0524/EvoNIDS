from __future__ import annotations

import copy
import gzip
import hashlib
import json
import math
import os
import platform
import time
from collections import Counter
from pathlib import Path
from typing import Any, Callable


TASK = "unknown_anomaly_detection"
ALGORITHM = "mlp_autoencoder"
FEATURE_VERSION = "tabular-autoencoder-v1"

ProgressCallback = Callable[[dict[str, Any]], None]


def train_autoencoder(
    path: Path,
    *,
    label_column: str,
    normal_labels: list[str],
    numeric_features: list[str],
    split: dict[str, int],
    random_seed: int,
    max_normal_rows: int,
    max_attack_rows: int,
    max_epochs: int,
    patience: int,
    batch_size: int,
    learning_rate: float,
    bottleneck_size: int,
    threshold_quantile: float,
    target_fpr: float | None = None,
    progress: ProgressCallback | None = None,
) -> dict[str, Any]:
    import joblib
    import numpy as np
    import pandas as pd
    import sklearn
    from sklearn.impute import SimpleImputer
    from sklearn.metrics import (
        accuracy_score,
        average_precision_score,
        confusion_matrix,
        f1_score,
        precision_score,
        recall_score,
        roc_auc_score,
    )
    from sklearn.model_selection import train_test_split
    from sklearn.pipeline import Pipeline
    from sklearn.preprocessing import RobustScaler
    import torch
    from torch import nn
    from torch.utils.data import DataLoader, TensorDataset

    if not numeric_features:
        raise ValueError("AutoEncoder requires at least one numeric feature")
    if not 0.9 <= threshold_quantile < 1:
        raise ValueError("threshold_quantile must be in [0.9, 1)")
    if bottleneck_size >= len(numeric_features):
        raise ValueError("bottleneck_size must be smaller than the input feature count")

    started = time.perf_counter()
    normal_frame, attack_frame, attack_labels, samples_seen = _load_training_frames(
        path,
        label_column=label_column,
        normal_labels=normal_labels,
        numeric_features=numeric_features,
        max_normal_rows=max_normal_rows,
        max_attack_rows=max_attack_rows,
        random_seed=random_seed,
        progress=progress,
    )
    if len(normal_frame) < 1_000:
        raise ValueError("At least 1,000 normal flows are required for AutoEncoder training")
    if len(attack_frame) < 100:
        raise ValueError("At least 100 attack flows are required for an independent evaluation")

    test_fraction = float(split["test"]) / 100
    validation_fraction = float(split["validation"]) / 100
    if test_fraction <= 0 or validation_fraction <= 0 or float(split["train"]) <= 0:
        raise ValueError("Training requires non-zero train, validation and test percentages")
    normal_train_validation, normal_test = train_test_split(
        normal_frame,
        test_size=test_fraction,
        random_state=random_seed,
    )
    relative_validation = validation_fraction / (1 - test_fraction)
    normal_train, normal_validation = train_test_split(
        normal_train_validation,
        test_size=relative_validation,
        random_state=random_seed + 1,
    )

    preprocessor = Pipeline(
        steps=[
            ("imputer", SimpleImputer(strategy="median")),
            ("scaler", RobustScaler(quantile_range=(5.0, 95.0))),
        ]
    )
    train_x = _clip_float32(preprocessor.fit_transform(normal_train), np=np)
    validation_x = _clip_float32(preprocessor.transform(normal_validation), np=np)
    normal_test_x = _clip_float32(preprocessor.transform(normal_test), np=np)
    attack_test_x = _clip_float32(preprocessor.transform(attack_frame), np=np)

    input_size = len(numeric_features)
    shoulder = max(bottleneck_size * 3, min(32, input_size))
    torch.manual_seed(random_seed)
    torch.set_num_threads(max(1, min(12, (os.cpu_count() or 4) - 2)))
    model = TabularAutoEncoder(
        input_size=input_size,
        shoulder_size=shoulder,
        bottleneck_size=bottleneck_size,
    )
    optimizer = torch.optim.AdamW(
        model.parameters(),
        lr=learning_rate,
        weight_decay=1e-4,
    )
    criterion = nn.MSELoss()
    generator = torch.Generator().manual_seed(random_seed)
    train_loader = DataLoader(
        TensorDataset(torch.from_numpy(train_x)),
        batch_size=min(batch_size, len(train_x)),
        shuffle=True,
        generator=generator,
        num_workers=0,
    )
    validation_tensor = torch.from_numpy(validation_x)
    best_state: dict[str, Any] | None = None
    best_validation_loss = math.inf
    best_epoch = 0
    stale_epochs = 0
    epoch_history: list[dict[str, float | int]] = []
    epoch_started = time.perf_counter()
    for epoch in range(1, max_epochs + 1):
        model.train()
        running_loss = 0.0
        for (batch,) in train_loader:
            optimizer.zero_grad(set_to_none=True)
            reconstructed = model(batch)
            loss = criterion(reconstructed, batch)
            loss.backward()
            optimizer.step()
            running_loss += float(loss.detach()) * len(batch)
        train_loss = running_loss / len(train_x)
        model.eval()
        with torch.inference_mode():
            validation_prediction = model(validation_tensor)
            validation_loss = float(criterion(validation_prediction, validation_tensor))
        improved = validation_loss < best_validation_loss - 1e-6
        if improved:
            best_validation_loss = validation_loss
            best_epoch = epoch
            best_state = copy.deepcopy(model.state_dict())
            stale_epochs = 0
        else:
            stale_epochs += 1
        elapsed = time.perf_counter() - epoch_started
        average_epoch_seconds = elapsed / epoch
        eta_seconds = average_epoch_seconds * max(0, max_epochs - epoch)
        epoch_record = {
            "epoch": epoch,
            "train_loss": train_loss,
            "validation_loss": validation_loss,
            "best_validation_loss": best_validation_loss,
            "eta_seconds": eta_seconds,
        }
        epoch_history.append(epoch_record)
        if progress is not None:
            progress(
                {
                    "stage": "training",
                    "epoch": epoch,
                    "maxEpochs": max_epochs,
                    "trainLoss": train_loss,
                    "validationLoss": validation_loss,
                    "bestValidationLoss": best_validation_loss,
                    "etaSeconds": eta_seconds,
                    "staleEpochs": stale_epochs,
                }
            )
        if stale_epochs >= patience:
            break

    if best_state is None:
        raise RuntimeError("AutoEncoder did not produce a valid epoch")
    model.load_state_dict(best_state)
    model.eval()

    validation_errors, _ = reconstruction_errors(model, validation_x, np=np)
    if target_fpr is not None:
        if not 0 < target_fpr < 1:
            raise ValueError("target_fpr must be in (0, 1)")
        threshold = float(np.quantile(validation_errors, 1.0 - target_fpr))
        effective_quantile = round(1.0 - target_fpr, 6)
    else:
        threshold = float(np.quantile(validation_errors, threshold_quantile))
        effective_quantile = threshold_quantile
    normal_errors, normal_prediction = reconstruction_errors(model, normal_test_x, np=np)
    prediction_started = time.perf_counter()
    attack_errors, attack_prediction = reconstruction_errors(model, attack_test_x, np=np)
    prediction_seconds = time.perf_counter() - prediction_started

    actual = np.concatenate(
        (np.zeros(len(normal_errors), dtype=np.int8), np.ones(len(attack_errors), dtype=np.int8))
    )
    errors = np.concatenate((normal_errors, attack_errors))
    predicted = (errors > threshold).astype(np.int8)
    operating_points = []
    if validation_errors.size:
        for point_fpr in (0.005, 0.01, 0.02, 0.05, 0.10):
            point_threshold = float(np.quantile(validation_errors, 1.0 - point_fpr))
            point_predicted = (errors > point_threshold).astype(np.int8)
            operating_points.append(
                {
                    "target_fpr": point_fpr,
                    "threshold": point_threshold,
                    "attack_recall": float(np.mean(attack_errors > point_threshold)),
                    "precision": float(precision_score(actual, point_predicted, zero_division=0)),
                    "f1": float(f1_score(actual, point_predicted, zero_division=0)),
                }
            )
    matrix = confusion_matrix(actual, predicted, labels=[0, 1]).astype(int)
    tn, fp, fn, tp = matrix.ravel()
    label_array = np.asarray(attack_labels, dtype=object)
    per_attack_class = []
    for label in sorted(set(attack_labels)):
        selected = label_array == label
        class_errors = attack_errors[selected]
        per_attack_class.append(
            {
                "label": label,
                "support": int(selected.sum()),
                "detected": int((class_errors > threshold).sum()),
                "recall": float((class_errors > threshold).mean()),
                "median_error": float(np.median(class_errors)),
            }
        )

    feature_baseline = {
        feature: float(value)
        for feature, value in zip(numeric_features, normal_train.median(numeric_only=True), strict=True)
    }
    train_seconds = time.perf_counter() - started
    metrics = {
        "accuracy": float(accuracy_score(actual, predicted)),
        "precision": float(precision_score(actual, predicted, zero_division=0)),
        "recall": float(recall_score(actual, predicted, zero_division=0)),
        "f1": float(f1_score(actual, predicted, zero_division=0)),
        "roc_auc": float(roc_auc_score(actual, errors)),
        "average_precision": float(average_precision_score(actual, errors)),
        "normal_false_positive_rate": float(fp / (fp + tn)) if fp + tn else 0.0,
        "threshold": threshold,
        "threshold_quantile": effective_quantile,
        "target_fpr": target_fpr,
        "operating_points": operating_points,
        "normal_validation_error_mean": float(validation_errors.mean()),
        "normal_validation_error_std": float(validation_errors.std()),
        "normal_test_error_mean": float(normal_errors.mean()),
        "attack_test_error_mean": float(attack_errors.mean()),
        "train_samples": int(len(normal_train)),
        "validation_samples": int(len(normal_validation)),
        "normal_test_samples": int(len(normal_test)),
        "attack_test_samples": int(len(attack_frame)),
        "feature_count": len(numeric_features),
        "numeric_features": numeric_features,
        "best_epoch": best_epoch,
        "epochs_completed": len(epoch_history),
        "epoch_history": epoch_history,
        "confusion_matrix": matrix.tolist(),
        "per_attack_class": per_attack_class,
        "train_seconds": train_seconds,
        "test_predict_ms": prediction_seconds * 1000,
        "throughput_fps": float(len(attack_frame) / prediction_seconds)
        if prediction_seconds > 0
        else 0.0,
    }
    return {
        "preprocessor": preprocessor,
        "model": model,
        "threshold": threshold,
        "feature_baseline": feature_baseline,
        "metrics": metrics,
        "samples_seen": samples_seen,
        "samples_used": int(len(normal_frame) + len(attack_frame)),
        "normal_samples_used": int(len(normal_frame)),
        "attack_samples_used": int(len(attack_frame)),
        "runtime_versions": {
            "python": platform.python_version(),
            "numpy": np.__version__,
            "pandas": pd.__version__,
            "scikitLearn": sklearn.__version__,
            "joblib": joblib.__version__,
            "torch": torch.__version__,
        },
        "architecture": {
            "inputSize": input_size,
            "shoulderSize": shoulder,
            "bottleneckSize": bottleneck_size,
        },
        "model_state": {key: value.detach().cpu() for key, value in model.state_dict().items()},
        "normal_test_preview": normal_prediction[:5].astype(float).tolist(),
        "attack_test_preview": attack_prediction[:5].astype(float).tolist(),
    }


def score_frame(artifact: dict[str, Any], frame: Any) -> dict[str, Any]:
    import numpy as np
    import pandas as pd

    features = list(artifact["numericFeatures"])
    numeric = pd.DataFrame(
        {
            column: pd.to_numeric(frame[column], errors="coerce")
            if column in frame
            else np.nan
            for column in features
        }
    )
    transformed = _clip_float32(artifact["preprocessor"].transform(numeric), np=np)
    model = model_from_artifact(artifact)
    errors, prediction = reconstruction_errors(model, transformed, np=np)
    threshold = float(artifact["threshold"])
    scores = 1 - np.exp(-math.log(2) * errors / max(threshold, np.finfo(float).eps))
    feature_errors = np.square(transformed - prediction)
    return {
        "errors": errors,
        "scores": np.clip(scores, 0, 1),
        "exceeds": errors > threshold,
        "featureErrors": feature_errors,
        "transformed": transformed,
    }


def reconstruction_errors(model: Any, values: Any, *, np: Any) -> tuple[Any, Any]:
    prediction = _torch_predict(model, values)
    errors = np.mean(np.square(values - prediction), axis=1)
    return errors, prediction


def model_from_artifact(artifact: dict[str, Any]) -> Any:
    architecture = artifact["architecture"]
    model = TabularAutoEncoder(
        input_size=int(architecture["inputSize"]),
        shoulder_size=int(architecture["shoulderSize"]),
        bottleneck_size=int(architecture["bottleneckSize"]),
    )
    model.load_state_dict(artifact["modelState"])
    model.eval()
    return model


def write_artifact(
    artifact_path: Path,
    *,
    run_id: str,
    dataset: dict[str, Any],
    config: dict[str, Any],
    result: dict[str, Any],
) -> tuple[str, Path]:
    import joblib

    artifact_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = artifact_path.with_suffix(".joblib.tmp")
    metadata_path = artifact_path.with_name("metadata.json")
    payload = {
        "formatVersion": 1,
        "task": TASK,
        "algorithm": ALGORITHM,
        "featureVersion": FEATURE_VERSION,
        "trainingRunId": run_id,
        "dataset": dataset,
        "config": config,
        "runtimeVersions": result["runtime_versions"],
        "numericFeatures": result["metrics"]["numeric_features"],
        "featureBaseline": result["feature_baseline"],
        "threshold": result["threshold"],
        "metrics": result["metrics"],
        "preprocessor": result["preprocessor"],
        "architecture": result["architecture"],
        "modelState": result["model_state"],
    }
    joblib.dump(payload, temporary, compress=3)
    temporary.replace(artifact_path)
    artifact_sha256 = sha256_file(artifact_path)
    metadata_payload = {
        key: value for key, value in payload.items() if key not in {"preprocessor", "modelState"}
    } | {
        "artifactSha256": artifact_sha256,
    }
    metadata_path.write_text(
        json.dumps(metadata_payload, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return artifact_sha256, metadata_path


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load_training_frames(
    path: Path,
    *,
    label_column: str,
    normal_labels: list[str],
    numeric_features: list[str],
    max_normal_rows: int,
    max_attack_rows: int,
    random_seed: int,
    progress: ProgressCallback | None,
) -> tuple[Any, Any, list[str], int]:
    import numpy as np
    import pandas as pd

    rng = np.random.default_rng(random_seed)
    normal_parts: list[Any] = []
    attack_reservoirs: dict[str, Any] = {}
    samples_seen = 0
    normal_seen = 0
    attack_seen: Counter[str] = Counter()
    normal_set = {value.strip() for value in normal_labels}
    usecols = [*numeric_features, label_column]

    with _open_text(path) as handle:
        reader = pd.read_csv(
            handle,
            usecols=usecols,
            chunksize=100_000,
            low_memory=False,
        )
        for chunk_index, chunk in enumerate(reader, start=1):
            chunk.columns = [str(value).strip() for value in chunk.columns]
            labels = chunk[label_column].astype("string").str.strip()
            numeric = chunk[numeric_features].apply(pd.to_numeric, errors="coerce")
            normal_mask = labels.isin(normal_set)
            normal_chunk = numeric.loc[normal_mask]
            normal_seen += len(normal_chunk)
            if len(normal_chunk):
                normal_chunk = normal_chunk.copy()
                normal_chunk["__priority"] = rng.random(len(normal_chunk))
                normal_parts.append(normal_chunk)
                combined = pd.concat(normal_parts, ignore_index=True)
                if len(combined) > max_normal_rows:
                    combined = combined.nsmallest(max_normal_rows, "__priority")
                normal_parts = [combined]

            attack_labels = labels.loc[~normal_mask]
            for label, indices in attack_labels.groupby(attack_labels, dropna=True).groups.items():
                label_text = str(label)
                if not label_text or label_text == "<NA>":
                    continue
                attack_seen[label_text] += len(indices)
                candidate = numeric.loc[indices].copy()
                candidate["__label"] = label_text
                candidate["__priority"] = rng.random(len(candidate))
                existing = attack_reservoirs.get(label_text)
                if existing is not None:
                    candidate = pd.concat([existing, candidate], ignore_index=True)
                attack_reservoirs[label_text] = candidate

            samples_seen += len(chunk)
            if progress is not None:
                progress(
                    {
                        "stage": "loading",
                        "chunk": chunk_index,
                        "samplesSeen": samples_seen,
                        "normalSeen": normal_seen,
                        "attackLabelsSeen": len(attack_seen),
                    }
                )

    attack_quotas = _proportional_quotas(dict(attack_seen), max_rows=max_attack_rows)
    attack_parts: list[Any] = []
    for label, frame in attack_reservoirs.items():
        quota = attack_quotas.get(label, 0)
        if quota:
            attack_parts.append(frame.nsmallest(quota, "__priority"))
    if not normal_parts or not attack_parts:
        raise ValueError("Dataset did not provide both normal and attack flows")
    normal_frame = normal_parts[0].drop(columns=["__priority"]).reset_index(drop=True)
    attack_with_labels = pd.concat(attack_parts, ignore_index=True)
    attack_labels = attack_with_labels.pop("__label").astype(str).tolist()
    attack_frame = attack_with_labels.drop(columns=["__priority"]).reset_index(drop=True)
    return normal_frame, attack_frame, attack_labels, samples_seen


def _proportional_quotas(counts: dict[str, int], *, max_rows: int) -> dict[str, int]:
    if sum(counts.values()) <= max_rows:
        return counts
    minimums = {label: min(count, 20) for label, count in counts.items()}
    remaining = max_rows - sum(minimums.values())
    if remaining < 0:
        return {
            label: min(count, max(1, max_rows // len(counts)))
            for label, count in counts.items()
        }
    capacities = {label: counts[label] - minimums[label] for label in counts}
    quotas = dict(minimums)
    while remaining > 0 and sum(capacities.values()) > 0:
        total_capacity = sum(capacities.values())
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


def _clip_float32(values: Any, *, np: Any) -> Any:
    return np.clip(np.asarray(values, dtype=np.float32), -12.0, 12.0)


def _open_text(path: Path) -> Any:
    if path.name.lower().endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8-sig", newline="")
    return path.open("rt", encoding="utf-8-sig", newline="")


class TabularAutoEncoder:
    def __new__(
        cls,
        *,
        input_size: int,
        shoulder_size: int,
        bottleneck_size: int,
    ) -> Any:
        import torch
        from torch import nn

        class Network(nn.Module):
            def __init__(self) -> None:
                super().__init__()
                self.network = nn.Sequential(
                    nn.Linear(input_size, shoulder_size),
                    nn.GELU(),
                    nn.Linear(shoulder_size, bottleneck_size),
                    nn.GELU(),
                    nn.Linear(bottleneck_size, shoulder_size),
                    nn.GELU(),
                    nn.Linear(shoulder_size, input_size),
                )

            def forward(self, values: Any) -> Any:
                return self.network(values)

        torch.set_grad_enabled(True)
        return Network()


def _torch_predict(model: Any, values: Any, *, batch_size: int = 8_192) -> Any:
    import numpy as np
    import torch

    tensor = torch.from_numpy(np.asarray(values, dtype=np.float32))
    predictions: list[Any] = []
    model.eval()
    with torch.inference_mode():
        for start in range(0, len(tensor), batch_size):
            predictions.append(model(tensor[start : start + batch_size]).cpu())
    return torch.cat(predictions).numpy()
