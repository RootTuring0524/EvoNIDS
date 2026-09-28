"""EvoNIDS model evaluation protocol CLI (Phase 6 prerequisite).

Runs the mandated evaluation protocol (app/services/model_evaluation.py) against
a real dataset CSV/CSV.GZ using the repository's existing model artifacts
(model-artifacts/full-baseline/*/model.joblib, model-artifacts/full-autoencoder/*/model.joblib)
or a freshly trained baseline when none exists.

Honesty rules enforced here:

* every metric comes from ``model_evaluation`` which returns ``None``
  (NOT_MEASURED, rendered as 未测量) instead of a fabricated number whenever a
  metric is undefined for the data;
* evaluating a model that was trained on the whole dataset file (as the current
  full-baseline / full-autoencoder artifacts were) is **in-sample evidence** for
  every strategy: the report records the overlap risk qualitatively and never
  lets those numbers pose as out-of-sample generalisation;
* a strategy that cannot be computed for the given rows (single-class split,
  missing time/group column, ...) is recorded with its exact error, never with
  invented metrics.

Local real dataset: datasets/CICIDS2017/cicids2017_pcap_flow_full_v1.csv.gz
(2,120,625 rows, label column ``Label``).  A full 2M-row run takes minutes of
scanning; use ``--max-rows 20000`` for a smoke run.
"""
from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import json
import platform
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence

BACKEND_DIR = Path(__file__).resolve().parent.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.services import model_evaluation as ev  # noqa: E402

DEFAULT_CSV = BACKEND_DIR / "datasets" / "CICIDS2017" / "cicids2017_pcap_flow_full_v1.csv.gz"
DEFAULT_OUTPUT = BACKEND_DIR / "model-artifacts" / "evaluation"
DEFAULT_SEED = 20260814

IDENTIFIER_COLUMNS = {"capture_day", "source_ip", "destination_ip", "start_time", "timestamp"}

# built-in family map for the CICIDS2017 labels produced by the local extractor
CICIDS_FAMILY_MAP = {
    "BENIGN": "benign",
    "DDoS": "DDoS",
    "DoS GoldenEye": "DoS",
    "DoS Hulk": "DoS",
    "DoS Slowhttptest": "DoS",
    "DoS slowloris": "DoS",
    "Heartbleed": "Heartbleed",
    "Infiltration": "Infiltration",
    "PortScan": "PortScan",
    "FTP-Patator": "BruteForce",
    "SSH-Patator": "BruteForce",
    "Web Attack Brute Force": "WebAttack",
    "Web Attack SQL Injection": "WebAttack",
    "Web Attack XSS": "WebAttack",
}

CHUNK = 100_000


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, default=DEFAULT_CSV, help="dataset CSV or CSV.GZ")
    parser.add_argument(
        "--strategies",
        type=str,
        default=",".join(ev.STRATEGIES),
        help="comma separated split strategies: random,time_ordered,group_holdout,family_holdout",
    )
    parser.add_argument(
        "--max-rows",
        type=int,
        default=0,
        help="deterministic per-class sample cap; 0 = use every row (memory heavy for 2M rows)",
    )
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT, help="output directory")
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--test-ratio", type=float, default=ev.DEFAULT_TEST_RATIO)
    parser.add_argument("--label-column", type=str, default="Label")
    parser.add_argument("--normal-labels", type=str, default="BENIGN", help="comma separated normal labels")
    parser.add_argument("--time-column", type=str, default="start_time")
    parser.add_argument("--group-column", type=str, default="source_ip")
    parser.add_argument("--family-map", type=Path, default=None, help="optional JSON {label: family}")
    parser.add_argument(
        "--baseline-artifact",
        type=Path,
        default=None,
        help="explicit full-baseline model.joblib (default: discover model-artifacts/full-baseline)",
    )
    parser.add_argument(
        "--autoencoder-artifact",
        type=Path,
        default=None,
        help="explicit full-autoencoder model.joblib (default: discover model-artifacts/full-autoencoder)",
    )
    parser.add_argument(
        "--fresh-baseline",
        action="store_true",
        help="train a fresh HistGradientBoosting baseline per strategy instead of reusing an artifact",
    )
    parser.add_argument("--max-iter", type=int, default=200, help="fresh baseline max iterations")
    parser.add_argument("--learning-rate", type=float, default=0.08)
    parser.add_argument("--max-leaf-nodes", type=int, default=31)
    parser.add_argument("--l2", type=float, default=0.2)
    return parser.parse_args()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


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


def _proportional_sample_quotas(counts: dict[str, int], *, max_rows: int) -> dict[str, int]:
    """Per-class deterministic sample quotas (min 10 per class, capacity proportional)."""
    counts = {str(label).strip(): int(count) for label, count in counts.items() if int(count) > 0}
    if sum(counts.values()) <= max_rows:
        return counts
    minimums = {label: min(count, 10) for label, count in counts.items()}
    remaining = max_rows - sum(minimums.values())
    if remaining < 0:
        return {
            label: min(count, max(1, max_rows // max(1, len(counts))))
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


def _scan_dataset(
    path: Path,
    *,
    encoding: str,
    delimiter: str,
    label_column: str,
    seed: int,
    max_rows: int,
) -> dict[str, Any]:
    """One streaming pass over the file: column stats + per-class sample.

    Returns the sampled/evaluation frame (plain columns incl. label, time and
    group columns), full-file class counts, numeric feature selection and
    runtime stats.  Deterministic for a given (seed, max_rows, file).
    """
    import numpy as np
    import pandas as pd

    opener = gzip.open if path.name.lower().endswith(".gz") else open
    rng = np.random.default_rng(seed)
    stats: dict[str, list[float]] = {}
    columns: list[str] | None = None
    label_counter: Counter[str] = Counter()
    reservoirs: dict[str, Any] = {}
    full_parts: list[Any] = []
    samples_seen = 0
    seq_counter = 0
    scan_started = time.perf_counter()

    def reservoir_push(key: str, candidate: Any, cap: int) -> None:
        nonlocal seq_counter
        candidate = candidate.copy()
        candidate["__evonids_priority"] = rng.random(len(candidate))
        candidate["__evonids_seq"] = list(range(seq_counter, seq_counter + len(candidate)))
        seq_counter += len(candidate)
        existing = reservoirs.get(key)
        if existing is not None:
            candidate = pd.concat([existing, candidate], ignore_index=True)
        reservoirs[key] = candidate.nsmallest(cap, "__evonids_priority")

    with opener(path, "rt", encoding=encoding, newline="") as handle:
        for chunk_index, chunk in enumerate(
            pd.read_csv(handle, sep=delimiter, chunksize=CHUNK, low_memory=False), start=1
        ):
            chunk.columns = [str(value).strip() for value in chunk.columns]
            if columns is None:
                columns = list(chunk.columns)
                for name in columns:
                    stats[name] = [0.0, np.inf, -np.inf]
            if label_column not in chunk.columns:
                raise ValueError(f"label column {label_column!r} not found in dataset")
            labels = chunk[label_column].astype("string").str.strip()
            # full-file numeric stats per column (excluding the label)
            for name in columns:
                if name == label_column:
                    continue
                numeric = pd.to_numeric(chunk[name], errors="coerce")
                arr = numeric.to_numpy(dtype=np.float64)
                valid = ~np.isnan(arr)
                stats[name][0] += float(valid.sum())
                if valid.any():
                    stats[name][1] = min(stats[name][1], float(arr[valid].min()))
                    stats[name][2] = max(stats[name][2], float(arr[valid].max()))
            seen = len(chunk)
            samples_seen += seen
            label_counter.update(str(value) for value in labels.dropna())
            if max_rows > 0:
                by_label = labels.groupby(labels, dropna=True).groups
                for label, indices in by_label.items():
                    text = str(label)
                    if not text or text in {"<NA>", "nan"}:
                        continue
                    reservoir_push(text, chunk.loc[indices], max_rows)
            else:
                chunk = chunk.copy()
                chunk["__evonids_seq"] = list(range(seq_counter, seq_counter + seen))
                seq_counter += seen
                full_parts.append(chunk)
            elapsed = time.perf_counter() - scan_started
            print(
                f"[scan] chunk={chunk_index:02d} rows={samples_seen:,} "
                f"rate={samples_seen / elapsed:,.0f} rows/s elapsed={elapsed:.0f}s",
                flush=True,
            )

    numeric_features = [
        name
        for name in (columns or [])
        if name != label_column
        and name not in IDENTIFIER_COLUMNS
        and (samples_seen == 0 or stats[name][0] / samples_seen >= 0.8)
        and stats[name][1] < stats[name][2]
    ]

    if max_rows > 0:
        quotas = _proportional_sample_quotas(dict(label_counter), max_rows=max_rows)
        selected: list[Any] = []
        for label, frame in reservoirs.items():
            quota = quotas.get(label, 0)
            if quota <= 0:
                continue
            picked = frame.nsmallest(quota, "__evonids_priority")
            if len(picked):
                selected.append(picked)
        if not selected:
            raise ValueError("sampling selected no rows; increase --max-rows")
        frame = (
            pd.concat(selected, ignore_index=True)
            .drop(columns=["__evonids_priority"])
            .sort_values("__evonids_seq")
            .drop(columns=["__evonids_seq"])
            .reset_index(drop=True)
        )
        sample_method = (
            "single-pass per-class priority reservoir over the full file with deterministic "
            f"quotas (min 10/class, seed={seed}); sample rows preserve original file order"
        )
    else:
        if not full_parts:
            raise ValueError("dataset produced no rows")
        frame = (
            pd.concat(full_parts, ignore_index=True)
            .sort_values("__evonids_seq")
            .drop(columns=["__evonids_seq"])
            .reset_index(drop=True)
        )
        sample_method = "every row of the file is used (no sampling)"

    print(
        f"[scan] done: {samples_seen:,} rows in {time.perf_counter() - scan_started:.1f}s; "
        f"evaluation rows={len(frame):,} classes={len(label_counter)}",
        flush=True,
    )
    return {
        "frame": frame,
        "columns": columns or [],
        "fullClassCounts": dict(sorted(label_counter.items(), key=lambda item: -item[1])),
        "numericFeatures": numeric_features,
        "droppedFeatures": [
            name
            for name in (columns or [])
            if name != label_column and name not in numeric_features
        ],
        "samplesSeen": samples_seen,
        "sampleMethod": sample_method,
        "columnStats": stats,
    }


def _discover_artifacts(root: Path, task_subdir: str) -> list[Path]:
    directory = (root / task_subdir).resolve()
    if not directory.is_dir():
        return []
    return sorted(directory.glob("*/model.joblib"))


def _load_artifact(path: Path) -> dict[str, Any]:
    import joblib

    payload = joblib.load(path)
    if not isinstance(payload, dict):
        raise ValueError(f"artifact {path} is not a dict payload")
    return payload


def _numeric_matrix(frame: Any, features: list[str]) -> tuple[Any, list[str]]:
    import numpy as np
    import pandas as pd

    present = [name for name in features if name in frame.columns]
    if not present:
        raise ValueError("none of the requested numeric features exist in the frame")
    converted = frame[present].apply(pd.to_numeric, errors="coerce")
    return converted.to_numpy(dtype=np.float64), present


def _fill_median(matrix: Any, np: Any) -> Any:
    if matrix.size == 0 or not np.isnan(matrix).any():
        return matrix
    medians = np.nanmedian(matrix, axis=0)
    return np.where(np.isnan(matrix), medians, matrix)


def _fit_and_predict_fresh_baseline(
    train_frame: Any,
    test_frame: Any,
    *,
    features: list[str],
    label_column: str,
    seed: int,
    max_iter: int,
    learning_rate: float,
    max_leaf_nodes: int,
    l2: float,
) -> tuple[Any, Any, dict[str, Any]]:
    import numpy as np
    from sklearn.ensemble import HistGradientBoostingClassifier

    train_x, present = _numeric_matrix(train_frame, features)
    test_x, _ = _numeric_matrix(test_frame, present)
    train_x = _fill_median(train_x, np=np)
    test_x = _fill_median(test_x, np=np)
    train_y = train_frame[label_column].astype("string").str.strip().astype(str).tolist()
    if len(present) < 1:
        raise ValueError("no usable numeric features for training")
    if len(set(train_y)) < 2:
        raise ValueError("fresh baseline needs at least two classes in the train split")
    per_class = Counter(train_y)
    rare = [label for label, count in per_class.items() if count < 3]
    if rare:
        raise ValueError(f"fresh baseline needs >=3 rows per train class; too few: {rare}")
    classifier = HistGradientBoostingClassifier(
        learning_rate=learning_rate,
        max_iter=max_iter,
        max_leaf_nodes=max_leaf_nodes,
        l2_regularization=l2,
        class_weight="balanced",
        early_stopping=True,
        validation_fraction=0.1,
        random_state=seed,
    )
    started = time.perf_counter()
    classifier.fit(train_x, train_y)
    fit_seconds = time.perf_counter() - started
    prediction = classifier.predict(test_x)
    return classifier, prediction, {
        "fitSeconds": float(fit_seconds),
        "iterationsUsed": int(classifier.n_iter_),
        "featuresUsed": present,
        "trainRows": int(len(train_x)),
        "testRows": int(len(test_x)),
        "algorithm": "hist_gradient_boosting",
    }


def _multiclass_evaluation_for(
    strategy: str,
    manifest: dict[str, Any],
    test_frame: Any,
    test_truth: list[str],
    test_prediction: Sequence[str],
    *,
    normal_labels: list[str],
    seed: int,
    numeric_features: list[str],
    fresh: bool,
    provenance: dict[str, Any],
) -> dict[str, Any]:
    train_classes = sorted((manifest.get("splits") or {}).get("train", {}).get("classCounts", {}).keys())
    evaluation = ev.evaluate_multiclass(
        test_truth,
        test_prediction,
        normal_labels=normal_labels,
        train_classes=train_classes,
    )
    overlap = overlap_risk(strategy=strategy, fresh=fresh, provenance=provenance)
    return {
        "modelKind": "multiclass_classifier",
        "strategy": strategy,
        "manifest": manifest,
        "overlap": overlap,
        "evaluation": evaluation,
    }


def _binary_evaluation_for(
    strategy: str,
    manifest: dict[str, Any],
    test_frame: Any,
    *,
    normal_labels: list[str],
    seed: int,
    artifact: dict[str, Any],
    artifact_path: Path,
    provenance: dict[str, Any],
) -> dict[str, Any]:
    """Score test rows with the autoencoder artifact and evaluate binary scores."""
    from app.services.autoencoder import score_frame

    truth = test_frame["Label"].astype("string").str.strip().astype(str).tolist()
    normal_set = {str(value) for value in normal_labels}
    scored = score_frame(artifact, test_frame)
    scores = scored["scores"].astype(float).tolist()
    binary_y = [0 if value in normal_set else 1 for value in truth]
    n_pos = sum(1 for value in binary_y if value == 1)
    n_neg = len(binary_y) - n_pos
    if n_pos == 0 or n_neg == 0:
        # still evaluated: the function returns NOT_MEASURED entries honestly
        print(
            f"[warn] strategy={strategy} autoencoder: single-class test rows "
            f"(pos={n_pos} neg={n_neg}); metrics will be NOT_MEASURED",
            flush=True,
        )
    thresholds = [0.5]  # score_frame maps the artifact error threshold to score 0.5
    evaluation = ev.evaluate_binary_scores(
        binary_y,
        scores,
        thresholds=thresholds,
        positive_label=1,
    )
    overlap = overlap_risk(strategy=strategy, fresh=False, provenance=provenance)
    return {
        "modelKind": "binary_anomaly_scores",
        "strategy": strategy,
        "manifest": manifest,
        "overlap": overlap,
        "evaluation": evaluation,
    }


def overlap_risk(strategy: str, *, fresh: bool, provenance: dict[str, Any]) -> dict[str, Any]:
    if fresh:
        return {
            "risk": "none",
            "basis": "model was trained on this strategy's train split only; test rows were never used",
        }
    trained_whole = bool(provenance.get("trainedOnWholeDataset", False))
    if not trained_whole:
        return {
            "risk": "unknown",
            "basis": "model provenance does not state its training rows; assume overlap possible",
        }
    notes = {
        "random": (
            "highest expected overlap: the artifact was trained on a random stratified split of the "
            "whole file, so most random-split test rows were seen at training time (in-sample evidence)"
        ),
        "time_ordered": (
            "high expected overlap: training drew rows from every capture day, including the test "
            "time window (in-sample temporal evidence, not forward-chaining)"
        ),
        "group_holdout": (
            "high expected overlap: held-out host groups were present in the artifact's training rows"
        ),
        "family_holdout": (
            "high expected overlap: held-out families/labels were present in the artifact's training rows"
        ),
    }
    return {
        "risk": "high",
        "basis": notes.get(strategy, "artifact trained on the whole dataset file"),
    }


def _model_provenance_baseline(payload: dict[str, Any], path: Path) -> dict[str, Any]:
    metrics = payload.get("metrics") or {}
    config = payload.get("config") or {}
    return {
        "task": payload.get("task"),
        "algorithm": payload.get("algorithm"),
        "runId": payload.get("run_id"),
        "artifactPath": str(path),
        "trainedOnWholeDataset": True,
        "trainingMaxRows": config.get("maxRows"),
        "trainingSplit": {
            "train_rows": metrics.get("train_rows"),
            "validation_rows": metrics.get("validation_rows"),
            "test_rows": metrics.get("test_rows"),
            "total_rows": metrics.get("total_rows"),
        },
        "selfReportedTestMetrics": {
            "accuracy": metrics.get("accuracy"),
            "macro_f1": metrics.get("macro_f1"),
            "weighted_f1": metrics.get("weighted_f1"),
            "validation_macro_f1": metrics.get("validation_macro_f1"),
            "ovr_roc_auc": metrics.get("ovr_roc_auc"),
        },
        "csvSha256": config.get("csvSha256"),
        "runtimeVersions": payload.get("runtime_versions"),
    }


def _model_provenance_autoencoder(payload: dict[str, Any], path: Path) -> dict[str, Any]:
    metrics = payload.get("metrics") or {}
    config = payload.get("config") or {}
    dataset = payload.get("dataset") or {}
    return {
        "task": payload.get("task"),
        "algorithm": payload.get("algorithm"),
        "runId": payload.get("trainingRunId"),
        "artifactPath": str(path),
        "trainedOnWholeDataset": True,
        "datasetSha256": dataset.get("sha256"),
        "config": {
            "targetFpr": config.get("targetFpr"),
            "thresholdQuantile": config.get("thresholdQuantile"),
            "bottleneckSize": config.get("bottleneckSize"),
            "maxEpochs": config.get("maxEpochs"),
        },
        "selfReportedTestMetrics": {
            "roc_auc": metrics.get("roc_auc"),
            "average_precision": metrics.get("average_precision"),
            "normal_false_positive_rate": metrics.get("normal_false_positive_rate"),
            "normal_test_error_mean": metrics.get("normal_test_error_mean"),
        },
        "runtimeVersions": payload.get("runtime_versions"),
    }


def _load_family_map(args: argparse.Namespace, labels: set[str]) -> dict[str, str]:
    if args.family_map is not None:
        data = json.loads(args.family_map.read_text(encoding="utf-8"))
        mapping = {str(key).strip(): str(value).strip() for key, value in data.items()}
        print(f"[family-map] loaded {len(mapping)} mappings from {args.family_map}", flush=True)
        return mapping
    if labels and labels.issubset(set(CICIDS_FAMILY_MAP.keys())):
        print("[family-map] using built-in CICIDS2017 label->family map", flush=True)
        return dict(CICIDS_FAMILY_MAP)
    print("[family-map] labels are not CICIDS2017 names; treating each label as its own family", flush=True)
    return {label: label for label in sorted(labels)}


def main() -> None:
    args = parse_args()
    import numpy as np

    started = time.perf_counter()
    print("=" * 78, flush=True)
    print("EvoNIDS model evaluation protocol CLI", flush=True)
    print(f"dataset   : {args.dataset}", flush=True)
    print(f"strategies: {args.strategies}", flush=True)
    print(f"max_rows  : {args.max_rows or 'ALL (every row)'}", flush=True)
    print(f"seed      : {args.seed}", flush=True)
    print(f"output    : {args.output}", flush=True)
    print("=" * 78, flush=True)

    strategies = [value.strip() for value in args.strategies.split(",") if value.strip()]
    for strategy in strategies:
        if strategy not in ev.STRATEGIES:
            raise SystemExit(f"unknown strategy {strategy!r}; expected one of {ev.STRATEGIES}")
    dataset_path = args.dataset.expanduser().resolve()
    if not dataset_path.is_file():
        raise FileNotFoundError(f"missing dataset: {dataset_path}")
    normal_labels = [value.strip() for value in args.normal_labels.split(",") if value.strip()]

    print("[sha256] hashing dataset file ...", flush=True)
    dataset_sha256 = _sha256(dataset_path)
    print(f"[sha256] {dataset_sha256}", flush=True)

    encoding, delimiter = _detect_csv_format(dataset_path)
    print(f"[csv] encoding={encoding} delimiter={delimiter!r}", flush=True)

    scanned = _scan_dataset(
        dataset_path,
        encoding=encoding,
        delimiter=delimiter,
        label_column=args.label_column,
        seed=args.seed,
        max_rows=args.max_rows,
    )
    frame: Any = scanned["frame"]
    numeric_features = list(scanned["numericFeatures"])
    full_counts = dict(scanned["fullClassCounts"])
    samples_seen = int(scanned["samplesSeen"])
    labels_in_sample = frame[args.label_column].astype("string").str.strip().astype(str).tolist()
    sample_counts = dict(sorted(Counter(labels_in_sample).items(), key=lambda item: -item[1]))
    print(f"[labels] sample distribution: {sample_counts}", flush=True)

    family_map = _load_family_map(args, set(full_counts.keys()))
    used_family_map = {label: family_map[label] for label in sample_counts if label in family_map}
    used_family_map.update({label: label for label in sample_counts if label not in family_map})

    # ------------------------------------------------------------------ models
    baseline_artifact_path: Path | None = None
    autoencoder_artifact_path: Path | None = None
    if not args.fresh_baseline:
        candidates = _discover_artifacts(BACKEND_DIR / "model-artifacts", "full-baseline")
        if args.baseline_artifact is not None:
            candidates = [args.baseline_artifact.expanduser().resolve()]
        if candidates:
            baseline_artifact_path = candidates[0]
            print(f"[artifact] full-baseline: {baseline_artifact_path}", flush=True)
        ae_candidates = _discover_artifacts(BACKEND_DIR / "model-artifacts", "full-autoencoder")
        if args.autoencoder_artifact is not None:
            ae_candidates = [args.autoencoder_artifact.expanduser().resolve()]
        if ae_candidates:
            autoencoder_artifact_path = ae_candidates[0]
            print(f"[artifact] full-autoencoder: {autoencoder_artifact_path}", flush=True)

    baseline_payload: dict[str, Any] | None = None
    autoencoder_payload: dict[str, Any] | None = None
    if baseline_artifact_path is not None:
        print("[load] full-baseline artifact ...", flush=True)
        baseline_payload = _load_artifact(baseline_artifact_path)
        print(
            f"[load] task={baseline_payload.get('task')} algorithm={baseline_payload.get('algorithm')}",
            flush=True,
        )
    if autoencoder_artifact_path is not None:
        print("[load] full-autoencoder artifact ...", flush=True)
        autoencoder_payload = _load_artifact(autoencoder_artifact_path)
        print(
            f"[load] task={autoencoder_payload.get('task')} algorithm={autoencoder_payload.get('algorithm')}",
            flush=True,
        )
    if baseline_payload is None and not args.fresh_baseline:
        print("[warn] no full-baseline artifact found; will train a fresh baseline per strategy", flush=True)

    # ------------------------------------------------------------- strategies
    models_reports: list[dict[str, Any]] = []

    if baseline_payload is not None or args.fresh_baseline:
        baseline_strategies: list[dict[str, Any]] = []
        artifact_features = list((baseline_payload.get("metrics") or {}).get("numeric_features") or [])
        for strategy in strategies:
            print("-" * 78, flush=True)
            print(f"[baseline] strategy={strategy} seed={args.seed}", flush=True)
            try:
                manifest = ev.split_manifest(
                    frame,
                    strategy=strategy,
                    seed=args.seed,
                    label_column=args.label_column,
                    test_ratio=args.test_ratio,
                    time_column=args.time_column,
                    group_column=args.group_column,
                    family_map=used_family_map,
                    normal_labels=normal_labels,
                    dataset_sha256=dataset_sha256,
                    include_row_indices=True,
                )
                train_rows = manifest["splits"]["train"]["rows"]
                test_rows = manifest["splits"]["test"]["rows"]
                print(
                    f"[baseline] strategy={strategy} train={train_rows:,} test={test_rows:,}",
                    flush=True,
                )
                test_indices = manifest["splits"]["test"]["rowIndices"]
                test_frame = frame.iloc[test_indices].reset_index(drop=True)
                test_truth = (
                    test_frame[args.label_column].astype("string").str.strip().astype(str).tolist()
                )
                drift = _drift_for(frame, manifest, numeric_features, args.label_column)

                if baseline_payload is not None and not args.fresh_baseline:
                    pipeline = baseline_payload["pipeline"]
                    features_for_model = artifact_features or numeric_features
                    test_x, present = _numeric_matrix(test_frame, features_for_model)
                    test_x = _fill_median(test_x, np=np)
                    predict_started = time.perf_counter()
                    prediction = pipeline.predict(test_x).astype(str).tolist()
                    predict_seconds = time.perf_counter() - predict_started
                    provenance = _model_provenance_baseline(baseline_payload, baseline_artifact_path or Path())
                    fresh_used = False
                    print(
                        f"[baseline] predict test={test_rows:,} in {predict_seconds:.2f}s "
                        f"(artifact reuse; overlap risk: high - in-sample)",
                        flush=True,
                    )
                else:
                    _classifier, prediction, fit_info = _fit_and_predict_fresh_baseline(
                        frame.iloc[manifest["splits"]["train"]["rowIndices"]].reset_index(drop=True),
                        test_frame,
                        features=numeric_features,
                        label_column=args.label_column,
                        seed=args.seed,
                        max_iter=args.max_iter,
                        learning_rate=args.learning_rate,
                        max_leaf_nodes=args.max_leaf_nodes,
                        l2=args.l2,
                    )
                    print(
                        f"[baseline] fresh fit {fit_info['fitSeconds']:.1f}s "
                        f"iters={fit_info['iterationsUsed']}",
                        flush=True,
                    )
                    provenance: dict[str, Any] = {
                        "task": "known_attack_classification_baseline",
                        "algorithm": "hist_gradient_boosting",
                        "trainedOnWholeDataset": False,
                        "freshStrategyTrain": True,
                        "fitInfo": fit_info,
                    }
                    fresh_used = True

                result = _multiclass_evaluation_for(
                    strategy,
                    manifest,
                    test_frame,
                    test_truth,
                    prediction,
                    normal_labels=normal_labels,
                    seed=args.seed,
                    numeric_features=numeric_features,
                    fresh=fresh_used,
                    provenance=provenance,
                )
                result["featureDrift"] = drift
                macro_f1 = result["evaluation"]["aggregates"]["macroF1"].get("value")
                print(
                    f"[baseline] strategy={strategy} accuracy={result['evaluation'].get('accuracy')} "
                    f"macroF1={macro_f1}",
                    flush=True,
                )
                baseline_strategies.append(result)
            except Exception as exc:  # per-strategy honesty: record, never invent
                print(f"[baseline] strategy={strategy} ERROR: {type(exc).__name__}: {exc}", flush=True)
                baseline_strategies.append(
                    {
                        "modelKind": "multiclass_classifier",
                        "strategy": strategy,
                        "error": f"{type(exc).__name__}: {exc}",
                    }
                )
        models_reports.append(
            {
                "id": "fresh-baseline" if (baseline_payload is None or args.fresh_baseline) else "full-baseline",
                "name": "Known-Attack Classification Baseline (HistGradientBoosting, CPU)",
                "task": "known_attack_classification_baseline",
                "algorithm": "hist_gradient_boosting",
                "trainedOnWholeDataset": baseline_payload is not None and not args.fresh_baseline,
                "overlapNote": (
                    "artifact trained on a random stratified split of the whole file; all strategy "
                    "numbers below are in-sample evidence (see per-strategy overlap fields)"
                    if baseline_payload is not None and not args.fresh_baseline
                    else "fresh model trained per strategy on the protocol train split; numbers are out-of-sample"
                ),
                "artifact": {
                    "path": str(baseline_artifact_path) if baseline_artifact_path else None,
                    "sha256": None,
                    "provenance": (
                        _model_provenance_baseline(baseline_payload, baseline_artifact_path or Path())
                        if baseline_payload is not None
                        else None
                    ),
                },
                "strategies": baseline_strategies,
            }
        )

    if autoencoder_payload is not None:
        ae_strategies: list[dict[str, Any]] = []
        for strategy in strategies:
            print("-" * 78, flush=True)
            print(f"[autoencoder] strategy={strategy} seed={args.seed}", flush=True)
            try:
                manifest = ev.split_manifest(
                    frame,
                    strategy=strategy,
                    seed=args.seed,
                    label_column=args.label_column,
                    test_ratio=args.test_ratio,
                    time_column=args.time_column,
                    group_column=args.group_column,
                    family_map=used_family_map,
                    normal_labels=normal_labels,
                    dataset_sha256=dataset_sha256,
                    include_row_indices=True,
                )
                train_rows = manifest["splits"]["train"]["rows"]
                test_rows = manifest["splits"]["test"]["rows"]
                test_indices = manifest["splits"]["test"]["rowIndices"]
                test_frame = frame.iloc[test_indices].reset_index(drop=True)
                truth_series = test_frame[args.label_column].astype("string").str.strip()
                normal_set = {str(value) for value in normal_labels}
                n_attack = int((~truth_series.isin(normal_set)).sum())
                print(
                    f"[autoencoder] strategy={strategy} train={train_rows:,} test={test_rows:,} "
                    f"test_attack={n_attack:,}",
                    flush=True,
                )
                result = _binary_evaluation_for(
                    strategy,
                    manifest,
                    test_frame,
                    normal_labels=normal_labels,
                    seed=args.seed,
                    artifact=autoencoder_payload,
                    artifact_path=autoencoder_artifact_path or Path(),
                    provenance=_model_provenance_autoencoder(
                        autoencoder_payload, autoencoder_artifact_path or Path()
                    ),
                )
                result["featureDrift"] = _drift_for(frame, manifest, numeric_features, args.label_column)
                roc = result["evaluation"].get("rocAuc")
                print(f"[autoencoder] strategy={strategy} rocAuc={roc}", flush=True)
                ae_strategies.append(result)
            except Exception as exc:
                print(f"[autoencoder] strategy={strategy} ERROR: {type(exc).__name__}: {exc}", flush=True)
                ae_strategies.append(
                    {
                        "modelKind": "binary_anomaly_scores",
                        "strategy": strategy,
                        "error": f"{type(exc).__name__}: {exc}",
                    }
                )
        models_reports.append(
            {
                "id": "full-autoencoder",
                "name": "Unknown-Anomaly AutoEncoder (MLP, CPU)",
                "task": "unknown_anomaly_detection",
                "algorithm": "mlp_autoencoder",
                "trainedOnWholeDataset": True,
                "overlapNote": (
                    "artifact trained on the whole dataset file (all BENIGN and attack rows); all "
                    "strategy numbers below are in-sample evidence (see per-strategy overlap fields)"
                ),
                "artifact": {
                    "path": str(autoencoder_artifact_path) if autoencoder_artifact_path else None,
                    "sha256": None,
                    "provenance": (
                        _model_provenance_autoencoder(autoencoder_payload, autoencoder_artifact_path or Path())
                        if autoencoder_payload is not None
                        else None
                    ),
                },
                "strategies": ae_strategies,
            }
        )
    if not models_reports:
        models_reports.append(
            {
                "id": "no-model",
                "name": "No evaluable model artifact found",
                "task": None,
                "algorithm": None,
                "strategies": [],
                "overlapNote": (
                    "Neither a baseline artifact nor an autoencoder artifact is available "
                    "and --fresh-baseline was not requested."
                ),
            }
        )

    # -------------------------------------------------------------- reporting
    if int(len(frame)) > 250_000:
        # keep manifests explicit but bound the JSON size: row-level indices are
        # dropped from the serialised report (reproducible via seed + strategy)
        for model in models_reports:
            for strategy in model.get("strategies") or []:
                manifest = strategy.get("manifest") or {}
                splits = manifest.get("splits") or {}
                for block in splits.values():
                    if "rowIndices" in block:
                        block.pop("rowIndices", None)
                        block["rowIndicesOmitted"] = True
                if splits:
                    manifest["rowIndicesIncluded"] = False

    report: dict[str, Any] = {
        "protocolVersion": ev.PROTOCOL_VERSION,
        "generatedAtUtc": datetime.now(timezone.utc).isoformat(),
        "command": " ".join(sys.argv),
        "dataset": {
            "path": str(dataset_path),
            "fileName": dataset_path.name,
            "sha256": dataset_sha256,
            "bytes": int(dataset_path.stat().st_size),
            "labelColumn": args.label_column,
            "normalLabels": normal_labels,
            "timeColumn": args.time_column,
            "groupColumn": args.group_column,
            "familyMap": used_family_map,
            "rowsLoaded": samples_seen,
            "rowsUsed": int(len(frame)),
            "sampling": {
                "maxRows": args.max_rows,
                "method": scanned["sampleMethod"],
                "seed": args.seed,
            },
            "labelDistribution": sample_counts,
            "fullLabelDistribution": full_counts,
            "numericFeatures": numeric_features,
            "droppedFeatures": scanned["droppedFeatures"],
        },
        "runtime": {
            "python": platform.python_version(),
            "platform": platform.platform(),
            "machine": platform.machine(),
            "processor": platform.processor(),
            "cpuCount": _cpu_count(),
            "hostname": platform.node(),
            "versions": _runtime_versions(),
        },
        "models": models_reports,
    }

    out_dir = args.output.expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / "evaluation-report.json"
    md_path = out_dir / "evaluation-report.md"
    json_path.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, allow_nan=False),
        encoding="utf-8",
    )
    markdown = ev.render_report_markdown(report)
    md_path.write_text(markdown, encoding="utf-8")
    print("=" * 78, flush=True)
    print(f"[report] {json_path}", flush=True)
    print(f"[report] {md_path}", flush=True)
    print(f"[complete] elapsed={time.perf_counter() - started:.0f}s", flush=True)


def _drift_for(frame: Any, manifest: dict[str, Any], numeric_features: list[str], label_column: str) -> dict[str, Any]:
    import numpy as np

    from app.services.model_evaluation import drift_report

    train_indices = manifest["splits"]["train"].get("rowIndices")
    test_indices = manifest["splits"]["test"].get("rowIndices")
    if train_indices is None or test_indices is None:
        return {
            "kind": "drift",
            "skipped": True,
            "reason": "row indices omitted for very large splits; drift not computed",
        }
    present = [name for name in numeric_features if name in frame.columns]
    try:
        train_numeric, present_used = _numeric_matrix(frame.iloc[train_indices], present)
        test_numeric, _ = _numeric_matrix(frame.iloc[test_indices], present_used)
        train_numeric = _fill_median(train_numeric, np=np)
        test_numeric = _fill_median(test_numeric, np=np)
        if train_numeric.shape[0] == 0 or test_numeric.shape[0] == 0:
            return {
                "kind": "drift",
                "skipped": True,
                "reason": "empty train or test rows; drift not measured",
            }
        report = drift_report(train_numeric, test_numeric, feature_names=present_used)
        return report
    except Exception as exc:
        return {
            "kind": "drift",
            "skipped": True,
            "reason": f"{type(exc).__name__}: {exc}",
        }


def _cpu_count() -> int:
    try:
        import os

        return int(os.cpu_count() or 0)
    except Exception:
        return 0


def _runtime_versions() -> dict[str, str]:
    versions: dict[str, str] = {"python": platform.python_version()}
    for module_name in ("numpy", "pandas", "sklearn", "joblib", "scipy", "torch"):
        try:
            module = __import__(module_name)
            versions[module_name] = getattr(module, "__version__", "unknown")
        except Exception:
            versions[module_name] = "unavailable"
    return versions


if __name__ == "__main__":
    main()
