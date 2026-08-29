"""Train the known-attack CPU baseline (HistGradientBoosting) on the FULL CICIDS2017 flow table.

Standalone script (no database, no API):
  * reads the CSV directly and streams scan progress to the console in real time
  * fits on EVERY row by default (--max-rows 0); optional deterministic per-class cap
  * reports honest metrics: accuracy, balanced accuracy, macro/weighted P/R/F1,
    per-class precision/recall/F1, OvR ROC-AUC and PR-AUC, confusion matrix
  * writes a joblib artifact + JSON metadata + latest-summary.json
"""
from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import json
import platform
import threading
import time
import uuid
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
DEFAULT_CSV = HERE.parent / "data" / "CICIDS2017" / "cicids2017_pcap_flow_full_v1.csv.gz"
DEFAULT_OUTPUT = HERE.parent / "artifacts" / "baseline"
LABEL_COLUMN = "Label"
IDENTIFIER_COLUMNS = {"capture_day", "source_ip", "destination_ip", "start_time"}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--csv", type=Path, default=DEFAULT_CSV)
    parser.add_argument("--max-rows", type=int, default=0, help="0 = use every row")
    parser.add_argument("--max-iter", type=int, default=200)
    parser.add_argument("--learning-rate", type=float, default=0.08)
    parser.add_argument("--max-leaf-nodes", type=int, default=31)
    parser.add_argument("--l2", type=float, default=0.2)
    parser.add_argument("--random-seed", type=int, default=20260728)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    return parser.parse_args()


def _detect_csv_format(path: Path) -> tuple[str, str]:
    opener = gzip.open if path.name.lower().endswith(".gz") else open
    for encoding in ("utf-8-sig", "latin-1"):
        try:
            with opener(path, "rt", encoding=encoding, newline="") as handle:
                sample = handle.read(65_536)
            try:
                dialect = csv.Sniffer().sniff(sample, delimiters=",;\t|")
                return encoding, dialect.delimiter
            except csv.Error:
                return encoding, ","
        except UnicodeDecodeError:
            continue
    raise ValueError(f"Dataset encoding is not supported: {path}")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _class_quotas(label_distribution: dict[str, int], *, max_rows: int) -> dict[str, int]:
    counts = {
        str(k).strip(): int(v)
        for k, v in label_distribution.items()
        if str(k).strip() not in {"", "<NA>", "nan"} and int(v) > 0
    }
    if len(counts) < 2:
        raise ValueError("Known-attack classification requires at least two labels")
    minimum = 10 * len(counts)
    if max_rows < minimum:
        raise ValueError(f"maxRows must be at least {minimum} to keep 10 rows for each of {len(counts)} classes")
    total = sum(counts.values())
    if total <= max_rows:
        return counts
    quotas = {label: 10 for label in counts}
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


def _fit_ticker(label: str, stop_event: threading.Event) -> None:
    started = time.perf_counter()
    while not stop_event.is_set():
        time.sleep(3)
        if stop_event.is_set():
            break
        print(f"[fit] {label} elapsed={time.perf_counter() - started:.0f}s", flush=True)


def main() -> None:
    args = parse_args()
    import numpy as np
    import pandas as pd

    path = args.csv.resolve()
    if not path.is_file():
        raise FileNotFoundError(f"missing csv: {path}")
    encoding, delimiter = _detect_csv_format(path)

    print("=" * 78, flush=True)
    print("EvoNIDS FULL baseline training (HistGradientBoosting, CPU)", flush=True)
    print(f"csv       : {path}", flush=True)
    print(f"max_rows  : {args.max_rows or 'ALL (every row)'}", flush=True)
    print(f"max_iter  : {args.max_iter}  lr={args.learning_rate}  leaf={args.max_leaf_nodes}  l2={args.l2}", flush=True)
    print(f"seed      : {args.random_seed}", flush=True)
    print("=" * 78, flush=True)

    print("[sha256] hashing dataset ...", flush=True)
    csv_sha256 = _sha256(path)
    print(f"[sha256] {csv_sha256}", flush=True)

    # ---------- scan pass: one real-time pass, store per-column float32 + labels ----------
    opener = gzip.open if path.name.lower().endswith(".gz") else open
    columns: list[str] | None = None
    numeric_arrays: dict[str, list[np.ndarray]] = {}
    column_stats: dict[str, list[float]] = {}  # name -> [notna_count, min, max]
    labels: list[str] = []
    total_rows = 0
    scan_started = time.perf_counter()
    with opener(path, "rt", encoding=encoding, newline="") as handle:
        reader = pd.read_csv(handle, sep=delimiter, chunksize=100_000, low_memory=False)
        for chunk_index, chunk in enumerate(reader, start=1):
            chunk.columns = [str(c).strip() for c in chunk.columns]
            if columns is None:
                columns = list(chunk.columns)
                for c in columns:
                    numeric_arrays[c] = []
                    column_stats[c] = [0.0, np.inf, -np.inf]
            for c in columns:
                if c == LABEL_COLUMN:
                    labels.extend(chunk[c].astype("string").str.strip().fillna("").astype(str).tolist())
                    continue
                arr = pd.to_numeric(chunk[c], errors="coerce").to_numpy(dtype=np.float32)
                numeric_arrays[c].append(arr)
                valid = ~np.isnan(arr)
                column_stats[c][0] += float(valid.sum())
                if valid.any():
                    column_stats[c][1] = min(column_stats[c][1], float(arr[valid].min()))
                    column_stats[c][2] = max(column_stats[c][2], float(arr[valid].max()))
            total_rows += len(chunk)
            elapsed = time.perf_counter() - scan_started
            print(
                f"[scan] chunk={chunk_index:02d} rows={total_rows:,} "
                f"rate={total_rows / elapsed:,.0f} rows/s elapsed={elapsed:.0f}s",
                flush=True,
            )
    scan_seconds = time.perf_counter() - scan_started
    print(f"[scan] done: {total_rows:,} rows in {scan_seconds:.1f}s", flush=True)
    del reader

    # ---------- select numeric features ----------
    numeric_features = [
        c
        for c in columns
        if c != LABEL_COLUMN
        and c not in IDENTIFIER_COLUMNS
        and column_stats[c][0] / max(total_rows, 1) >= 0.8
        and column_stats[c][1] < column_stats[c][2]
    ]
    dropped = [c for c in columns if c != LABEL_COLUMN and c not in numeric_features]
    print(f"[features] numeric={len(numeric_features)} dropped={len(dropped)}", flush=True)
    if dropped:
        print(f"[features] dropped: {', '.join(dropped)}", flush=True)
    if not numeric_features:
        raise ValueError("No usable numeric features found")

    # ---------- stack into one float32 matrix ----------
    label_array = np.asarray(labels, dtype=object)
    del labels
    features = np.empty((total_rows, len(numeric_features)), dtype=np.float32)
    for index, c in enumerate(numeric_features):
        features[:, index] = np.concatenate(numeric_arrays[c])
    del numeric_arrays

    # ---------- label distribution + rare-class guard ----------
    counts = Counter(label_array.tolist())
    print("[labels] distribution:", flush=True)
    for label, count in sorted(counts.items(), key=lambda item: -item[1]):
        print(f"  {label:<24} {count:>9,}  ({count / total_rows:6.1%})", flush=True)
    rare = [label for label, count in counts.items() if count < 8]
    if rare:
        print(f"[labels] WARNING: excluding classes with <8 rows (unsplittable): {rare}", flush=True)
    keep_labels = np.asarray([label for label in counts if counts[label] >= 8], dtype=object)
    keep_mask = np.isin(label_array, keep_labels)
    y = label_array[keep_mask].astype(str)
    x = features[keep_mask]
    print(f"[labels] kept={len(y):,} rows across {len(keep_labels)} classes", flush=True)
    del features, label_array

    # ---------- optional deterministic per-class cap ----------
    if args.max_rows > 0:
        quotas = _class_quotas(dict(Counter(y.tolist())), max_rows=args.max_rows)
        rng = np.random.default_rng(args.random_seed)
        priority = rng.random(len(y))
        keep_idx: list[np.ndarray] = []
        for label, quota in quotas.items():
            idx = np.where(y == label)[0]
            if quota >= len(idx):
                keep_idx.append(idx)
            else:
                keep_idx.append(idx[np.argpartition(priority[idx], quota)[:quota]])
        keep_idx = np.concatenate(keep_idx)
        x, y = x[keep_idx], y[keep_idx]
        print(f"[sample] kept {len(y):,} rows via deterministic per-class quotas", flush=True)

    # ---------- impute + split ----------
    nan_counts = int(np.isnan(x).sum())
    if nan_counts:
        print(f"[impute] filling {nan_counts:,} NaN cells with column medians", flush=True)
        col_medians = np.nanmedian(x, axis=0)
        x = np.where(np.isnan(x), col_medians, x)

    from sklearn.model_selection import train_test_split

    train_validation_x, test_x, train_validation_y, test_y = train_test_split(
        x, y, test_size=0.15, random_state=args.random_seed, stratify=y
    )
    train_x, validation_x, train_y, validation_y = train_test_split(
        train_validation_x,
        train_validation_y,
        test_size=0.15 / 0.85,
        random_state=args.random_seed + 1,
        stratify=train_validation_y,
    )
    del train_validation_x, train_validation_y
    print(
        f"[split] train={len(train_x):,} validation={len(validation_x):,} test={len(test_x):,} "
        f"(70/15/15 stratified)",
        flush=True,
    )

    # ---------- fit ----------
    from sklearn.ensemble import HistGradientBoostingClassifier

    clf = HistGradientBoostingClassifier(
        learning_rate=args.learning_rate,
        max_iter=args.max_iter,
        max_leaf_nodes=args.max_leaf_nodes,
        l2_regularization=args.l2,
        class_weight="balanced",
        early_stopping=True,
        validation_fraction=0.1,
        random_state=args.random_seed,
    )
    stop_event = threading.Event()
    ticker = threading.Thread(
        target=_fit_ticker,
        args=(f"HistGradientBoosting on {len(train_x):,} rows (early stopping on)", stop_event),
        daemon=True,
    )
    ticker.start()
    fit_started = time.perf_counter()
    clf.fit(train_x, train_y)
    stop_event.set()
    ticker.join(timeout=2)
    fit_seconds = time.perf_counter() - fit_started
    print(f"[fit] completed in {fit_seconds:.1f}s (iterations used: {clf.n_iter_})", flush=True)

    # ---------- evaluate ----------
    from sklearn.metrics import (
        accuracy_score,
        average_precision_score,
        balanced_accuracy_score,
        confusion_matrix,
        f1_score,
        precision_recall_fscore_support,
        roc_auc_score,
    )

    validation_prediction = clf.predict(validation_x)
    prediction_started = time.perf_counter()
    test_prediction = clf.predict(test_x)
    test_proba = clf.predict_proba(test_x)
    prediction_seconds = time.perf_counter() - prediction_started

    from sklearn.metrics import precision_score, recall_score

    class_labels = sorted(set(np.concatenate([train_y, validation_y, test_y])).union(set(clf.classes_)))
    precision, recall, f1, support = precision_recall_fscore_support(
        test_y, test_prediction, labels=class_labels, zero_division=0
    )
    # Robust OvR AUC: restrict to classes actually present in the test set.
    test_classes = sorted(set(test_y))
    proba_classes = list(clf.classes_)
    missing = [c for c in proba_classes if c not in test_classes]
    if missing:
        print(f"[warn] classes absent from test set (skipped in OvR AUC): {missing}", flush=True)
        keep_columns = [i for i, c in enumerate(proba_classes) if c in test_classes]
        auc_proba = test_proba[:, keep_columns]
    else:
        auc_proba = test_proba
    if len(test_classes) >= 2:
        ovr_roc_auc = float(
            roc_auc_score(test_y, auc_proba, multi_class="ovr", average="macro", labels=test_classes)
        )
        ovr_pr_auc = float(average_precision_score(test_y, auc_proba, average="macro"))
    else:
        ovr_roc_auc = float("nan")
        ovr_pr_auc = float("nan")
    metrics = {
        "accuracy": float(accuracy_score(test_y, test_prediction)),
        "balanced_accuracy": float(balanced_accuracy_score(test_y, test_prediction)),
        "macro_precision": float(precision_score(test_y, test_prediction, average="macro", zero_division=0)),
        "macro_recall": float(recall_score(test_y, test_prediction, average="macro", zero_division=0)),
        "macro_f1": float(f1_score(test_y, test_prediction, average="macro", zero_division=0)),
        "weighted_f1": float(f1_score(test_y, test_prediction, average="weighted", zero_division=0)),
        "validation_macro_f1": float(
            f1_score(validation_y, validation_prediction, average="macro", zero_division=0)
        ),
        "ovr_roc_auc": ovr_roc_auc,
        "ovr_pr_auc": ovr_pr_auc,
        "train_rows": int(len(train_x)),
        "validation_rows": int(len(validation_x)),
        "test_rows": int(len(test_x)),
        "total_rows": int(total_rows),
        "feature_count": len(numeric_features),
        "labels": class_labels,
        "class_metrics": [
            {
                "label": label,
                "support": int(support[i]),
                "precision": float(precision[i]),
                "recall": float(recall[i]),
                "f1": float(f1[i]),
            }
            for i, label in enumerate(class_labels)
        ],
        "confusion_matrix": confusion_matrix(test_y, test_prediction, labels=class_labels)
        .astype(int)
        .tolist(),
        "numeric_features": numeric_features,
        "dropped_features": dropped,
        "fit_seconds": fit_seconds,
        "scan_seconds": scan_seconds,
        "predict_seconds": prediction_seconds,
    }

    print("-" * 78, flush=True)
    print(
        f"[val]   macro_f1={metrics['validation_macro_f1']:.4f}",
        flush=True,
    )
    print(
        f"[test]  accuracy={metrics['accuracy']:.4f}  balanced_accuracy={metrics['balanced_accuracy']:.4f}",
        flush=True,
    )
    print(
        f"[test]  macro P/R/F1 = {metrics['macro_precision']:.4f} / {metrics['macro_recall']:.4f} / {metrics['macro_f1']:.4f}   "
        f"weighted_f1={metrics['weighted_f1']:.4f}",
        flush=True,
    )
    print(
        f"[test]  OvR ROC-AUC={metrics['ovr_roc_auc']:.4f}   OvR PR-AUC={metrics['ovr_pr_auc']:.4f}",
        flush=True,
    )
    print("[test]  per class:", flush=True)
    for row in metrics["class_metrics"]:
        print(
            f"  {row['label']:<24} support={row['support']:>8,}  "
            f"precision={row['precision']:>6.3f}  recall={row['recall']:>6.3f}  f1={row['f1']:>6.3f}",
            flush=True,
        )

    # ---------- persist ----------
    import joblib
    import sklearn

    run_id = f"TRN-FULL-BASE-{uuid.uuid4().hex.upper()[:12]}"
    run_dir = args.output_dir.resolve() / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    artifact_path = run_dir / "model.joblib"
    payload = {
        "formatVersion": 1,
        "task": "known_attack_classification_baseline",
        "algorithm": "hist_gradient_boosting",
        "run_id": run_id,
        "pipeline": clf,
        "config": {
            "maxRows": args.max_rows,
            "maxIter": args.max_iter,
            "learningRate": args.learning_rate,
            "maxLeafNodes": args.max_leaf_nodes,
            "l2Regularization": args.l2,
            "randomSeed": args.random_seed,
            "classWeight": "balanced",
            "earlyStopping": True,
            "csvPath": str(path),
            "csvSha256": csv_sha256,
        },
        "runtime_versions": {
            "python": platform.python_version(),
            "numpy": np.__version__,
            "pandas": pd.__version__,
            "scikitLearn": sklearn.__version__,
            "joblib": joblib.__version__,
        },
        "metrics": metrics,
    }
    joblib.dump(payload, artifact_path, compress=3)
    metadata = {k: v for k, v in payload.items() if k != "pipeline"}
    metadata["artifactSha256"] = _sha256(artifact_path)
    (run_dir / "metadata.json").write_text(json.dumps(metadata, ensure_ascii=False, indent=2), encoding="utf-8")
    summary_dir = args.output_dir.resolve()
    (summary_dir / "full-latest-summary.json").write_text(
        json.dumps(metadata, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(f"[artifact] {artifact_path}", flush=True)
    print(f"[sha256]   {metadata['artifactSha256']}", flush=True)
    print(f"[complete] {run_id} succeeded", flush=True)


if __name__ == "__main__":
    main()
