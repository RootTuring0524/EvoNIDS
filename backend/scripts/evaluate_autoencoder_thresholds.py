from __future__ import annotations

import argparse
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sqlalchemy import select

from app.db.models import TrainingRun
from app.db.session import SessionLocal
from app.services.autoencoder import score_frame


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Evaluate AutoEncoder reconstruction-error thresholds over the full labeled flow table."
    )
    parser.add_argument(
        "--dataset",
        type=Path,
        default=Path("./datasets/CICIDS2017/cicids2017_pcap_flow_research_v1.csv.gz"),
    )
    parser.add_argument("--run-id")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    with SessionLocal() as db:
        if args.run_id:
            run = db.get(TrainingRun, args.run_id)
        else:
            run = db.scalar(
                select(TrainingRun)
                .where(
                    TrainingRun.task == "unknown_anomaly_detection",
                    TrainingRun.state == "succeeded",
                )
                .order_by(TrainingRun.completed_at.desc())
                .limit(1)
            )
        if run is None or not run.artifact_uri:
            raise RuntimeError("No succeeded AutoEncoder training artifact was found")
        artifact_path = Path(run.artifact_uri)
        run_id = run.id
    artifact = joblib.load(artifact_path)
    errors: list[np.ndarray] = []
    normal_mask_parts: list[np.ndarray] = []
    labels: list[np.ndarray] = []
    rows = 0
    for chunk_index, chunk in enumerate(
        pd.read_csv(args.dataset, compression="infer", chunksize=100_000, low_memory=False),
        start=1,
    ):
        result = score_frame(artifact, chunk)
        chunk_labels = chunk["Label"].astype("string").str.strip().fillna("<missing>").to_numpy()
        errors.append(result["errors"])
        normal_mask_parts.append(chunk_labels == "BENIGN")
        labels.append(chunk_labels)
        rows += len(chunk)
        print(f"[score] chunk={chunk_index:02d} rows={rows:,}", flush=True)

    all_errors = np.concatenate(errors)
    all_normal = np.concatenate(normal_mask_parts)
    all_labels = np.concatenate(labels)
    normal_errors = all_errors[all_normal]
    attack_errors = all_errors[~all_normal]
    print(f"[run] {run_id}", flush=True)
    print(
        f"[distribution] normal={len(normal_errors):,} attack={len(attack_errors):,} "
        f"normal_median={np.median(normal_errors):.6f} attack_median={np.median(attack_errors):.6f}",
        flush=True,
    )
    print("quantile  threshold    normal_fpr  attack_recall  precision   f1", flush=True)
    for quantile in (0.90, 0.925, 0.95, 0.975, 0.98, 0.985, 0.99, 0.995):
        threshold = float(np.quantile(normal_errors, quantile))
        normal_fpr = float((normal_errors > threshold).mean())
        attack_recall = float((attack_errors > threshold).mean())
        true_positive = int((attack_errors > threshold).sum())
        false_positive = int((normal_errors > threshold).sum())
        precision = true_positive / max(1, true_positive + false_positive)
        f1 = 2 * precision * attack_recall / max(1e-12, precision + attack_recall)
        print(
            f"{quantile:>7.3f}  {threshold:>10.6f}  {normal_fpr:>10.4%}  "
            f"{attack_recall:>13.4%}  {precision:>9.4%}  {f1:>7.4%}",
            flush=True,
        )
    print("[per-class @ normal q97.5]", flush=True)
    threshold = float(np.quantile(normal_errors, 0.975))
    for label in sorted(set(all_labels[~all_normal])):
        selected = all_labels == label
        class_errors = all_errors[selected]
        print(
            f"  {label:<34} support={len(class_errors):>7,} "
            f"recall={(class_errors > threshold).mean():>8.3%} "
            f"median_error={np.median(class_errors):.6f}",
            flush=True,
        )


if __name__ == "__main__":
    main()
