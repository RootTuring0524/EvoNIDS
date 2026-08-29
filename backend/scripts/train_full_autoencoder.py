"""Train the MLP AutoEncoder (unknown-anomaly detection) on the FULL CICIDS2017 flow table.

Standalone wrapper around app.services.autoencoder.train_autoencoder with the threshold bug fixed:
  * the decision threshold is now selected on the VALIDATION set at a target normal
    false-positive rate (default 5% FPR -> quantile 0.95), instead of the previous hard
    quantiles (0.995/0.95 without FPR awareness) that produced 1.9% attack recall;
  * real-time console output: chunk loading + per-epoch loss/ETA;
  * honest metrics: attack recall / precision / F1 / normal FPR / AUROC / AUPRC / per-class recall.
"""
from __future__ import annotations

import argparse
import sys
import uuid
from pathlib import Path

HERE = Path(__file__).resolve().parent
BACKEND_DIR = HERE.parent
sys.path.insert(0, str(BACKEND_DIR))

from app.services.autoencoder import (  # noqa: E402
    ALGORITHM,
    FEATURE_VERSION,
    TASK,
    sha256_file,
    train_autoencoder,
    write_artifact,
)

IDENTIFIER_FEATURES = {"capture_day", "source_ip", "destination_ip", "start_time"}
LABEL_COLUMN = "Label"
DEFAULT_CSV = HERE.parent / "data" / "CICIDS2017" / "cicids2017_pcap_flow_full_v1.csv.gz"
DEFAULT_OUTPUT = HERE.parent / "artifacts" / "autoencoder"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--csv", type=Path, default=DEFAULT_CSV)
    parser.add_argument("--target-fpr", type=float, default=0.05, help="threshold = validation quantile at 1-FPR")
    parser.add_argument("--epochs", type=int, default=40)
    parser.add_argument("--patience", type=int, default=6)
    parser.add_argument("--batch-size", type=int, default=1024)
    parser.add_argument("--learning-rate", type=float, default=0.001)
    parser.add_argument("--bottleneck-size", type=int, default=8)
    parser.add_argument("--cap-normal", type=int, default=0, help="max normal training flows (0 = ALL)")
    parser.add_argument("--cap-attack", type=int, default=0, help="max attack eval flows (0 = ALL)")
    parser.add_argument("--random-seed", type=int, default=20260728)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--smoke", action="store_true", help="tiny fast run for script verification")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.smoke:
        args.cap_normal = min(args.cap_normal, 5_000) if args.cap_normal else 5_000
        args.cap_attack = min(args.cap_attack, 10_000) if args.cap_attack else 10_000
        args.epochs = min(args.epochs, 2)
        args.patience = min(args.patience, 2)

    import pandas as pd

    path = args.csv.resolve()
    if not path.is_file():
        raise FileNotFoundError(f"missing csv: {path}")
    if not 0 < args.target_fpr < 0.2:
        raise ValueError("--target-fpr must be in (0, 0.2)")
    threshold_quantile = round(1.0 - args.target_fpr, 4)

    header = pd.read_csv(path, nrows=0, compression="infer")
    columns = [str(c).strip() for c in header.columns]
    if LABEL_COLUMN not in columns:
        raise ValueError(f"label column {LABEL_COLUMN} not found")
    sample = pd.read_csv(path, nrows=3000, usecols=[c for c in columns if c not in IDENTIFIER_FEATURES and c != LABEL_COLUMN], compression="infer")
    numeric_features = [
        str(c)
        for c in sample.columns
        if pd.to_numeric(sample[c], errors="coerce").notna().mean() >= 0.8
        and pd.to_numeric(sample[c], errors="coerce").nunique(dropna=True) > 1
    ]
    if not numeric_features:
        raise ValueError("No usable numeric features found")

    run_id = f"TRN-AE-FULL-{uuid.uuid4().hex.upper()[:12]}"
    print("=" * 78, flush=True)
    print("EvoNIDS FULL AutoEncoder training (unknown-anomaly detection, PyTorch CPU)", flush=True)
    print(f"run_id        : {run_id}", flush=True)
    print(f"csv           : {path}", flush=True)
    print(f"features      : {len(numeric_features)}", flush=True)
    print(f"target FPR    : {args.target_fpr:.1%}  ->  threshold quantile {threshold_quantile} (validation set)", flush=True)
    print(f"epochs/batch  : {args.epochs} / {args.batch_size}  (early-stop patience={args.patience})", flush=True)
    print(f"normal cap    : {args.cap_normal or 'ALL'}   attack cap: {args.cap_attack or 'ALL'}", flush=True)
    print("=" * 78, flush=True)

    print("[sha256] hashing dataset ...", flush=True)
    csv_sha256 = sha256_file(path)
    print(f"[sha256] {csv_sha256}", flush=True)

    def report(event: dict) -> None:
        if event["stage"] == "loading":
            print(
                f"[load] chunk={event['chunk']:02d} rows={event['samplesSeen']:,} "
                f"normal_seen={event['normalSeen']:,} attack_labels={event['attackLabelsSeen']}",
                flush=True,
            )
        elif event["stage"] == "training":
            print(
                f"[epoch {event['epoch']:02d}/{event['maxEpochs']:02d}] "
                f"train_mse={event['trainLoss']:.6f} val_mse={event['validationLoss']:.6f} "
                f"best={event['bestValidationLoss']:.6f} stale={event['staleEpochs']} eta={event['etaSeconds']:.0f}s",
                flush=True,
            )

    result = train_autoencoder(
        path,
        label_column=LABEL_COLUMN,
        normal_labels=["BENIGN"],
        numeric_features=numeric_features,
        split={"train": 70, "validation": 15, "test": 15},
        random_seed=args.random_seed,
        max_normal_rows=args.cap_normal if args.cap_normal > 0 else 10_000_000,
        max_attack_rows=args.cap_attack if args.cap_attack > 0 else 10_000_000,
        max_epochs=args.epochs,
        patience=args.patience,
        batch_size=args.batch_size,
        learning_rate=args.learning_rate,
        bottleneck_size=args.bottleneck_size,
        threshold_quantile=threshold_quantile,
        progress=report,
    )

    metrics = result["metrics"]
    config = {
        "framework": "pytorch-cpu",
        "targetFpr": args.target_fpr,
        "thresholdQuantile": threshold_quantile,
        "maxNormalRows": args.cap_normal,
        "maxAttackRows": args.cap_attack,
        "maxEpochs": args.epochs,
        "patience": args.patience,
        "batchSize": args.batch_size,
        "learningRate": args.learning_rate,
        "bottleneckSize": args.bottleneck_size,
        "randomSeed": args.random_seed,
        "csvPath": str(path),
        "csvSha256": csv_sha256,
    }
    dataset_info = {
        "id": "DS-CIC-2017-PCAP-FULL",
        "name": "CICIDS2017 PCAP Flow Research Set (full working hours, no sampling)",
        "version": "full-working-hours-v1",
        "sha256": csv_sha256,
        "labelColumn": LABEL_COLUMN,
        "normalLabels": ["BENIGN"],
    }
    artifact_path = args.output_dir.resolve() / run_id / "model.joblib"
    artifact_sha256, metadata_path = write_artifact(
        artifact_path,
        run_id=run_id,
        dataset=dataset_info,
        config=config,
        result=result,
    )

    print("-" * 78, flush=True)
    print(
        f"[result] threshold={metrics['threshold']:.6f}  "
        f"attack_recall={metrics['recall']:.2%}  "
        f"precision={metrics['precision']:.2%}  "
        f"f1={metrics['f1']:.4f}  "
        f"normal_fpr={metrics['normal_false_positive_rate']:.2%}",
        flush=True,
    )
    print(
        f"[result] AUROC={metrics['roc_auc']:.4f}  AUPRC={metrics['average_precision']:.4f}  "
        f"epochs_completed={metrics['epochs_completed']}  train_seconds={metrics['train_seconds']:.1f}",
        flush=True,
    )
    print("[result] per attack class:", flush=True)
    for row in metrics["per_attack_class"]:
        print(
            f"  {row['label']:<24} support={row['support']:>7,}  detected={row['detected']:>7,}  "
            f"recall={row['recall']:>7.2%}  median_err={row['median_error']:.4f}",
            flush=True,
        )
    print(f"[artifact] {artifact_path}", flush=True)
    print(f"[sha256]   {artifact_sha256}", flush=True)
    print(f"[complete] {run_id} succeeded", flush=True)


if __name__ == "__main__":
    main()
