"""Compute the multi-FPR operating-point table for the trained FULL AutoEncoder.

Loads the persisted artifact (preprocessor + model state), re-reads the full CSV,
calibrates thresholds on a fixed 400k random normal subset at target FPRs of
0.5/1/2/5/10%, and evaluates attack recall / precision / F1 / held-out normal FPR.
This is a post-hoc diagnostic: thresholds are calibrated on a fresh normal subset
(documented below), not the exact training validation split.
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, r"D:\IDS System\backend")
from app.services.autoencoder import _clip_float32, model_from_artifact, reconstruction_errors  # noqa: E402

ARTIFACT = Path(r"D:\test-harness\evonids-full-training\artifacts\autoencoder\TRN-AE-FULL-C02138437669\model.joblib")
CSV = Path(r"D:\test-harness\evonids-full-training\data\CICIDS2017\cicids2017_pcap_flow_full_v1.csv.gz")
OUT = Path(r"D:\test-harness\evonids-full-training\artifacts\autoencoder\TRN-AE-FULL-C02138437669\operating-points.json")
TARGET_FPRS = (0.005, 0.01, 0.02, 0.05, 0.10)
CALIBRATION_ROWS = 400_000
HELDOUT_ROWS = 400_000
SEED = 20260814


def main() -> None:
    import joblib

    started = time.perf_counter()
    print("=" * 78, flush=True)
    print("EvoNIDS AutoEncoder 多FPR操作点表（基于已训练产物）", flush=True)
    print(f"artifact : {ARTIFACT}", flush=True)
    print(f"csv      : {CSV}", flush=True)
    print(f"说明     : 阈值在 {CALIBRATION_ROWS:,} 条随机正常流上按 1-FPR 分位校准；", flush=True)
    print(f"          hold-out 正常流 {HELDOUT_ROWS:,} 条 + 全部攻击流独立评估", flush=True)
    print("=" * 78, flush=True)

    artifact = joblib.load(ARTIFACT)
    model = model_from_artifact(artifact)
    preprocessor = artifact["preprocessor"]
    features = list(artifact["numericFeatures"])
    print(f"[artifact] 特征数={len(features)} 训练阈值={artifact['threshold']:.6f}", flush=True)

    print("[load] 读取完整数据集 ...", flush=True)
    frame = pd.read_csv(CSV, usecols=[*features, "Label"], compression="infer", low_memory=False)
    labels = frame["Label"].astype("string").str.strip()
    print(f"[load] rows={len(frame):,}  elapsed={time.perf_counter() - started:.0f}s", flush=True)

    rng = np.random.default_rng(SEED)
    normal_index = np.where(labels == "BENIGN")[0]
    rng.shuffle(normal_index)
    calibration_index = normal_index[:CALIBRATION_ROWS]
    heldout_index = normal_index[CALIBRATION_ROWS : CALIBRATION_ROWS + HELDOUT_ROWS]
    attack_index = np.where(labels != "BENIGN")[0]
    print(
        f"[split] 校准正常流={len(calibration_index):,}  hold-out正常流={len(heldout_index):,}  攻击流={len(attack_index):,}",
        flush=True,
    )

    def errors_of(index: np.ndarray) -> np.ndarray:
        numeric = pd.DataFrame(
            {
                column: pd.to_numeric(frame.loc[index, column], errors="coerce")
                for column in features
            }
        )
        transformed = _clip_float32(preprocessor.transform(numeric), np=np)
        errors, _ = reconstruction_errors(model, transformed, np=np)
        return errors

    print("[compute] 校准集重建误差 ...", flush=True)
    calibration_errors = errors_of(calibration_index)
    print("[compute] hold-out 正常集重建误差 ...", flush=True)
    heldout_errors = errors_of(heldout_index)
    print("[compute] 攻击集重建误差（全量攻击）...", flush=True)
    attack_errors = errors_of(attack_index)

    rows: list[dict[str, float | int]] = []
    print("-" * 78, flush=True)
    print(f"{'target_fpr':>10}  {'threshold':>10}  {'attack_recall':>13}  {'precision':>9}  {'f1':>7}  {'actual_normal_fpr':>17}", flush=True)
    for fpr in TARGET_FPRS:
        threshold = float(np.quantile(calibration_errors, 1.0 - fpr))
        attack_prediction = attack_errors > threshold
        heldout_prediction = heldout_errors > threshold
        true_positive = int(attack_prediction.sum())
        false_negative = int((~attack_prediction).sum())
        false_positive = int(heldout_prediction.sum())
        true_negative = int((~heldout_prediction).sum())
        recall = true_positive / (true_positive + false_negative)
        precision = true_positive / (true_positive + false_positive) if true_positive + false_positive else 0.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        actual_fpr = false_positive / (false_positive + true_negative)
        rows.append(
            {
                "target_fpr": fpr,
                "threshold": threshold,
                "attack_recall": float(recall),
                "precision": float(precision),
                "f1": float(f1),
                "actual_normal_fpr": float(actual_fpr),
                "detected_attacks": true_positive,
            }
        )
        print(
            f"{fpr:>9.1%}  {threshold:>10.6f}  {recall:>12.2%}  {precision:>9.2%}  {f1:>7.3f}  {actual_fpr:>16.2%}",
            flush=True,
        )

    payload = {
        "method": "post-hoc operating points from the persisted FULL AutoEncoder artifact",
        "artifactSha256": None,
        "calibration": {
            "source": "fresh random normal subset of the full extracted CSV",
            "rows": int(len(calibration_index)),
            "seed": SEED,
            "note": "not the training validation split; thresholds calibrated at 1-FPR quantiles",
        },
        "heldoutNormalRows": int(len(heldout_index)),
        "attackRows": int(len(attack_index)),
        "rows": rows,
    }
    OUT.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    print("-" * 78, flush=True)
    print(f"[complete] {OUT}", flush=True)
    print(f"[complete] elapsed={time.perf_counter() - started:.0f}s", flush=True)


if __name__ == "__main__":
    main()
