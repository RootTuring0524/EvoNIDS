from __future__ import annotations

import argparse
import json
import math
import time
import uuid
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
from sqlalchemy import select

from app.db.base import utc_now
from app.db.models import Alert, AuditEvent, DatasetAsset, Flow, Inference, ModelVersion, TrainingRun
from app.db.session import SessionLocal
from app.services.autoencoder import score_frame
from scripts.import_cicids2017_replay import (
    DATASET_ID,
    alert_category,
    collect_rows,
    stable_id,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Score replay flows with the HGB baseline and PyTorch AutoEncoder, then persist fusion evidence."
    )
    parser.add_argument(
        "--dataset",
        type=Path,
        default=Path("./datasets/CICIDS2017/cicids2017_pcap_flow_research_v1.csv.gz"),
    )
    parser.add_argument("--benign-rows", type=int, default=80)
    parser.add_argument("--rows-per-attack", type=int, default=24)
    return parser.parse_args()


def latest_artifact(task: str) -> tuple[TrainingRun, ModelVersion, dict[str, Any]]:
    with SessionLocal() as db:
        run = db.scalar(
            select(TrainingRun)
            .where(
                TrainingRun.dataset_id == DATASET_ID,
                TrainingRun.task == task,
                TrainingRun.state == "succeeded",
            )
            .order_by(TrainingRun.completed_at.desc())
            .limit(1)
        )
        if run is None or not run.artifact_uri or not run.model_id:
            raise RuntimeError(f"No succeeded artifact was found for task {task}")
        model = db.get(ModelVersion, run.model_id)
        if model is None:
            raise RuntimeError(f"Model registry row is missing: {run.model_id}")
        artifact = joblib.load(run.artifact_uri)
        db.expunge(run)
        db.expunge(model)
        return run, model, artifact


def main() -> None:
    args = parse_args()
    dataset_path = args.dataset.resolve()
    rows = collect_rows(
        dataset_path,
        benign_rows=args.benign_rows,
        rows_per_attack=args.rows_per_attack,
    )
    if not rows:
        raise RuntimeError("Replay selection returned no rows")
    frame = pd.DataFrame(rows)
    baseline_run, baseline_model, baseline_artifact = latest_artifact(
        "known_attack_classification_baseline"
    )
    autoencoder_run, autoencoder_model, autoencoder_artifact = latest_artifact(
        "unknown_anomaly_detection"
    )
    with SessionLocal() as db:
        dataset = db.get(DatasetAsset, DATASET_ID)
        if dataset is None:
            raise RuntimeError(f"Dataset registry entry is missing: {DATASET_ID}")
        dataset_sha256 = dataset.sha256

    numeric_features = baseline_artifact["metrics"]["numeric_features"]
    baseline_frame = pd.DataFrame(
        {
            column: pd.to_numeric(frame[column], errors="coerce")
            for column in numeric_features
        }
    )
    baseline_pipeline = baseline_artifact["pipeline"]
    baseline_started = time.perf_counter()
    predictions = np.asarray(baseline_pipeline.predict(baseline_frame), dtype=object)
    probabilities = baseline_pipeline.predict_proba(baseline_frame)
    baseline_seconds = time.perf_counter() - baseline_started
    classes = [str(value) for value in baseline_pipeline.classes_]
    benign_index = classes.index("BENIGN")
    confidences = probabilities.max(axis=1)
    known_risks = 1 - probabilities[:, benign_index]

    autoencoder_started = time.perf_counter()
    autoencoder_result = score_frame(autoencoder_artifact, frame)
    autoencoder_seconds = time.perf_counter() - autoencoder_started
    errors = autoencoder_result["errors"]
    anomaly_scores = autoencoder_result["scores"]
    exceeds = autoencoder_result["exceeds"]
    feature_errors = autoencoder_result["featureErrors"]
    threshold = float(autoencoder_artifact["threshold"])
    feature_names = list(autoencoder_artifact["numericFeatures"])
    feature_baseline = dict(autoencoder_artifact["featureBaseline"])

    print(
        f"[models] known={baseline_model.id} autoencoder={autoencoder_model.id}",
        flush=True,
    )
    print(
        f"[inference] rows={len(rows):,} "
        f"known={baseline_seconds * 1000:.2f}ms "
        f"autoencoder={autoencoder_seconds * 1000:.2f}ms",
        flush=True,
    )

    inference_count = 0
    updated_alert_ids: set[str] = set()
    fusion_distribution: dict[str, int] = {}
    with SessionLocal() as db:
        for index, row in enumerate(rows):
            ground_truth = row["Label"].strip()
            identity = "|".join(
                (
                    DATASET_ID,
                    row["start_time"],
                    row["source_ip"],
                    row["source_port"],
                    row["destination_ip"],
                    row["destination_port"],
                    ground_truth,
                )
            )
            flow_id = stable_id("FLOW-CIC", identity)
            flow = db.get(Flow, flow_id)
            if flow is None:
                continue
            prediction = str(predictions[index])
            confidence = float(confidences[index])
            known_risk = float(known_risks[index])
            error = float(errors[index])
            anomaly_score = float(anomaly_scores[index])
            is_anomaly = bool(exceeds[index])
            top_indices = np.argsort(probabilities[index])[-3:][::-1]
            top_k = [
                {
                    "label": classes[class_index],
                    "probability": float(probabilities[index, class_index]),
                }
                for class_index in top_indices
            ]
            deviation_indices = np.argsort(feature_errors[index])[-5:][::-1]
            deviating_features = [
                {
                    "field": feature_names[feature_index],
                    "observed": safe_float(row.get(feature_names[feature_index])),
                    "baseline": float(feature_baseline.get(feature_names[feature_index], 0.0)),
                    "deviation": float(math.sqrt(feature_errors[index, feature_index])),
                }
                for feature_index in deviation_indices
            ]
            fusion = fuse(
                known_prediction=prediction,
                known_risk=known_risk,
                anomaly_score=anomaly_score,
                exceeds_threshold=is_anomaly,
            )
            fusion_distribution[fusion["lean"]] = fusion_distribution.get(fusion["lean"], 0) + 1
            inference_id = stable_id("INF-DUAL", identity)
            inference = db.get(Inference, inference_id)
            inference_values = {
                "flow_id": flow_id,
                "transformer_model_id": baseline_model.id,
                "autoencoder_model_id": autoencoder_model.id,
                "transformer_output": {
                    "prediction": prediction,
                    "confidence": confidence,
                    "top_k": top_k,
                    "model_version": f"{baseline_model.name} {baseline_model.version}",
                    "inference_ms": baseline_seconds * 1000 / len(rows),
                    "abnormal_features": [],
                    "is_known_class": prediction != "BENIGN" and confidence >= 0.5,
                    "pretraining_task": "Not applicable (CPU baseline)",
                },
                "autoencoder_output": {
                    "reconstruction_error": error,
                    "threshold": threshold,
                    "anomaly_score": anomaly_score,
                    "exceeds_threshold": is_anomaly,
                    "deviating_features": deviating_features,
                    "model_version": f"{autoencoder_model.name} {autoencoder_model.version}",
                    "inference_ms": autoencoder_seconds * 1000 / len(rows),
                    "trained_on": "normal_traffic",
                },
                "fusion_output": fusion,
                "latency_ms": (baseline_seconds + autoencoder_seconds) * 1000 / len(rows),
            }
            if inference is None:
                inference = Inference(id=inference_id, **inference_values)
                db.add(inference)
            else:
                for key, value in inference_values.items():
                    setattr(inference, key, value)

            packet_count = max(
                1,
                int(safe_float(row.get("total_fwd_packets")))
                + int(safe_float(row.get("total_bwd_packets"))),
            )
            flow.features = {
                **flow.features,
                **{
                    feature: safe_float(row.get(feature))
                    for feature in feature_names
                },
                "groundTruthLabel": ground_truth,
                "modelPrediction": prediction,
                "confidence": confidence,
                "knownAttackRisk": known_risk,
                "flow_duration": safe_float(row.get("duration_us")) / 1_000_000,
                "forward_packet_count": int(safe_float(row.get("total_fwd_packets"))),
                "backward_packet_count": int(safe_float(row.get("total_bwd_packets"))),
                "forward_bytes": int(safe_float(row.get("total_fwd_bytes"))),
                "backward_bytes": int(safe_float(row.get("total_bwd_bytes"))),
                "packets_per_second": safe_float(row.get("flow_packets_per_second")),
                "bytes_per_second": safe_float(row.get("flow_bytes_per_second")),
                "syn_ratio": safe_float(row.get("syn_flag_count")) / packet_count,
                "ack_ratio": safe_float(row.get("ack_flag_count")) / packet_count,
                "rst_ratio": safe_float(row.get("rst_flag_count")) / packet_count,
                "average_packet_size": safe_float(row.get("average_packet_size")),
                "autoencoderReconstructionError": error,
                "autoencoderAnomalyScore": anomaly_score,
                "finalRiskScore": fusion["final_score"],
                "baselineTrainingRunId": baseline_run.id,
                "autoencoderTrainingRunId": autoencoder_run.id,
            }
            flow.anomaly_score = float(fusion["final_score"])
            flow.verdict = (
                "malicious"
                if fusion["final_score"] >= 65
                else "suspicious"
                if fusion["final_score"] >= 40
                else "benign"
            )
            inference_count += 1

            alert_id = stable_id("ALERT-CIC", ground_truth)
            alert = db.get(Alert, alert_id)
            if alert is None or alert.flow_id != flow_id:
                continue
            alert.inference_id = inference_id
            alert.risk_score = float(fusion["final_score"])
            alert.confidence = confidence
            alert.detector = f"{baseline_model.id} + {autoencoder_model.id}"
            alert.category = alert_category(ground_truth)
            alert.evidence = [
                f"CPU 已知攻击基线：{prediction}（置信度 {confidence:.2%}）",
                (
                    f"PyTorch AutoEncoder：重构误差 {error:.6f}，"
                    f"阈值 {threshold:.6f}，{'超过' if is_anomaly else '未超过'}阈值"
                ),
                (
                    f"融合结论：{fusion['lean']}，风险 {fusion['final_score']:.2f}/100，"
                    f"通道关系 {fusion['agreement']}"
                ),
                f"CICIDS2017 评估标签：{ground_truth}",
                f"数据 SHA-256：{dataset_sha256}",
            ]
            updated_alert_ids.add(alert.id)

        db.add(
            AuditEvent(
                id=f"AUD-{uuid.uuid4().hex.upper()}",
                created_at=utc_now(),
                actor="dual-channel-backfill",
                action="inference.dual_channel.backfilled",
                object_type="dataset_asset",
                object_id=DATASET_ID,
                outcome="completed",
                request_id="local-dual-channel-backfill",
                before_state=None,
                after_state={
                    "inferences": inference_count,
                    "alerts": len(updated_alert_ids),
                    "knownModelId": baseline_model.id,
                    "autoencoderModelId": autoencoder_model.id,
                    "fusionDistribution": fusion_distribution,
                },
                note=(
                    "Representative replay flows were rescored with the real HGB CPU baseline "
                    "and PyTorch AutoEncoder; fusion evidence was persisted without claiming a Transformer run."
                ),
            )
        )
        db.commit()
    print(
        "[complete] "
        + json.dumps(
            {
                "inferences": inference_count,
                "alerts": len(updated_alert_ids),
                "fusionDistribution": fusion_distribution,
                "knownModelId": baseline_model.id,
                "autoencoderModelId": autoencoder_model.id,
            },
            ensure_ascii=False,
        ),
        flush=True,
    )


def fuse(
    *,
    known_prediction: str,
    known_risk: float,
    anomaly_score: float,
    exceeds_threshold: bool,
) -> dict[str, Any]:
    known_attack = known_prediction != "BENIGN"
    if known_attack and exceeds_threshold:
        transformer_weight, autoencoder_weight = 0.65, 0.35
        agreement = "consistent"
        lean = "dual_confirmed"
        explanation = (
            "CPU classification baseline and normal-traffic AutoEncoder both report attack evidence. "
            "The baseline supplies the known class; the AutoEncoder independently confirms distribution shift."
        )
    elif known_attack:
        transformer_weight, autoencoder_weight = 0.8, 0.2
        agreement = "partial"
        lean = "known_attack"
        explanation = (
            "The CPU classification baseline identifies a known attack, while the AutoEncoder remains "
            "inside its normal reconstruction threshold. The known-class result therefore carries more weight."
        )
    elif exceeds_threshold:
        transformer_weight, autoencoder_weight = 0.3, 0.7
        agreement = "conflicting"
        lean = "unknown_anomaly"
        explanation = (
            "The classifier predicts BENIGN but the normal-traffic AutoEncoder exceeds its threshold. "
            "This flow is retained as an unknown-anomaly candidate for Agent and analyst review."
        )
    else:
        transformer_weight, autoencoder_weight = 0.7, 0.3
        agreement = "consistent"
        lean = "normal"
        explanation = (
            "Both the CPU classification baseline and AutoEncoder remain within their normal decision regions."
        )
    final_score = 100 * (
        transformer_weight * known_risk + autoencoder_weight * anomaly_score
    )
    return {
        "final_score": round(float(min(100, max(0, final_score))), 2),
        "transformer_weight": transformer_weight,
        "auto_encoder_weight": autoencoder_weight,
        "context_adjustment": 0.0,
        "agreement": agreement,
        "lean": lean,
        "explanation": explanation,
    }


def safe_float(value: Any) -> float:
    try:
        result = float(value)
        return result if math.isfinite(result) else 0.0
    except (TypeError, ValueError):
        return 0.0


if __name__ == "__main__":
    main()
