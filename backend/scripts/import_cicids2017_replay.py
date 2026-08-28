from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import json
import uuid
from collections import Counter
from datetime import timedelta
from pathlib import Path
from typing import Any

from sqlalchemy import select

from app.db.base import utc_now
from app.db.models import Alert, AuditEvent, DatasetAsset, Flow, Sensor, TrainingRun
from app.db.session import SessionLocal


DATASET_ID = "DS-CIC-2017-PCAP-V1"
SENSOR_ID = "SENSOR-CICIDS2017-REPLAY"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run the latest real baseline artifact over representative CICIDS2017 flows and import a replay."
    )
    parser.add_argument(
        "--dataset",
        type=Path,
        default=Path("./datasets/CICIDS2017/cicids2017_pcap_flow_research_v1.csv.gz"),
    )
    parser.add_argument("--benign-rows", type=int, default=80)
    parser.add_argument("--rows-per-attack", type=int, default=24)
    return parser.parse_args()


def stable_id(prefix: str, value: str) -> str:
    digest = hashlib.blake2b(value.encode("utf-8"), digest_size=10).hexdigest().upper()
    return f"{prefix}-{digest}"


def collect_rows(path: Path, *, benign_rows: int, rows_per_attack: int) -> list[dict[str, str]]:
    selected: list[dict[str, str]] = []
    counts: Counter[str] = Counter()
    opener = gzip.open if path.name.lower().endswith(".gz") else open
    with opener(path, "rt", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            label = row["Label"].strip()
            quota = benign_rows if label == "BENIGN" else rows_per_attack
            if counts[label] >= quota:
                continue
            identity = "|".join(
                (
                    row["capture_day"],
                    row["start_time"],
                    row["source_ip"],
                    row["source_port"],
                    row["destination_ip"],
                    row["destination_port"],
                    label,
                )
            )
            # Keep a deterministic spread instead of the first burst of every class.
            if int.from_bytes(hashlib.blake2b(identity.encode(), digest_size=2).digest(), "big") % 5:
                continue
            selected.append(row)
            counts[label] += 1
    print(f"[select] replay rows={len(selected):,} labels={dict(sorted(counts.items()))}", flush=True)
    return selected


def load_latest_artifact() -> tuple[TrainingRun, DatasetAsset, dict[str, Any]]:
    import joblib

    with SessionLocal() as db:
        run = db.scalar(
            select(TrainingRun)
            .where(
                TrainingRun.dataset_id == DATASET_ID,
                TrainingRun.task == "known_attack_classification_baseline",
                TrainingRun.state == "succeeded",
            )
            .order_by(TrainingRun.completed_at.desc())
            .limit(1)
        )
        if run is None or not run.artifact_uri:
            raise RuntimeError("No succeeded CICIDS2017 training run with a local artifact was found")
        dataset = db.get(DatasetAsset, DATASET_ID)
        if dataset is None:
            raise RuntimeError(f"Dataset registry entry is missing: {DATASET_ID}")
        artifact_path = Path(run.artifact_uri)
        if not artifact_path.is_file():
            raise FileNotFoundError(f"Model artifact is missing: {artifact_path}")
        payload = joblib.load(artifact_path)
        db.expunge(run)
        db.expunge(dataset)
        return run, dataset, payload


def predict(rows: list[dict[str, str]], artifact: dict[str, Any]) -> tuple[list[str], list[float]]:
    import numpy as np
    import pandas as pd

    numeric_features = artifact["metrics"]["numeric_features"]
    frame = pd.DataFrame(
        {
            column: pd.to_numeric([row.get(column) for row in rows], errors="coerce")
            for column in numeric_features
        }
    )
    pipeline = artifact["pipeline"]
    predictions = [str(value) for value in pipeline.predict(frame)]
    if hasattr(pipeline, "predict_proba"):
        probabilities = pipeline.predict_proba(frame)
        confidence = np.max(probabilities, axis=1).astype(float).tolist()
    else:
        confidence = [1.0] * len(predictions)
    return predictions, confidence


def protocol_name(value: str) -> str:
    return {"6": "TCP", "17": "UDP", "1": "ICMP"}.get(value, f"IP-{value}")


def service_name(protocol: str, destination_port: int) -> str:
    if protocol == "ICMP":
        return "icmp"
    return {
        21: "ftp",
        22: "ssh",
        25: "smtp",
        53: "dns",
        80: "http",
        110: "pop3",
        143: "imap",
        443: "https",
        444: "heartbleed-lab",
    }.get(destination_port, "unknown")


def alert_category(label: str) -> str:
    if label == "DDoS":
        return "DDoS"
    if label.startswith("DoS "):
        return "DoS"
    if label in {"FTP-Patator", "SSH-Patator"}:
        return "Brute Force"
    if label.startswith("Web Attack "):
        return "Web Attack"
    if label == "PortScan":
        return "Port Scan"
    if label == "Infiltration":
        return "Infiltration"
    if label == "Bot":
        return "Botnet"
    return "Unknown Anomaly"


def upsert_replay(
    *,
    rows: list[dict[str, str]],
    predictions: list[str],
    confidence: list[float],
    run: TrainingRun,
    dataset: DatasetAsset,
) -> dict[str, int]:
    now = utc_now()
    flow_count = 0
    alert_count = 0
    with SessionLocal() as db:
        alert_labels_done: set[str] = set()
        sensor = db.get(Sensor, SENSOR_ID)
        if sensor is None:
            sensor = Sensor(
                id=SENSOR_ID,
                name="CICIDS2017 受控回放传感器",
                location="本机离线实验区",
                version="pcap-replay-v1",
                state="online",
                last_seen_at=now,
                metadata_json={
                    "mode": "offline_replay",
                    "datasetId": dataset.id,
                    "datasetSha256": dataset.sha256,
                    "trainingRunId": run.id,
                },
            )
            db.add(sensor)
        else:
            sensor.state = "online"
            sensor.last_seen_at = now
            sensor.metadata_json = {
                **sensor.metadata_json,
                "datasetId": dataset.id,
                "datasetSha256": dataset.sha256,
                "trainingRunId": run.id,
            }
        for index, (row, prediction, score) in enumerate(zip(rows, predictions, confidence, strict=True)):
            ground_truth = row["Label"].strip()
            identity = "|".join(
                (
                    dataset.id,
                    row["start_time"],
                    row["source_ip"],
                    row["source_port"],
                    row["destination_ip"],
                    row["destination_port"],
                    ground_truth,
                )
            )
            flow_id = stable_id("FLOW-CIC", identity)
            protocol = protocol_name(row["protocol"])
            source_port = int(float(row["source_port"]))
            destination_port = int(float(row["destination_port"]))
            packets = int(float(row["total_fwd_packets"])) + int(float(row["total_bwd_packets"]))
            byte_count = int(float(row["total_fwd_bytes"])) + int(float(row["total_bwd_bytes"]))
            replay_time = now - timedelta(seconds=(len(rows) - index) * 7)
            values = {
                "external_id": stable_id("CIC2017", identity),
                "sensor_id": SENSOR_ID,
                "time": replay_time,
                "source": row["source_ip"],
                "destination": row["destination_ip"],
                "source_port": source_port,
                "destination_port": destination_port,
                "protocol": protocol,
                "service": service_name(protocol, destination_port),
                "activity": f"离线回放 · 模型预测 {prediction} · 真值 {ground_truth}",
                "packets": packets,
                "bytes": byte_count,
                "duration_ms": max(0, int(float(row["duration_us"]) / 1000)),
                "verdict": "benign" if prediction == "BENIGN" else "malicious",
                "anomaly_score": round(score * 100, 3),
                "feature_version": run.feature_version,
                "features": {
                    "groundTruthLabel": ground_truth,
                    "modelPrediction": prediction,
                    "confidence": score,
                    "captureDay": row["capture_day"],
                    "flowBytesPerSecond": float(row["flow_bytes_per_second"]),
                    "flowPacketsPerSecond": float(row["flow_packets_per_second"]),
                    "synFlagCount": int(float(row["syn_flag_count"])),
                    "datasetId": dataset.id,
                    "trainingRunId": run.id,
                },
                "raw_reference": {
                    "mode": "CICIDS2017 offline replay",
                    "originalCaptureTimeUtc": row["start_time"],
                    "datasetSha256": dataset.sha256,
                    "artifactSha256": run.artifact_sha256,
                },
            }
            flow = db.get(Flow, flow_id)
            if flow is None:
                flow = Flow(id=flow_id, **values)
                db.add(flow)
            else:
                for key, value in values.items():
                    setattr(flow, key, value)
            flow_count += 1
            if ground_truth == "BENIGN" or ground_truth in alert_labels_done:
                continue
            alert_labels_done.add(ground_truth)
            alert_id = stable_id("ALERT-CIC", ground_truth)
            alert = db.get(Alert, alert_id)
            alert_values = {
                "flow_id": flow_id,
                "inference_id": None,
                "timestamp": replay_time,
                "severity": "critical" if ground_truth in {"DDoS", "Heartbleed"} else "high",
                "status": "new",
                "title": f"CICIDS2017 回放：{prediction}",
                "category": alert_category(ground_truth),
                "source_ip": row["source_ip"],
                "destination_ip": row["destination_ip"],
                "destination_port": destination_port,
                "protocol": protocol,
                "sensor": SENSOR_ID,
                "risk_score": round(score * 100, 2),
                "confidence": round(score, 6),
                "detector": run.model_id or run.id,
                "owner": None,
                "evidence": [
                    f"真实模型预测：{prediction}",
                    f"CICIDS2017 标签：{ground_truth}",
                    f"训练运行：{run.id}",
                    f"数据 SHA-256：{dataset.sha256}",
                ],
            }
            if alert is None:
                alert = Alert(id=alert_id, **alert_values)
                db.add(alert)
            else:
                for key, value in alert_values.items():
                    setattr(alert, key, value)
            alert_count += 1
        db.add(
            AuditEvent(
                id=f"AUD-{uuid.uuid4().hex.upper()}",
                created_at=now,
                actor="cicids2017-replay-importer",
                action="replay.imported",
                object_type="dataset_asset",
                object_id=dataset.id,
                outcome="completed",
                request_id="local-cicids2017-replay",
                before_state=None,
                after_state={
                    "flows": flow_count,
                    "alerts": alert_count,
                    "trainingRunId": run.id,
                    "artifactSha256": run.artifact_sha256,
                },
                note="Representative PCAP-derived flows were scored by the real local artifact and imported as replay data.",
            )
        )
        db.commit()
    return {"flows": flow_count, "alerts": alert_count}


def main() -> None:
    args = parse_args()
    dataset_path = args.dataset.resolve()
    if not dataset_path.is_file():
        raise FileNotFoundError(f"Derived dataset is missing: {dataset_path}")
    rows = collect_rows(
        dataset_path,
        benign_rows=args.benign_rows,
        rows_per_attack=args.rows_per_attack,
    )
    run, dataset, artifact = load_latest_artifact()
    predictions, confidence = predict(rows, artifact)
    result = upsert_replay(
        rows=rows,
        predictions=predictions,
        confidence=confidence,
        run=run,
        dataset=dataset,
    )
    correct = sum(row["Label"].strip() == prediction for row, prediction in zip(rows, predictions, strict=True))
    summary = {
        "datasetId": dataset.id,
        "trainingRunId": run.id,
        "artifactSha256": run.artifact_sha256,
        "replayRows": len(rows),
        "replayAccuracy": correct / len(rows) if rows else 0.0,
        **result,
    }
    print(f"[complete] {json.dumps(summary, ensure_ascii=False)}", flush=True)


if __name__ == "__main__":
    main()
