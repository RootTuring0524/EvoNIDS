from __future__ import annotations

import hashlib
import io
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import Alert, Flow, Sensor
from app.db.base import utc_now
from app.domain.features import FEATURE_VERSION
from app.ingestion.eve import EveParseFailure, EveRecord, flow_payload, iter_eve_stream


def ingest_eve_text(db: Session, *, sensor_id: str, content: str) -> dict[str, Any]:
    sensor = db.get(Sensor, sensor_id)
    if sensor is None:
        sensor = Sensor(id=sensor_id, name=sensor_id, state="online", metadata_json={"source": "eve-import"})
        db.add(sensor)
        db.flush()

    received_at = utc_now()
    sensor.last_seen_at = received_at
    if sensor.state != "maintenance":
        sensor.state = "online"

    failures: list[EveParseFailure] = []
    failure_counts: dict[str, int] = {}
    records = iter_eve_stream(io.StringIO(content), failures, failure_counts)
    accepted = created_flows = created_alerts = duplicates = 0

    for record in records:
        accepted += 1
        if record.event_type == "flow":
            outcome = _ingest_flow(db, sensor_id, record)
            created_flows += int(outcome == "created")
            duplicates += int(outcome == "duplicate")
        elif record.event_type == "alert":
            outcome = _ingest_alert(db, sensor_id, record)
            created_alerts += int(outcome == "created")
            duplicates += int(outcome == "duplicate")

    rejected = failure_counts.get("rejected", len(failures))
    previous_metadata = dict(sensor.metadata_json or {})
    sensor.metadata_json = {
        **previous_metadata,
        "source": previous_metadata.get("source", "eve-import"),
        "lastAcceptedEvents": accepted,
        "lastRejectedEvents": rejected,
        "lastDuplicateEvents": duplicates,
        "lifetimeAcceptedEvents": int(previous_metadata.get("lifetimeAcceptedEvents", 0)) + accepted,
        "lifetimeRejectedEvents": int(previous_metadata.get("lifetimeRejectedEvents", 0)) + rejected,
        "lastIngestedAt": received_at.isoformat(),
    }
    db.commit()
    return {
        "sensor_id": sensor_id,
        "accepted_events": accepted,
        "created_flows": created_flows,
        "created_alerts": created_alerts,
        "duplicate_events": duplicates,
        "rejected_events": rejected,
        "failures": [
            {"line_number": failure.line_number, "reason": failure.reason}
            for failure in failures[:25]
        ],
    }


def _ingest_flow(db: Session, sensor_id: str, record: EveRecord) -> str:
    existing = db.scalar(
        select(Flow.id).where(Flow.sensor_id == sensor_id, Flow.external_id == record.flow_id)
    )
    if existing is not None:
        return "duplicate"

    payload = flow_payload(record)
    if payload is None:
        return "ignored"
    packet_count = payload["forward_packet_count"] + payload["backward_packet_count"]
    byte_count = payload["forward_bytes"] + payload["backward_bytes"]
    duration_seconds = payload["flow_duration"]
    features = {
        **payload,
        "packets_per_second": packet_count / duration_seconds if duration_seconds > 0 else 0.0,
        "bytes_per_second": byte_count / duration_seconds if duration_seconds > 0 else 0.0,
        "syn_ratio": 0.0,
        "ack_ratio": 0.0,
        "rst_ratio": 0.0,
        "destination_port_count_60s": 0,
        "destination_ip_count_60s": 0,
        "flow_count_60s": 0,
        "average_packet_size": byte_count / packet_count if packet_count > 0 else 0.0,
    }
    flow = Flow(
        id=_stable_id("FLOW", sensor_id, record.flow_id),
        external_id=record.flow_id,
        sensor_id=sensor_id,
        time=_parse_timestamp(record.timestamp),
        source=record.source_ip or "0.0.0.0",
        destination=record.destination_ip or "0.0.0.0",
        source_port=record.source_port or 0,
        destination_port=record.destination_port or 0,
        protocol=record.protocol or "unknown",
        service=_service(record),
        activity="Suricata EVE flow",
        packets=packet_count,
        bytes=byte_count,
        duration_ms=round(duration_seconds * 1000),
        verdict="benign",
        anomaly_score=0.0,
        feature_version=FEATURE_VERSION,
        features=features,
        raw_reference={
            "eventType": record.event_type,
            "lineNumber": record.line_number,
            "communityId": record.community_id,
        },
    )
    db.add(flow)
    db.flush()
    return "created"


def _ingest_alert(db: Session, sensor_id: str, record: EveRecord) -> str:
    alert_data = record.payload.get("alert")
    if not isinstance(alert_data, dict):
        return "ignored"
    signature_id = str(alert_data.get("signature_id", "unknown"))
    alert_id = _stable_id("ALT", sensor_id, record.flow_id, signature_id, record.timestamp)
    if db.get(Alert, alert_id) is not None:
        return "duplicate"

    signature = str(alert_data.get("signature", "Suricata alert"))
    severity, risk = _severity(alert_data.get("severity"))
    linked_flow = db.scalar(
        select(Flow).where(Flow.sensor_id == sensor_id, Flow.external_id == record.flow_id)
    )
    if linked_flow is not None:
        linked_flow.verdict = "malicious"
        linked_flow.anomaly_score = max(linked_flow.anomaly_score, risk / 100)
    db.add(
        Alert(
            id=alert_id,
            flow_id=linked_flow.id if linked_flow else None,
            inference_id=None,
            timestamp=_parse_timestamp(record.timestamp),
            severity=severity,
            status="new",
            title=signature,
            category=_category(signature),
            source_ip=record.source_ip or "0.0.0.0",
            destination_ip=record.destination_ip or "0.0.0.0",
            destination_port=record.destination_port or 0,
            protocol=record.protocol or "unknown",
            sensor=sensor_id,
            risk_score=risk,
            confidence=100.0,
            detector=f"Suricata signature {signature_id}",
            owner=None,
            evidence=[
                f"suricata:signature:{signature_id}",
                f"eve:line:{record.line_number}",
            ],
        )
    )
    return "created"


def _stable_id(prefix: str, *parts: str) -> str:
    digest = hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()[:20].upper()
    return f"{prefix}-{digest}"


def _parse_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _severity(value: Any) -> tuple[str, float]:
    try:
        numeric = int(value)
    except (TypeError, ValueError):
        numeric = 3
    return {
        1: ("critical", 95.0),
        2: ("high", 84.0),
        3: ("medium", 66.0),
    }.get(numeric, ("low", 42.0))


def _category(signature: str) -> str:
    lowered = signature.lower()
    mappings = [
        (("ddos",), "DDoS"),
        (("dos", "flood"), "DoS"),
        (("port scan", "nmap", "network scan"), "Port Scan"),
        (("brute", "password", "login attempt"), "Brute Force"),
        (("botnet",), "Botnet"),
        (("command and control", " c2", "c2 "), "C2 Communication"),
        (("web attack", "sql injection", "xss"), "Web Attack"),
        (("infiltration",), "Infiltration"),
        (("exfil", "outbound"), "Abnormal Outbound Connection"),
    ]
    for needles, category in mappings:
        if any(needle in lowered for needle in needles):
            return category
    return "Unknown Anomaly"


def _service(record: EveRecord) -> str:
    app_proto = record.payload.get("app_proto")
    return str(app_proto).upper() if app_proto else "unknown"
