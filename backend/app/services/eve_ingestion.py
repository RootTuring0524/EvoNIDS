from __future__ import annotations

import hashlib
import io
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import distinct, func, select
from sqlalchemy.orm import Session

from app.db.models import Alert, Flow, IngestionBatch, Sensor
from app.db.base import utc_now
from app.domain.features import FEATURE_VERSION
from app.domain.flow_features import (
    ONLINE_FEATURE_VERSION,
    OnlineFeatureVector,
    WindowCounts,
    build_online_features,
)
from app.ingestion.eve import EveParseFailure, EveRecord, flow_payload, iter_eve_stream
from app.services.entities import observe_communications
from app.services.evidence import record_eve_evidence
from app.services.online_detection import DetectionMode, run_online_detection
from app.services.rbac import DEFAULT_WORKSPACE


@dataclass(slots=True)
class IngestOutcome:
    accepted: int = 0
    created_flows: int = 0
    created_alerts: int = 0
    duplicates: int = 0
    rejected: int = 0
    failures: list[EveParseFailure] = field(default_factory=list)
    flows: list[Flow] = field(default_factory=list)
    observations: list[tuple[str, str, datetime]] = field(default_factory=list)
    vectors: dict[str, OnlineFeatureVector] = field(default_factory=dict)
    rule_risk_by_flow: dict[str, float] = field(default_factory=dict)
    first_event_at: datetime | None = None
    last_event_at: datetime | None = None
    # Tenant of the ingestion principal. Carried on the outcome so every row
    # written for this batch (evidence, detection signals) is stamped with the
    # same workspace the sensor credential belongs to - never with client input.
    workspace_id: str = DEFAULT_WORKSPACE

    def as_response(self) -> dict[str, Any]:
        return {
            "sensor_id": None,
            "accepted_events": self.accepted,
            "created_flows": self.created_flows,
            "created_alerts": self.created_alerts,
            "duplicate_events": self.duplicates,
            "rejected_events": self.rejected,
            "failures": [
                {"line_number": failure.line_number, "reason": failure.reason}
                for failure in self.failures[:25]
            ],
        }


def ingest_eve_text(
    db: Session,
    *,
    sensor_id: str,
    content: str,
    detection_mode: DetectionMode = "shadow",
    workspace_id: str = DEFAULT_WORKSPACE,
) -> dict[str, Any]:
    received_at = utc_now()
    sensor = _ensure_sensor(db, sensor_id)
    sensor.last_seen_at = received_at
    if sensor.state != "maintenance":
        sensor.state = "online"

    outcome = _ingest_records(
        db,
        sensor_id=sensor_id,
        content=content,
        received_at=received_at,
        workspace_id=workspace_id,
    )
    detection = _apply_detection(db, outcome, mode=detection_mode)
    _update_sensor_metadata(sensor, outcome)
    db.commit()
    response = outcome.as_response()
    response["sensor_id"] = sensor_id
    response["detection"] = detection
    return response


def ingest_eve_batch(
    db: Session,
    *,
    sensor_id: str,
    batch_id: str,
    content: str,
    encoding: str,
    payload_bytes: int,
    clock_skew_seconds: float | None = None,
    detection_mode: DetectionMode = "shadow",
    workspace_id: str = DEFAULT_WORKSPACE,
) -> dict[str, Any]:
    """Idempotent batch ingestion used by the collector.

    Replaying the same ``batch_id`` with identical content returns the original
    outcome (``replayed: true``) instead of double-counting events. Reusing a
    batch id for different content is rejected by the caller as a 409 conflict.
    """
    content_sha256 = hashlib.sha256(content.encode("utf-8")).hexdigest()
    existing = db.scalar(
        select(IngestionBatch).where(
            IngestionBatch.sensor_id == sensor_id, IngestionBatch.batch_id == batch_id
        )
    )
    if existing is not None:
        if existing.content_sha256 != content_sha256:
            raise BatchConflict(
                f"batch {batch_id} was already ingested with a different content hash"
            )
        return {
            "sensor_id": sensor_id,
            "batchId": batch_id,
            "replayed": True,
            "accepted_events": existing.accepted_count,
            "created_flows": existing.created_flows,
            "created_alerts": existing.created_alerts,
            "duplicate_events": existing.duplicate_count,
            "rejected_events": existing.rejected_count,
            "failures": [],
            "detection": {"mode": "replayed", "flowsScored": 0, "signals": 0, "assessments": 0},
        }

    received_at = utc_now()
    sensor = _ensure_sensor(db, sensor_id)
    sensor.last_seen_at = received_at
    if sensor.state != "maintenance":
        sensor.state = "online"
    if clock_skew_seconds is not None:
        sensor.clock_skew_seconds = round(float(clock_skew_seconds), 3)

    outcome = _ingest_records(
        db,
        sensor_id=sensor_id,
        content=content,
        received_at=received_at,
        workspace_id=workspace_id,
    )
    detection = _apply_detection(db, outcome, mode=detection_mode)
    _update_sensor_metadata(sensor, outcome)
    db.add(
        IngestionBatch(
            id=_stable_id("BATCH", sensor_id, batch_id),
            sensor_id=sensor_id,
            batch_id=batch_id,
            received_at=received_at,
            content_sha256=content_sha256,
            encoding=encoding,
            payload_bytes=payload_bytes,
            event_count=outcome.accepted + outcome.rejected,
            accepted_count=outcome.accepted,
            duplicate_count=outcome.duplicates,
            rejected_count=outcome.rejected,
            created_flows=outcome.created_flows,
            created_alerts=outcome.created_alerts,
            first_event_at=outcome.first_event_at,
            last_event_at=outcome.last_event_at,
            clock_skew_seconds=clock_skew_seconds,
            status="accepted" if outcome.rejected == 0 else "partial",
            detail={
                "failures": [
                    {"lineNumber": failure.line_number, "reason": failure.reason}
                    for failure in outcome.failures[:25]
                ],
                "detection": detection,
            },
        )
    )
    db.commit()
    response = outcome.as_response()
    response["sensor_id"] = sensor_id
    response["batchId"] = batch_id
    response["replayed"] = False
    response["detection"] = detection
    return response


class BatchConflict(RuntimeError):
    """Raised when a batch id is reused with different content."""


def _apply_detection(db: Session, outcome: IngestOutcome, *, mode: DetectionMode) -> dict[str, Any]:
    if mode == "disabled" or not outcome.flows:
        return {
            "mode": mode,
            "flowsScored": 0,
            "signals": 0,
            "assessments": 0,
            "alertsCreated": 0,
            "degraded": False,
            "degradedReasons": [],
            "models": {},
        }
    detection = run_online_detection(
        db,
        flows=outcome.flows,
        vectors=outcome.vectors,
        mode=mode,
        rule_risk_by_flow=outcome.rule_risk_by_flow,
        workspace_id=outcome.workspace_id,
    )
    return {
        "mode": detection.mode,
        "flowsScored": detection.flows_scored,
        "signals": detection.signals,
        "assessments": detection.assessments,
        "alertsCreated": detection.alerts_created,
        "degraded": detection.degraded,
        "degradedReasons": list(detection.degraded_reasons),
        "models": detection.models,
    }


def _ensure_sensor(db: Session, sensor_id: str) -> Sensor:
    sensor = db.get(Sensor, sensor_id)
    if sensor is None:
        sensor = Sensor(id=sensor_id, name=sensor_id, state="online", metadata_json={"source": "eve-import"})
        db.add(sensor)
        db.flush()
    return sensor


def _ingest_records(
    db: Session,
    *,
    sensor_id: str,
    content: str,
    received_at: datetime,
    workspace_id: str = DEFAULT_WORKSPACE,
) -> IngestOutcome:
    failures: list[EveParseFailure] = []
    failure_counts: dict[str, int] = {}
    records = iter_eve_stream(io.StringIO(content), failures, failure_counts)
    outcome = IngestOutcome(failures=failures)
    window_cache: dict[str, WindowCounts] = {}

    for record in records:
        outcome.accepted += 1
        event_time = _parse_timestamp(record.timestamp)
        if outcome.first_event_at is None or event_time < outcome.first_event_at:
            outcome.first_event_at = event_time
        if outcome.last_event_at is None or event_time > outcome.last_event_at:
            outcome.last_event_at = event_time
        if record.event_type == "flow":
            status = _ingest_flow(
                db,
                sensor_id,
                record,
                received_at=received_at,
                event_time=event_time,
                outcome=outcome,
                window_cache=window_cache,
            )
            outcome.created_flows += int(status == "created")
            outcome.duplicates += int(status == "duplicate")
        elif record.event_type == "alert":
            status = _ingest_alert(db, sensor_id, record, received_at=received_at, outcome=outcome)
            outcome.created_alerts += int(status == "created")
            outcome.duplicates += int(status == "duplicate")

    outcome.rejected = failure_counts.get("rejected", len(failures))
    # One bulk upsert per batch instead of one flush plus two lookups per event.
    _flush_entities(db, sensor_id=sensor_id, outcome=outcome)
    return outcome


def _window_counts(
    db: Session,
    *,
    sensor_id: str,
    source_ip: str,
    event_time: datetime,
    cache: dict[str, WindowCounts],
) -> WindowCounts:
    cached = cache.get(source_ip)
    if cached is not None:
        return cached
    since = event_time - timedelta(seconds=60)
    row = db.execute(
        select(
            func.count(distinct(Flow.destination_port)),
            func.count(distinct(Flow.destination)),
            func.count(Flow.id),
            func.count(distinct(Flow.source_port)),
        ).where(
            Flow.sensor_id == sensor_id,
            Flow.source == source_ip,
            Flow.time >= since,
            Flow.time <= event_time,
        )
    ).one()
    counts = WindowCounts(
        destination_port_count=int(row[0] or 0),
        destination_ip_count=int(row[1] or 0),
        flow_count=int(row[2] or 0),
        source_port_count=int(row[3] or 0),
    )
    cache[source_ip] = counts
    return counts


def _ingest_flow(
    db: Session,
    sensor_id: str,
    record: EveRecord,
    *,
    received_at: datetime,
    event_time: datetime,
    outcome: IngestOutcome,
    window_cache: dict[str, WindowCounts],
) -> str:
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
    source_ip = record.source_ip or "0.0.0.0"
    flow = Flow(
        id=_stable_id("FLOW", sensor_id, record.flow_id),
        external_id=record.flow_id,
        sensor_id=sensor_id,
        time=event_time,
        source=source_ip,
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
        feature_version=ONLINE_FEATURE_VERSION,
        features={},
        raw_reference={
            "eventType": record.event_type,
            "lineNumber": record.line_number,
            "communityId": record.community_id,
            "legacyFeatureVersion": FEATURE_VERSION,
        },
    )
    db.add(flow)
    # Flush before the window query so the flow is part of its own 60s window.
    db.flush()
    window = _window_counts(
        db, sensor_id=sensor_id, source_ip=source_ip, event_time=event_time, cache=window_cache
    )
    vector = build_online_features(
        payload, sensor_id=sensor_id, observed_at=event_time, window=window
    )
    flow.features = {
        **payload,
        "packets_per_second": packet_count / duration_seconds if duration_seconds > 0 else 0.0,
        "bytes_per_second": byte_count / duration_seconds if duration_seconds > 0 else 0.0,
        "syn_ratio": 0.0,
        "ack_ratio": 0.0,
        "rst_ratio": 0.0,
        "destination_port_count_60s": vector.values["destination_port_count_60s"],
        "destination_ip_count_60s": vector.values["destination_ip_count_60s"],
        "flow_count_60s": vector.values["flow_count_60s"],
        "average_packet_size": byte_count / packet_count if packet_count > 0 else 0.0,
        "onlineContract": vector.as_record(),
    }
    record_eve_evidence(
        db,
        sensor_id=sensor_id,
        record=record,
        received_at=received_at,
        source_ref_type="flow",
        source_ref_id=flow.id,
    )
    _collect_entities(outcome, record)
    outcome.flows.append(flow)
    outcome.vectors[flow.id] = vector
    return "created"


def _ingest_alert(
    db: Session, sensor_id: str, record: EveRecord, *, received_at: datetime, outcome: IngestOutcome
) -> str:
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
        outcome.rule_risk_by_flow[linked_flow.id] = max(
            outcome.rule_risk_by_flow.get(linked_flow.id, 0.0), risk / 100
        )
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
    record_eve_evidence(
        db,
        sensor_id=sensor_id,
        record=record,
        received_at=received_at,
        source_ref_type="alert",
        source_ref_id=alert_id,
    )
    _collect_entities(outcome, record)
    return "created"


def _update_sensor_metadata(sensor: Sensor, outcome: IngestOutcome) -> None:
    previous_metadata = dict(sensor.metadata_json or {})
    sensor.metadata_json = {
        **previous_metadata,
        "source": previous_metadata.get("source", "eve-import"),
        "lastAcceptedEvents": outcome.accepted,
        "lastRejectedEvents": outcome.rejected,
        "lastDuplicateEvents": outcome.duplicates,
        "lifetimeAcceptedEvents": int(previous_metadata.get("lifetimeAcceptedEvents", 0)) + outcome.accepted,
        "lifetimeRejectedEvents": int(previous_metadata.get("lifetimeRejectedEvents", 0)) + outcome.rejected,
        "lastIngestedAt": utc_now().isoformat(),
    }


def _stable_id(prefix: str, *parts: str) -> str:
    digest = hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()[:20].upper()
    return f"{prefix}-{digest}"


def _parse_timestamp(value: str) -> datetime:
    """Parse an EVE timestamp into naive UTC, matching the storage convention."""
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
    return parsed


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


def _collect_entities(outcome: IngestOutcome, record: EveRecord) -> None:
    """Queue the src/dst pair of an accepted event for the batch entity upsert.

    Collecting instead of writing per event removes a flush and two lookups per
    event; :func:`_flush_entities` applies the identical semantics once per batch.
    """
    source_ip = (record.source_ip or "").strip()
    destination_ip = (record.destination_ip or "").strip()
    if not source_ip or not destination_ip or source_ip == "0.0.0.0" or destination_ip == "0.0.0.0":
        return
    if source_ip == destination_ip:
        return
    outcome.observations.append((source_ip, destination_ip, _parse_timestamp(record.timestamp)))


def _flush_entities(db: Session, *, sensor_id: str, outcome: IngestOutcome) -> None:
    if not outcome.observations:
        return
    observe_communications(db, sensor_id=sensor_id, observations=outcome.observations)


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
