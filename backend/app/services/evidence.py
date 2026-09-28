"""Generic evidence registry: ingestion-time records, raw artifacts, queries.

Every accepted raw event becomes one ``EvidenceRecord`` (content SHA-256,
observation/receipt times, parser identity, integrity and data-missing markers,
pointers to the derived flow/alert rows) plus one bounded raw ``EvidenceArtifact``.
Deterministic record ids keep the registry idempotent across retried uploads.
"""
from __future__ import annotations

import hashlib
from datetime import datetime

from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from app.db.base import utc_now
from app.db.models import EvidenceArtifact, EvidenceRecord
from app.ingestion.eve import EveRecord
from app.services.rbac import DEFAULT_WORKSPACE

MAX_ARTIFACT_BYTES = 1_048_576  # 1 MiB per raw event line (upload is bounded at 10 MiB)
PARSER_VERSION = "evonids-eve-v1"


def _evidence_id(sensor_id: str, event_type: str, external_id: str, observed_at: str) -> str:
    digest = hashlib.sha256(
        "\x1f".join((sensor_id, event_type, external_id, observed_at)).encode("utf-8")
    ).hexdigest()[:20].upper()
    return f"EVD-{digest}"


def record_eve_evidence(
    db: Session,
    *,
    sensor_id: str,
    record: EveRecord,
    received_at: datetime,
    source_ref_type: str,
    source_ref_id: str,
    workspace_id: str = DEFAULT_WORKSPACE,
) -> None:
    """Persist the evidence registry row (+ raw artifact) for one accepted event.

    Idempotent: a deterministic id means a retried upload never duplicates rows.
    ``workspace_id`` is stamped from the ingestion principal, never from the
    uploaded payload, and a replay of an existing row never moves it between
    workspaces.
    """
    if record.event_type == "alert":
        alert_payload = record.payload.get("alert")
        signature_id = str(
            alert_payload.get("signature_id", "unknown") if isinstance(alert_payload, dict) else "unknown"
        )
        external_id = f"{record.flow_id}:{signature_id}"
    else:
        external_id = record.flow_id

    observed_at = _parse_timestamp(record.timestamp)
    evidence_id = _evidence_id(sensor_id, record.event_type, external_id, record.timestamp)
    if db.get(EvidenceRecord, evidence_id) is not None:
        return

    raw_bytes = record.raw_line.encode("utf-8")
    content_sha256 = hashlib.sha256(raw_bytes).hexdigest()
    raw_size = len(raw_bytes)
    truncated = raw_size > MAX_ARTIFACT_BYTES

    fields: dict = {
        "event_type": record.event_type,
        "community_id": record.community_id,
        "src_ip": record.source_ip,
        "src_port": record.source_port,
        "dst_ip": record.destination_ip,
        "dst_port": record.destination_port,
        "protocol": record.protocol,
        "app_proto": record.payload.get("app_proto"),
    }
    if record.event_type == "alert" and isinstance(record.payload.get("alert"), dict):
        alert = record.payload["alert"]
        fields["alert"] = {
            "signature_id": alert.get("signature_id"),
            "severity": alert.get("severity"),
            "signature": str(alert.get("signature", ""))[:500],
        }

    db.add(
        EvidenceRecord(
            id=evidence_id,
            workspace_id=workspace_id,
            source_type="suricata_eve",
            sensor_id=sensor_id,
            event_type=record.event_type,
            external_id=external_id[:160],
            observed_at=observed_at,
            received_at=received_at,
            content_sha256=content_sha256,
            integrity="complete" if not truncated else "partial",
            data_missing="none" if not truncated else "artifact_truncated",
            parser_version=PARSER_VERSION,
            redacted=False,
            source_ref_type=source_ref_type,
            source_ref_id=source_ref_id,
            artifact_size_bytes=raw_size,
            fields=fields,
            created_at=utc_now(),
            updated_at=utc_now(),
        )
    )
    if not truncated:
        db.add(
            EvidenceArtifact(
                evidence_id=evidence_id,
                content_hash=content_sha256,
                size_bytes=raw_size,
                content_text=record.raw_line,
            )
        )


def list_evidence(
    db: Session,
    *,
    source_type: str = "all",
    sensor_id: str = "",
    event_type: str = "",
    external_id: str = "",
    content_sha256: str = "",
    page: int = 1,
    page_size: int = 25,
    workspace_id: str = DEFAULT_WORKSPACE,
) -> tuple[list[EvidenceRecord], int]:
    """List evidence inside one workspace (the caller's own, always)."""
    filters = [EvidenceRecord.workspace_id == workspace_id]
    if source_type != "all":
        filters.append(EvidenceRecord.source_type == source_type)
    if sensor_id.strip():
        filters.append(EvidenceRecord.sensor_id == sensor_id.strip())
    if event_type.strip():
        filters.append(EvidenceRecord.event_type == event_type.strip())
    if external_id.strip():
        filters.append(EvidenceRecord.external_id == external_id.strip())
    if content_sha256.strip():
        filters.append(EvidenceRecord.content_sha256 == content_sha256.strip())
    total = int(db.scalar(select(func.count()).select_from(EvidenceRecord).where(*filters)) or 0)
    rows = list(
        db.scalars(
            select(EvidenceRecord)
            .where(*filters)
            .order_by(desc(EvidenceRecord.observed_at), desc(EvidenceRecord.id))
            .offset((page - 1) * page_size)
            .limit(page_size)
        ).all()
    )
    return rows, total


def get_evidence(db: Session, evidence_id: str, *, workspace_id: str | None = None) -> EvidenceRecord:
    """Fetch one evidence record, optionally pinned to a workspace.

    Another tenant's record is reported as missing (404) so ids cannot be
    enumerated across workspaces.
    """
    row = db.get(EvidenceRecord, evidence_id)
    if row is None or (workspace_id is not None and row.workspace_id != workspace_id):
        from fastapi import HTTPException

        raise HTTPException(status_code=404, detail=f"Evidence {evidence_id} was not found")
    return row


def evidence_artifact(db: Session, evidence_id: str) -> EvidenceArtifact | None:
    return db.get(EvidenceArtifact, evidence_id)


def _parse_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))
