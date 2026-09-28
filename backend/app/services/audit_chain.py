"""Tamper-evident audit log: per-tenant hash chain plus export/verify tooling.

Requirements this satisfies (productionisation brief, section VIII):

* the audit log must resist modification — a hash chain makes any edit, deletion
  or reordering of the stored rows detectable;
* the chain must be verifiable offline from an export, so an auditor does not
  have to trust the running service;
* verification must state exactly where the chain breaks and why.

Design notes:

* ``AuditEvent`` gains ``sequence`` and ``prev_hash``; ``content_hash`` is derived
  from the *canonical* JSON of the row's immutable fields, so re-serialising a row
  (key order, unicode escaping) cannot change the digest;
* rows written before this migration have no chain: they are verified as
  ``unchained`` rather than silently treated as valid;
* the chain is per workspace, which keeps a tenant's audit trail independent;
* :func:`verify_chain` never writes, so it is safe on a replica.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Iterable, Sequence

from sqlalchemy import desc, func, select
from sqlalchemy import event as sa_event
from sqlalchemy.orm import Session

from app.db.base import utc_now
from app.db.models import AuditEvent

GENESIS_HASH = "0" * 64
CHAIN_VERSION = "audit-chain-v1"


def canonical_payload(
    *,
    event_id: str,
    created_at: datetime,
    actor: str,
    action: str,
    object_type: str,
    object_id: str,
    outcome: str,
    request_id: str | None,
    before_state: dict[str, Any] | None,
    after_state: dict[str, Any] | None,
    note: str | None,
    workspace_id: str,
    sequence: int,
) -> str:
    """Deterministic JSON for the immutable part of an audit row."""
    document = {
        "version": CHAIN_VERSION,
        "id": event_id,
        "createdAt": created_at.replace(tzinfo=None).isoformat(timespec="microseconds"),
        "actor": actor,
        "action": action,
        "objectType": object_type,
        "objectId": object_id,
        "outcome": outcome,
        "requestId": request_id,
        "before": before_state,
        "after": after_state,
        "note": note,
        "workspaceId": workspace_id,
        "sequence": sequence,
    }
    return json.dumps(document, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def content_hash(prev_hash: str, payload: str) -> str:
    digest = hashlib.sha256()
    digest.update(prev_hash.encode("utf-8"))
    digest.update(b"\x1f")
    digest.update(payload.encode("utf-8"))
    return digest.hexdigest()


def _chain_audit_row(mapper: Any, connection: Any, target: AuditEvent) -> None:
    """Fill the chain columns for ANY audit row that is being inserted.

    Every service writes ``AuditEvent(...)`` directly, so chaining is enforced at
    the mapper level instead of asking each call site to remember it. The lookup
    runs on the same connection and transaction as the insert, so the sequence is
    the one this row will actually occupy.
    """
    if target.content_hash:
        return
    workspace = getattr(target, "workspace_id", None) or "default"
    target.workspace_id = workspace
    row = connection.execute(
        select(AuditEvent.sequence, AuditEvent.content_hash)
        .where(AuditEvent.workspace_id == workspace)
        .order_by(desc(AuditEvent.sequence))
        .limit(1)
    ).first()
    previous_sequence = int(row[0]) if row is not None and row[0] is not None else 0
    previous_hash = str(row[1]) if row is not None and row[1] else GENESIS_HASH
    target.sequence = previous_sequence + 1
    target.prev_hash = previous_hash
    created = target.created_at
    if created is not None and created.tzinfo is not None:
        created = created.replace(tzinfo=None)
        target.created_at = created
    payload = canonical_payload(
        event_id=target.id,
        created_at=created or utc_now(),
        actor=target.actor,
        action=target.action,
        object_type=target.object_type,
        object_id=target.object_id,
        outcome=target.outcome,
        request_id=target.request_id,
        before_state=target.before_state,
        after_state=target.after_state,
        note=target.note,
        workspace_id=workspace,
        sequence=target.sequence,
    )
    target.content_hash = content_hash(previous_hash, payload)


sa_event.listen(AuditEvent, "before_insert", _chain_audit_row)


def append_event(
    db: Session,
    *,
    event_id: str,
    actor: str,
    action: str,
    object_type: str,
    object_id: str,
    outcome: str,
    request_id: str | None = None,
    before_state: dict[str, Any] | None = None,
    after_state: dict[str, Any] | None = None,
    note: str | None = None,
    workspace_id: str = "default",
    created_at: datetime | None = None,
) -> AuditEvent:
    """Append one chained audit event (the only supported write path)."""
    stamp = created_at or utc_now()
    # The session may be configured with autoflush off, so pending rows in this
    # transaction would not be visible to the max(sequence) query and two events
    # would collide on the unique (workspace_id, sequence) index.
    db.flush()
    previous = db.scalar(
        select(AuditEvent)
        .where(AuditEvent.workspace_id == workspace_id)
        .order_by(desc(AuditEvent.sequence))
        .limit(1)
    )
    sequence = (previous.sequence + 1) if previous is not None and previous.sequence else 1
    prev_hash = previous.content_hash if previous is not None and previous.content_hash else GENESIS_HASH
    payload = canonical_payload(
        event_id=event_id,
        created_at=stamp,
        actor=actor,
        action=action,
        object_type=object_type,
        object_id=object_id,
        outcome=outcome,
        request_id=request_id,
        before_state=before_state,
        after_state=after_state,
        note=note,
        workspace_id=workspace_id,
        sequence=sequence,
    )
    event = AuditEvent(
        id=event_id,
        created_at=stamp.replace(tzinfo=None) if stamp.tzinfo else stamp,
        actor=actor,
        action=action,
        object_type=object_type,
        object_id=object_id,
        outcome=outcome,
        request_id=request_id,
        before_state=before_state,
        after_state=after_state,
        note=note,
        workspace_id=workspace_id,
        sequence=sequence,
        prev_hash=prev_hash,
        content_hash=content_hash(prev_hash, payload),
    )
    db.add(event)
    return event


@dataclass(slots=True)
class ChainBreak:
    event_id: str
    sequence: int | None
    reason: str
    expected: str | None = None
    observed: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "eventId": self.event_id,
            "sequence": self.sequence,
            "reason": self.reason,
            "expected": self.expected,
            "observed": self.observed,
        }


@dataclass(slots=True)
class ChainVerification:
    workspace_id: str
    checked: int
    chained: int
    unchained: int
    valid: bool
    breaks: list[ChainBreak] = field(default_factory=list)
    head_hash: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "workspaceId": self.workspace_id,
            "checked": self.checked,
            "chained": self.chained,
            "unchained": self.unchained,
            "valid": self.valid,
            "headHash": self.head_hash,
            "breaks": [item.as_dict() for item in self.breaks[:100]],
            "note": (
                "逐行重算哈希链；unchained 计数是本次迁移之前写入、没有链的历史记录，"
                "它们被明确标记而不是当作已验证。"
            ),
        }


def verify_chain(
    db: Session, *, workspace_id: str = "default", limit: int = 50_000
) -> ChainVerification:
    """Recompute the audit chain and report the first inconsistencies."""
    rows = list(
        db.scalars(
            select(AuditEvent)
            .where(AuditEvent.workspace_id == workspace_id)
            .order_by(AuditEvent.sequence.asc(), AuditEvent.created_at.asc())
            .limit(limit)
        ).all()
    )
    result = ChainVerification(
        workspace_id=workspace_id, checked=len(rows), chained=0, unchained=0, valid=True
    )
    expected_prev = GENESIS_HASH
    expected_sequence = 1
    for row in rows:
        if not row.content_hash or row.sequence is None:
            result.unchained += 1
            continue
        if row.sequence != expected_sequence:
            result.valid = False
            result.breaks.append(
                ChainBreak(
                    event_id=row.id,
                    sequence=row.sequence,
                    reason="sequence_gap",
                    expected=str(expected_sequence),
                    observed=str(row.sequence),
                )
            )
            expected_sequence = row.sequence
        if row.prev_hash != expected_prev:
            result.valid = False
            result.breaks.append(
                ChainBreak(
                    event_id=row.id,
                    sequence=row.sequence,
                    reason="previous_hash_mismatch",
                    expected=expected_prev,
                    observed=row.prev_hash,
                )
            )
        payload = canonical_payload(
            event_id=row.id,
            created_at=row.created_at,
            actor=row.actor,
            action=row.action,
            object_type=row.object_type,
            object_id=row.object_id,
            outcome=row.outcome,
            request_id=row.request_id,
            before_state=row.before_state,
            after_state=row.after_state,
            note=row.note,
            workspace_id=row.workspace_id,
            sequence=row.sequence,
        )
        recomputed = content_hash(row.prev_hash or GENESIS_HASH, payload)
        if recomputed != row.content_hash:
            result.valid = False
            result.breaks.append(
                ChainBreak(
                    event_id=row.id,
                    sequence=row.sequence,
                    reason="content_hash_mismatch",
                    expected=recomputed,
                    observed=row.content_hash,
                )
            )
        expected_prev = row.content_hash
        expected_sequence = row.sequence + 1
        result.chained += 1
    result.head_hash = expected_prev if result.chained else None
    return result


def export_events(
    db: Session,
    *,
    workspace_id: str = "default",
    since: datetime | None = None,
    limit: int = 100_000,
) -> dict[str, Any]:
    """Portable export an auditor can verify without access to the database."""
    query = select(AuditEvent).where(AuditEvent.workspace_id == workspace_id)
    if since is not None:
        query = query.where(AuditEvent.created_at >= since)
    rows = list(db.scalars(query.order_by(AuditEvent.sequence.asc()).limit(limit)).all())
    events = [
        {
            "id": row.id,
            "createdAt": row.created_at.replace(tzinfo=None).isoformat(timespec="microseconds"),
            "actor": row.actor,
            "action": row.action,
            "objectType": row.object_type,
            "objectId": row.object_id,
            "outcome": row.outcome,
            "requestId": row.request_id,
            "before": row.before_state,
            "after": row.after_state,
            "note": row.note,
            "workspaceId": row.workspace_id,
            "sequence": row.sequence,
            "prevHash": row.prev_hash,
            "contentHash": row.content_hash,
        }
        for row in rows
    ]
    verification = verify_chain(db, workspace_id=workspace_id, limit=limit)
    return {
        "version": CHAIN_VERSION,
        "workspaceId": workspace_id,
        "exportedAt": utc_now().isoformat(),
        "count": len(events),
        "headHash": verification.head_hash,
        "verification": verification.as_dict(),
        "events": events,
    }


def verify_export(document: dict[str, Any]) -> dict[str, Any]:
    """Verify an export produced by :func:`export_events`.

    The recomputation is self-contained: an auditor only needs this function and
    the exported file, not the database.
    """
    events = document.get("events")
    if not isinstance(events, list):
        return {"valid": False, "checked": 0, "breaks": [{"reason": "export_missing_events"}]}
    breaks: list[dict[str, Any]] = []
    expected_prev = GENESIS_HASH
    expected_sequence = 1
    chained = 0
    for index, raw_event in enumerate(events):
        event = raw_event
        if not isinstance(event, dict):
            breaks.append({"index": index, "reason": "event_not_an_object"})
            continue
        if not event.get("contentHash") or event.get("sequence") is None:
            continue
        if event["sequence"] != expected_sequence:
            breaks.append(
                {
                    "index": index,
                    "eventId": event.get("id"),
                    "reason": "sequence_gap",
                    "expected": expected_sequence,
                    "observed": event["sequence"],
                }
            )
            expected_sequence = event["sequence"]
        if event.get("prevHash") != expected_prev:
            breaks.append(
                {
                    "index": index,
                    "eventId": event.get("id"),
                    "reason": "previous_hash_mismatch",
                    "expected": expected_prev,
                    "observed": event.get("prevHash"),
                }
            )
        created_raw = str(event.get("createdAt", ""))
        try:
            created = datetime.fromisoformat(created_raw)
        except ValueError:
            breaks.append({"index": index, "eventId": event.get("id"), "reason": "invalid_timestamp"})
            continue
        payload = canonical_payload(
            event_id=str(event.get("id", "")),
            created_at=created,
            actor=str(event.get("actor", "")),
            action=str(event.get("action", "")),
            object_type=str(event.get("objectType", "")),
            object_id=str(event.get("objectId", "")),
            outcome=str(event.get("outcome", "")),
            request_id=event.get("requestId"),
            before_state=event.get("before"),
            after_state=event.get("after"),
            note=event.get("note"),
            workspace_id=str(event.get("workspaceId", "default")),
            sequence=int(event["sequence"]),
        )
        recomputed = content_hash(str(event.get("prevHash")), payload)
        if recomputed != event.get("contentHash"):
            breaks.append(
                {
                    "index": index,
                    "eventId": event.get("id"),
                    "reason": "content_hash_mismatch",
                    "expected": recomputed,
                    "observed": event.get("contentHash"),
                }
            )
        expected_prev = str(event["contentHash"])
        expected_sequence = int(event["sequence"]) + 1
        chained += 1
    return {
        "valid": not breaks,
        "checked": len(events),
        "chained": chained,
        "unchained": len(events) - chained,
        "headHash": expected_prev if chained else None,
        "breaks": breaks[:100],
    }


def chain_stats(db: Session, *, workspace_id: str = "default") -> dict[str, Any]:
    total = db.scalar(
        select(func.count()).select_from(AuditEvent).where(AuditEvent.workspace_id == workspace_id)
    ) or 0
    chained = db.scalar(
        select(func.count())
        .select_from(AuditEvent)
        .where(AuditEvent.workspace_id == workspace_id, AuditEvent.content_hash.is_not(None))
    ) or 0
    head = db.scalar(
        select(AuditEvent.content_hash)
        .where(AuditEvent.workspace_id == workspace_id)
        .order_by(desc(AuditEvent.sequence))
        .limit(1)
    )
    return {
        "workspaceId": workspace_id,
        "version": CHAIN_VERSION,
        "totalEvents": int(total),
        "chainedEvents": int(chained),
        "unchainedEvents": int(total) - int(chained),
        "headHash": head,
    }


def iter_canonical_payloads(rows: Sequence[AuditEvent]) -> Iterable[str]:
    for row in rows:
        yield canonical_payload(
            event_id=row.id,
            created_at=row.created_at,
            actor=row.actor,
            action=row.action,
            object_type=row.object_type,
            object_id=row.object_id,
            outcome=row.outcome,
            request_id=row.request_id,
            before_state=row.before_state,
            after_state=row.after_state,
            note=row.note,
            workspace_id=row.workspace_id,
            sequence=row.sequence or 0,
        )
