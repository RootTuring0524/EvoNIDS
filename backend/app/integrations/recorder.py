"""Persist delivery outcomes into ``integration_deliveries``.

Upsert semantics, one row per ``(connector, dedup_key)``:

* the first delivery inserts the row (``attempts`` = the real attempt count);
* a later delivery — a retry, a manual re-dispatch from the console — updates it
  in place: ``attempts`` accumulates, ``state``/``last_error``/summaries are
  replaced with the latest *real* outcome, ``updated_at`` moves.

Nothing here invents a state: the values written are exactly the ones the
connector produced.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Callable

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.integrations.base import ConnectorResult, Notification
from app.integrations.models import IntegrationDelivery

MAX_ERROR_CHARS = 1_000
MAX_SUMMARY_BYTES = 8_192


def _bounded_summary(summary: dict[str, Any] | None) -> dict[str, Any]:
    """Keep the stored JSON honest but bounded (a hostile body is not an archive)."""
    import json

    payload = dict(summary or {})
    try:
        encoded = json.dumps(payload, ensure_ascii=False, default=str)
    except (TypeError, ValueError):
        return {"value": str(payload)[:MAX_SUMMARY_BYTES]}
    if len(encoded) <= MAX_SUMMARY_BYTES:
        return payload
    return {"truncated": True, "bytes": len(encoded), "preview": encoded[:MAX_SUMMARY_BYTES]}


class DeliveryRecorder:
    """Records outcomes through a session factory (one short transaction each)."""

    def __init__(self, session_factory: Callable[[], Session]) -> None:
        self._session_factory = session_factory

    def record(self, event: Notification, result: ConnectorResult) -> IntegrationDelivery:
        with self._session_factory() as db:
            return self.record_with_session(db, event, result)

    def record_with_session(
        self, db: Session, event: Notification, result: ConnectorResult
    ) -> IntegrationDelivery:
        dedup_key = result.dedup_key or event.dedup_key
        row = db.scalar(
            select(IntegrationDelivery).where(
                IntegrationDelivery.connector == result.connector,
                IntegrationDelivery.dedup_key == dedup_key,
            )
        )
        request_summary = _bounded_summary(result.request_summary)
        response_summary = _bounded_summary(_with_meta(result))
        if row is None:
            row = IntegrationDelivery(
                id=f"DEL-{uuid.uuid4().hex[:20].upper()}",
                connector=result.connector,
                event_type=result.event_type or event.event_type,
                object_id=result.object_id or event.object_id,
                dedup_key=dedup_key,
                state=result.state,
                attempts=max(result.attempts, 0),
                last_error=(result.error or "")[:MAX_ERROR_CHARS] or None,
                request_summary=request_summary,
                response_summary=response_summary,
            )
            db.add(row)
        else:
            row.state = result.state
            row.attempts = max(row.attempts or 0, 0) + max(result.attempts, 0)
            row.last_error = (result.error or "")[:MAX_ERROR_CHARS] or None
            row.event_type = result.event_type or event.event_type
            row.object_id = result.object_id or event.object_id
            row.request_summary = request_summary
            row.response_summary = response_summary
            row.updated_at = datetime.now(timezone.utc)
        db.commit()
        db.refresh(row)
        return row


def _with_meta(result: ConnectorResult) -> dict[str, Any]:
    payload = dict(result.response_summary or {})
    if result.error_code:
        payload["errorCode"] = result.error_code
    if result.skipped_reason:
        payload["skippedReason"] = result.skipped_reason
    if result.status is not None:
        payload["status"] = result.status
    payload["durationMs"] = round(result.duration_ms, 3)
    return payload


__all__ = ["DeliveryRecorder", "_bounded_summary"]
