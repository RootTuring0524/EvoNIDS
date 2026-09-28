"""Build a :class:`Notification` from the platform's alert / case rows.

The outbound layer must not depend on the API schema, so this module reads the
ORM rows it needs and produces a small, redacted-ready document. Only the fields
a downstream SIEM or ticket needs are copied; evidence blobs are summarised, not
dumped.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping, Sequence

from app.integrations.base import (
    CAPABILITY_ALERT,
    CAPABILITY_CASE,
    Notification,
    build_dedup_key,
    severity_from_risk,
)

MAX_EVIDENCE_ITEMS = 20


def alert_to_notification(
    alert: Any, *, evidence: Sequence[Any] | None = None
) -> Notification:
    """Turn an ``Alert`` row (or an equivalent mapping) into a Notification."""
    payload = {
        "id": _get(alert, "id"),
        "title": _get(alert, "title") or "(untitled alert)",
        "severity": _get(alert, "severity"),
        "status": _get(alert, "status"),
        "category": _get(alert, "category"),
        "timestamp": _iso(_get(alert, "timestamp")),
        "sensor": _get(alert, "sensor"),
        "sourceIp": _get(alert, "source_ip"),
        "destinationIp": _get(alert, "destination_ip"),
        "destinationPort": _get(alert, "destination_port"),
        "protocol": _get(alert, "protocol"),
        "riskScore": _get(alert, "risk_score"),
        "detector": _get(alert, "detector"),
        "flowId": _get(alert, "flow_id"),
        "hostname": _get(alert, "hostname"),
        "domain": _get(alert, "domain"),
    }
    severity = payload["severity"]
    if severity not in {"critical", "high", "medium", "low", "info"}:
        severity = severity_from_risk(payload["riskScore"])
    return Notification(
        event_type=CAPABILITY_ALERT,
        object_id=str(payload["id"]),
        title=str(payload["title"]),
        severity=severity,  # type: ignore[arg-type]
        dedup_key=build_dedup_key(CAPABILITY_ALERT, str(payload["id"])),
        alert={key: value for key, value in payload.items() if value is not None},
        evidence=evidence_documents(evidence or ()),
        tags=(f"severity:{severity}", f"category:{payload['category']}") if payload["category"] else (),
    )


def case_to_notification(case: Any, *, evidence: Sequence[Any] | None = None) -> Notification:
    payload = {
        "id": _get(case, "id"),
        "title": _get(case, "title") or "(untitled case)",
        "severity": _get(case, "severity"),
        "status": _get(case, "status"),
        "assignee": _get(case, "assignee"),
        "createdAt": _iso(_get(case, "created_at")),
        "updatedAt": _iso(_get(case, "updated_at")),
        "alertIds": list(_get(case, "alert_ids") or []),
        "summary": _get(case, "summary"),
    }
    severity = payload["severity"]
    if severity not in {"critical", "high", "medium", "low", "info"}:
        severity = "medium" if payload["status"] == "investigating" else "low"
    return Notification(
        event_type=CAPABILITY_CASE,
        object_id=str(payload["id"]),
        title=str(payload["title"]),
        severity=severity,  # type: ignore[arg-type]
        dedup_key=build_dedup_key(CAPABILITY_CASE, str(payload["id"])),
        case={key: value for key, value in payload.items() if value is not None},
        evidence=evidence_documents(evidence or ()),
        tags=(f"status:{payload['status']}",) if payload["status"] else (),
    )


def evidence_documents(rows: Iterable[Any]) -> list[dict[str, Any]]:
    """Summarise evidence rows: identifiers and metadata only, never raw content."""
    documents: list[dict[str, Any]] = []
    for row in list(rows)[:MAX_EVIDENCE_ITEMS]:
        document = {
            "id": _get(row, "id"),
            "eventType": _get(row, "event_type"),
            "observedAt": _iso(_get(row, "observed_at")),
            "contentSha256": _get(row, "content_sha256"),
            "sourceRefId": _get(row, "source_ref_id"),
            "integrity": _get(row, "integrity"),
        }
        documents.append({key: value for key, value in document.items() if value is not None})
    return documents


def _get(row: Any, name: str) -> Any:
    if isinstance(row, Mapping):
        return row.get(name)
    return getattr(row, name, None)


def _iso(value: Any) -> str | None:
    if value is None:
        return None
    isoformat = getattr(value, "isoformat", None)
    if callable(isoformat):
        return str(isoformat())
    return str(value)


__all__ = [
    "alert_to_notification",
    "case_to_notification",
    "evidence_documents",
]
