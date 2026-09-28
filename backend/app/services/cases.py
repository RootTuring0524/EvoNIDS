"""Case management service: cases, alert aggregation, status lifecycle, timeline.

The immutable audit log stays the record of truth; ``case_timeline_events`` is a
case-scoped, human-readable mirror written by this service. Alert aggregation is
explicit (manual create + attach/detach); ``suggest_cases_for_alert`` offers
deterministic correlation suggestions (shared source/destination endpoints with
already attached alerts) but never auto-creates cases.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass

from fastapi import HTTPException
from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from app.db.base import utc_now
from app.db.models import Alert, AuditEvent, Case, CaseAlert, CaseTimelineEvent
from app.schemas.api import CaseCreate, CaseUpdate
from app.services.rbac import DEFAULT_WORKSPACE

ALLOWED_STATUS_TRANSITIONS: dict[str, set[str]] = {
    "open": {"investigating"},
    "investigating": {"open", "contained", "closed"},
    "contained": {"closed", "investigating"},
    "closed": {"investigating", "archived"},
    "archived": set(),
}

NOTE_REQUIRED_STATUSES = {"contained", "closed", "archived"}

# Statuses that end a case. Reaching one requires the ``case:close`` permission
# (reviewer or admin), so the analyst who investigated a case cannot also be the
# one who signs it off.
CLOSING_STATUSES = frozenset({"contained", "closed", "archived"})


@dataclass(slots=True)
class CaseStats:
    total: int


def new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex.upper()[:12]}"


def _audit(
    db: Session,
    *,
    action: str,
    object_id: str,
    actor: str,
    request_id: str | None,
    note: str,
    after_state: dict | None = None,
) -> None:
    db.add(
        AuditEvent(
            id=f"AUD-{uuid.uuid4().hex.upper()}",
            created_at=utc_now(),
            actor=actor,
            action=action,
            object_type="case",
            object_id=object_id,
            outcome="completed",
            request_id=request_id,
            before_state=None,
            after_state=after_state,
            note=note,
        )
    )


def _timeline(
    db: Session,
    *,
    case_id: str,
    event_type: str,
    actor: str,
    note: str | None,
    payload: dict | None = None,
) -> None:
    db.add(
        CaseTimelineEvent(
            id=new_id("TLN"),
            case_id=case_id,
            created_at=utc_now(),
            event_type=event_type,
            actor=actor,
            note=note,
            payload=payload,
        )
    )


def create_case(
    db: Session,
    payload: CaseCreate,
    *,
    actor: str,
    request_id: str | None,
    workspace_id: str = DEFAULT_WORKSPACE,
) -> Case:
    now = utc_now()
    case_id = new_id("CASE")
    row = Case(
        id=case_id,
        # Stamped from the authenticated principal by the caller; never from the
        # request payload (see app.services.rbac.effective_workspace).
        workspace_id=workspace_id,
        title=payload.title.strip(),
        summary=payload.summary.strip(),
        severity=payload.severity,
        status="open",
        assignee=None,
        created_by=actor,
        alert_count=0,
        highest_risk_score=0.0,
        created_at=now,
        updated_at=now,
    )
    db.add(row)
    _audit(
        db,
        action="case.created",
        object_id=case_id,
        actor=actor,
        request_id=request_id,
        after_state={"title": row.title, "severity": row.severity},
        note="Case created",
    )
    _timeline(db, case_id=case_id, event_type="case.created", actor=actor, note="Case created")
    db.commit()
    db.refresh(row)
    return row


def list_cases(
    db: Session,
    *,
    search: str = "",
    status: str = "all",
    severity: str = "all",
    page: int = 1,
    page_size: int = 25,
    workspace_id: str = DEFAULT_WORKSPACE,
) -> tuple[list[Case], int]:
    """List cases inside one workspace.

    ``workspace_id`` is always supplied by the caller from the authenticated
    principal, so a request can never widen its own visibility.
    """
    filters = [Case.workspace_id == workspace_id]
    if status != "all":
        filters.append(Case.status == status)
    if severity != "all":
        filters.append(Case.severity == severity)
    if search.strip():
        term = f"%{search.strip()}%"
        filters.append(Case.title.ilike(term))
    total = int(db.scalar(select(func.count()).select_from(Case).where(*filters)) or 0)
    rows = list(
        db.scalars(
            select(Case)
            .where(*filters)
            .order_by(desc(Case.updated_at))
            .offset((page - 1) * page_size)
            .limit(page_size)
        ).all()
    )
    return rows, total


def get_case(db: Session, case_id: str, *, workspace_id: str | None = None) -> Case:
    """Fetch one case, optionally pinned to a workspace.

    A case that exists in another workspace is reported exactly like a missing
    one (404), so the endpoint does not leak the existence of another tenant's
    case to a caller who guessed the id.
    """
    row = db.get(Case, case_id)
    if row is None or (workspace_id is not None and row.workspace_id != workspace_id):
        raise HTTPException(status_code=404, detail=f"Case {case_id} was not found")
    return row


def case_alerts(db: Session, case_id: str) -> list[Alert]:
    return list(
        db.scalars(
            select(Alert)
            .join(CaseAlert, CaseAlert.alert_id == Alert.id)
            .where(CaseAlert.case_id == case_id)
            .order_by(desc(Alert.timestamp))
        ).all()
    )


def case_timeline(db: Session, case_id: str, *, limit: int = 200) -> list[CaseTimelineEvent]:
    return list(
        db.scalars(
            select(CaseTimelineEvent)
            .where(CaseTimelineEvent.case_id == case_id)
            .order_by(desc(CaseTimelineEvent.created_at))
            .limit(limit)
        ).all()
    )


def update_case(
    db: Session,
    row: Case,
    update: CaseUpdate,
    *,
    actor: str,
    request_id: str | None,
) -> Case:
    before = {"title": row.title, "status": row.status, "summary": row.summary, "assignee": row.assignee}
    note = (update.note or "").strip()
    if update.summary is not None:
        row.summary = update.summary.strip()
    if update.assignee is not None:
        row.assignee = update.assignee.strip() or None
    if update.status is not None and update.status != row.status:
        allowed = ALLOWED_STATUS_TRANSITIONS.get(row.status, set())
        if update.status not in allowed:
            raise HTTPException(
                status_code=409,
                detail=f"Case transition {row.status} -> {update.status} is not allowed",
            )
        if update.status in NOTE_REQUIRED_STATUSES and len(note) < 10:
            raise HTTPException(
                status_code=400,
                detail="A note of at least 10 characters is required for this transition",
            )
        _timeline(
            db,
            case_id=row.id,
            event_type=f"case.{update.status}",
            actor=actor,
            note=note or f"Case moved to {update.status}",
        )
        row.status = update.status
    row.updated_at = utc_now()
    after = {"title": row.title, "status": row.status, "summary": row.summary, "assignee": row.assignee}
    if before == after:
        raise HTTPException(status_code=400, detail="The request does not change the case")
    _audit(
        db,
        action="case.update",
        object_id=row.id,
        actor=actor,
        request_id=request_id,
        after_state=after,
        note=note or "Case updated",
    )
    db.commit()
    db.refresh(row)
    return row


def attach_alert(
    db: Session,
    row: Case,
    alert: Alert,
    *,
    actor: str,
    request_id: str | None,
) -> Case:
    existing = db.scalar(
        select(CaseAlert).where(CaseAlert.case_id == row.id, CaseAlert.alert_id == alert.id)
    )
    if existing is not None:
        raise HTTPException(status_code=409, detail=f"Alert {alert.id} is already attached to case {row.id}")
    db.add(
        CaseAlert(
            id=new_id("CA"),
            case_id=row.id,
            alert_id=alert.id,
            created_at=utc_now(),
            updated_at=utc_now(),
        )
    )
    row.alert_count += 1
    row.highest_risk_score = max(row.highest_risk_score, alert.risk_score)
    row.updated_at = utc_now()
    _timeline(
        db,
        case_id=row.id,
        event_type="case.alert_attached",
        actor=actor,
        note=f"Alert {alert.id} attached ({alert.title})",
        payload={"alertId": alert.id, "riskScore": alert.risk_score},
    )
    _audit(
        db,
        action="case.alert_attached",
        object_id=row.id,
        actor=actor,
        request_id=request_id,
        after_state={"alertId": alert.id, "alertCount": row.alert_count},
        note=f"Alert {alert.id} attached",
    )
    db.commit()
    db.refresh(row)
    return row


def detach_alert(
    db: Session,
    row: Case,
    alert: Alert,
    *,
    actor: str,
    request_id: str | None,
) -> Case:
    link = db.scalar(
        select(CaseAlert).where(CaseAlert.case_id == row.id, CaseAlert.alert_id == alert.id)
    )
    if link is None:
        raise HTTPException(status_code=404, detail=f"Alert {alert.id} is not attached to case {row.id}")
    db.delete(link)
    row.alert_count = max(0, row.alert_count - 1)
    row.updated_at = utc_now()
    _timeline(
        db,
        case_id=row.id,
        event_type="case.alert_detached",
        actor=actor,
        note=f"Alert {alert.id} detached",
        payload={"alertId": alert.id},
    )
    _audit(
        db,
        action="case.alert_detached",
        object_id=row.id,
        actor=actor,
        request_id=request_id,
        after_state={"alertId": alert.id, "alertCount": row.alert_count},
        note=f"Alert {alert.id} detached",
    )
    db.commit()
    db.refresh(row)
    return row


def suggest_cases_for_alert(
    db: Session, alert: Alert, *, limit: int = 10, workspace_id: str = DEFAULT_WORKSPACE
) -> list[dict]:
    """Return open/investigating cases sharing at least one endpoint with alert.

    Deterministic and transparent: shared endpoints and the concrete attached
    alert ids are returned so the analyst sees *why* a case was suggested. Only
    cases in the caller's workspace are considered.
    """
    alert_ips = {ip for ip in (alert.source_ip, alert.destination_ip) if ip and ip != "0.0.0.0"}
    if not alert_ips:
        return []
    open_cases = list(
        db.scalars(
            select(Case)
            .where(Case.status.in_(("open", "investigating")), Case.workspace_id == workspace_id)
            .order_by(desc(Case.updated_at))
        ).all()
    )
    suggestions: list[dict] = []
    for case in open_cases:
        attached = list(
            db.scalars(
                select(Alert)
                .join(CaseAlert, CaseAlert.alert_id == Alert.id)
                .where(CaseAlert.case_id == case.id)
            ).all()
        )
        shared: set[str] = set()
        matching_alert_ids: list[str] = []
        for attached_alert in attached:
            case_ips = {
                ip for ip in (attached_alert.source_ip, attached_alert.destination_ip) if ip and ip != "0.0.0.0"
            }
            overlap = alert_ips & case_ips
            if overlap:
                shared |= overlap
                matching_alert_ids.append(attached_alert.id)
        if not shared:
            continue
        suggestions.append(
            {
                "case_id": case.id,
                "case_title": case.title,
                "case_status": case.status,
                "shared_ips": sorted(shared),
                "matching_alert_ids": matching_alert_ids[:20],
                "updated_at": case.updated_at,
            }
        )
        if len(suggestions) >= limit:
            break
    suggestions.sort(
        key=lambda item: (len(item["shared_ips"]), str(item["updated_at"])),
        reverse=True,
    )
    return suggestions[:limit]
