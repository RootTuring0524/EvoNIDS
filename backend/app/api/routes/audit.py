from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import and_, desc, func, or_, select
from sqlalchemy.orm import Session

from app.api.security import require_admin_token
from app.db.base import utc_now
from app.db.models import AuditEvent, Case, CaseAlert
from app.db.session import get_db
from app.schemas.api import AuditEventRead, AuditEventsResponse, ConsoleAuditEvent

router = APIRouter()

CASE_ID_PATTERN = r"^CASE-[A-F0-9]{12}$"
# Object types whose audit records carry the owning case id inside their
# before/after state JSON instead of in the structured object_id column.
CASE_SCOPED_STATE_TYPES = ("case_alert", "case_note", "case_timeline")


def _state_mentions_case(state: object, case_id: str) -> bool:
    """Return True when a before/after state JSON document references case_id.

    Walks nested dicts/lists and treats a leaf string as a reference when it
    contains the case id (either as an exact value or embedded in free text,
    e.g. a note inside a ``case_note`` record). Non-text leaves never match,
    because case ids are always stored as strings.
    """
    if isinstance(state, str):
        return case_id in state
    if isinstance(state, list):
        return any(_state_mentions_case(item, case_id) for item in state)
    if isinstance(state, dict):
        return any(
            _state_mentions_case(key, case_id) or _state_mentions_case(value, case_id)
            for key, value in state.items()
        )
    return False


def _case_scope_filter(db: Session, case_id: str):
    """Return a WHERE fragment selecting audit events that belong to a case.

    An event belongs to ``case_id`` when it is a ``case`` event about that case,
    when it is a ``case_alert``/``case_note``/``case_timeline`` record whose
    before/after state JSON mentions the case, or when it is an ``alert`` event
    for an alert currently attached to the case via the ``case_alerts`` table.

    The state-JSON scan is deliberately bounded to the three case-scoped object
    types above (a small, specialized slice of the audit log); a broader
    index-backed approach would need a schema change and is out of scope here.
    """
    conditions = [
        and_(AuditEvent.object_type == "case", AuditEvent.object_id == case_id),
    ]
    attached_alert_ids = {
        alert_id
        for (alert_id,) in db.execute(
            select(CaseAlert.alert_id).where(CaseAlert.case_id == case_id)
        ).all()
    }
    if attached_alert_ids:
        conditions.append(
            and_(
                AuditEvent.object_type == "alert",
                AuditEvent.object_id.in_(sorted(attached_alert_ids)),
            )
        )
    state_rows = db.execute(
        select(AuditEvent.id, AuditEvent.before_state, AuditEvent.after_state).where(
            AuditEvent.object_type.in_(CASE_SCOPED_STATE_TYPES)
        )
    ).all()
    state_ids = [
        event_id
        for event_id, before_state, after_state in state_rows
        if _state_mentions_case(before_state, case_id)
        or _state_mentions_case(after_state, case_id)
    ]
    if state_ids:
        conditions.append(AuditEvent.id.in_(state_ids))
    return or_(*conditions)


@router.get("", response_model=AuditEventsResponse, response_model_by_alias=True)
def list_audit_events(
    search: str = "",
    object_type: str = Query("all", alias="objectType"),
    outcome: str = "all",
    case_id: str | None = Query(None, alias="caseId", pattern=CASE_ID_PATTERN),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, alias="pageSize", ge=1, le=200),
    db: Session = Depends(get_db),
) -> AuditEventsResponse:
    filters = []
    if case_id:
        if db.get(Case, case_id) is None:
            raise HTTPException(status_code=404, detail=f"Case {case_id} was not found")
        filters.append(_case_scope_filter(db, case_id))
    if object_type != "all":
        filters.append(AuditEvent.object_type == object_type)
    if outcome != "all":
        filters.append(AuditEvent.outcome == outcome)
    if search.strip():
        term = f"%{search.strip()}%"
        filters.append(
            or_(
                AuditEvent.id.ilike(term),
                AuditEvent.actor.ilike(term),
                AuditEvent.action.ilike(term),
                AuditEvent.object_id.ilike(term),
                AuditEvent.request_id.ilike(term),
            )
        )
    total = db.scalar(select(func.count()).select_from(AuditEvent).where(*filters)) or 0
    rows = db.scalars(
        select(AuditEvent)
        .where(*filters)
        .order_by(desc(AuditEvent.created_at))
        .offset((page - 1) * page_size)
        .limit(page_size)
    ).all()
    return AuditEventsResponse(
        items=[AuditEventRead.model_validate(row) for row in rows],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.post(
    "/console",
    status_code=201,
    dependencies=[Depends(require_admin_token)],
)
def record_console_event(
    payload: ConsoleAuditEvent,
    request: Request,
    db: Session = Depends(get_db),
) -> dict[str, str]:
    """Persist console authentication events (login success/failure/lock, logout).

    The Nuxt console forwards these events with its server-side admin token so
    console access attempts land in the same tamper-evident audit stream as every
    other operation. The console itself is best-effort: a failed forward never
    blocks the login flow.
    """
    outcome = "completed" if payload.action.endswith("success") else "failed"
    db.add(
        AuditEvent(
            id=f"AUD-{uuid.uuid4().hex.upper()}",
            created_at=utc_now(),
            actor="console",
            action=payload.action,
            object_type="console_session",
            object_id="console",
            outcome=outcome,
            request_id=getattr(request.state, "request_id", None),
            before_state=None,
            after_state=None,
            note=payload.note,
        )
    )
    db.commit()
    return {"accepted": "true"}
