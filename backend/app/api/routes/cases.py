"""Case management API (create / list / detail / update / attach / detach).

Authorization is expressed as permissions from ``app.services.rbac`` rather than
as "is this an admin token": creating a case and writing a note are analyst
work, while closing one is a reviewer (four-eyes) decision. Every handler also
receives the caller's workspace, which is the only workspace it can read or
write - a ``workspaceId`` in the body or query string is ignored by design.
"""
from __future__ import annotations

from typing import Literal, cast

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session

from app.api.security import (
    request_actor,
    request_workspace,
    require_permission,
    require_reader,
)
from app.db.models import Alert, Case
from app.db.session import get_db
from app.schemas.api import (
    AlertRead,
    CaseAttachRequest,
    CaseCreate,
    CaseDetail,
    CaseRead,
    CaseSuggestionItem,
    CaseSuggestionResponse,
    CaseTimelineItem,
    CasesResponse,
    CaseUpdate,
)
from app.services import cases as cases_service

router = APIRouter()


def _to_read(row: Case) -> CaseRead:
    return CaseRead(
        id=row.id,
        title=row.title,
        summary=row.summary,
        severity=cast("Literal['critical', 'high', 'medium', 'low']", row.severity),
        status=cast("Literal['open', 'investigating', 'contained', 'closed', 'archived']", row.status),
        assignee=row.assignee,
        created_by=row.created_by,
        alert_count=row.alert_count,
        highest_risk_score=row.highest_risk_score,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


@router.get("", response_model=CasesResponse, response_model_by_alias=True)
def list_cases(
    request: Request,
    search: str = "",
    status: str = Query("all"),
    severity: str = Query("all"),
    page: int = Query(1, ge=1),
    page_size: int = Query(25, alias="pageSize", ge=1, le=200),
    _: object = Depends(require_reader("case:read")),
    db: Session = Depends(get_db),
) -> CasesResponse:
    rows, total = cases_service.list_cases(
        db,
        search=search,
        status=status,
        severity=severity,
        page=page,
        page_size=page_size,
        workspace_id=request_workspace(request),
    )
    return CasesResponse(
        items=[_to_read(row) for row in rows],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.post("", response_model=CaseRead, response_model_by_alias=True, status_code=201)
def create_case(
    payload: CaseCreate,
    request: Request,
    _: object = Depends(require_permission("case:create")),
    db: Session = Depends(get_db),
) -> CaseRead:
    row = cases_service.create_case(
        db,
        payload,
        actor=request_actor(request),
        request_id=getattr(request.state, "request_id", None),
        workspace_id=request_workspace(request),
    )
    return _to_read(row)


@router.get("/suggestions", response_model=CaseSuggestionResponse, response_model_by_alias=True)
def case_suggestions(
    request: Request,
    alert_id: str = Query(..., alias="alertId", min_length=1, max_length=96),
    _: object = Depends(require_reader("case:read")),
    db: Session = Depends(get_db),
) -> CaseSuggestionResponse:
    alert = db.get(Alert, alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} was not found")
    raw_items = cases_service.suggest_cases_for_alert(
        db, alert, workspace_id=request_workspace(request)
    )
    items = [
        CaseSuggestionItem(
            case_id=item["case_id"],
            case_title=item["case_title"],
            case_status=cast(
                "Literal['open', 'investigating', 'contained', 'closed', 'archived']",
                item["case_status"],
            ),
            shared_ips=list(item["shared_ips"]),
            matching_alert_ids=list(item["matching_alert_ids"]),
            updated_at=item["updated_at"],
        )
        for item in raw_items
    ]
    return CaseSuggestionResponse(items=items)


@router.get("/{case_id}", response_model=CaseDetail, response_model_by_alias=True)
def get_case(
    case_id: str,
    request: Request,
    _: object = Depends(require_reader("case:read")),
    db: Session = Depends(get_db),
) -> CaseDetail:
    row = cases_service.get_case(db, case_id, workspace_id=request_workspace(request))
    alerts = cases_service.case_alerts(db, case_id)
    timeline = cases_service.case_timeline(db, case_id)
    return CaseDetail(
        case=_to_read(row),
        alerts=[AlertRead.model_validate(alert) for alert in alerts],
        timeline=[
            CaseTimelineItem(
                id=event.id,
                event_type=event.event_type,
                actor=event.actor,
                note=event.note,
                created_at=event.created_at,
            )
            for event in timeline
        ],
    )


@router.patch("/{case_id}", response_model=CaseRead, response_model_by_alias=True)
def update_case(
    case_id: str,
    payload: CaseUpdate,
    request: Request,
    principal: object = Depends(require_permission("case:note")),
    db: Session = Depends(get_db),
) -> CaseRead:
    """Update a case; closing it additionally requires ``case:close``.

    The extra check is payload-dependent (the same PATCH moves a case through
    ``investigating``, which is analyst work, and into ``closed``, which is a
    reviewer decision), so it runs after the body is parsed.
    """
    from app.api.security import enforce_permission

    if payload.status in cases_service.CLOSING_STATUSES:
        enforce_permission(request, principal, "case:close")
    row = cases_service.get_case(db, case_id, workspace_id=request_workspace(request))
    updated = cases_service.update_case(
        db,
        row,
        payload,
        actor=request_actor(request),
        request_id=getattr(request.state, "request_id", None),
    )
    return _to_read(updated)


@router.post("/{case_id}/alerts", response_model=CaseRead, response_model_by_alias=True)
def attach_alert(
    case_id: str,
    payload: CaseAttachRequest,
    request: Request,
    _: object = Depends(require_permission("case:note")),
    db: Session = Depends(get_db),
) -> CaseRead:
    row = cases_service.get_case(db, case_id, workspace_id=request_workspace(request))
    alert = db.get(Alert, payload.alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail=f"Alert {payload.alert_id} was not found")
    attached = cases_service.attach_alert(
        db,
        row,
        alert,
        actor=request_actor(request),
        request_id=getattr(request.state, "request_id", None),
    )
    return _to_read(attached)


@router.delete("/{case_id}/alerts/{alert_id}", response_model=CaseRead, response_model_by_alias=True)
def detach_alert(
    case_id: str,
    alert_id: str,
    request: Request,
    _: object = Depends(require_permission("case:note")),
    db: Session = Depends(get_db),
) -> CaseRead:
    row = cases_service.get_case(db, case_id, workspace_id=request_workspace(request))
    alert = db.get(Alert, alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} was not found")
    detached = cases_service.detach_alert(
        db,
        row,
        alert,
        actor=request_actor(request),
        request_id=getattr(request.state, "request_id", None),
    )
    return _to_read(detached)
