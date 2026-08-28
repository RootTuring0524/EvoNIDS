from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import asc, desc, func, or_, select
from sqlalchemy.orm import Session

from app.api.security import require_admin_token
from app.db.base import utc_now
from app.db.models import AgentRun, Alert, AuditEvent
from app.db.session import get_db
from app.schemas.api import AgentAnalysis, AlertDetail, AlertRead, AlertsResponse, AlertUpdate
from app.services.alert_operations import build_alert_detail, update_alert


router = APIRouter()
SORT_FIELDS = {
    "severity": Alert.severity,
    "timestamp": Alert.timestamp,
    "title": Alert.title,
    "sourceIp": Alert.source_ip,
    "destinationIp": Alert.destination_ip,
    "category": Alert.category,
    "riskScore": Alert.risk_score,
    "status": Alert.status,
    "owner": Alert.owner,
}


@router.get("", response_model=AlertsResponse, response_model_by_alias=True)
def list_alerts(
    severity: str = "all",
    status: str = "all",
    category: str = "all",
    search: str = "",
    page: int = Query(1, ge=1),
    page_size: int = Query(25, alias="pageSize", ge=1, le=100),
    sort_by: str = Query("riskScore", alias="sortBy"),
    sort_dir: str = Query("desc", alias="sortDir", pattern="^(asc|desc)$"),
    db: Session = Depends(get_db),
) -> AlertsResponse:
    filters = []
    if severity != "all":
        filters.append(Alert.severity == severity)
    if status != "all":
        filters.append(Alert.status == status)
    if category != "all":
        filters.append(Alert.category == category)
    if search.strip():
        term = f"%{search.strip()}%"
        filters.append(
            or_(
                Alert.id.ilike(term),
                Alert.title.ilike(term),
                Alert.source_ip.ilike(term),
                Alert.destination_ip.ilike(term),
            )
        )

    total = db.scalar(select(func.count()).select_from(Alert).where(*filters)) or 0
    sort_column = SORT_FIELDS.get(sort_by, Alert.risk_score)
    order = asc(sort_column) if sort_dir == "asc" else desc(sort_column)
    rows = db.scalars(
        select(Alert)
        .where(*filters)
        .order_by(order, desc(Alert.timestamp))
        .offset((page - 1) * page_size)
        .limit(page_size)
    ).all()
    latest_agent_rows = db.scalars(
        select(AgentRun)
        .join(Alert, AgentRun.alert_id == Alert.id)
        .where(*filters)
        .order_by(desc(AgentRun.created_at))
    ).all()
    latest_by_alert: dict[str, AgentRun] = {}
    for agent_run in latest_agent_rows:
        latest_by_alert.setdefault(agent_run.alert_id, agent_run)
    decision_counts: dict[str, int] = {}
    completed = 0
    for agent_run in latest_by_alert.values():
        if agent_run.state == "completed":
            completed += 1
            decision_counts[agent_run.pattern_decision] = (
                decision_counts.get(agent_run.pattern_decision, 0) + 1
            )
    items = []
    for row in rows:
        agent_run = latest_by_alert.get(row.id)
        items.append(
            AlertRead.model_validate(row).model_copy(
                update={
                    "agent_state": agent_run.state if agent_run else "not_run",
                    "agent_decision": agent_run.pattern_decision if agent_run else None,
                    "agent_run_id": agent_run.id if agent_run else None,
                }
            )
        )
    return AlertsResponse(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        agent_completed=completed,
        agent_pending=max(0, total - completed),
        agent_decisions=decision_counts,
    )


@router.get("/{alert_id}", response_model=AlertDetail, response_model_by_alias=True)
def get_alert(alert_id: str, db: Session = Depends(get_db)) -> AlertDetail:
    row = db.get(Alert, alert_id)
    if row is None:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} was not found")
    return build_alert_detail(db, row)


@router.post(
    "/{alert_id}/agent-runs",
    response_model=AgentAnalysis,
    response_model_by_alias=True,
    dependencies=[Depends(require_admin_token)],
)
def persist_agent_run(
    alert_id: str,
    analysis: AgentAnalysis,
    request: Request,
    db: Session = Depends(get_db),
) -> AgentAnalysis:
    alert = db.get(Alert, alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} was not found")
    existing = db.get(AgentRun, analysis.run_id)
    if existing is not None:
        if existing.alert_id != alert_id:
            raise HTTPException(status_code=409, detail="Agent run ID is already bound to another alert")
        return analysis

    detail = build_alert_detail(db, alert)
    trusted_ids = {
        item.id
        for item in detail.rag
        if item.allowed and item.used_by_agent and item.prompt_injection_risk == "none"
    }
    supplied_ids = set(analysis.evidence_ids)
    if (
        not supplied_ids
        or len(supplied_ids) != len(analysis.evidence_ids)
        or not supplied_ids.issubset(trusted_ids)
    ):
        raise HTTPException(status_code=422, detail="Agent evidence IDs are outside the trusted context")

    db.add(
        AgentRun(
            id=analysis.run_id,
            alert_id=alert_id,
            display_model=analysis.display_model,
            state=analysis.state,
            hypothesis=analysis.hypothesis,
            pattern_decision=analysis.pattern_decision,
            summary=analysis.summary,
            recommendation=analysis.recommendation,
            evidence_ids=analysis.evidence_ids,
            steps=[step.model_dump() for step in analysis.steps],
            duration_ms=sum(step.duration_ms for step in analysis.steps),
        )
    )
    db.add(
        AuditEvent(
            id=f"AUD-{analysis.run_id}",
            created_at=utc_now(),
            actor=analysis.display_model,
            action="agent.analysis.persist",
            object_type="alert",
            object_id=alert_id,
            outcome=analysis.state,
            request_id=getattr(request.state, "request_id", None),
            before_state={"agentRun": None},
            after_state={
                "agentRun": analysis.run_id,
                "patternDecision": analysis.pattern_decision,
                "evidenceIds": analysis.evidence_ids,
            },
            note="Validated Agent analysis persisted after trusted-evidence enforcement.",
        )
    )
    db.commit()
    return analysis


@router.patch(
    "/{alert_id}",
    response_model=AlertDetail,
    response_model_by_alias=True,
    dependencies=[Depends(require_admin_token)],
)
def patch_alert(
    alert_id: str,
    update: AlertUpdate,
    request: Request,
    db: Session = Depends(get_db),
) -> AlertDetail:
    row = db.get(Alert, alert_id)
    if row is None:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} was not found")
    updated = update_alert(
        db,
        row,
        update,
        request_id=getattr(request.state, "request_id", None),
    )
    return build_alert_detail(db, updated)
