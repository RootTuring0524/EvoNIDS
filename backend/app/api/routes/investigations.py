from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session

from app.api.security import request_actor, require_analyst_token
from app.db.session import get_db
from app.schemas.api import (
    FeedbackCreate,
    FeedbackRead,
    InvestigationCreate,
    InvestigationDetail,
    InvestigationsResponse,
    InvestigationRunRead,
)
from app.services.investigation import (
    InvestigationRequest,
    add_feedback,
    create_run,
    list_runs,
    run_detail,
)


router = APIRouter()


@router.post("", response_model=InvestigationRunRead, status_code=202, response_model_by_alias=True)
def start_investigation(
    payload: InvestigationCreate,
    request: Request,
    _: None = Depends(require_analyst_token),
    db: Session = Depends(get_db),
) -> InvestigationRunRead:
    """Queue an AI investigation; execution happens in the background worker."""
    run = create_run(
        db,
        InvestigationRequest(
            alert_id=payload.alert_id,
            case_id=payload.case_id,
            requested_by=request_actor(request),
            max_tool_calls=payload.max_tool_calls,
            budget_usd=payload.budget_usd,
        ),
    )
    return InvestigationRunRead.model_validate(run)


@router.get("", response_model=InvestigationsResponse, response_model_by_alias=True)
def get_investigations(
    alert_id: str | None = Query(None, alias="alertId", max_length=96),
    state: str | None = Query(None, pattern="^(queued|running|succeeded|insufficient_evidence|degraded|failed|cancelled)$"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, alias="pageSize", ge=1, le=200),
    db: Session = Depends(get_db),
) -> InvestigationsResponse:
    return InvestigationsResponse.model_validate(
        list_runs(db, alert_id=alert_id, state=state, page=page, page_size=page_size)
    )


@router.get("/{run_id}", response_model=InvestigationDetail, response_model_by_alias=True)
def get_investigation(run_id: str, db: Session = Depends(get_db)) -> InvestigationDetail:
    return InvestigationDetail.model_validate(run_detail(db, run_id))


@router.post("/{run_id}/feedback", response_model=FeedbackRead, status_code=201, response_model_by_alias=True)
def post_feedback(
    run_id: str,
    payload: FeedbackCreate,
    request: Request,
    _: None = Depends(require_analyst_token),
    db: Session = Depends(get_db),
) -> FeedbackRead:
    if payload.object_type == "investigation_run" and payload.object_id != run_id:
        raise HTTPException(
            status_code=400, detail="object_id must match the investigation run id in the path"
        )
    row = add_feedback(
        db,
        object_type=payload.object_type,
        object_id=payload.object_id,
        verdict=payload.verdict,
        label=payload.label,
        comment=payload.comment,
        actor=request_actor(request),
    )
    return FeedbackRead.model_validate(row)


@router.post("/feedback", response_model=FeedbackRead, status_code=201, response_model_by_alias=True)
def post_object_feedback(
    payload: FeedbackCreate,
    request: Request,
    _: None = Depends(require_analyst_token),
    db: Session = Depends(get_db),
) -> FeedbackRead:
    """Analyst feedback for an alert, flow, claim or run (labels feed the next evaluation)."""
    row = add_feedback(
        db,
        object_type=payload.object_type,
        object_id=payload.object_id,
        verdict=payload.verdict,
        label=payload.label,
        comment=payload.comment,
        actor=request_actor(request),
    )
    return FeedbackRead.model_validate(row)
