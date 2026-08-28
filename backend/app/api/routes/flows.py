from fastapi import APIRouter, Depends, Query
from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from app.db.models import Flow
from app.db.session import get_db
from app.schemas.api import FlowRead, FlowsResponse


router = APIRouter()


@router.get("", response_model=FlowsResponse, response_model_by_alias=True)
def list_flows(
    page: int = Query(1, ge=1),
    page_size: int = Query(100, alias="pageSize", ge=1, le=500),
    db: Session = Depends(get_db),
) -> FlowsResponse:
    total = db.scalar(select(func.count()).select_from(Flow)) or 0
    rows = db.scalars(
        select(Flow).order_by(desc(Flow.time)).offset((page - 1) * page_size).limit(page_size)
    ).all()
    return FlowsResponse(items=[FlowRead.model_validate(row) for row in rows], total=total)

