from fastapi import APIRouter, Depends, Query
from sqlalchemy import desc, func, or_, select
from sqlalchemy.orm import Session

from app.db.models import AuditEvent
from app.db.session import get_db
from app.schemas.api import AuditEventRead, AuditEventsResponse


router = APIRouter()


@router.get("", response_model=AuditEventsResponse, response_model_by_alias=True)
def list_audit_events(
    search: str = "",
    object_type: str = Query("all", alias="objectType"),
    outcome: str = "all",
    page: int = Query(1, ge=1),
    page_size: int = Query(50, alias="pageSize", ge=1, le=200),
    db: Session = Depends(get_db),
) -> AuditEventsResponse:
    filters = []
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
