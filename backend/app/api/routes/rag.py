from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.orm import Session

from app.api.security import require_admin_token
from app.db.session import get_db
from app.schemas.api import RagEvidenceCreate, RagEvidenceRead, RagResponse
from app.services.knowledge_retrieval import create_evidence, search_evidence


router = APIRouter()


@router.get("", response_model=RagResponse, response_model_by_alias=True)
def search_rag(
    query: str = "",
    top_k: int = Query(10, alias="topK", ge=1, le=50),
    db: Session = Depends(get_db),
) -> RagResponse:
    return search_evidence(db, query=query, top_k=top_k)


@router.post("/evidence", response_model=RagEvidenceRead, response_model_by_alias=True, status_code=201)
def post_evidence(
    payload: RagEvidenceCreate,
    request: Request,
    _: None = Depends(require_admin_token),
    actor: str = Query("local-analyst", min_length=1, max_length=120),
    db: Session = Depends(get_db),
) -> RagEvidenceRead:
    row = create_evidence(
        db,
        payload,
        actor=actor,
        request_id=getattr(request.state, "request_id", None),
    )
    result = search_evidence(db, query=row.source_id, top_k=50, agent_limit=0)
    return next(item for item in result.items if item.id == row.id)
