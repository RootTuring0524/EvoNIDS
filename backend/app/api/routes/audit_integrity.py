"""Content-addressed upload of the audit chain plus verification endpoints.

Wiring the endpoints is deliberately thin; the chain logic and the offline
verifier live in :mod:`app.services.audit_chain` so the same code path is used by
the API and by an auditor running the export through a script.
"""
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.api.security import require_admin_token
from app.db.session import get_db
from app.services.audit_chain import chain_stats, export_events, verify_chain, verify_export


router = APIRouter()


@router.get("/integrity")
def audit_integrity(
    workspace_id: str = Query("default", alias="workspaceId", max_length=64),
    limit: int = Query(50_000, ge=1, le=500_000),
    db: Session = Depends(get_db),
) -> dict:
    """Recompute the audit hash chain and report any inconsistency."""
    verification = verify_chain(db, workspace_id=workspace_id, limit=limit)
    return {
        "stats": chain_stats(db, workspace_id=workspace_id),
        "verification": verification.as_dict(),
    }


@router.get("/export")
def audit_export(
    workspace_id: str = Query("default", alias="workspaceId", max_length=64),
    limit: int = Query(100_000, ge=1, le=500_000),
    _: None = Depends(require_admin_token),
    db: Session = Depends(get_db),
) -> dict:
    """Portable export (admin only): records plus the verification result."""
    return export_events(db, workspace_id=workspace_id, limit=limit)


@router.post("/verify")
def audit_verify_export(
    document: dict,
    _: None = Depends(require_admin_token),
) -> dict:
    """Verify an exported document without touching the database."""
    if not isinstance(document, dict) or "events" not in document:
        raise HTTPException(status_code=422, detail="the body must be an audit export document")
    return verify_export(document)
