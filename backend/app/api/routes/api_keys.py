"""Administrative API-key management (create / list / revoke)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.api.security import require_admin_token
from app.db.session import get_db
from app.schemas.api import ApiKeyCreate, ApiKeyCreated, ApiKeyRead, ApiKeysResponse
from app.services.api_keys import (
    ApiKeyPrincipal,
    create_api_key,
    list_api_keys,
    revoke_api_key,
)

router = APIRouter()


def _to_read(row) -> ApiKeyRead:
    return ApiKeyRead(
        id=row.id,
        name=row.name,
        scope=row.scope,
        prefix=row.prefix,
        enabled=row.enabled,
        last_used_at=row.last_used_at,
    )


@router.get("", response_model=ApiKeysResponse, response_model_by_alias=True)
def list_keys(
    request: Request,
    _: ApiKeyPrincipal = Depends(require_admin_token),
    db: Session = Depends(get_db),
) -> ApiKeysResponse:
    return ApiKeysResponse(items=[_to_read(row) for row in list_api_keys(db)])


@router.post("", response_model=ApiKeyCreated, response_model_by_alias=True, status_code=201)
def create_key(
    payload: ApiKeyCreate,
    request: Request,
    principal: ApiKeyPrincipal = Depends(require_admin_token),
    db: Session = Depends(get_db),
) -> ApiKeyCreated:
    row, secret = create_api_key(
        db,
        payload,
        actor=principal.display,
        request_id=getattr(request.state, "request_id", None),
    )
    created = ApiKeyCreated(**_to_read(row).model_dump(), secret=secret)
    return created


@router.post("/{key_id}/revoke", response_model=ApiKeyRead, response_model_by_alias=True)
def revoke_key(
    key_id: str,
    request: Request,
    principal: ApiKeyPrincipal = Depends(require_admin_token),
    db: Session = Depends(get_db),
) -> ApiKeyRead:
    row = revoke_api_key(
        db,
        key_id,
        actor=principal.display,
        request_id=getattr(request.state, "request_id", None),
    )
    if row is None:
        raise HTTPException(status_code=404, detail=f"API key {key_id} was not found")
    return _to_read(row)
