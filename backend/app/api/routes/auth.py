"""Identity introspection: what the current credential is allowed to do.

A single read endpoint that answers the question every RBAC rollout produces
("why was this call refused?"). It reports the principal derived from the
credential, its roles, its effective permission set and its workspace - all read
from the live matrix in ``app/services/rbac.py``, never from client input.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field

from app.api.security import principal_for
from app.services import rbac


router = APIRouter()


class IdentityResponse(BaseModel):
    display: str | None = None
    kind: str | None = None
    workspace_id: str = Field(alias="workspaceId")
    roles: list[str] = Field(default_factory=list)
    permissions: list[str] = Field(default_factory=list)

    model_config = {"populate_by_name": True}


@router.get("/me", response_model=IdentityResponse, response_model_by_alias=True)
def get_identity(
    request: Request,
    principal: object = Depends(principal_for),
) -> IdentityResponse:
    """Return the verified identity and its effective authorization."""
    return IdentityResponse.model_validate(rbac.summary(principal))
