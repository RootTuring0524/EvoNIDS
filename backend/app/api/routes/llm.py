from fastapi import APIRouter, Depends

from app.api.security import require_admin_token
from app.core.config import get_settings
from app.schemas.api import LlmProbeResponse, LlmStatusResponse
from app.services.llm_gateway import get_gateway


router = APIRouter()


@router.get("/status", response_model=LlmStatusResponse, response_model_by_alias=True)
def get_llm_status(_: None = Depends(require_admin_token)) -> LlmStatusResponse:
    """Provider health, circuit state and budget usage (admin only, no secrets)."""
    return LlmStatusResponse.model_validate(get_gateway(get_settings()).status())


@router.post("/probe", response_model=LlmProbeResponse, response_model_by_alias=True)
def probe_llm(_: None = Depends(require_admin_token)) -> LlmProbeResponse:
    """Verify the configured model id against the provider's model list."""
    return LlmProbeResponse.model_validate(get_gateway(get_settings()).probe())
