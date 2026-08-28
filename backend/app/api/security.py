import secrets

from fastapi import HTTPException, Request

from app.core.config import get_settings


def require_admin_token(request: Request) -> None:
    configured = get_settings().admin_api_token
    if configured is None:
        raise HTTPException(
            status_code=503,
            detail="Administrative writes are disabled until EVONIDS_ADMIN_API_TOKEN is configured",
        )
    supplied = request.headers.get("x-evonids-admin-token", "")
    if not supplied or not secrets.compare_digest(supplied, configured.get_secret_value()):
        raise HTTPException(status_code=401, detail="Invalid administrative credential")


def require_sensor_token(request: Request) -> None:
    settings = get_settings()
    configured = settings.sensor_ingest_token
    if configured is None:
        if settings.environment.lower() == "development":
            return
        raise HTTPException(
            status_code=503,
            detail="Sensor ingestion is disabled until EVONIDS_SENSOR_INGEST_TOKEN is configured",
        )
    supplied = request.headers.get("x-evonids-sensor-token", "")
    if not supplied or not secrets.compare_digest(supplied, configured.get_secret_value()):
        raise HTTPException(status_code=401, detail="Invalid sensor credential")
