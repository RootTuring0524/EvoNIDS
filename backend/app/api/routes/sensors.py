from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from app.api.security import request_actor, require_admin_token, require_sensor_token
from app.db.models import IngestionBatch, Sensor
from app.db.session import get_db
from app.schemas.api import (
    IngestionBatchesResponse,
    SensorHealthResponse,
    SensorHeartbeat,
    SensorRead,
    SensorUpdate,
    SensorsResponse,
)
from app.services.sensor_health import sensor_health_report
from app.services.sensor_operations import list_sensors, record_heartbeat, update_sensor


router = APIRouter()


@router.get("", response_model=SensorsResponse, response_model_by_alias=True)
def get_sensors(
    search: str = "",
    state: str = Query("all", pattern="^(all|online|degraded|offline|maintenance)$"),
    db: Session = Depends(get_db),
) -> SensorsResponse:
    return list_sensors(db, search=search, state=state)


@router.get("/health", response_model=SensorHealthResponse, response_model_by_alias=True)
def get_sensor_health(
    sensor_id: str | None = Query(None, alias="sensorId", max_length=80),
    window_seconds: int = Query(3600, alias="windowSeconds", ge=60, le=604800),
    db: Session = Depends(get_db),
) -> SensorHealthResponse:
    """Per-sensor data-quality metrics; unmeasurable metrics are marked unmeasured."""
    return sensor_health_report(db, sensor_id=sensor_id, window_seconds=window_seconds)


@router.get(
    "/{sensor_id}/batches", response_model=IngestionBatchesResponse, response_model_by_alias=True
)
def get_sensor_batches(
    sensor_id: str,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, alias="pageSize", ge=1, le=500),
    db: Session = Depends(get_db),
) -> IngestionBatchesResponse:
    if db.get(Sensor, sensor_id) is None:
        raise HTTPException(status_code=404, detail=f"Sensor {sensor_id} was not found")
    total = (
        db.scalar(
            select(func.count()).select_from(IngestionBatch).where(IngestionBatch.sensor_id == sensor_id)
        )
        or 0
    )
    rows = db.scalars(
        select(IngestionBatch)
        .where(IngestionBatch.sensor_id == sensor_id)
        .order_by(desc(IngestionBatch.received_at))
        .offset((page - 1) * page_size)
        .limit(page_size)
    ).all()
    return IngestionBatchesResponse.model_validate(
        {"items": rows, "total": total, "page": page, "page_size": page_size}
    )


@router.post("/{sensor_id}/heartbeat", response_model=SensorRead, response_model_by_alias=True)
def heartbeat(
    sensor_id: str,
    payload: SensorHeartbeat,
    _: None = Depends(require_sensor_token),
    db: Session = Depends(get_db),
) -> SensorRead:
    return record_heartbeat(db, sensor_id, payload)


@router.patch("/{sensor_id}", response_model=SensorRead, response_model_by_alias=True)
def patch_sensor(
    sensor_id: str,
    payload: SensorUpdate,
    request: Request,
    _: None = Depends(require_admin_token),
    db: Session = Depends(get_db),
) -> SensorRead:
    sensor = db.get(Sensor, sensor_id)
    if sensor is None:
        raise HTTPException(status_code=404, detail=f"Sensor {sensor_id} was not found")
    return update_sensor(
        db,
        sensor,
        payload,
        request_id=getattr(request.state, "request_id", None),
        actor=request_actor(request),
    )
