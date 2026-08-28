from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session

from app.api.security import require_admin_token, require_sensor_token
from app.db.models import Sensor
from app.db.session import get_db
from app.schemas.api import SensorHeartbeat, SensorRead, SensorUpdate, SensorsResponse
from app.services.sensor_operations import list_sensors, record_heartbeat, update_sensor


router = APIRouter()


@router.get("", response_model=SensorsResponse, response_model_by_alias=True)
def get_sensors(
    search: str = "",
    state: str = Query("all", pattern="^(all|online|degraded|offline|maintenance)$"),
    db: Session = Depends(get_db),
) -> SensorsResponse:
    return list_sensors(db, search=search, state=state)


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
    return update_sensor(db, sensor, payload, request_id=getattr(request.state, "request_id", None))
