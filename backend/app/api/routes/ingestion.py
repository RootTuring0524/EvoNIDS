from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session

from app.api.security import require_sensor_token
from app.db.session import get_db
from app.schemas.api import EveIngestionResponse
from app.services.eve_ingestion import ingest_eve_text


router = APIRouter()
MAX_EVE_BYTES = 10 * 1024 * 1024


@router.post("/eve", response_model=EveIngestionResponse, response_model_by_alias=True)
async def ingest_eve(
    request: Request,
    sensor_id: str = Query("lab-core-01", alias="sensorId", min_length=1, max_length=80),
    _: None = Depends(require_sensor_token),
    db: Session = Depends(get_db),
) -> EveIngestionResponse:
    body = await request.body()
    if len(body) > MAX_EVE_BYTES:
        raise HTTPException(status_code=413, detail="EVE payload exceeds the 10 MiB development limit")
    try:
        content = body.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise HTTPException(status_code=400, detail="EVE payload must be UTF-8 NDJSON") from exc
    result = ingest_eve_text(db, sensor_id=sensor_id, content=content)
    return EveIngestionResponse.model_validate(result)
