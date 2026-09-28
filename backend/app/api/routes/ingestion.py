import gzip
import hashlib

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from sqlalchemy.orm import Session

from app.api.security import require_sensor_token
from app.core.config import get_settings
from app.db.session import get_db
from app.schemas.api import EveBatchIngestionResponse, EveIngestionResponse
from app.services.eve_ingestion import BatchConflict, ingest_eve_batch, ingest_eve_text
from app.services.online_detection import parse_mode


router = APIRouter()
MAX_EVE_BYTES = 10 * 1024 * 1024
SENSOR_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$"


@router.post("/eve", response_model=EveIngestionResponse, response_model_by_alias=True)
async def ingest_eve(
    request: Request,
    sensor_id: str = Query("lab-core-01", alias="sensorId", min_length=1, max_length=80, pattern=SENSOR_ID_PATTERN),
    _: None = Depends(require_sensor_token),
    db: Session = Depends(get_db),
) -> EveIngestionResponse:
    declared_length = request.headers.get("content-length")
    if declared_length and declared_length.isdigit() and int(declared_length) > MAX_EVE_BYTES:
        raise HTTPException(status_code=413, detail="EVE payload exceeds the 10 MiB development limit")
    body = await request.body()
    if len(body) > MAX_EVE_BYTES:
        raise HTTPException(status_code=413, detail="EVE payload exceeds the 10 MiB development limit")
    try:
        content = body.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise HTTPException(status_code=400, detail="EVE payload must be UTF-8 NDJSON") from exc
    result = ingest_eve_text(
        db, sensor_id=sensor_id, content=content, detection_mode=parse_mode(get_settings().detection_mode)
    )
    return EveIngestionResponse.model_validate(result)


@router.post("/eve/batch", response_model=EveBatchIngestionResponse, response_model_by_alias=True)
async def ingest_eve_batch_route(
    request: Request,
    sensor_id: str = Query(..., alias="sensorId", min_length=1, max_length=80, pattern=SENSOR_ID_PATTERN),
    batch_id: str = Header(
        ...,
        alias="X-Evonids-Batch-Id",
        min_length=8,
        max_length=120,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,119}$",
    ),
    encoding: str = Header("identity", alias="X-Evonids-Encoding", pattern="^(identity|gzip)$"),
    event_count: int | None = Header(None, alias="X-Evonids-Event-Count", ge=0, le=5_000_000),
    clock_skew: float | None = Header(None, alias="X-Evonids-Clock-Skew-Seconds", ge=-86400, le=86400),
    _: None = Depends(require_sensor_token),
    db: Session = Depends(get_db),
) -> EveBatchIngestionResponse:
    """Idempotent collector batch upload.

    The collector retries on timeout, so ``X-Evonids-Batch-Id`` identifies the
    batch and a replay with identical content returns the original outcome
    instead of double counting. Reusing an id for different content is a 409.
    """
    settings = get_settings()
    max_bytes = min(settings.collector_max_payload_bytes, MAX_EVE_BYTES * 8)
    declared_length = request.headers.get("content-length")
    if declared_length and declared_length.isdigit() and int(declared_length) > max_bytes:
        raise HTTPException(status_code=413, detail=f"batch payload exceeds {max_bytes} bytes")
    body = await request.body()
    if len(body) > max_bytes:
        raise HTTPException(status_code=413, detail=f"batch payload exceeds {max_bytes} bytes")

    payload_bytes = len(body)
    if encoding == "gzip":
        try:
            body = gzip.decompress(body)
        except (OSError, EOFError) as exc:
            raise HTTPException(status_code=400, detail="gzip body could not be decompressed") from exc
        if len(body) > max_bytes * 8:
            raise HTTPException(status_code=413, detail="decompressed batch payload exceeds the limit")
    try:
        content = body.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise HTTPException(status_code=400, detail="EVE batch must be UTF-8 NDJSON") from exc

    declared_events = sum(1 for line in content.splitlines() if line.strip())
    if event_count is not None and declared_events > event_count:
        raise HTTPException(
            status_code=400,
            detail=f"declared event count {event_count} is smaller than the {declared_events} lines received",
        )
    if declared_events > settings.collector_max_batch_events:
        raise HTTPException(
            status_code=413,
            detail=f"batch contains {declared_events} events, above the {settings.collector_max_batch_events} limit",
        )
    try:
        result = ingest_eve_batch(
            db,
            sensor_id=sensor_id,
            batch_id=batch_id,
            content=content,
            encoding=encoding,
            payload_bytes=payload_bytes,
            clock_skew_seconds=clock_skew,
            detection_mode=parse_mode(settings.detection_mode),
        )
    except BatchConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    response = EveBatchIngestionResponse.model_validate(result)
    response.content_sha256 = hashlib.sha256(body).hexdigest()
    return response
