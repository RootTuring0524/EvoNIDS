from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.db.models import DetectionSignal, RiskAssessment
from app.db.session import get_db
from app.schemas.api import (
    DetectionFlowDetail,
    DetectionSignalsResponse,
    DetectionStatusResponse,
)
from app.services.online_detection import detector_status, parse_mode


router = APIRouter()


@router.get("/status", response_model=DetectionStatusResponse, response_model_by_alias=True)
def get_detection_status(db: Session = Depends(get_db)) -> DetectionStatusResponse:
    status = detector_status(db, mode=parse_mode(get_settings().detection_mode))
    return DetectionStatusResponse.model_validate(status)


@router.get("/signals", response_model=DetectionSignalsResponse, response_model_by_alias=True)
def list_detection_signals(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, alias="pageSize", ge=1, le=500),
    flow_id: str | None = Query(None, alias="flowId", max_length=96),
    sensor_id: str | None = Query(None, alias="sensorId", max_length=80),
    channel: str | None = Query(None, pattern="^(suricata|baseline|autoencoder)$"),
    decision: str | None = Query(None, pattern="^(alert|benign|abstain)$"),
    degraded: bool | None = Query(None),
    db: Session = Depends(get_db),
) -> DetectionSignalsResponse:
    filters = []
    if flow_id:
        filters.append(DetectionSignal.flow_id == flow_id)
    if sensor_id:
        filters.append(DetectionSignal.sensor_id == sensor_id)
    if channel:
        filters.append(DetectionSignal.channel == channel)
    if decision:
        filters.append(DetectionSignal.decision == decision)
    if degraded is not None:
        filters.append(DetectionSignal.degraded.is_(degraded))
    total = db.scalar(select(func.count()).select_from(DetectionSignal).where(*filters)) or 0
    rows = db.scalars(
        select(DetectionSignal)
        .where(*filters)
        .order_by(desc(DetectionSignal.created_at))
        .offset((page - 1) * page_size)
        .limit(page_size)
    ).all()
    return DetectionSignalsResponse.model_validate(
        {"items": rows, "total": total, "page": page, "page_size": page_size}
    )


@router.get("/flows/{flow_id}", response_model=DetectionFlowDetail, response_model_by_alias=True)
def get_flow_detection(flow_id: str, db: Session = Depends(get_db)) -> DetectionFlowDetail:
    signals = db.scalars(
        select(DetectionSignal)
        .where(DetectionSignal.flow_id == flow_id)
        .order_by(desc(DetectionSignal.created_at))
    ).all()
    assessments = db.scalars(
        select(RiskAssessment)
        .where(RiskAssessment.flow_id == flow_id)
        .order_by(desc(RiskAssessment.created_at))
    ).all()
    if not signals and not assessments:
        raise HTTPException(status_code=404, detail=f"No detection output was recorded for flow {flow_id}")
    return DetectionFlowDetail.model_validate(
        {"flow_id": flow_id, "signals": signals, "assessments": assessments}
    )
