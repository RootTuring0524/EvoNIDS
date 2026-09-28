from typing import cast, Literal
from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.security import request_actor, require_admin_token
from app.db.models import ModelVersion
from app.db.session import get_db
from app.schemas.api import (
    ModelRead,
    ModelRollbackRequest,
    ModelRolloutRead,
    ModelRolloutRequest,
    ModelRolloutsResponse,
    ModelsResponse,
)
from app.services.drift_monitoring import feature_drift_report, model_health, prediction_drift
from app.services.model_registry import (
    artifact_state,
    rollback_model,
    rollout_of,
    rollout_summary,
    set_rollout,
)


router = APIRouter()


@router.get("", response_model=ModelsResponse, response_model_by_alias=True)
def list_models(db: Session = Depends(get_db)) -> ModelsResponse:
    rows = db.scalars(select(ModelVersion).order_by(ModelVersion.name)).all()
    items = []
    for row in rows:
        metrics = row.metrics
        items.append(
            ModelRead(
                id=row.id,
                name=row.name,
                role=row.role,
                version=row.version,
                state=cast("Literal['healthy', 'degraded', 'training']", row.state),
                latency=float(metrics.get("latency_ms", 0.0)),
                throughput=float(metrics.get("throughput_fps", 0.0)),
                quality_label=str(metrics.get("quality_label", "Not evaluated")),
                quality_value=float(metrics.get("quality_value", 0.0)),
                artifact_state=cast("Literal['available', 'missing', 'unverified']", artifact_state(row.artifact_uri)),
                feature_version=row.feature_version,
                training_run_id=row.parameters.get("trainingRunId"),
                dataset_id=row.parameters.get("datasetId"),
                algorithm=row.parameters.get("algorithm"),
                artifact_sha256=row.parameters.get("artifactSha256"),
                updated_at=row.updated_at,
            )
        )
    return ModelsResponse(items=items)


@router.get("/health")
def get_model_health(db: Session = Depends(get_db)) -> dict:
    """Registry view: artifact availability, feature contract and shadow policy."""
    return model_health(db)


@router.get("/drift")
def get_drift(
    channel: str = Query("baseline", pattern="^(baseline|autoencoder)$"),
    window_hours: int = Query(24, alias="windowHours", ge=1, le=720),
    limit: int = Query(5_000, ge=1, le=100_000),
    sensor_id: str | None = Query(None, alias="sensorId", max_length=80),
    db: Session = Depends(get_db),
) -> dict:
    """Feature drift (PSI/KS) plus prediction drift; unmeasured stays unmeasured."""
    report = feature_drift_report(
        db, channel=channel, window_hours=window_hours, limit=limit, sensor_id=sensor_id
    )
    report["predictionDrift"] = prediction_drift(db, window_hours=window_hours)
    return report



@router.get("/rollouts", response_model=ModelRolloutsResponse, response_model_by_alias=True)
def get_model_rollouts(db: Session = Depends(get_db)) -> ModelRolloutsResponse:
    """Shadow/canary/active/retired state for every registered model."""
    return ModelRolloutsResponse.model_validate(rollout_summary(db))


@router.post("/{model_id}/rollout", response_model=ModelRolloutRead, response_model_by_alias=True)
def post_model_rollout(
    model_id: str,
    payload: ModelRolloutRequest,
    request: Request,
    _: None = Depends(require_admin_token),
    db: Session = Depends(get_db),
) -> ModelRolloutRead:
    model = set_rollout(
        db, model_id=model_id, state=payload.state, actor=request_actor(request), note=payload.note
    )
    return ModelRolloutRead.model_validate(_rollout_row(model))


@router.post("/rollback", response_model=ModelRolloutRead, response_model_by_alias=True)
def post_model_rollback(
    payload: ModelRollbackRequest,
    request: Request,
    _: None = Depends(require_admin_token),
    db: Session = Depends(get_db),
) -> ModelRolloutRead:
    """Reactivate the most recently retired model for a role (audited)."""
    model = rollback_model(db, role=payload.role, actor=request_actor(request), reason=payload.reason)
    return ModelRolloutRead.model_validate(_rollout_row(model))


def _rollout_row(model: ModelVersion) -> dict:
    info = rollout_of(model)
    return {
        "id": model.id,
        "name": model.name,
        "role": model.role,
        "version": model.version,
        "state": model.state,
        "rollout": info.state,
        "rollout_updated_at": info.updated_at,
        "rollout_updated_by": info.updated_by,
        "rollout_note": info.note,
        "artifact_state": artifact_state(model.artifact_uri),
        "feature_version": model.feature_version,
        "contract_matches": (model.parameters or {}).get("featureContract") == "flow-online-v1",
    }
