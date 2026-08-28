from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import ModelVersion
from app.db.session import get_db
from app.schemas.api import ModelRead, ModelsResponse
from app.services.model_registry import artifact_state


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
                state=row.state,
                latency=float(metrics.get("latency_ms", 0.0)),
                throughput=float(metrics.get("throughput_fps", 0.0)),
                quality_label=str(metrics.get("quality_label", "Not evaluated")),
                quality_value=float(metrics.get("quality_value", 0.0)),
                artifact_state=artifact_state(row.artifact_uri),
                feature_version=row.feature_version,
                training_run_id=row.parameters.get("trainingRunId"),
                dataset_id=row.parameters.get("datasetId"),
                algorithm=row.parameters.get("algorithm"),
                artifact_sha256=row.parameters.get("artifactSha256"),
                updated_at=row.updated_at,
            )
        )
    return ModelsResponse(items=items)
