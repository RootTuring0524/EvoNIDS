from fastapi import APIRouter, BackgroundTasks, Depends, Request, status
from sqlalchemy.orm import Session

from app.api.security import require_admin_token
from app.core.config import Settings, get_settings
from app.db.session import get_db
from app.schemas.api import TrainingRunCreate, TrainingRunRead, TrainingRunsResponse
from app.services.training import (
    execute_training_run,
    get_training_run,
    list_training_runs,
    queue_training_run,
    to_training_run_read,
)


router = APIRouter()


@router.get("", response_model=TrainingRunsResponse, response_model_by_alias=True)
def list_runs(db: Session = Depends(get_db)) -> TrainingRunsResponse:
    return list_training_runs(db)


@router.get("/{run_id}", response_model=TrainingRunRead, response_model_by_alias=True)
def read_run(run_id: str, db: Session = Depends(get_db)) -> TrainingRunRead:
    return get_training_run(db, run_id)


@router.post(
    "",
    response_model=TrainingRunRead,
    response_model_by_alias=True,
    status_code=status.HTTP_202_ACCEPTED,
    dependencies=[Depends(require_admin_token)],
)
def start_run(
    payload: TrainingRunCreate,
    background_tasks: BackgroundTasks,
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> TrainingRunRead:
    run = queue_training_run(
        db,
        payload,
        settings=settings,
        request_id=getattr(request.state, "request_id", None),
    )
    response = to_training_run_read(db, run)
    background_tasks.add_task(execute_training_run, run.id)
    return response
