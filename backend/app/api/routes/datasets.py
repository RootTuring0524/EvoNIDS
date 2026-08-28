from fastapi import APIRouter, BackgroundTasks, Depends, Request, Response, status
from sqlalchemy.orm import Session

from app.api.security import require_admin_token
from app.core.config import Settings, get_settings
from app.db.session import get_db
from app.schemas.api import DatasetRead, DatasetRegistration, DatasetsResponse
from app.services.dataset_catalog import (
    delete_dataset_registration,
    list_dataset_assets,
    profile_dataset_asset,
    queue_reprofile,
    register_dataset_asset,
    to_dataset_read,
)


router = APIRouter()


@router.get("", response_model=DatasetsResponse, response_model_by_alias=True)
def list_datasets(
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> DatasetsResponse:
    return list_dataset_assets(db, settings)


@router.post(
    "",
    response_model=DatasetRead,
    response_model_by_alias=True,
    status_code=status.HTTP_202_ACCEPTED,
    dependencies=[Depends(require_admin_token)],
)
def register_dataset(
    payload: DatasetRegistration,
    background_tasks: BackgroundTasks,
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> DatasetRead:
    row = register_dataset_asset(
        db,
        payload,
        settings=settings,
        request_id=getattr(request.state, "request_id", None),
    )
    background_tasks.add_task(profile_dataset_asset, row.id)
    return to_dataset_read(row, settings=settings)


@router.post(
    "/{dataset_id}/reprofile",
    response_model=DatasetRead,
    response_model_by_alias=True,
    status_code=status.HTTP_202_ACCEPTED,
    dependencies=[Depends(require_admin_token)],
)
def reprofile_dataset(
    dataset_id: str,
    background_tasks: BackgroundTasks,
    request: Request,
    actor: str = "local-admin",
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> DatasetRead:
    row = queue_reprofile(
        db,
        dataset_id,
        actor=actor,
        request_id=getattr(request.state, "request_id", None),
    )
    background_tasks.add_task(profile_dataset_asset, row.id)
    return to_dataset_read(row, settings=settings)


@router.delete(
    "/{dataset_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require_admin_token)],
)
def remove_dataset_registration(
    dataset_id: str,
    request: Request,
    actor: str = "local-admin",
    db: Session = Depends(get_db),
) -> Response:
    delete_dataset_registration(
        db,
        dataset_id,
        actor=actor,
        request_id=getattr(request.state, "request_id", None),
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)
