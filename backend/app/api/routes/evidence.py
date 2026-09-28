"""Evidence registry API (list open; raw detail behind a read permission)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.orm import Session

from app.api.security import request_workspace, require_permission, require_reader
from app.db.models import EvidenceRecord
from app.db.session import get_db
from app.schemas.api import EvidenceDetail, EvidenceListResponse, EvidenceRead
from app.services import evidence as evidence_service

router = APIRouter()


def _to_read(row: EvidenceRecord) -> EvidenceRead:
    return EvidenceRead(
        id=row.id,
        source_type=row.source_type,
        sensor_id=row.sensor_id,
        event_type=row.event_type,
        external_id=row.external_id,
        observed_at=row.observed_at,
        received_at=row.received_at,
        content_sha256=row.content_sha256,
        integrity=row.integrity,
        data_missing=row.data_missing,
        parser_version=row.parser_version,
        redacted=row.redacted,
        source_ref_type=row.source_ref_type,
        source_ref_id=row.source_ref_id,
        artifact_size_bytes=row.artifact_size_bytes,
        created_at=row.created_at,
    )


@router.get("", response_model=EvidenceListResponse, response_model_by_alias=True)
def list_evidence(
    request: Request,
    source_type: str = Query("all"),
    sensor_id: str = Query("", alias="sensorId"),
    event_type: str = Query("", alias="eventType"),
    external_id: str = Query("", alias="externalId"),
    content_sha256: str = Query("", alias="contentSha256"),
    page: int = Query(1, ge=1),
    page_size: int = Query(25, alias="pageSize", ge=1, le=200),
    _: object = Depends(require_reader("evidence:read")),
    db: Session = Depends(get_db),
) -> EvidenceListResponse:
    rows, total = evidence_service.list_evidence(
        db,
        source_type=source_type,
        sensor_id=sensor_id,
        event_type=event_type,
        external_id=external_id,
        content_sha256=content_sha256,
        page=page,
        page_size=page_size,
        workspace_id=request_workspace(request),
    )
    return EvidenceListResponse(
        items=[_to_read(row) for row in rows],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/{evidence_id}", response_model=EvidenceDetail, response_model_by_alias=True)
def get_evidence(
    evidence_id: str,
    request: Request,
    _: object = Depends(require_permission("evidence:raw")),
    db: Session = Depends(get_db),
) -> EvidenceDetail:
    row = evidence_service.get_evidence(
        db, evidence_id, workspace_id=request_workspace(request)
    )
    artifact = evidence_service.evidence_artifact(db, evidence_id)
    return EvidenceDetail(
        **_to_read(row).model_dump(),
        fields=dict(row.fields or {}),
        artifact_text=artifact.content_text if artifact is not None else None,
    )
