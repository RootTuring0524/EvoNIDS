"""Entity API: browse discovered entities and their aggregated relations."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import Entity
from app.db.session import get_db
from app.schemas.api import EntitiesResponse, EntityDetail, EntityRead, EntityRelationItem
from app.services import entities as entity_service

router = APIRouter()


def _to_read(row: Entity) -> EntityRead:
    return EntityRead(
        id=row.id,
        entity_type=row.entity_type,
        value=row.value,
        first_seen_at=row.first_seen_at,
        last_seen_at=row.last_seen_at,
        event_count=row.event_count,
        sensor_ids=row.sensor_ids or [],
        created_at=row.created_at,
    )


@router.get("", response_model=EntitiesResponse, response_model_by_alias=True)
def list_entities(
    entity_type: str = Query("", alias="entityType"),
    search: str = "",
    page: int = Query(1, ge=1),
    page_size: int = Query(25, alias="pageSize", ge=1, le=200),
    db: Session = Depends(get_db),
) -> EntitiesResponse:
    rows, total = entity_service.list_entities(
        db,
        entity_type=entity_type,
        search=search,
        page=page,
        page_size=page_size,
    )
    return EntitiesResponse(
        items=[_to_read(row) for row in rows],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/{entity_id}", response_model=EntityDetail, response_model_by_alias=True)
def get_entity(entity_id: str, db: Session = Depends(get_db)) -> EntityDetail:
    row = entity_service.get_entity(db, entity_id)
    relations = entity_service.entity_relations(db, entity_id)
    values: dict[str, str] = {}
    if relations:
        ids = [relation.entity_a for relation in relations] + [
            relation.entity_b for relation in relations
        ]
        for entity in db.scalars(select(Entity).where(Entity.id.in_(set(ids)))).all():
            values[entity.id] = entity.value
    items = [
        EntityRelationItem(
            id=relation.id,
            relation_type=relation.relation_type,
            other_entity_id=(
                relation.entity_b if relation.entity_a == row.id else relation.entity_a
            ),
            other_entity_value=values.get(
                relation.entity_b if relation.entity_a == row.id else relation.entity_a, ""
            ),
            event_count=relation.event_count,
            first_seen_at=relation.first_seen_at,
            last_seen_at=relation.last_seen_at,
        )
        for relation in relations
    ]
    return EntityDetail(**_to_read(row).model_dump(), relations=items)
