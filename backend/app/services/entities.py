"""Entity discovery and relations: automatic, aggregated, never hand-curated.

Entities are IP values observed in accepted events; relations aggregate the
directed communication into an undirected pair. Both are upserted in the same
transaction as the event rows so the graph always reflects persisted facts.
"""
from __future__ import annotations

import hashlib
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import desc, func, or_, select
from sqlalchemy.orm import Session

from app.db.base import utc_now
from app.db.models import Entity, EntityRelation

ENTITY_TYPE_IP = "ip"
RELATION_COMMUNICATES = "communicates_with"


def _entity_id(entity_type: str, value: str) -> str:
    digest = hashlib.sha256(f"{entity_type}\x1f{value}".encode("utf-8")).hexdigest()[:20].upper()
    return f"ENT-{digest}"


def _relation_id(relation_type: str, a: str, b: str) -> str:
    digest = hashlib.sha256(f"{relation_type}\x1f{a}\x1f{b}".encode("utf-8")).hexdigest()[:20].upper()
    return f"REL-{digest}"


def observe_communication(
    db: Session,
    *,
    sensor_id: str,
    source_ip: str,
    destination_ip: str,
    observed_at: datetime,
) -> None:
    """Upsert the source/destination entities and their aggregated relation."""
    now = utc_now()
    # SQLite returns naive datetimes for DateTime(timezone=True) columns, so
    # store and compare naive-UTC consistently.
    event_time = observed_at.astimezone(UTC).replace(tzinfo=None) if observed_at.tzinfo else observed_at

    def _touch_entity(value: str) -> str:
        entity_id = _entity_id(ENTITY_TYPE_IP, value)
        row = entity_cache.get(entity_id)
        if row is None:
            db.add(
                Entity(
                    id=entity_id,
                    entity_type=ENTITY_TYPE_IP,
                    value=value,
                    first_seen_at=event_time,
                    last_seen_at=event_time,
                    event_count=1,
                    sensor_ids=[sensor_id],
                    created_at=now,
                    updated_at=now,
                )
            )
        else:
            row.event_count += 1
            if event_time < row.first_seen_at:
                row.first_seen_at = event_time
            if event_time > row.last_seen_at:
                row.last_seen_at = event_time
            if sensor_id not in (row.sensor_ids or []):
                row.sensor_ids = [*(row.sensor_ids or []), sensor_id]
            row.updated_at = now
        return entity_id

    # Two-phase upsert: resolve every existing row up front so repeated calls
    # inside one transaction never collide on the unique constraints. The
    # explicit flush makes rows added by earlier calls in this transaction
    # visible to the lookup below.
    db.flush()
    source_entity_id = _entity_id(ENTITY_TYPE_IP, source_ip)
    destination_entity_id = _entity_id(ENTITY_TYPE_IP, destination_ip)
    entity_cache: dict[str, Entity] = {
        row.id: row
        for row in db.scalars(
            select(Entity).where(Entity.id.in_((source_entity_id, destination_entity_id)))
        ).all()
    }
    for value in (source_ip, destination_ip):
        _touch_entity(value)

    entity_a = _entity_id(ENTITY_TYPE_IP, source_ip)
    entity_b = _entity_id(ENTITY_TYPE_IP, destination_ip)
    a, b = (entity_a, entity_b) if entity_a <= entity_b else (entity_b, entity_a)
    relation_id = _relation_id(RELATION_COMMUNICATES, a, b)
    relation = db.get(EntityRelation, relation_id)
    if relation is None:
        db.add(
            EntityRelation(
                id=relation_id,
                relation_type=RELATION_COMMUNICATES,
                entity_a=a,
                entity_b=b,
                first_seen_at=event_time,
                last_seen_at=event_time,
                event_count=1,
                created_at=now,
                updated_at=now,
            )
        )
    else:
        relation.event_count += 1
        if event_time < relation.first_seen_at:
            relation.first_seen_at = event_time
        if event_time > relation.last_seen_at:
            relation.last_seen_at = event_time
        relation.updated_at = now


@dataclass(slots=True)
class _EntityAggregate:
    value: str
    count: int = 0
    first: datetime | None = None
    last: datetime | None = None

    def add(self, event_time: datetime) -> None:
        self.count += 1
        if self.first is None or event_time < self.first:
            self.first = event_time
        if self.last is None or event_time > self.last:
            self.last = event_time


@dataclass(slots=True)
class _RelationAggregate:
    entity_a: str
    entity_b: str
    count: int = 0
    first: datetime | None = None
    last: datetime | None = None

    def add(self, event_time: datetime) -> None:
        self.count += 1
        if self.first is None or event_time < self.first:
            self.first = event_time
        if self.last is None or event_time > self.last:
            self.last = event_time


def observe_communications(
    db: Session,
    *,
    sensor_id: str,
    observations: Sequence[tuple[str, str, datetime]],
) -> None:
    """Bulk version of :func:`observe_communication` for one ingestion batch.

    Semantics are identical to calling the single-event helper for every tuple;
    the difference is that entities and relations are resolved with one query each
    instead of one flush plus two lookups per event. ``observations`` is a sequence
    of ``(source_ip, destination_ip, observed_at)``.
    """
    if not observations:
        return
    now = utc_now()
    normalised: list[tuple[str, str, datetime]] = [
        (
            source_ip,
            destination_ip,
            observed_at.astimezone(UTC).replace(tzinfo=None) if observed_at.tzinfo else observed_at,
        )
        for source_ip, destination_ip, observed_at in observations
    ]
    values = {
        value for source_ip, destination_ip, _ in normalised for value in (source_ip, destination_ip)
    }
    entity_ids = {value: _entity_id(ENTITY_TYPE_IP, value) for value in values}
    existing_entities = {
        row.id: row
        for row in db.scalars(select(Entity).where(Entity.id.in_(list(entity_ids.values())))).all()
    }

    entity_totals: dict[str, _EntityAggregate] = {}
    for source_ip, destination_ip, event_time in normalised:
        for value in (source_ip, destination_ip):
            entity_totals.setdefault(entity_ids[value], _EntityAggregate(value=value)).add(event_time)

    for entity_id, aggregate in entity_totals.items():
        row = existing_entities.get(entity_id)
        if row is None:
            db.add(
                Entity(
                    id=entity_id,
                    entity_type=ENTITY_TYPE_IP,
                    value=aggregate.value,
                    first_seen_at=aggregate.first or now,
                    last_seen_at=aggregate.last or now,
                    event_count=aggregate.count,
                    sensor_ids=[sensor_id],
                    created_at=now,
                    updated_at=now,
                )
            )
            continue
        row.event_count += aggregate.count
        if aggregate.first is not None and aggregate.first < row.first_seen_at:
            row.first_seen_at = aggregate.first
        if aggregate.last is not None and aggregate.last > row.last_seen_at:
            row.last_seen_at = aggregate.last
        if sensor_id not in (row.sensor_ids or []):
            row.sensor_ids = [*(row.sensor_ids or []), sensor_id]
        row.updated_at = now

    relation_totals: dict[str, _RelationAggregate] = {}
    for source_ip, destination_ip, event_time in normalised:
        entity_a = entity_ids[source_ip]
        entity_b = entity_ids[destination_ip]
        a, b = (entity_a, entity_b) if entity_a <= entity_b else (entity_b, entity_a)
        relation_totals.setdefault(
            _relation_id(RELATION_COMMUNICATES, a, b),
            _RelationAggregate(entity_a=a, entity_b=b),
        ).add(event_time)
    existing_relations = {
        row.id: row
        for row in db.scalars(
            select(EntityRelation).where(EntityRelation.id.in_(list(relation_totals)))
        ).all()
    }
    for relation_id, relation_aggregate in relation_totals.items():
        relation_row = existing_relations.get(relation_id)
        if relation_row is None:
            db.add(
                EntityRelation(
                    id=relation_id,
                    relation_type=RELATION_COMMUNICATES,
                    entity_a=relation_aggregate.entity_a,
                    entity_b=relation_aggregate.entity_b,
                    first_seen_at=relation_aggregate.first or now,
                    last_seen_at=relation_aggregate.last or now,
                    event_count=relation_aggregate.count,
                    created_at=now,
                    updated_at=now,
                )
            )
            continue
        relation_row.event_count += relation_aggregate.count
        if relation_aggregate.first is not None and relation_aggregate.first < relation_row.first_seen_at:
            relation_row.first_seen_at = relation_aggregate.first
        if relation_aggregate.last is not None and relation_aggregate.last > relation_row.last_seen_at:
            relation_row.last_seen_at = relation_aggregate.last
        relation_row.updated_at = now


def list_entities(
    db: Session,
    *,
    entity_type: str = "",
    search: str = "",
    page: int = 1,
    page_size: int = 25,
) -> tuple[list[Entity], int]:
    filters = []
    if entity_type.strip():
        filters.append(Entity.entity_type == entity_type.strip())
    if search.strip():
        term = f"%{search.strip()}%"
        filters.append(Entity.value.ilike(term))
    total = int(db.scalar(select(func.count()).select_from(Entity).where(*filters)) or 0)
    rows = list(
        db.scalars(
            select(Entity)
            .where(*filters)
            .order_by(desc(Entity.last_seen_at))
            .offset((page - 1) * page_size)
            .limit(page_size)
        ).all()
    )
    return rows, total


def get_entity(db: Session, entity_id: str) -> Entity:
    row = db.get(Entity, entity_id)
    if row is None:
        from fastapi import HTTPException

        raise HTTPException(status_code=404, detail=f"Entity {entity_id} was not found")
    return row


def entity_relations(db: Session, entity_id: str, *, limit: int = 100) -> list[EntityRelation]:
    return list(
        db.scalars(
            select(EntityRelation)
            .where(or_(EntityRelation.entity_a == entity_id, EntityRelation.entity_b == entity_id))
            .order_by(desc(EntityRelation.last_seen_at))
            .limit(limit)
        ).all()
    )


def entity_id_for_value(db: Session, value: str) -> Entity | None:
    return db.scalar(
        select(Entity).where(Entity.entity_type == ENTITY_TYPE_IP, Entity.value == value)
    )
