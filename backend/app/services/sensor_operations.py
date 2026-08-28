from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.db.base import utc_now
from app.db.models import Alert, AuditEvent, Flow, Sensor
from app.schemas.api import SensorHeartbeat, SensorRead, SensorSummary, SensorUpdate, SensorsResponse


ONLINE_SECONDS = 120
DEGRADED_SECONDS = 900


def _derived_state(sensor: Sensor, *, now: datetime) -> tuple[str, str]:
    if sensor.state == "maintenance":
        return "maintenance", "已由管理员置于维护模式"
    if sensor.last_seen_at is None:
        return "offline", "尚未收到探针心跳或数据"
    seen = sensor.last_seen_at
    if seen.tzinfo is None:
        seen = seen.replace(tzinfo=timezone.utc)
    age = max(0, int((now - seen).total_seconds()))
    if age <= ONLINE_SECONDS:
        return "online", f"{age} 秒前收到数据"
    if age <= DEGRADED_SECONDS:
        return "degraded", f"已 {age // 60} 分钟未收到数据"
    return "offline", f"已 {age // 60} 分钟未收到数据"


def _sensor_read(db: Session, sensor: Sensor, *, now: datetime) -> SensorRead:
    state, reason = _derived_state(sensor, now=now)
    flow_count = db.scalar(select(func.count()).select_from(Flow).where(Flow.sensor_id == sensor.id)) or 0
    alert_count = db.scalar(select(func.count()).select_from(Alert).where(Alert.sensor == sensor.id)) or 0
    critical_alerts = db.scalar(
        select(func.count()).select_from(Alert).where(Alert.sensor == sensor.id, Alert.severity == "critical")
    ) or 0
    metadata = sensor.metadata_json or {}
    return SensorRead(
        id=sensor.id,
        name=sensor.name,
        location=sensor.location,
        version=sensor.version,
        state=state,
        health_reason=reason,
        last_seen_at=sensor.last_seen_at,
        flow_count=flow_count,
        alert_count=alert_count,
        critical_alerts=critical_alerts,
        accepted_events=int(metadata.get("lifetimeAcceptedEvents", 0)),
        rejected_events=int(metadata.get("lifetimeRejectedEvents", 0)),
        ingest_source=str(metadata.get("source", "unknown")),
        last_error=str(metadata["lastError"]) if metadata.get("lastError") else None,
        created_at=sensor.created_at,
        updated_at=sensor.updated_at,
    )


def list_sensors(db: Session, *, search: str = "", state: str = "all") -> SensorsResponse:
    query = select(Sensor).order_by(Sensor.name.asc())
    if search.strip():
        term = f"%{search.strip()}%"
        query = query.where(or_(Sensor.id.ilike(term), Sensor.name.ilike(term), Sensor.location.ilike(term)))
    now = utc_now()
    rows = [_sensor_read(db, sensor, now=now) for sensor in db.scalars(query).all()]
    if state != "all":
        rows = [row for row in rows if row.state == state]
    all_rows = [_sensor_read(db, sensor, now=now) for sensor in db.scalars(select(Sensor)).all()]
    counts = {name: sum(row.state == name for row in all_rows) for name in ("online", "degraded", "offline", "maintenance")}
    return SensorsResponse(
        items=rows,
        summary=SensorSummary(
            total=len(all_rows),
            online=counts["online"],
            degraded=counts["degraded"],
            offline=counts["offline"],
            maintenance=counts["maintenance"],
            flows=sum(row.flow_count for row in all_rows),
            alerts=sum(row.alert_count for row in all_rows),
            rejected_events=sum(row.rejected_events for row in all_rows),
        ),
    )


def record_heartbeat(db: Session, sensor_id: str, payload: SensorHeartbeat) -> SensorRead:
    sensor = db.get(Sensor, sensor_id)
    if sensor is None:
        sensor = Sensor(id=sensor_id, name=payload.name or sensor_id, state="online", metadata_json={})
        db.add(sensor)
    sensor.name = payload.name or sensor.name
    if payload.location is not None:
        sensor.location = payload.location
    if payload.version is not None:
        sensor.version = payload.version
    sensor.last_seen_at = utc_now()
    if sensor.state != "maintenance":
        sensor.state = "online"
    sensor.metadata_json = {**(sensor.metadata_json or {}), **payload.metadata_json, "source": "heartbeat"}
    db.commit()
    db.refresh(sensor)
    return _sensor_read(db, sensor, now=utc_now())


def update_sensor(
    db: Session,
    sensor: Sensor,
    payload: SensorUpdate,
    *,
    request_id: str | None,
) -> SensorRead:
    before = {"name": sensor.name, "location": sensor.location, "state": sensor.state}
    if payload.name is not None:
        sensor.name = payload.name
    if payload.location is not None:
        sensor.location = payload.location
    if payload.state is not None:
        sensor.state = payload.state
    after = {"name": sensor.name, "location": sensor.location, "state": sensor.state}
    db.add(
        AuditEvent(
            id=f"AUD-{uuid.uuid4().hex.upper()}",
            created_at=utc_now(),
            actor=payload.actor,
            action="sensor.update",
            object_type="sensor",
            object_id=sensor.id,
            outcome="completed",
            request_id=request_id,
            before_state=before,
            after_state=after,
            note=payload.note,
        )
    )
    db.commit()
    db.refresh(sensor)
    return _sensor_read(db, sensor, now=utc_now())
