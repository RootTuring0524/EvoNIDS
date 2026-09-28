"""Sensor data-quality metrics derived from the ingestion batch ledger.

Every metric is explicitly marked ``measured``. A metric that cannot be computed
from the data actually present returns ``value=None`` and ``measured=False``
instead of a fabricated zero; the UI and the API surface that distinction.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.base import utc_now
from app.db.models import IngestionBatch, Sensor
from app.schemas.api import SensorDataQuality, SensorHealthResponse, SensorMetric
from app.services.sensor_operations import derived_state

DEFAULT_WINDOW_SECONDS = 3600
MAX_WINDOW_SECONDS = 7 * 24 * 3600


def _as_naive_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value
    return value.astimezone(timezone.utc).replace(tzinfo=None)


def percentile(values: list[float], fraction: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    rank = fraction * (len(ordered) - 1)
    lower = int(rank)
    upper = min(lower + 1, len(ordered) - 1)
    weight = rank - lower
    return ordered[lower] * (1 - weight) + ordered[upper] * weight


def _metric(value: float | None, *, unit: str, note: str | None = None) -> SensorMetric:
    rounded = round(float(value), 4) if value is not None else None
    return SensorMetric(
        value=rounded,
        measured=value is not None,
        unit=unit,
        note=note if value is not None else (note or "窗口内没有可用于计算的批次"),
    )


def sensor_data_quality(
    db: Session, sensor: Sensor, *, window_seconds: int = DEFAULT_WINDOW_SECONDS
) -> SensorDataQuality:
    window = max(60, min(window_seconds, MAX_WINDOW_SECONDS))
    now = utc_now()
    since = _as_naive_utc(now) - timedelta(seconds=window)
    batches = list(
        db.scalars(
            select(IngestionBatch)
            .where(IngestionBatch.sensor_id == sensor.id, IngestionBatch.received_at >= since)
            .order_by(IngestionBatch.received_at.asc())
        ).all()
    )
    accepted = sum(row.accepted_count for row in batches)
    rejected = sum(row.rejected_count for row in batches)
    duplicates = sum(row.duplicate_count for row in batches)
    total = accepted + rejected + duplicates
    reject_rate = rejected / total if total > 0 else None
    duplicate_rate = duplicates / total if total > 0 else None

    latencies: list[float] = []
    for row in batches:
        if row.last_event_at is None:
            continue
        delta = (_as_naive_utc(row.received_at) - _as_naive_utc(row.last_event_at)).total_seconds() * 1000
        if delta >= 0:
            latencies.append(delta)

    gap_threshold = max(2 * max(sensor.expected_interval_seconds, 1), 120)
    gap_count = 0
    missing_seconds = 0.0
    event_times = sorted(
        _as_naive_utc(row.last_event_at) for row in batches if row.last_event_at is not None
    )
    for previous, current in zip(event_times, event_times[1:]):
        delta = (current - previous).total_seconds()
        if delta > gap_threshold:
            gap_count += 1
            missing_seconds += delta - max(sensor.expected_interval_seconds, 1)

    skew_candidates = [sensor.clock_skew_seconds] if sensor.clock_skew_seconds is not None else []
    skew_candidates.extend(
        row.clock_skew_seconds for row in batches if row.clock_skew_seconds is not None
    )
    worst_skew = max(skew_candidates, key=abs) if skew_candidates else None

    state, reason = derived_state(sensor, now=now)
    last_batch_at = _as_naive_utc(batches[-1].received_at) if batches else None
    return SensorDataQuality(
        sensor_id=sensor.id,
        state=state,
        health_reason=reason,
        window_seconds=window,
        batches=len(batches),
        events_accepted=accepted,
        events_rejected=rejected,
        events_duplicate=duplicates,
        reject_rate=_metric(reject_rate, unit="ratio"),
        duplicate_rate=_metric(duplicate_rate, unit="ratio"),
        ingest_latency_p50_ms=_metric(percentile(latencies, 0.5), unit="ms"),
        ingest_latency_p95_ms=_metric(percentile(latencies, 0.95), unit="ms"),
        clock_skew_seconds=_metric(
            worst_skew,
            unit="seconds",
            note="正值表示探针时钟快于服务端；绝对值超过 30 秒应检查 NTP",
        ),
        gap_count=_metric(
            float(gap_count) if batches else None,
            unit="gaps",
            note="窗口内批次之间的时间间隔超过 2×期望上报间隔时计为一次数据缺口",
        ),
        estimated_missing_seconds=_metric(
            float(missing_seconds) if batches else None,
            unit="seconds",
        ),
        spool_depth=sensor.spool_depth,
        dropped_events=sensor.dropped_events,
        expected_interval_seconds=sensor.expected_interval_seconds,
        last_batch_at=last_batch_at,
        last_event_at=event_times[-1] if event_times else None,
        last_heartbeat_at=sensor.last_heartbeat_at,
    )


def sensor_health_report(
    db: Session, *, sensor_id: str | None = None, window_seconds: int = DEFAULT_WINDOW_SECONDS
) -> SensorHealthResponse:
    query = select(Sensor).order_by(Sensor.name.asc())
    if sensor_id is not None:
        query = query.where(Sensor.id == sensor_id)
    sensors = list(db.scalars(query).all())
    return SensorHealthResponse(
        items=[sensor_data_quality(db, sensor, window_seconds=window_seconds) for sensor in sensors]
    )
