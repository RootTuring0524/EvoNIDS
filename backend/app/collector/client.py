"""Collector client: batching, gzip, rate limiting, retry/backoff, spool, heartbeat.

Delivery contract:

* At-least-once. Every batch carries a stable ``X-Evonids-Batch-Id``; the server
  deduplicates by ``(sensorId, batchId)`` and returns the original outcome on a
  replay, so a retry can never double count an event.
* Never silently drop. A batch that cannot be delivered is written to the disk
  spool before the process moves on; only an acknowledged batch is deleted.
* Bounded. Retries use exponential backoff with jitter, a maximum attempt count,
  and a hard spool cap that refuses new data rather than overwriting old data.
"""

from __future__ import annotations

import gzip
import json
import random
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Sequence

from app.collector.spool import DiskSpool, SpoolFull, SpoolSegment
from app.collector.transport import Transport, TransportError

AGENT_VERSION = "0.2.0"
RETRYABLE_STATUS = frozenset({408, 425, 429, 500, 502, 503, 504})


@dataclass(frozen=True, slots=True)
class CollectorConfig:
    sensor_id: str
    endpoint: str
    token: str
    spool_root: str | Path = "./collector-spool"
    batch_max_events: int = 2_000
    batch_max_bytes: int = 4 * 1024 * 1024
    compress: bool = True
    timeout_seconds: float = 15.0
    max_attempts: int = 5
    base_backoff_seconds: float = 0.5
    max_backoff_seconds: float = 60.0
    rate_limit_events_per_second: float = 0.0
    spool_max_bytes: int = 512 * 1024 * 1024
    spool_max_segments: int = 20_000
    expected_interval_seconds: int = 60
    verify_tls: bool = True
    client_cert: str | None = None
    client_key: str | None = None
    capabilities: tuple[str, ...] = ("suricata-eve",)


@dataclass(slots=True)
class BatchResult:
    batch_id: str
    status: str
    attempts: int = 0
    http_status: int | None = None
    accepted_events: int = 0
    duplicate_events: int = 0
    rejected_events: int = 0
    elapsed_ms: float = 0.0
    error: str | None = None

    @property
    def delivered(self) -> bool:
        return self.status in {"delivered", "duplicate"}


@dataclass(slots=True)
class CollectorMetrics:
    batches_submitted: int = 0
    events_submitted: int = 0
    bytes_submitted: int = 0
    batches_delivered: int = 0
    batches_duplicate: int = 0
    batches_spooled: int = 0
    batches_dead_lettered: int = 0
    retries: int = 0
    heartbeats: int = 0
    heartbeat_failures: int = 0
    last_error: str | None = None
    last_clock_skew_seconds: float | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "batchesSubmitted": self.batches_submitted,
            "eventsSubmitted": self.events_submitted,
            "bytesSubmitted": self.bytes_submitted,
            "batchesDelivered": self.batches_delivered,
            "batchesDuplicate": self.batches_duplicate,
            "batchesSpooled": self.batches_spooled,
            "batchesDeadLettered": self.batches_dead_lettered,
            "retries": self.retries,
            "heartbeats": self.heartbeats,
            "heartbeatFailures": self.heartbeat_failures,
            "lastError": self.last_error,
            "lastClockSkewSeconds": self.last_clock_skew_seconds,
            **self.extra,
        }


def chunk_events(
    lines: Sequence[str], *, max_events: int, max_bytes: int
) -> list[list[str]]:
    """Split NDJSON lines into batches bounded by count and encoded size."""
    batches: list[list[str]] = []
    current: list[str] = []
    current_bytes = 0
    for line in lines:
        encoded = len(line.encode("utf-8")) + 1
        if current and (len(current) >= max_events or current_bytes + encoded > max_bytes):
            batches.append(current)
            current = []
            current_bytes = 0
        current.append(line)
        current_bytes += encoded
    if current:
        batches.append(current)
    return batches


class CollectorClient:
    def __init__(
        self,
        config: CollectorConfig,
        transport: Transport,
        *,
        spool: DiskSpool | None = None,
        clock: Callable[[], float] = time.time,
        monotonic: Callable[[], float] = time.monotonic,
        sleeper: Callable[[float], None] = time.sleep,
        random_source: Callable[[], float] = random.random,
    ) -> None:
        self.config = config
        self.transport = transport
        self.spool = spool or DiskSpool(
            config.spool_root,
            max_bytes=config.spool_max_bytes,
            max_segments=config.spool_max_segments,
        )
        self.clock = clock
        self.monotonic = monotonic
        self.sleeper = sleeper
        self.random = random_source
        self.metrics = CollectorMetrics()
        self._pacing_started: float | None = None
        self._paced_events = 0

    # ------------------------------------------------------------------ URLs
    @property
    def ingest_url(self) -> str:
        return f"{self.config.endpoint.rstrip('/')}/ingestion/eve/batch?sensorId={self.config.sensor_id}"

    @property
    def heartbeat_url(self) -> str:
        return f"{self.config.endpoint.rstrip('/')}/sensors/{self.config.sensor_id}/heartbeat"

    def _headers(self, *, batch_id: str, encoding: str, event_count: int, skew: float | None) -> dict[str, str]:
        headers = {
            "Content-Type": "application/x-ndjson",
            "Authorization": f"Bearer {self.config.token}",
            "X-Evonids-Batch-Id": batch_id,
            "X-Evonids-Encoding": encoding,
            "X-Evonids-Event-Count": str(event_count),
            "X-Evonids-Agent-Version": AGENT_VERSION,
            "User-Agent": f"evonids-collector/{AGENT_VERSION}",
        }
        if skew is not None:
            headers["X-Evonids-Clock-Skew-Seconds"] = f"{skew:.3f}"
        return headers

    # -------------------------------------------------------------- delivery
    def submit(self, lines: Iterable[str]) -> list[BatchResult]:
        """Batch, spool and deliver events; returns one result per batch."""
        results: list[BatchResult] = []
        for batch in chunk_events(
            list(lines), max_events=self.config.batch_max_events, max_bytes=self.config.batch_max_bytes
        ):
            payload = "\n".join(batch) + "\n"
            batch_id = f"{self.config.sensor_id}-{int(self.clock())}-{uuid.uuid4().hex[:12]}"
            self._pace(len(batch))
            segment: SpoolSegment | None = None
            try:
                segment = self.spool.append(payload, event_count=len(batch), batch_id=batch_id)
            except SpoolFull as exc:
                self.metrics.last_error = str(exc)
                results.append(BatchResult(batch_id=batch_id, status="spool_full", error=str(exc)))
                continue
            result = self._deliver_segment(segment, already_spooled=True)
            results.append(result)
            if result.delivered:
                self.spool.ack(segment)
            elif result.status == "dead_letter":
                # A rejected batch will never succeed on retry (bad payload or a
                # batch-id conflict), so it is quarantined instead of blocking
                # the spool head forever.
                self.spool.dead_letter_segment(segment, reason=result.error or "unrecoverable")
        return results

    def flush_spool(self, *, limit: int | None = None) -> list[BatchResult]:
        """Retry every pending spooled batch in order (oldest first)."""
        results: list[BatchResult] = []
        for segment in self.spool.pending()[: limit if limit is not None else None]:
            result = self._deliver_segment(segment, already_spooled=True)
            results.append(result)
            if result.delivered:
                self.spool.ack(segment)
            elif result.status == "dead_letter":
                self.spool.dead_letter_segment(segment, reason=result.error or "unrecoverable")
        return results

    def _deliver_segment(self, segment: SpoolSegment, *, already_spooled: bool) -> BatchResult:
        payload = self.spool.read(segment).encode("utf-8")
        event_count = segment.event_count
        encoding = "identity"
        body = payload
        if self.config.compress:
            body = gzip.compress(payload)
            encoding = "gzip"
        started = self.monotonic()
        self.metrics.batches_submitted += 1
        self.metrics.events_submitted += event_count
        self.metrics.bytes_submitted += len(payload)
        attempts = 0
        last_error: str | None = None
        while attempts < max(self.config.max_attempts, 1):
            attempts += 1
            try:
                response = self.transport.send(
                    "POST",
                    self.ingest_url,
                    headers=self._headers(
                        batch_id=segment.batch_id,
                        encoding=encoding,
                        event_count=event_count,
                        skew=segment.clock_skew_seconds,
                    ),
                    body=body,
                    timeout=self.config.timeout_seconds,
                )
            except TransportError as exc:
                last_error = f"transport_error: {exc}"
                self.metrics.retries += 1
                self._backoff(attempts)
                continue
            self._observe_skew(response)
            if response.status in (200, 201):
                payload_json = response.json() or {}
                replayed = bool(payload_json.get("replayed"))
                self.metrics.batches_duplicate += int(replayed)
                self.metrics.batches_delivered += int(not replayed)
                return BatchResult(
                    batch_id=segment.batch_id,
                    status="duplicate" if replayed else "delivered",
                    attempts=attempts,
                    http_status=response.status,
                    accepted_events=int(payload_json.get("acceptedEvents") or event_count),
                    duplicate_events=int(payload_json.get("duplicateEvents") or 0),
                    rejected_events=int(payload_json.get("rejectedEvents") or 0),
                    elapsed_ms=round((self.monotonic() - started) * 1000, 3),
                )
            if response.status in RETRYABLE_STATUS:
                last_error = f"http_{response.status}"
                self.metrics.retries += 1
                self._backoff(attempts, response=response)
                continue
            detail = response.json()
            message = detail.get("message") if isinstance(detail, dict) else None
            self.metrics.last_error = f"http_{response.status}: {message or response.status}"
            if response.status == 409:
                return BatchResult(
                    batch_id=segment.batch_id,
                    status="dead_letter",
                    attempts=attempts,
                    http_status=response.status,
                    error=f"batch id conflict: {message}",
                    elapsed_ms=round((self.monotonic() - started) * 1000, 3),
                )
            return BatchResult(
                batch_id=segment.batch_id,
                status="dead_letter",
                attempts=attempts,
                http_status=response.status,
                error=f"non-retryable status {response.status}: {message or ''}".strip(),
                elapsed_ms=round((self.monotonic() - started) * 1000, 3),
            )
        self.metrics.batches_spooled += int(already_spooled)
        self.metrics.last_error = last_error
        return BatchResult(
            batch_id=segment.batch_id,
            status="spooled" if already_spooled else "failed",
            attempts=attempts,
            error=last_error or "exhausted attempts",
            elapsed_ms=round((self.monotonic() - started) * 1000, 3),
        )

    def _backoff(self, attempt: int, *, response: Any | None = None) -> None:
        delay = min(
            self.config.base_backoff_seconds * (2 ** (attempt - 1)),
            self.config.max_backoff_seconds,
        )
        retry_after = None
        if response is not None:
            raw = response.headers.get("retry-after")
            if raw and raw.isdigit():
                retry_after = float(raw)
        delay = max(delay, retry_after or 0.0)
        jitter = delay * 0.25 * self.random()
        self.sleeper(delay + jitter)

    def _pace(self, events: int) -> None:
        limit = self.config.rate_limit_events_per_second
        if limit <= 0:
            return
        now = self.monotonic()
        if self._pacing_started is None:
            self._pacing_started = now
        self._paced_events += events
        expected = self._paced_events / limit
        elapsed = now - self._pacing_started
        if expected > elapsed:
            self.sleeper(expected - elapsed)

    def _observe_skew(self, response: Any) -> None:
        server_time = response.server_time_epoch()
        if server_time is None:
            return
        skew = self.clock() - server_time
        self.metrics.last_clock_skew_seconds = round(skew, 3)

    # ------------------------------------------------------------- heartbeat
    def heartbeat(self, *, spool_depth: int | None = None, dropped_events: int = 0) -> dict[str, Any]:
        body = json.dumps(
            {
                "agentVersion": AGENT_VERSION,
                "capabilities": list(self.config.capabilities),
                "spoolDepth": self.spool.depth() if spool_depth is None else spool_depth,
                "droppedEvents": dropped_events,
                "clockSkewSeconds": self.metrics.last_clock_skew_seconds,
                "expectedIntervalSeconds": self.config.expected_interval_seconds,
                "metadata": {"collectorMetrics": self.metrics.as_dict()},
            }
        ).encode("utf-8")
        try:
            response = self.transport.send(
                "POST",
                self.heartbeat_url,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {self.config.token}",
                    "User-Agent": f"evonids-collector/{AGENT_VERSION}",
                },
                body=body,
                timeout=self.config.timeout_seconds,
            )
        except TransportError as exc:
            self.metrics.heartbeat_failures += 1
            self.metrics.last_error = f"heartbeat_transport_error: {exc}"
            return {"delivered": False, "error": str(exc)}
        self._observe_skew(response)
        if response.status in (200, 201):
            self.metrics.heartbeats += 1
            payload = response.json() or {}
            return {"delivered": True, "sensor": payload}
        self.metrics.heartbeat_failures += 1
        self.metrics.last_error = f"heartbeat_http_{response.status}"
        return {"delivered": False, "httpStatus": response.status}
