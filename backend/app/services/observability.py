"""Observability: Prometheus metrics, W3C trace propagation, runtime gauges.

No external dependency is available in this environment (no ``prometheus_client``,
no OpenTelemetry SDK), so the metrics are collected in-process and rendered in the
standard Prometheus text exposition format by hand, and tracing is limited to
honest W3C ``traceparent`` propagation (parse, generate, propagate into logs and
responses). There is **no exporter and no collector** wired up: the endpoint is
what an operator scrapes, and that limitation is stated in the docs rather than
implied away.
"""

from __future__ import annotations

import re
import secrets
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping, Sequence

LATENCY_BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0)
TRACEPARENT_PATTERN = re.compile(
    r"^(?P<version>[0-9a-f]{2})-(?P<trace_id>[0-9a-f]{32})-(?P<span_id>[0-9a-f]{16})-(?P<flags>[0-9a-f]{2})$"
)
METRIC_NAME_PATTERN = re.compile(r"^[a-zA-Z_:][a-zA-Z0-9_:]*$")


@dataclass(frozen=True, slots=True)
class TraceContext:
    trace_id: str
    span_id: str
    sampled: bool
    parent_span_id: str | None = None
    upstream: bool = False

    def header(self) -> str:
        flags = "01" if self.sampled else "00"
        return f"00-{self.trace_id}-{self.span_id}-{flags}"

    def as_dict(self) -> dict[str, Any]:
        return {
            "traceId": self.trace_id,
            "spanId": self.span_id,
            "parentSpanId": self.parent_span_id,
            "sampled": self.sampled,
            "upstream": self.upstream,
        }


def parse_traceparent(value: str | None) -> TraceContext | None:
    """Parse a W3C traceparent header; returns None when absent or malformed."""
    if not value:
        return None
    match = TRACEPARENT_PATTERN.match(value.strip().lower())
    if match is None:
        return None
    if match.group("version") == "ff":
        return None
    trace_id = match.group("trace_id")
    parent_span_id = match.group("span_id")
    if trace_id == "0" * 32 or parent_span_id == "0" * 16:
        return None
    return TraceContext(
        trace_id=trace_id,
        span_id=secrets.token_hex(8),
        sampled=bool(int(match.group("flags"), 16) & 0x01),
        parent_span_id=parent_span_id,
        upstream=True,
    )


def new_trace_context(*, sampled: bool = True) -> TraceContext:
    return TraceContext(trace_id=secrets.token_hex(16), span_id=secrets.token_hex(8), sampled=sampled)


def continue_or_start_trace(value: str | None) -> TraceContext:
    return parse_traceparent(value) or new_trace_context()


@dataclass
class Histogram:
    buckets: Sequence[float]
    counts: list[int] = field(default_factory=list)
    total: float = 0.0
    observations: int = 0

    def __post_init__(self) -> None:
        if not self.counts:
            self.counts = [0] * len(self.buckets)

    def observe(self, value: float) -> None:
        self.total += value
        self.observations += 1
        for index, edge in enumerate(self.buckets):
            if value <= edge:
                self.counts[index] += 1


class MetricsRegistry:
    """Minimal counter/gauge/histogram registry rendered as Prometheus text."""

    def __init__(self) -> None:
        self._counters: dict[tuple[str, tuple[tuple[str, str], ...]], float] = defaultdict(float)
        self._gauges: dict[tuple[str, tuple[tuple[str, str], ...]], float] = {}
        self._histograms: dict[tuple[str, tuple[tuple[str, str], ...]], Histogram] = {}
        self._help: dict[str, str] = {}
        self._lock = threading.Lock()
        self._started_at = time.time()

    def describe(self, name: str, help_text: str, kind: str = "counter") -> None:
        self._help[name] = f"{help_text}\n# TYPE {name} {kind}"

    def inc(self, name: str, *, labels: Mapping[str, Any] | None = None, value: float = 1.0) -> None:
        _validate_name(name)
        key = (name, _label_tuple(labels))
        with self._lock:
            self._counters[key] += value

    def set_gauge(self, name: str, value: float, *, labels: Mapping[str, Any] | None = None) -> None:
        _validate_name(name)
        key = (name, _label_tuple(labels))
        with self._lock:
            self._gauges[key] = float(value)

    def observe(
        self, name: str, value: float, *, labels: Mapping[str, Any] | None = None, buckets: Sequence[float] = LATENCY_BUCKETS
    ) -> None:
        _validate_name(name)
        key = (name, _label_tuple(labels))
        with self._lock:
            histogram = self._histograms.get(key)
            if histogram is None:
                histogram = Histogram(buckets=tuple(buckets))
                self._histograms[key] = histogram
            histogram.observe(value)

    def render(self) -> str:
        with self._lock:
            counters = dict(self._counters)
            gauges = dict(self._gauges)
            histograms = {key: (item.buckets, list(item.counts), item.total, item.observations) for key, item in self._histograms.items()}
            help_lines = dict(self._help)
        lines: list[str] = [
            "# HELP evonids_uptime_seconds Process uptime in seconds",
            "# TYPE evonids_uptime_seconds gauge",
            f"evonids_uptime_seconds {round(time.time() - self._started_at, 3)}",
        ]
        for name in sorted({key[0] for key in counters}):
            lines.append(f"# HELP {name} {help_lines.get(name, name).splitlines()[0]}")
            lines.append(f"# TYPE {name} {_kind_of(help_lines.get(name), 'counter')}")
            for (metric_name, labels), value in sorted(counters.items()):
                if metric_name == name:
                    lines.append(f"{name}{_render_labels(labels)} {_render_number(value)}")
        for name in sorted({key[0] for key in gauges}):
            lines.append(f"# HELP {name} {help_lines.get(name, name).splitlines()[0]}")
            lines.append(f"# TYPE {name} {_kind_of(help_lines.get(name), 'gauge')}")
            for (metric_name, labels), value in sorted(gauges.items()):
                if metric_name == name:
                    lines.append(f"{name}{_render_labels(labels)} {_render_number(value)}")
        for (name, labels), (buckets, counts, total, observations) in sorted(histograms.items()):
            lines.append(f"# HELP {name} {help_lines.get(name, name).splitlines()[0]}")
            lines.append(f"# TYPE {name} histogram")
            for edge, count in zip(buckets, counts):
                bucket_labels = (*labels, ("le", _render_number(edge)))
                lines.append(f"{name}_bucket{_render_labels(bucket_labels)} {count}")
            lines.append(
                f"{name}_bucket{_render_labels((*labels, ('le', '+Inf')))} {observations}"
            )
            lines.append(f"{name}_sum{_render_labels(labels)} {_render_number(total)}")
            lines.append(f"{name}_count{_render_labels(labels)} {observations}")
        return "\n".join(lines) + "\n"

    def reset(self) -> None:
        """Test helper: drop every sample."""
        with self._lock:
            self._counters.clear()
            self._gauges.clear()
            self._histograms.clear()


def _kind_of(help_line: str | None, default: str) -> str:
    if help_line and "# TYPE" in help_line:
        return help_line.split("# TYPE", 1)[1].strip().split()[1]
    return default


def _validate_name(name: str) -> None:
    if not METRIC_NAME_PATTERN.match(name):
        raise ValueError(f"invalid metric name: {name!r}")


def _label_tuple(labels: Mapping[str, Any] | None) -> tuple[tuple[str, str], ...]:
    if not labels:
        return ()
    return tuple(sorted((str(key), str(value)) for key, value in labels.items()))


def _render_labels(labels: Iterable[tuple[str, str]]) -> str:
    items = list(labels)
    if not items:
        return ""
    body = ",".join(f'{key}="{_escape_label(value)}"' for key, value in items)
    return "{" + body + "}"


def _escape_label(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _render_number(value: float) -> str:
    if value == int(value) and abs(value) < 1e15:
        return str(int(value))
    return repr(round(float(value), 9))


REGISTRY = MetricsRegistry()
REGISTRY.describe("evonids_http_requests_total", "HTTP requests by method, route and status")
REGISTRY.describe("evonids_http_request_duration_seconds", "HTTP request latency in seconds")
REGISTRY.describe("evonids_http_requests_in_flight", "Concurrent HTTP requests", kind="gauge")
REGISTRY.describe("evonids_ingestion_events_total", "Ingested EVE events by result")
REGISTRY.describe("evonids_detection_signals_total", "Detection signals written by channel and decision")
REGISTRY.describe("evonids_alerts_created_total", "Alerts created by source")
REGISTRY.describe("evonids_queue_depth", "Durable queue depth by queue name", kind="gauge")
REGISTRY.describe("evonids_sensors", "Registered sensors by derived state", kind="gauge")
REGISTRY.describe("evonids_llm_calls_total", "LLM gateway calls by provider and outcome")
REGISTRY.describe("evonids_audit_events_total", "Audit events written by action", kind="gauge")
REGISTRY.describe("evonids_errors_total", "Errors by component and code")

IN_FLIGHT = {"value": 0.0}


def request_started() -> float:
    IN_FLIGHT["value"] += 1.0
    REGISTRY.set_gauge("evonids_http_requests_in_flight", IN_FLIGHT["value"])
    return time.perf_counter()


def request_finished(*, method: str, route: str, status: int, started: float) -> None:
    IN_FLIGHT["value"] = max(IN_FLIGHT["value"] - 1.0, 0.0)
    REGISTRY.set_gauge("evonids_http_requests_in_flight", IN_FLIGHT["value"])
    labels = {"method": method, "route": route, "status": str(status)}
    REGISTRY.inc("evonids_http_requests_total", labels=labels)
    REGISTRY.observe(
        "evonids_http_request_duration_seconds", time.perf_counter() - started, labels=labels
    )


def route_label(request: Any) -> str:
    """Use the matched route template, never the raw path (cardinality control)."""
    route = request.scope.get("route") if hasattr(request, "scope") else None
    path = getattr(route, "path", None)
    if path:
        return str(path)
    return "unmatched"


def collect_runtime_gauges(db: Any) -> None:
    """Refresh point-in-time gauges from the database when metrics are scraped."""
    from sqlalchemy import func, select

    from app.db.models import Alert, DetectionSignal, IngestionBatch, InvestigationRun, Sensor, TrainingRun

    try:
        queued_training = db.scalar(
            select(func.count()).select_from(TrainingRun).where(TrainingRun.state == "queued")
        ) or 0
        running_training = db.scalar(
            select(func.count()).select_from(TrainingRun).where(TrainingRun.state == "running")
        ) or 0
        queued_investigations = db.scalar(
            select(func.count()).select_from(InvestigationRun).where(InvestigationRun.state == "queued")
        ) or 0
        running_investigations = db.scalar(
            select(func.count()).select_from(InvestigationRun).where(InvestigationRun.state == "running")
        ) or 0
        alerts = db.scalar(select(func.count()).select_from(Alert)) or 0
        signals = db.scalar(select(func.count()).select_from(DetectionSignal)) or 0
        batches = db.scalar(select(func.count()).select_from(IngestionBatch)) or 0
        sensors_total = db.scalar(select(func.count()).select_from(Sensor)) or 0
        offline = db.scalar(
            select(func.count()).select_from(Sensor).where(Sensor.state == "offline")
        ) or 0
    except Exception:  # noqa: BLE001 - metrics must never break a scrape
        REGISTRY.inc("evonids_errors_total", labels={"component": "metrics", "code": "gauge_collection"})
        return
    REGISTRY.set_gauge("evonids_queue_depth", float(queued_training), labels={"queue": "training"})
    REGISTRY.set_gauge("evonids_queue_depth", float(running_training), labels={"queue": "training_running"})
    REGISTRY.set_gauge(
        "evonids_queue_depth", float(queued_investigations), labels={"queue": "investigation"}
    )
    REGISTRY.set_gauge(
        "evonids_queue_depth", float(running_investigations), labels={"queue": "investigation_running"}
    )
    REGISTRY.set_gauge("evonids_alerts_created_total", float(alerts), labels={"source": "lifetime"})
    REGISTRY.set_gauge(
        "evonids_detection_signals_total", float(signals), labels={"channel": "lifetime", "decision": "any"}
    )
    REGISTRY.set_gauge("evonids_queue_depth", float(batches), labels={"queue": "ingestion_batches_lifetime"})
    REGISTRY.set_gauge("evonids_sensors", float(sensors_total), labels={"state": "total"})
    REGISTRY.set_gauge("evonids_sensors", float(offline), labels={"state": "offline"})


def metrics_snapshot() -> dict[str, Any]:
    """Small JSON view for the health/readiness pages (not a Prometheus scrape)."""
    text = REGISTRY.render()
    return {
        "lines": len(text.splitlines()),
        "inFlight": IN_FLIGHT["value"],
        "uptimeSeconds": round(time.time() - REGISTRY._started_at, 3),  # noqa: SLF001 - same module
    }
