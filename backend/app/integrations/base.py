"""Connector contract, delivery results and the enabled/disabled registry.

The outbound integration layer is a plugin framework: a connector declares what
it is called, which event types it can carry (``capabilities``) and how to
deliver one event. Everything else — retries, backoff, circuit breaking,
timeouts, isolation between connectors and persistence of outcomes — is provided
by this package, so a new connector is a small, self-contained object.

Honesty rules enforced by these types:

* a connector that cannot run is *absent from the registry*, never a stub that
  reports success;
* a delivery that did not happen is ``failed`` with an error string, never
  ``delivered``;
* ``ConnectorResult`` carries the real attempt count, the real HTTP/exit status
  and a redacted request/response summary.
"""

from __future__ import annotations

import random
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Iterable, Literal, Mapping, Protocol, Sequence, runtime_checkable

from app.integrations.redaction import redact_mapping

Severity = Literal["critical", "high", "medium", "low", "info"]
DeliveryState = Literal["delivered", "failed", "skipped"]

SEVERITY_ORDER: tuple[Severity, ...] = ("critical", "high", "medium", "low", "info")

# Capabilities a connector can declare. The dispatcher only offers an event to a
# connector that declares the capability the event needs.
CAPABILITY_ALERT = "alert"
CAPABILITY_CASE = "case"
CAPABILITY_EVIDENCE = "evidence"
CAPABILITY_TEST = "test"
CAPABILITIES: tuple[str, ...] = (
    CAPABILITY_ALERT,
    CAPABILITY_CASE,
    CAPABILITY_EVIDENCE,
    CAPABILITY_TEST,
)

DEFAULT_MAX_SUMMARY_CHARS = 2_000


def severity_from_risk(risk_score: float | None) -> Severity:
    """Map the platform's 0..100 risk score onto the notification severity."""
    if risk_score is None:
        return "info"
    if risk_score >= 85:
        return "critical"
    if risk_score >= 65:
        return "high"
    if risk_score >= 40:
        return "medium"
    if risk_score > 0:
        return "low"
    return "info"


@dataclass(frozen=True, slots=True)
class Notification:
    """One outbound event: what happened, about which object, how urgent.

    ``dedup_key`` is stable for a given (event type, object, severity revision)
    so a retry or a duplicate dispatch collapses onto one delivery row.
    """

    event_type: str
    object_id: str
    title: str
    severity: Severity = "info"
    occurred_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    dedup_key: str = ""
    alert: Mapping[str, Any] | None = None
    case: Mapping[str, Any] | None = None
    evidence: Sequence[Mapping[str, Any]] = ()
    tags: Sequence[str] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.event_type:
            raise ValueError("Notification.event_type must not be empty")
        if not self.object_id:
            raise ValueError("Notification.object_id must not be empty")
        if not self.dedup_key:
            object.__setattr__(self, "dedup_key", build_dedup_key(self.event_type, self.object_id))

    @property
    def required_capability(self) -> str:
        if self.event_type == CAPABILITY_TEST:
            return CAPABILITY_TEST
        if self.event_type == CAPABILITY_CASE:
            return CAPABILITY_CASE
        if self.event_type == CAPABILITY_EVIDENCE:
            return CAPABILITY_EVIDENCE
        return CAPABILITY_ALERT

    def occurred_at_iso(self) -> str:
        return isoformat_utc(self.occurred_at)

    def as_dict(self) -> dict[str, Any]:
        return {
            "eventType": self.event_type,
            "objectId": self.object_id,
            "title": self.title,
            "severity": self.severity,
            "occurredAt": self.occurred_at_iso(),
            "dedupKey": self.dedup_key,
            "alert": redact_mapping(self.alert) if self.alert is not None else None,
            "case": redact_mapping(self.case) if self.case is not None else None,
            "evidence": redact_mapping(list(self.evidence)),
            "tags": list(self.tags),
            "metadata": redact_mapping(dict(self.metadata)),
        }


def isoformat_utc(value: datetime) -> str:
    """ISO-8601 in UTC with millisecond precision; naive values are read as UTC."""
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def build_dedup_key(event_type: str, object_id: str, *, revision: str = "") -> str:
    """Stable, human-readable deduplication key for one outbound event."""
    parts = [event_type.strip().lower(), object_id.strip()]
    if revision:
        parts.append(revision.strip())
    return "|".join(parts)


@dataclass(frozen=True, slots=True)
class ConnectorResult:
    """Outcome of one delivery attempt series for one connector."""

    connector: str
    state: DeliveryState
    attempts: int = 0
    status: int | None = None
    error: str | None = None
    error_code: str | None = None
    dedup_key: str = ""
    event_type: str = ""
    object_id: str = ""
    duration_ms: float = 0.0
    skipped_reason: str | None = None
    request_summary: dict[str, Any] = field(default_factory=dict)
    response_summary: dict[str, Any] = field(default_factory=dict)

    @property
    def delivered(self) -> bool:
        return self.state == "delivered"

    def as_dict(self) -> dict[str, Any]:
        return {
            "connector": self.connector,
            "state": self.state,
            "attempts": self.attempts,
            "status": self.status,
            "error": self.error,
            "errorCode": self.error_code,
            "dedupKey": self.dedup_key,
            "eventType": self.event_type,
            "objectId": self.object_id,
            "durationMs": round(self.duration_ms, 3),
            "skippedReason": self.skipped_reason,
            "requestSummary": self.request_summary,
            "responseSummary": self.response_summary,
        }

    @classmethod
    def skipped(cls, connector: str, event: Notification, reason: str) -> ConnectorResult:
        return cls(
            connector=connector,
            state="skipped",
            attempts=0,
            skipped_reason=reason,
            dedup_key=event.dedup_key,
            event_type=event.event_type,
            object_id=event.object_id,
            request_summary=summarise_request(event),
        )


def summarise_request(event: Notification) -> dict[str, Any]:
    """Redacted, bounded summary of what a connector was asked to deliver."""
    return {
        "eventType": event.event_type,
        "objectId": event.object_id,
        "severity": event.severity,
        "title": redact_mapping(event.title),
        "dedupKey": event.dedup_key,
        "occurredAt": event.occurred_at_iso(),
    }


def summarise_response(payload: Mapping[str, Any] | str | None) -> dict[str, Any]:
    """Redacted, bounded summary of what a remote endpoint answered."""
    if payload is None:
        return {}
    if isinstance(payload, str):
        return {"body": redact_mapping(payload[:DEFAULT_MAX_SUMMARY_CHARS])}
    return redact_mapping({str(key): value for key, value in list(payload.items())[:40]})


class DeliveryError(RuntimeError):
    """A connector delivery failed.

    ``retryable`` distinguishes a transport/5xx/429 failure (worth another
    attempt) from a 4xx rejection that would fail identically forever.
    """

    def __init__(
        self,
        message: str,
        *,
        code: str = "delivery_error",
        retryable: bool = False,
        status: int | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.retryable = retryable
        self.status = status


class NonRetryableDeliveryError(DeliveryError):
    def __init__(self, message: str, *, code: str = "rejected", status: int | None = None) -> None:
        super().__init__(message, code=code, retryable=False, status=status)


class RetryableDeliveryError(DeliveryError):
    def __init__(self, message: str, *, code: str = "transport_error", status: int | None = None) -> None:
        super().__init__(message, code=code, retryable=True, status=status)


class CircuitOpenError(DeliveryError):
    def __init__(self, message: str) -> None:
        super().__init__(message, code="circuit_open", retryable=False)


class DeliveryBlockedError(DeliveryError):
    """The connector refused the target before any network call (SSRF guard)."""

    def __init__(self, message: str, *, code: str = "blocked_target") -> None:
        super().__init__(message, code=code, retryable=False)


@dataclass(frozen=True, slots=True)
class ResiliencePolicy:
    """Timeout, retry and circuit-breaker settings shared by all connectors."""

    timeout_seconds: float = 10.0
    max_attempts: int = 3
    base_backoff_seconds: float = 0.5
    max_backoff_seconds: float = 8.0
    circuit_failure_threshold: int = 5
    circuit_reset_seconds: float = 60.0

    @property
    def attempts(self) -> int:
        return max(1, self.max_attempts)


@runtime_checkable
class Connector(Protocol):
    """What the dispatcher needs from a connector."""

    name: str

    @property
    def capabilities(self) -> frozenset[str]: ...

    def describe(self) -> dict[str, Any]: ...

    def health(self) -> dict[str, Any]: ...

    def deliver(self, event: Notification) -> ConnectorResult: ...


@dataclass(slots=True)
class ConnectorStats:
    delivered: int = 0
    failed: int = 0
    skipped: int = 0
    attempts: int = 0
    last_error: str | None = None
    last_delivered_at: str | None = None
    last_failed_at: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "delivered": self.delivered,
            "failed": self.failed,
            "skipped": self.skipped,
            "attempts": self.attempts,
            "lastError": self.last_error,
            "lastDeliveredAt": self.last_delivered_at,
            "lastFailedAt": self.last_failed_at,
        }


class CircuitBreaker:
    """Per-connector consecutive-failure breaker (same shape as the LLM gateway)."""

    def __init__(
        self,
        *,
        failure_threshold: int = 5,
        reset_seconds: float = 60.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.failure_threshold = max(1, failure_threshold)
        self.reset_seconds = max(0.0, reset_seconds)
        self._clock = clock
        self._lock = threading.Lock()
        self._consecutive_failures = 0
        self._opened_at: float | None = None
        self.openings = 0

    @property
    def state(self) -> str:
        with self._lock:
            return "open" if self._is_open_locked() else "closed"

    def _is_open_locked(self) -> bool:
        if self._opened_at is None:
            return False
        if self._clock() - self._opened_at >= self.reset_seconds:
            # Half-open: the next call is allowed to probe the endpoint again.
            self._opened_at = None
            self._consecutive_failures = 0
            return False
        return True

    def check(self) -> None:
        with self._lock:
            if self._is_open_locked():
                raise CircuitOpenError(
                    f"circuit is open after {self._consecutive_failures} consecutive failures"
                )

    def record_success(self) -> None:
        with self._lock:
            self._consecutive_failures = 0
            self._opened_at = None

    def record_failure(self) -> None:
        with self._lock:
            self._consecutive_failures += 1
            if self._consecutive_failures >= self.failure_threshold:
                self._opened_at = self._clock()
                self.openings += 1

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            open_remaining = 0.0
            if self._opened_at is not None:
                open_remaining = max(self.reset_seconds - (self._clock() - self._opened_at), 0.0)
            return {
                "state": "open" if self._is_open_locked() else "closed",
                "consecutiveFailures": self._consecutive_failures,
                "resetInSeconds": round(open_remaining, 3),
                "openings": self.openings,
                "failureThreshold": self.failure_threshold,
            }


@dataclass(frozen=True, slots=True)
class DeliveryAttempt:
    """What one transport call produced, before retry/circuit bookkeeping."""

    status: int | None = None
    request_summary: dict[str, Any] = field(default_factory=dict)
    response_summary: dict[str, Any] = field(default_factory=dict)
    deliverable: bool = True
    retryable: bool = False
    error: str | None = None
    error_code: str | None = None
    # A connector may decline an event by configuration (for example a syslog
    # channel whose minimum severity is higher than the event's severity). That
    # is reported as ``skipped``, never as a failure.
    skipped: bool = False
    skipped_reason: str | None = None

    @property
    def summary_state(self) -> str:
        return "ok" if self.deliverable else "failed"


class ResilientConnector:
    """Adds retry/backoff, a circuit breaker and stats to any connector.

    The wrapped connector performs exactly one transport call per
    ``deliver_once``; this wrapper owns everything about *how often* that call is
    made. Keeping the split explicit is what makes the retry and circuit
    behaviour testable without a network.
    """

    def __init__(
        self,
        connector: Any,
        *,
        policy: ResiliencePolicy | None = None,
        clock: Callable[[], float] = time.monotonic,
        sleeper: Callable[[float], None] = time.sleep,
        random_source: Callable[[], float] = random.random,
        wall_clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    ) -> None:
        self._connector = connector
        self.policy = policy or ResiliencePolicy()
        self._clock = clock
        self._sleeper = sleeper
        self._random = random_source
        self._wall_clock = wall_clock
        self.breaker = CircuitBreaker(
            failure_threshold=self.policy.circuit_failure_threshold,
            reset_seconds=self.policy.circuit_reset_seconds,
            clock=clock,
        )
        self.stats = ConnectorStats()

    # ------------------------------------------------------------- delegation
    @property
    def name(self) -> str:
        return str(self._connector.name)

    @property
    def capabilities(self) -> frozenset[str]:
        caps = self._connector.capabilities
        return frozenset(str(cap) for cap in caps)

    @property
    def inner(self) -> Any:
        return self._connector

    def describe(self) -> dict[str, Any]:
        payload = dict(self._connector.describe())
        payload.setdefault("name", self.name)
        payload["capabilities"] = sorted(self.capabilities)
        return payload

    def health(self) -> dict[str, Any]:
        payload = dict(self._connector.health())
        payload.setdefault("connector", self.name)
        payload["circuit"] = self.breaker.snapshot()
        payload["stats"] = self.stats.as_dict()
        return payload

    # --------------------------------------------------------------- delivery
    def deliver(self, event: Notification) -> ConnectorResult:
        started = self._clock()
        failure: DeliveryError | None = None
        attempts = 0
        try:
            self.breaker.check()
        except CircuitOpenError as error:
            self.stats.skipped += 1
            return ConnectorResult(
                connector=self.name,
                state="skipped",
                attempts=0,
                error=str(error),
                error_code=error.code,
                skipped_reason="circuit_open",
                dedup_key=event.dedup_key,
                event_type=event.event_type,
                object_id=event.object_id,
                duration_ms=(self._clock() - started) * 1000,
                request_summary=summarise_request(event),
            )
        while attempts < self.policy.attempts:
            attempts += 1
            self.stats.attempts += 1
            try:
                outcome = self._connector.deliver_once(event)
            except DeliveryError as error:
                failure = error
                if not error.retryable:
                    break
                self._backoff(attempts)
                continue
            except Exception as error:  # noqa: BLE001 - a connector bug must degrade, not crash
                failure = NonRetryableDeliveryError(
                    f"{type(error).__name__}: {error}"[:255], code="connector_error"
                )
                break
            if outcome.deliverable:
                self.breaker.record_success()
                self.stats.delivered += 1
                self.stats.last_delivered_at = isoformat_utc(self._wall_clock())
                return ConnectorResult(
                    connector=self.name,
                    state="delivered",
                    attempts=attempts,
                    status=outcome.status,
                    dedup_key=event.dedup_key,
                    event_type=event.event_type,
                    object_id=event.object_id,
                    duration_ms=(self._clock() - started) * 1000,
                    request_summary=outcome.request_summary or summarise_request(event),
                    response_summary=outcome.response_summary,
                )
            failure = (
                RetryableDeliveryError(
                    outcome.error or "delivery failed",
                    code=outcome.error_code or "retryable",
                    status=outcome.status,
                )
                if outcome.retryable
                else NonRetryableDeliveryError(
                    outcome.error or "delivery failed",
                    code=outcome.error_code or "rejected",
                    status=outcome.status,
                )
            )
            if outcome.skipped:
                self.stats.skipped += 1
                self.breaker.record_success()
                return ConnectorResult(
                    connector=self.name,
                    state="skipped",
                    attempts=attempts,
                    status=outcome.status,
                    error=outcome.error,
                    error_code=outcome.error_code,
                    skipped_reason=outcome.skipped_reason or outcome.error_code or "skipped_by_connector",
                    dedup_key=event.dedup_key,
                    event_type=event.event_type,
                    object_id=event.object_id,
                    duration_ms=(self._clock() - started) * 1000,
                    request_summary=outcome.request_summary or summarise_request(event),
                    response_summary=outcome.response_summary,
                )
            if not outcome.retryable:
                break
            if attempts >= self.policy.max_attempts:
                # The final attempt is not followed by a sleep: waiting after the
                # decision to give up only delays the honest failure.
                break
            self._backoff(attempts)
        self.breaker.record_failure()
        self.stats.failed += 1
        self.stats.last_failed_at = isoformat_utc(self._wall_clock())
        assert failure is not None  # the loop only exits with a recorded failure
        self.stats.last_error = f"{failure.code}: {failure}"[:255]
        return ConnectorResult(
            connector=self.name,
            state="failed",
            attempts=attempts,
            status=failure.status,
            error=str(failure)[:255],
            error_code=failure.code,
            dedup_key=event.dedup_key,
            event_type=event.event_type,
            object_id=event.object_id,
            duration_ms=(self._clock() - started) * 1000,
            request_summary=summarise_request(event),
        )

    def _backoff(self, attempt: int) -> None:
        delay = min(
            self.policy.base_backoff_seconds * (2 ** (attempt - 1)), self.policy.max_backoff_seconds
        )
        self._sleeper(round(delay + delay * 0.25 * self._random(), 6))


class ConnectorRegistry:
    """Explicit enable/disable per connector, driven by configuration.

    A disabled connector is *registered* (so ``GET /integrations`` can honestly
    report "configured but disabled") but is never offered an event.
    """

    def __init__(self) -> None:
        self._connectors: dict[str, Any] = {}
        self._disabled: dict[str, str] = {}

    def register(self, connector: Any, *, enabled: bool = True, disabled_reason: str = "") -> None:
        name = str(connector.name)
        self._connectors[name] = connector
        if enabled:
            self._disabled.pop(name, None)
        else:
            self._disabled[name] = disabled_reason or "disabled by configuration"

    def disable(self, name: str, reason: str = "disabled by configuration") -> None:
        if name not in self._connectors:
            raise KeyError(f"connector {name!r} is not registered")
        self._disabled[name] = reason

    def enable(self, name: str) -> None:
        if name not in self._connectors:
            raise KeyError(f"connector {name!r} is not registered")
        self._disabled.pop(name, None)

    def get(self, name: str) -> Any | None:
        return self._connectors.get(name)

    def is_enabled(self, name: str) -> bool:
        return name in self._connectors and name not in self._disabled

    def disabled_reason(self, name: str) -> str | None:
        return self._disabled.get(name)

    def names(self) -> list[str]:
        return sorted(self._connectors)

    def enabled(self) -> list[Any]:
        return [self._connectors[name] for name in self.names() if name not in self._disabled]

    def all(self) -> list[Any]:
        return [self._connectors[name] for name in self.names()]

    def matching(self, capability: str) -> list[Any]:
        """Enabled connectors that declare ``capability``."""
        return [
            connector
            for connector in self.enabled()
            if capability in _capabilities_of(connector)
        ]

    def descriptors(self) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for name in self.names():
            connector = self._connectors[name]
            enabled = name not in self._disabled
            describe = getattr(connector, "describe", None)
            payload = dict(describe()) if callable(describe) else {"name": name}
            payload["name"] = name
            payload["enabled"] = enabled
            if not enabled:
                payload["disabledReason"] = self._disabled.get(name)
            payload["capabilities"] = sorted(_capabilities_of(connector))
            rows.append(payload)
        return rows

    def health_report(self) -> dict[str, Any]:
        rows = []
        for name in self.names():
            connector = self._connectors[name]
            enabled = name not in self._disabled
            health = dict(connector.health()) if hasattr(connector, "health") else {"state": "unknown"}
            health["enabled"] = enabled
            if not enabled:
                health.setdefault("state", "disabled")
                health["state"] = "disabled"
                health["disabledReason"] = self._disabled.get(name)
            rows.append(health)
        healthy = sum(1 for row in rows if row.get("enabled") and row.get("state") == "ok")
        return {
            "enabled": bool(self.enabled()),
            "total": len(rows),
            "enabledCount": sum(1 for row in rows if row["enabled"]),
            "healthyCount": healthy,
            "degradedCount": sum(
                1 for row in rows if row["enabled"] and row.get("state") not in {"ok", "disabled"}
            ),
            "connectors": rows,
        }


def _capabilities_of(connector: Any) -> frozenset[str]:
    caps = getattr(connector, "capabilities", ())
    if isinstance(caps, str):
        return frozenset({caps})
    return frozenset(str(cap) for cap in caps if isinstance(cap, str))


def capability_index(connectors: Iterable[Any]) -> dict[str, list[str]]:
    index: dict[str, list[str]] = {capability: [] for capability in CAPABILITIES}
    for connector in connectors:
        for capability in _capabilities_of(connector):
            index.setdefault(capability, []).append(str(connector.name))
    return {capability: sorted(names) for capability, names in index.items()}
