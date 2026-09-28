"""The orchestration layer: select connectors, deliver in isolation, record.

Everything that can go wrong is a recorded outcome, never an exception:

* a connector that raises is caught, recorded as ``failed`` and the next
  connector still runs;
* a connector that hangs is bounded by its own timeout policy;
* a connector that is disabled or does not declare the event's capability is
  recorded as ``skipped`` with the reason;
* persistence failures are logged and do not change the delivery result that the
  caller sees (the platform must not report a delivery as successful just
  because the row was written, nor hide a real delivery because the row was not).
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Protocol, Sequence

from app.integrations.base import (
    CAPABILITY_TEST,
    ConnectorRegistry,
    ConnectorResult,
    Notification,
    Severity,
    isoformat_utc,
)

logger = logging.getLogger("evonids.integrations")


@dataclass(frozen=True, slots=True)
class IntegrationEvent:
    """A delivery request: the notification plus where it came from.

    ``IntegrationEvent`` is the same document as
    :class:`~app.integrations.base.Notification` with the routing information the
    dispatcher needs (``requested_by`` for the audit trail, ``capability``
    override for manual dispatches).
    """

    notification: Notification
    requested_by: str = "system"
    capability: str = ""
    source: str = "api"

    @property
    def event_type(self) -> str:
        return self.notification.event_type

    @property
    def object_id(self) -> str:
        return self.notification.object_id

    @property
    def dedup_key(self) -> str:
        return self.notification.dedup_key

    @property
    def required_capability(self) -> str:
        return self.capability or self.notification.required_capability

    def as_dict(self) -> dict[str, Any]:
        return {
            "notification": self.notification.as_dict(),
            "requestedBy": self.requested_by,
            "capability": self.required_capability,
            "source": self.source,
        }


@dataclass(slots=True)
class DispatchOutcome:
    """Aggregate result of dispatching one event to every matching connector."""

    dedup_key: str
    event_type: str
    object_id: str
    results: list[ConnectorResult] = field(default_factory=list)
    duration_ms: float = 0.0

    @property
    def delivered(self) -> list[ConnectorResult]:
        return [result for result in self.results if result.state == "delivered"]

    @property
    def failed(self) -> list[ConnectorResult]:
        return [result for result in self.results if result.state == "failed"]

    @property
    def skipped(self) -> list[ConnectorResult]:
        return [result for result in self.results if result.state == "skipped"]

    @property
    def ok(self) -> bool:
        """True when nothing failed. No matching connector at all is not a failure."""
        return not self.failed

    def as_dict(self) -> dict[str, Any]:
        return {
            "dedupKey": self.dedup_key,
            "eventType": self.event_type,
            "objectId": self.object_id,
            "ok": self.ok,
            "deliveredCount": len(self.delivered),
            "failedCount": len(self.failed),
            "skippedCount": len(self.skipped),
            "durationMs": round(self.duration_ms, 3),
            "results": [result.as_dict() for result in self.results],
        }


class DeliveryRecorder(Protocol):
    """Persists one delivery result (``app.integrations.recorder`` implements it)."""

    def record(self, event: Notification, result: ConnectorResult) -> Any: ...


class NullRecorder:
    """Used when no database session is available; records nothing, honestly."""

    def record(self, event: Notification, result: ConnectorResult) -> None:  # noqa: ARG002
        return None


class IntegrationDispatcher:
    def __init__(
        self,
        registry: ConnectorRegistry,
        *,
        recorder: DeliveryRecorder | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.registry = registry
        self.recorder = recorder or NullRecorder()
        self._clock = clock
        self.stats: dict[str, int] = {"dispatched": 0, "delivered": 0, "failed": 0, "skipped": 0}

    # ------------------------------------------------------------- dispatch
    def dispatch(
        self,
        event: Notification | IntegrationEvent,
        *,
        connectors: Sequence[str] | None = None,
    ) -> DispatchOutcome:
        """Deliver one event; never raises into the caller."""
        notification = event.notification if isinstance(event, IntegrationEvent) else event
        requested = event.required_capability if isinstance(event, IntegrationEvent) else notification.required_capability
        started = self._clock()
        outcome = DispatchOutcome(
            dedup_key=notification.dedup_key,
            event_type=notification.event_type,
            object_id=notification.object_id,
        )
        try:
            candidates = self._select(requested, connectors)
            outcome.results.extend(self._skipped_results(requested, connectors))
        except Exception as error:  # noqa: BLE001 - selection bugs must not break ingestion
            logger.error(
                "integration dispatch selection failed",
                extra={"eventType": notification.event_type, "error": f"{type(error).__name__}: {error}"[:255]},
            )
            outcome.duration_ms = (self._clock() - started) * 1000
            return outcome
        for connector in candidates:
            connector_started = self._clock()
            try:
                result = connector.deliver(notification)
            except Exception as error:  # noqa: BLE001 - one connector must never block the others
                result = ConnectorResult(
                    connector=str(getattr(connector, "name", "unknown")),
                    state="failed",
                    attempts=0,
                    error=f"{type(error).__name__}: {error}"[:255],
                    error_code="dispatcher_caught",
                    dedup_key=notification.dedup_key,
                    event_type=notification.event_type,
                    object_id=notification.object_id,
                    duration_ms=(self._clock() - connector_started) * 1000,
                )
            if result.dedup_key == "":
                result = ConnectorResult(
                    connector=result.connector,
                    state=result.state,
                    attempts=result.attempts,
                    status=result.status,
                    error=result.error,
                    error_code=result.error_code,
                    dedup_key=notification.dedup_key,
                    event_type=notification.event_type,
                    object_id=notification.object_id,
                    duration_ms=result.duration_ms,
                    skipped_reason=result.skipped_reason,
                    request_summary=result.request_summary,
                    response_summary=result.response_summary,
                )
            outcome.results.append(result)
            self._record(notification, result)
        self.stats["dispatched"] += 1
        self.stats["delivered"] += len(outcome.delivered)
        self.stats["failed"] += len(outcome.failed)
        self.stats["skipped"] += len(outcome.skipped)
        outcome.duration_ms = (self._clock() - started) * 1000
        return outcome

    def dispatch_result(self, event: Notification | IntegrationEvent) -> dict[str, Any]:
        return self.dispatch(event).as_dict()

    def deliver_to(self, connector_name: str, event: Notification) -> DispatchOutcome:
        """Deliver one event to exactly one connector (used by the test endpoint)."""
        return self.dispatch(event, connectors=[connector_name])

    # -------------------------------------------------------------- helpers
    def _select(self, capability: str, only: Sequence[str] | None) -> list[Any]:
        if only is None:
            return self.registry.matching(capability)
        selected = []
        for name in only:
            connector = self.registry.get(name)
            if connector is None or not self.registry.is_enabled(name):
                continue
            # A connector that does not declare the capability must never receive
            # the event; ``_skipped_results`` reports it as capability_mismatch.
            if capability not in set(getattr(connector, "capabilities", frozenset())):
                continue
            selected.append(connector)
        return selected

    def _skipped_results(self, capability: str, only: Sequence[str] | None) -> list[ConnectorResult]:
        """Explain, per requested connector, why it was not used."""
        # Even an unrestricted dispatch must explain why a configured connector
        # was not used: a silent omission hides a misconfigured capability set.
        names = list(only) if only is not None else list(self.registry.names())
        results: list[ConnectorResult] = []
        for name in names:
            connector = self.registry.get(name)
            if connector is None:
                continue
            if not self.registry.is_enabled(name):
                results.append(
                    ConnectorResult(
                        connector=name,
                        state="skipped",
                        attempts=0,
                        skipped_reason=self.registry.disabled_reason(name) or "disabled",
                        error=self.registry.disabled_reason(name),
                        error_code="connector_disabled",
                    )
                )
                continue
            capabilities: object = getattr(connector, "capabilities", frozenset())
            declared = set(capabilities) if isinstance(capabilities, (set, frozenset, list, tuple)) else set()
            if capability not in declared:
                results.append(
                    ConnectorResult(
                        connector=name,
                        state="skipped",
                        attempts=0,
                        skipped_reason="capability_mismatch",
                        error=f"connector does not declare capability {capability!r}",
                        error_code="capability_mismatch",
                    )
                )
        return results

    def _record(self, event: Notification, result: ConnectorResult) -> None:
        try:
            self.recorder.record(event, result)
        except Exception as error:  # noqa: BLE001 - persistence must not mask the delivery
            logger.warning(
                "integration delivery was not persisted",
                extra={
                    "connector": result.connector,
                    "state": result.state,
                    "dedupKey": result.dedup_key,
                    "error": f"{type(error).__name__}: {error}"[:255],
                },
            )

    # --------------------------------------------------------------- health
    def health_report(self) -> dict[str, Any]:
        report = self.registry.health_report()
        report["dispatcher"] = {
            "stats": dict(self.stats),
            "capabilities": sorted(
                {
                    capability
                    for connector in self.registry.enabled()
                    for capability in getattr(connector, "capabilities", frozenset())
                }
            ),
            "generatedAt": isoformat_utc(datetime.now(timezone.utc)),
        }
        report["configured"] = bool(self.registry.all())
        return report


def synthetic_test_event(
    *, connector: str, now: datetime | None = None, severity: Severity = "info"
) -> Notification:
    """A clearly-labelled synthetic event for ``POST /integrations/{name}/test``.

    The event is marked ``synthetic`` in its tags and metadata so neither the
    receiver nor a later reader can mistake it for a real detection.
    """
    occurred = now or datetime.now(timezone.utc)
    return Notification(
        event_type=CAPABILITY_TEST,
        object_id=f"TEST-{connector}",
        title=f"EvoNIDS 集成自检事件（connector={connector}）",
        severity=severity,
        occurred_at=occurred,
        dedup_key=f"test|{connector}",
        tags=("synthetic", "integration-self-test"),
        metadata={"synthetic": True, "connector": connector},
    )


__all__ = [
    "DispatchOutcome",
    "IntegrationDispatcher",
    "IntegrationEvent",
    "NullRecorder",
    "synthetic_test_event",
]
