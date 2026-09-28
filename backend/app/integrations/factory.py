"""Build connectors from configuration and expose the process-wide dispatcher.

Nothing is constructed until configuration asks for it: with an empty
environment the registry has zero connectors, the dispatcher delivers nothing and
``health_report()`` says so. A test therefore cannot accidentally reach the
network through an implicit default connector.

Transports are injectable here (``http_transport`` / ``syslog_transport``) so the
API-level tests exercise the real dispatcher, the real retry/circuit logic and the
real recorder, with only the socket replaced.
"""

from __future__ import annotations

import os
import threading
from typing import Any, Callable, Mapping

from app.integrations.base import (
    ConnectorRegistry,
    ResiliencePolicy,
)
from app.integrations.dispatcher import IntegrationDispatcher
from app.integrations.settings import (
    IntegrationSettings,
    SyslogSettings,
    TicketSettings,
    WebhookSettings,
    load_integration_settings,
)
from app.integrations.stix import StixExportConnector
from app.integrations.syslog_cef import SyslogConnector, SyslogTransport
from app.integrations.ticketing import build_ticket_connector
from app.integrations.url_guard import HttpTransport
from app.integrations.webhook import WebhookConnector

DEFAULT_WEBHOOK_CAPABILITIES = ("alert", "evidence", "test")


def webhook_policy(settings: WebhookSettings) -> ResiliencePolicy:
    return ResiliencePolicy(
        timeout_seconds=settings.timeout_seconds,
        max_attempts=settings.max_attempts,
        base_backoff_seconds=settings.base_backoff_seconds,
        max_backoff_seconds=settings.max_backoff_seconds,
        circuit_failure_threshold=settings.circuit_failure_threshold,
        circuit_reset_seconds=settings.circuit_reset_seconds,
    )


def ticket_policy(settings: TicketSettings) -> ResiliencePolicy:
    return ResiliencePolicy(
        timeout_seconds=settings.timeout_seconds,
        max_attempts=settings.max_attempts,
        base_backoff_seconds=settings.base_backoff_seconds,
        max_backoff_seconds=settings.max_backoff_seconds,
        circuit_failure_threshold=settings.circuit_failure_threshold,
        circuit_reset_seconds=settings.circuit_reset_seconds,
    )


def syslog_policy(settings: SyslogSettings) -> ResiliencePolicy:
    # A syslog sender has no idempotency ledger to lean on, so it retries the
    # same way but with a tighter budget and no circuit breaker pressure.
    return ResiliencePolicy(
        timeout_seconds=settings.timeout_seconds,
        max_attempts=2,
        base_backoff_seconds=0.25,
        max_backoff_seconds=2.0,
        circuit_failure_threshold=5,
        circuit_reset_seconds=60.0,
    )


def build_registry(
    settings: IntegrationSettings,
    *,
    http_transport: HttpTransport | None = None,
    resolver: Any = None,
    syslog_transport: SyslogTransport | None = None,
    clock: Callable[[], float] | None = None,
    resilient: bool = True,
) -> ConnectorRegistry:
    """Assemble the registry for one configuration snapshot."""
    from app.integrations.base import ResilientConnector

    registry = ConnectorRegistry()
    if not settings.enabled:
        return registry

    wrap: Callable[[Any, ResiliencePolicy], Any]
    if resilient:
        def wrap(connector: Any, policy: ResiliencePolicy) -> Any:
            kwargs: dict[str, Any] = {"policy": policy}
            if clock is not None:
                kwargs["clock"] = clock
            return ResilientConnector(connector, **kwargs)
    else:
        def wrap(connector: Any, policy: ResiliencePolicy) -> Any:  # noqa: ARG001
            return connector

    for webhook in settings.webhooks:
        connector = WebhookConnector(webhook, transport=http_transport, resolver=resolver)
        registry.register(wrap(connector, webhook_policy(webhook)), enabled=True)

    if settings.syslog is not None:
        syslog_connector = SyslogConnector(settings.syslog, transport=syslog_transport)
        registry.register(wrap(syslog_connector, syslog_policy(settings.syslog)), enabled=True)

    if settings.stix is not None:
        stix_connector = StixExportConnector(settings.stix)
        # Local file export: no retry, no breaker — a filesystem write either
        # works or reports a real error.
        registry.register(stix_connector, enabled=True)

    if settings.tickets is not None:
        ticket_connector = build_ticket_connector(settings.tickets, transport=http_transport)
        registry.register(wrap(ticket_connector, ticket_policy(settings.tickets)), enabled=True)

    return registry


def build_dispatcher(
    settings: IntegrationSettings | None = None,
    *,
    recorder: Any = None,
    http_transport: HttpTransport | None = None,
    syslog_transport: SyslogTransport | None = None,
) -> IntegrationDispatcher:
    active = settings if settings is not None else load_integration_settings()
    registry = build_registry(
        active, http_transport=http_transport, syslog_transport=syslog_transport
    )
    return IntegrationDispatcher(registry, recorder=recorder)


_DISPATCHER: IntegrationDispatcher | None = None
_DISPATCHER_SIGNATURE: tuple[str, ...] | None = None
_DISPATCHER_LOCK = threading.Lock()


def environment_signature(source: Mapping[str, str] | None = None) -> tuple[str, ...]:
    env = os.environ if source is None else source
    keys = (
        "EVONIDS_INTEGRATIONS_ENABLED",
        "EVONIDS_WEBHOOK_URLS",
        "EVONIDS_WEBHOOK_SECRET",
        "EVONIDS_SYSLOG_HOST",
        "EVONIDS_SYSLOG_FORMAT",
        "EVONIDS_STIX_EXPORT_DIR",
        "EVONIDS_TICKET_BASE_URL",
    )
    return tuple(f"{key}={env.get(key, '')}" for key in keys)


def get_dispatcher() -> IntegrationDispatcher:
    """Process-wide dispatcher, rebuilt when the relevant environment changes."""
    global _DISPATCHER, _DISPATCHER_SIGNATURE
    signature = environment_signature()
    with _DISPATCHER_LOCK:
        if _DISPATCHER is None or _DISPATCHER_SIGNATURE != signature:
            from app.db.session import SessionLocal
            from app.integrations.recorder import DeliveryRecorder

            settings = load_integration_settings()
            registry = build_registry(settings)
            _DISPATCHER = IntegrationDispatcher(registry, recorder=DeliveryRecorder(SessionLocal))
            _DISPATCHER_SIGNATURE = signature
        return _DISPATCHER


def set_dispatcher(dispatcher: IntegrationDispatcher | None) -> None:
    """Install an explicit dispatcher (tests, or a caller with its own transports)."""
    global _DISPATCHER, _DISPATCHER_SIGNATURE
    with _DISPATCHER_LOCK:
        _DISPATCHER = dispatcher
        _DISPATCHER_SIGNATURE = environment_signature() if dispatcher is not None else None


def reset_dispatcher() -> None:
    global _DISPATCHER, _DISPATCHER_SIGNATURE
    with _DISPATCHER_LOCK:
        _DISPATCHER = None
        _DISPATCHER_SIGNATURE = None


__all__ = [
    "build_dispatcher",
    "build_registry",
    "environment_signature",
    "get_dispatcher",
    "reset_dispatcher",
    "set_dispatcher",
    "syslog_policy",
    "ticket_policy",
    "webhook_policy",
]
