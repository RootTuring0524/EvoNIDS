"""Ticketing / SIEM connector interface and one concrete HTTP implementation.

The interface is deliberately tiny (create / update) so an operator can bind it
to Jira, ServiceNow, TheHive, an internal SOC queue or a SIEM's case API by
supplying paths and a token.

Two rules this module enforces:

1. **redaction before the wire** — the ticket payload is built from
   :func:`build_ticket_payload`, which redacts every value through
   :mod:`app.integrations.redaction`. There is no code path that serialises a
   raw alert/case/evidence payload to a ticketing endpoint.
2. **the same SSRF guard as webhooks** — the ticketing base URL goes through
   :func:`app.integrations.url_guard.validate_target_url` before any request, so
   a mistyped internal address cannot turn the platform into a probe.

Delivery is idempotent by construction: the dedup key is sent as the external
reference and as the ``X-Evonids-Idempotency-Key`` header, and a ticket id
returned by a previous delivery is reused for updates.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field, replace
from typing import Any, Callable, Mapping, Protocol
from urllib.parse import urljoin

from app.integrations.base import (
    DeliveryAttempt,
    Notification,
    summarise_request,
)
from app.integrations.redaction import redact_mapping, redact_text
from app.integrations.settings import TicketSettings
from app.integrations.url_guard import (
    HttpTransport,
    HttpxTransport,
    TargetPolicy,
    TransportResponse,
    validate_target_url,
)

RETRYABLE_STATUSES = frozenset({408, 425, 429, 500, 502, 503, 504})
USER_AGENT = "evonids-integrations/0.1.1"

STATUS_OPEN = "open"
STATUS_UPDATE = "update"

# Alert/case fields that belong in a ticket regardless of the schema version.
TICKET_SUMMARY_FIELDS: tuple[tuple[str, str], ...] = (
    ("sourceIp", "源地址"),
    ("destinationIp", "目的地址"),
    ("destinationPort", "目的端口"),
    ("protocol", "协议"),
    ("category", "分类"),
    ("sensor", "传感器"),
    ("status", "状态"),
    ("riskScore", "风险分"),
    ("assignee", "负责人"),
)


@dataclass(frozen=True, slots=True)
class TicketPayload:
    """What a ticketing endpoint receives (already redacted)."""

    dedup_key: str
    title: str
    description: str
    severity: str
    labels: tuple[str, ...]
    external_ref: str
    project: str
    status: str
    occurred_at: str
    fields: Mapping[str, Any] = field(default_factory=dict)
    ticket_id: str | None = None

    def as_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "title": self.title,
            "description": self.description,
            "priority": self.severity,
            "labels": list(self.labels),
            "externalRef": self.external_ref,
            "dedupKey": self.dedup_key,
            "occurredAt": self.occurred_at,
            "status": self.status,
            "fields": dict(self.fields),
        }
        if self.project:
            payload["project"] = self.project
        if self.ticket_id:
            payload["ticketId"] = self.ticket_id
        return payload


@dataclass(frozen=True, slots=True)
class TicketResult:
    """Outcome of a ticketing call, transport-agnostic."""

    ticket_id: str | None
    status: str
    raw: Mapping[str, Any] = field(default_factory=dict)

    @property
    def created(self) -> bool:
        return self.status == STATUS_OPEN


class TicketBackend(Protocol):
    """The interface a concrete ticketing system implements."""

    def create_ticket(self, payload: TicketPayload) -> TicketResult: ...

    def update_ticket(self, ticket_id: str, payload: TicketPayload) -> TicketResult: ...

    def health(self) -> dict[str, Any]: ...


def build_ticket_payload(event: Notification, *, project: str = "", ticket_id: str | None = None) -> TicketPayload:
    """Build a redacted ticket payload for one notification.

    ``summary`` lines are derived from the alert or case fields that are useful
    to a responder; everything is passed through :func:`redact_mapping`, so a
    credential-shaped value can never reach the ticketing endpoint even when it
    arrived inside an evidence blob.
    """
    source = dict(event.alert or event.case or {})
    redacted_source = redact_mapping(source)
    fields: dict[str, Any] = {}
    assert isinstance(redacted_source, dict)
    for key, label in TICKET_SUMMARY_FIELDS:
        value = redacted_source.get(key)
        if value not in (None, "", [], {}):
            fields[key] = value
    if event.alert is not None:
        fields["objectType"] = "alert"
    elif event.case is not None:
        fields["objectType"] = "case"
    else:
        fields["objectType"] = event.event_type
    fields["objectId"] = event.object_id
    if event.evidence:
        fields["evidenceIds"] = [
            str(item.get("id") or item.get("evidenceId"))
            for item in event.evidence[:20]
            if isinstance(item, Mapping) and (item.get("id") or item.get("evidenceId"))
        ]
    if event.metadata:
        fields["metadata"] = redact_mapping(dict(event.metadata))

    description_lines = [
        f"事件类型：{event.event_type}",
        f"对象：{event.object_id}",
        f"严重级别：{event.severity}",
        f"发生时间：{event.occurred_at_iso()}",
        f"去重键：{event.dedup_key}",
        "",
        f"摘要：{redact_text(event.title, limit=300)}",
    ]
    for key, label in TICKET_SUMMARY_FIELDS:
        value = fields.get(key)
        if value not in (None, "", [], {}):
            description_lines.append(f"{label}：{value}")
    if event.evidence:
        description_lines.append(f"证据条目：{len(event.evidence)} 条")
    description_lines.append("")
    description_lines.append("（本工单由 EvoNIDS 自动创建，敏感字段已在发送前脱敏。）")

    return TicketPayload(
        dedup_key=event.dedup_key,
        title=redact_text(f"[EvoNIDS][{event.severity.upper()}] {event.title}", limit=200),
        description="\n".join(description_lines),
        severity=event.severity,
        labels=tuple(["evonids", event.event_type, *[str(tag) for tag in event.tags[:8]]]),
        external_ref=f"evonids:{event.event_type}:{event.object_id}",
        project=project,
        status=STATUS_UPDATE if ticket_id else STATUS_OPEN,
        occurred_at=event.occurred_at_iso(),
        fields=fields,
        ticket_id=ticket_id,
    )


class HttpTicketBackend:
    """Generic REST ticketing backend (create/update via configurable paths)."""

    def __init__(
        self,
        settings: TicketSettings,
        *,
        transport: HttpTransport | None = None,
    ) -> None:
        self.settings = settings
        self._transport = transport
        self.calls: list[dict[str, Any]] = []

    @property
    def transport(self) -> HttpTransport:
        if self._transport is None:
            self._transport = HttpxTransport()
        return self._transport

    @property
    def policy(self) -> TargetPolicy:
        return TargetPolicy(
            allowed_hosts=self.settings.allowed_hosts,
            allow_http=self.settings.allow_http,
        )

    def _url(self, path: str, **values: str) -> str:
        formatted = path.format(**values) if values else path
        return urljoin(self.settings.base_url.rstrip("/") + "/", formatted.lstrip("/"))

    def _headers(self, payload: TicketPayload) -> dict[str, str]:
        headers = {
            "Content-Type": "application/json; charset=utf-8",
            "User-Agent": USER_AGENT,
            "Accept": "application/json",
            "X-Evonids-Idempotency-Key": payload.dedup_key,
            "X-Evonids-Dedup-Key": payload.dedup_key,
            "X-Evonids-External-Ref": payload.external_ref,
        }
        if self.settings.token:
            header = self.settings.auth_header or "Authorization"
            # The header name is configurable (some SIEMs want ``X-Api-Key``);
            # ``Authorization`` gets the standard bearer scheme, others get the
            # raw token, which is what those APIs expect.
            headers[header] = (
                f"Bearer {self.settings.token}" if header.lower() == "authorization" else self.settings.token
            )
        return headers

    def _send(self, method: str, url: str, payload: TicketPayload) -> TicketResult:
        validate_target_url(url, policy=self.policy)
        body = json.dumps(payload.as_dict(), ensure_ascii=False, sort_keys=True).encode("utf-8")
        headers = self._headers(payload)
        self.calls.append({"method": method, "url": url, "headers": dict(headers), "body": body})
        response: TransportResponse = self.transport.send(
            method, url, headers=headers, body=body, timeout=self.settings.timeout_seconds
        )
        data = response.json()
        if 200 <= response.status < 300:
            ticket_id = None
            if isinstance(data, Mapping):
                for key in ("id", "ticketId", "ticket_id", "key", "number"):
                    value = data.get(key)
                    if value not in (None, ""):
                        ticket_id = str(value)
                        break
            return TicketResult(
                ticket_id=ticket_id or payload.ticket_id,
                status=STATUS_OPEN,
                raw=dict(data) if isinstance(data, Mapping) else {"body": response.text(500)},
            )
        retryable = response.status in RETRYABLE_STATUSES
        raise _http_error(response.status, retryable, response.text(300))

    def create_ticket(self, payload: TicketPayload) -> TicketResult:
        return self._send(
            "POST",
            self._url(self.settings.create_path),
            replace(payload, status=STATUS_OPEN, ticket_id=None),
        )

    def update_ticket(self, ticket_id: str, payload: TicketPayload) -> TicketResult:
        return self._send(
            "PATCH",
            self._url(self.settings.update_path, ticket_id=ticket_id),
            replace(payload, status=STATUS_UPDATE, ticket_id=ticket_id),
        )

    def health(self) -> dict[str, Any]:
        try:
            validate_target_url(self.settings.base_url, policy=self.policy)
        except Exception as error:  # noqa: BLE001 - health must never raise
            return {
                "connector": self.settings.name,
                "kind": "ticket",
                "state": "misconfigured",
                "reason": f"{type(error).__name__}: {error}"[:255],
                "probe": "not_attempted",
            }
        return {
            "connector": self.settings.name,
            "kind": "ticket",
            "state": "ok",
            "target": self.settings.base_url,
            "tokenConfigured": bool(self.settings.token),
            "probe": "not_attempted",
            "note": "未主动探测工单系统；状态来自配置与 SSRF 校验。",
        }


def _payload_fields(payload: TicketPayload) -> dict[str, Any]:
    """Public snake_case field mapping (what the HTTP body is built from)."""
    return {
        "dedup_key": payload.dedup_key,
        "title": payload.title,
        "description": payload.description,
        "severity": payload.severity,
        "labels": payload.labels,
        "external_ref": payload.external_ref,
        "project": payload.project,
        "occurred_at": payload.occurred_at,
        "fields": payload.fields,
    }


__all__ = [
    "HttpTicketBackend",
    "TicketBackend",
    "TicketConnector",
    "TicketPayload",
    "TicketResult",
    "_payload_fields",
    "build_ticket_connector",
    "build_ticket_payload",
]


def _http_error(status: int, retryable: bool, detail: str) -> Exception:
    from app.integrations.base import NonRetryableDeliveryError, RetryableDeliveryError

    message = f"ticketing endpoint returned HTTP {status}: {redact_text(detail, limit=200)}"[:255]
    if retryable:
        return RetryableDeliveryError(message, code=f"http_{status}", status=status)
    return NonRetryableDeliveryError(message, code=f"http_{status}", status=status)


class TicketConnector:
    """Connector wrapper around a :class:`TicketBackend`.

    ``deliver_once`` creates a ticket for a new case/alert and updates the
    existing ticket when the same dedup key was delivered before, so a retried
    dispatch cannot open a duplicate ticket.
    """

    def __init__(
        self,
        backend: TicketBackend,
        *,
        name: str | None = None,
        project: str = "",
        capabilities: tuple[str, ...] = ("case", "test"),
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._backend = backend
        self.name = name or getattr(getattr(backend, "settings", None), "name", "ticket")
        self._project = project or str(getattr(getattr(backend, "settings", None), "project", ""))
        self._capabilities = capabilities
        self._clock = clock
        self._tickets: dict[str, str] = {}

    @property
    def capabilities(self) -> frozenset[str]:
        return frozenset(self._capabilities)

    def describe(self) -> dict[str, Any]:
        backend = self._backend
        describe = getattr(backend, "describe", None)
        payload = dict(describe()) if callable(describe) else {}
        payload.update(
            {
                "name": self.name,
                "kind": "ticket",
                "project": self._project,
                "ticketsTracked": len(self._tickets),
            }
        )
        return payload

    def health(self) -> dict[str, Any]:
        payload = dict(self._backend.health())
        payload["connector"] = self.name
        payload["ticketsTracked"] = len(self._tickets)
        return payload

    def ticket_for(self, dedup_key: str) -> str | None:
        return self._tickets.get(dedup_key)

    def deliver_once(self, event: Notification) -> DeliveryAttempt:
        existing = self._tickets.get(event.dedup_key)
        payload = build_ticket_payload(event, project=self._project, ticket_id=existing)
        result = (
            self._backend.update_ticket(existing, payload)
            if existing
            else self._backend.create_ticket(payload)
        )
        if result.ticket_id:
            self._tickets[event.dedup_key] = result.ticket_id
        return DeliveryAttempt(
            status=None,
            request_summary=summarise_request(event),
            response_summary={
                "ticketId": result.ticket_id,
                "operation": "update" if existing else "create",
                "payloadSha256": hashlib.sha256(
                    json.dumps(payload.as_dict(), ensure_ascii=False, sort_keys=True).encode("utf-8")
                ).hexdigest(),
            },
            deliverable=True,
        )


def build_ticket_connector(
    settings: TicketSettings, *, transport: HttpTransport | None = None
) -> TicketConnector:
    return TicketConnector(
        HttpTicketBackend(settings, transport=transport),
        name=settings.name,
        project=settings.project,
        capabilities=settings.capabilities,
    )
