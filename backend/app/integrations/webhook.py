"""Generic webhook connector: signed JSON POST with retry and circuit breaking.

Design points that matter for a security platform:

* the body is a **redacted** JSON envelope — an integration target never receives
  a raw credential-shaped field;
* the signature is HMAC-SHA256 over ``"<timestamp>.<body>"`` (Stripe-style), so a
  receiver cannot be tricked by a body replay with a fresh timestamp;
* an idempotency key derived from the stable dedup key travels in
  ``X-Evonids-Idempotency-Key`` so a retry collapses on the receiver side;
* the target URL is validated by :mod:`app.integrations.url_guard` before any
  request is made (scheme allow-list, host allow-list, private/loopback/link-local
  and metadata-range refusal);
* redirects are never followed by the real transport, because a redirect to
  ``127.0.0.1`` would bypass the guard.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from typing import Any, Callable
from urllib.parse import urlsplit

from app.integrations.base import (
    DeliveryAttempt,
    DeliveryBlockedError,
    Notification,
    summarise_request,
)
from app.integrations.settings import WebhookSettings
from app.integrations.redaction import redact_mapping, redact_text
from app.integrations.url_guard import (
    HttpTransport,
    HttpxTransport,
    TargetPolicy,
    TransportResponse,
    _resolve as default_resolver,
    validate_target_url,
)

USER_AGENT = "evonids-integrations/0.1.1"
SIGNATURE_VERSION = "v1"
RETRYABLE_STATUSES = frozenset({408, 425, 429, 500, 502, 503, 504})


def sign_payload(secret: str, timestamp: int, body: bytes) -> str:
    """HMAC-SHA256 over ``"<timestamp>.<body>"``, returned as ``v1=<hex>``."""
    signed = f"{timestamp}.".encode("utf-8") + body
    digest = hmac.new(secret.encode("utf-8"), signed, hashlib.sha256).hexdigest()
    return f"{SIGNATURE_VERSION}={digest}"


def build_envelope(event: Notification) -> dict[str, Any]:
    """The JSON document a webhook receiver sees (already redacted)."""
    return {
        "eventType": event.event_type,
        "objectId": event.object_id,
        "title": redact_text(event.title),
        "severity": event.severity,
        "occurredAt": event.occurred_at_iso(),
        "dedupKey": event.dedup_key,
        "capability": event.required_capability,
        "alert": _mapping(event.alert),
        "case": _mapping(event.case),
        "evidence": redact_mapping(list(event.evidence)),
        "tags": redact_mapping(list(event.tags)),
        "metadata": _mapping(event.metadata) or {},
        "source": {"product": "EvoNIDS", "component": "integrations"},
    }


def _mapping(value: Any) -> dict[str, Any] | None:
    """Redact a nested payload before it leaves the process.

    The docstring of :func:`build_envelope` promises redaction, so this must go
    through :func:`redact_mapping` - a shallow copy would ship secrets verbatim.
    """
    if value is None:
        return None
    return redact_mapping({str(key): item for key, item in dict(value).items()})


class WebhookConnector:
    """One webhook target. ``deliver_once`` performs exactly one HTTP POST."""

    def __init__(
        self,
        settings: WebhookSettings,
        *,
        transport: HttpTransport | None = None,
        clock: Callable[[], float] = time.time,
        resolver: Any = None,
    ) -> None:
        self.settings = settings
        self.name = settings.name
        self._transport = transport
        self._clock = clock
        self._policy = TargetPolicy(
            allowed_hosts=settings.allowed_hosts,
            allow_http=settings.allow_http,
        )
        self.calls: list[dict[str, Any]] = []
        # Injectable DNS resolver: production keeps the real one, tests inject a
        # deterministic map so no test can ever perform a network lookup.
        self._resolver = resolver

    # ------------------------------------------------------------- inspection
    @property
    def capabilities(self) -> frozenset[str]:
        return frozenset(self.settings.capabilities)

    @property
    def transport(self) -> HttpTransport:
        if self._transport is None:
            self._transport = HttpxTransport()
        return self._transport

    @property
    def target(self) -> str:
        parts = urlsplit(self.settings.url)
        host = parts.hostname or ""
        if parts.port:
            host = f"{host}:{parts.port}"
        return f"{parts.scheme}://{host}{parts.path}"

    def describe(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "kind": "webhook",
            "target": self.target,
            "signed": bool(self.settings.secret),
            "timeoutSeconds": self.settings.timeout_seconds,
            "maxAttempts": self.settings.max_attempts,
            "allowHttp": self.settings.allow_http,
            "allowedHosts": list(self.settings.allowed_hosts),
        }

    def health(self) -> dict[str, Any]:
        """Configuration health. This connector has no separate probe endpoint.

        A webhook receiver cannot be probed without either delivering a real
        event or inventing one, and inventing one is exactly what this framework
        refuses to do. ``state`` therefore reports whether the connector is
        *usable* (target passes the SSRF guard), and delivery success or failure
        is read from the recorded stats — never guessed.
        """
        try:
            validate_target_url(
                self.settings.url, policy=self._policy, resolver=self._resolver or default_resolver
            )
        except DeliveryBlockedError as error:
            return {
                "connector": self.name,
                "kind": "webhook",
                "state": "misconfigured",
                "reason": f"{error.code}: {error}",
                "probe": "not_attempted",
            }
        return {
            "connector": self.name,
            "kind": "webhook",
            "state": "ok",
            "target": self.target,
            "probe": "not_attempted",
            "note": "未主动探测目标；状态来自配置校验，投递成败见 stats。",
        }

    # --------------------------------------------------------------- delivery
    def _now(self) -> int:
        return int(self._clock())

    def build_headers(self, body: bytes) -> dict[str, str]:
        timestamp = self._now()
        headers = {
            "Content-Type": "application/json; charset=utf-8",
            "User-Agent": USER_AGENT,
            "X-Evonids-Event": "integration",
            "X-Evonids-Timestamp": str(timestamp),
            "X-Evonids-Signature-Version": SIGNATURE_VERSION,
        }
        if self.settings.secret:
            headers["X-Evonids-Signature"] = sign_payload(self.settings.secret, timestamp, body)
        return headers

    def deliver_once(self, event: Notification) -> DeliveryAttempt:
        # Guard first: a refused target must never produce an HTTP call.
        validate_target_url(
            self.settings.url, policy=self._policy, resolver=self._resolver or default_resolver
        )
        payload = build_envelope(event)
        body = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        headers = self.build_headers(body)
        headers["X-Evonids-Idempotency-Key"] = event.dedup_key
        headers["X-Evonids-Dedup-Key"] = event.dedup_key
        self.calls.append({"url": self.settings.url, "headers": dict(headers), "body": body})
        response: TransportResponse = self.transport.send(
            "POST",
            self.settings.url,
            headers=headers,
            body=body,
            timeout=self.settings.timeout_seconds,
        )
        summary = {
            "status": response.status,
            "body": response.text(500),
            "contentType": response.headers.get("content-type"),
        }
        if 200 <= response.status < 300:
            return DeliveryAttempt(
                status=response.status,
                request_summary=summarise_request(event),
                response_summary=summary,
                deliverable=True,
            )
        retryable = response.status in RETRYABLE_STATUSES
        return DeliveryAttempt(
            status=response.status,
            request_summary=summarise_request(event),
            response_summary=summary,
            deliverable=False,
            retryable=retryable,
            error=f"webhook receiver returned HTTP {response.status}"[:255],
            error_code=f"http_{response.status}",
        )
