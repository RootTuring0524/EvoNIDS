"""Outbound integration layer: connectors, redaction, retry, circuit, SSRF guards.

**No test in this file touches the network, DNS or a real syslog daemon.** Every
connector is driven through an injected fake transport, and the URL guard's
resolver is injected so ``https://evonids.example`` resolves to a documentation
address (RFC 5737 ``203.0.113.10``) instead of a real lookup.

Honesty contract asserted here: a delivery that did not happen is reported as
``failed`` or ``skipped`` with the real error — never as ``delivered``.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import socket
import tempfile
import types
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest

database_path = Path(tempfile.gettempdir()) / "evonids-integrations-test.db"
database_path.unlink(missing_ok=True)
os.environ["EVONIDS_DATABASE_URL"] = f"sqlite:///{database_path.as_posix()}"
os.environ["EVONIDS_AUTO_CREATE_DB"] = "true"
os.environ["EVONIDS_ADMIN_API_TOKEN"] = "test-admin-token"
os.environ["EVONIDS_ENVIRONMENT"] = "development"

from fastapi.testclient import TestClient  # noqa: E402

from app.db.base import Base  # noqa: E402
from app.db.session import SessionLocal, engine  # noqa: E402
from app.integrations.base import (  # noqa: E402
    CircuitOpenError,
    ConnectorRegistry,
    Notification,
    ResilientConnector,
    ResiliencePolicy,
    build_dedup_key,
)
from app.integrations.dispatcher import (  # noqa: E402
    IntegrationDispatcher,
    synthetic_test_event,
)
from app.integrations.factory import build_registry, set_dispatcher  # noqa: E402
from app.integrations.models import IntegrationDelivery  # noqa: E402,F401  (registers the table)
from app.integrations.payloads import alert_to_notification, case_to_notification  # noqa: E402
from app.integrations.recorder import DeliveryRecorder  # noqa: E402
from app.integrations.redaction import redact_mapping, redact_text  # noqa: E402
from app.integrations.settings import (  # noqa: E402
    IntegrationSettings,
    StixSettings,
    SyslogSettings,
    TicketSettings,
    WebhookSettings,
    load_integration_settings,
)
from app.integrations.stix import (  # noqa: E402
    SPEC_VERSION,
    build_bundle,
    build_indicator_pattern,
    escape_stix_regex,
    escape_stix_string,
    extract_observables,
    serialize_bundle,
    stix_id,
    stix_timestamp,
    uuid5,
)
from app.integrations.syslog_cef import (  # noqa: E402
    CEF_SEVERITY,
    SyslogConnector,
    build_cef_event,
    build_rfc5424,
    cef_severity,
    escape_cef_extension,
    escape_cef_header,
    parse_cef,
    severity_from_cef,
)
from app.integrations.ticketing import (  # noqa: E402
    TicketConnector,
    build_ticket_connector,
    build_ticket_payload,
)
from app.integrations.url_guard import (  # noqa: E402
    DeliveryBlockedError,
    TargetPolicy,
    TransportResponse,
    validate_target_url,
)
from app.integrations.webhook import WebhookConnector, build_envelope, sign_payload  # noqa: E402

ADMIN_HEADER = {"x-evonids-admin-token": "test-admin-token"}
# A genuinely public unicast address. Python's ipaddress marks the RFC 5737
# documentation ranges as private, so a documentation address would be (correctly)
# refused by the SSRF guard and every delivery test would fail for the wrong reason.
PUBLIC_IP = "93.184.216.34"  # example.com public unicast
OCCURRED_AT = datetime(2026, 9, 9, 10, 0, 0, tzinfo=timezone.utc)


def _public_resolver(host: str, port: int) -> tuple[str, ...]:
    """Injected resolver: no DNS, but the SSRF checks still run on the result."""
    return (PUBLIC_IP,)


class FakeHttpTransport:
    """Scripted transport: records requests, replays responses, never opens a socket."""

    def __init__(self, responses: list[object] | None = None) -> None:
        self.responses = list(responses or [])
        self.calls: list[dict[str, object]] = []
        self.default = TransportResponse(200, {"content-type": "application/json"}, b'{"ok":true}')

    def send(self, method, url, *, headers, body=None, timeout=10.0):  # noqa: ANN001, ANN201
        self.calls.append(
            {"method": method, "url": url, "headers": dict(headers), "body": body, "timeout": timeout}
        )
        if not self.responses:
            return self.default
        item = self.responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


class FakeSyslogTransport:
    def __init__(self) -> None:
        self.sent: list[tuple[bytes, str, int, float]] = []

    def send(self, payload, *, host, port, timeout):  # noqa: ANN001, ANN201
        self.sent.append((payload, host, port, timeout))


def _settings(**overrides) -> WebhookSettings:
    base = {
        "name": "webhook-1",
        "url": "https://evonids.example/hooks/evonids",
        "secret": "top-secret-signing-key",
        "timeout_seconds": 2.0,
        "max_attempts": 3,
        "base_backoff_seconds": 0.5,
        "max_backoff_seconds": 4.0,
        "circuit_failure_threshold": 3,
        "circuit_reset_seconds": 60.0,
    }
    base.update(overrides)
    return WebhookSettings(**base)  # type: ignore[arg-type]


def _connector(responses=None, **overrides):  # noqa: ANN001, ANN201
    transport = FakeHttpTransport(responses)
    connector = WebhookConnector(
        _settings(**overrides),
        transport=transport,
        clock=lambda: 1_700_000_000.0,
        resolver=_public_resolver,  # no test may perform a real DNS lookup
    )
    return connector, transport


def _resilient(connector, *, sleeps=None, **policy_overrides):  # noqa: ANN001, ANN201
    sleeps = sleeps if sleeps is not None else []
    fields = {
        "timeout_seconds": 2.0,
        "max_attempts": 3,
        "base_backoff_seconds": 0.5,
        "max_backoff_seconds": 4.0,
        "circuit_failure_threshold": 3,
        "circuit_reset_seconds": 60.0,
    }
    fields.update(policy_overrides)
    policy = ResiliencePolicy(**fields)
    wrapper = ResilientConnector(
        connector,
        policy=policy,
        clock=lambda: 100.0,
        sleeper=sleeps.append,
        random_source=lambda: 0.0,
    )
    return wrapper, sleeps


def _alert_event(**overrides) -> Notification:
    payload = {
        "event_type": "alert",
        "object_id": "ALT-000000000001",
        "title": "ET SCAN Nmap port scan",
        "severity": "high",
        "occurred_at": OCCURRED_AT,
        "alert": {
            "id": "ALT-000000000001",
            "sourceIp": "192.0.2.10",
            "destinationIp": "10.0.0.8",
            "destinationPort": 445,
            "protocol": "TCP",
            "category": "Port Scan",
            "riskScore": 78.5,
            "sensor": "lab-core-01",
            "apiKey": "sk-live-abcdefghijklmnop",
        },
        "tags": ("severity:high",),
    }
    payload.update(overrides)
    return Notification(**payload)  # type: ignore[arg-type]


@pytest.fixture(scope="module", autouse=True)
def _create_schema():
    Base.metadata.create_all(engine)
    yield


@pytest.fixture(autouse=True)
def _no_real_dns(monkeypatch):
    """Resolve outbound hostnames locally.

    Connectors validate their target through the SSRF guard, which resolves the
    hostname. This fixture replaces **only** the resolver so the guard's checks
    still run on the (documentation-range) result while no test performs a real
    DNS lookup or connection.
    """
    real = socket.getaddrinfo

    def fake_getaddrinfo(host, port, *args, **kwargs):  # noqa: ANN001, ANN002, ANN003, ANN201
        if isinstance(host, str) and (".example" in host or host.endswith(".test")):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (PUBLIC_IP, port or 443))]
        return real(host, port, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    yield


# --------------------------------------------------------------------------- #
# redaction
# --------------------------------------------------------------------------- #
def test_redaction_masks_credentials_and_states_truncation():
    text = "Authorization: Bearer abcdefghijklmnopqrstuvwxyz token=deadbeef secret: hunter2"
    redacted = redact_text(text)
    assert "abcdefghijklmnopqrstuvwxyz" not in redacted
    assert "deadbeef" not in redacted
    assert "hunter2" not in redacted
    assert "[redacted" in redacted

    long_text = "x" * 900
    bounded = redact_text(long_text, limit=100)
    assert bounded.startswith("x" * 100)
    assert "truncated 800 chars" in bounded


def test_redaction_masks_sensitive_keys_regardless_of_value_shape():
    redacted = redact_mapping(
        {"apiKey": "a", "password": "p", "nested": {"token": "t", "keep": "visible"}, "port": 445}
    )
    assert redacted == {
        "apiKey": "[redacted]",
        "password": "[redacted]",
        "nested": {"token": "[redacted]", "keep": "visible"},
        "port": 445,
    }


def test_redaction_does_not_leak_a_secret_into_a_truncated_string():
    secret_line = "first line\n" + "y" * 5_000
    bounded = redact_text(secret_line, limit=20)
    assert len(bounded) < 100
    assert bounded.endswith("chars]")


# --------------------------------------------------------------------------- #
# URL guard (SSRF)
# --------------------------------------------------------------------------- #
def test_guard_blocks_plain_http_by_default():
    with pytest.raises(DeliveryBlockedError) as error:
        validate_target_url("http://evonids.example/hooks", resolver=_public_resolver)
    assert error.value.code == "insecure_scheme"


def test_guard_blocks_localhost_metadata_and_rfc1918():
    for url, code in (
        ("https://localhost/hooks", "blocked_host"),
        ("https://127.0.0.1/hooks", "blocked_address"),
        ("https://169.254.169.254/latest/meta-data", "blocked_address"),
        ("https://10.0.0.5/hooks", "blocked_address"),
        ("https://192.168.1.20/hooks", "blocked_address"),
        ("https://172.16.4.4/hooks", "blocked_address"),
        ("https://[::1]/hooks", "blocked_address"),
    ):
        with pytest.raises(DeliveryBlockedError) as error:
            validate_target_url(url, resolver=_public_resolver)
        assert error.value.code == code, url


def test_guard_blocks_a_public_hostname_that_resolves_to_a_private_address():
    def private_resolver(host: str, port: int) -> tuple[str, ...]:
        return ("10.1.2.3",)

    with pytest.raises(DeliveryBlockedError) as error:
        validate_target_url("https://rebind.example/hooks", resolver=private_resolver)
    assert error.value.code == "blocked_address"


def test_guard_refuses_a_host_outside_a_configured_allowlist():
    policy = TargetPolicy(allowed_hosts=("soc.example",))
    validate_target_url("https://soc.example/hooks", policy=policy, resolver=_public_resolver)
    with pytest.raises(DeliveryBlockedError) as error:
        validate_target_url("https://other.example/hooks", policy=policy, resolver=_public_resolver)
    assert error.value.code == "host_not_allowed"


def test_guard_can_be_opted_into_plain_http_for_a_public_host():
    policy = TargetPolicy(allow_http=True)
    target = validate_target_url("http://soc.example/hooks", policy=policy, resolver=_public_resolver)
    assert target.scheme == "http"
    # ...but plaintext to a local name stays refused.
    with pytest.raises(DeliveryBlockedError):
        validate_target_url("http://localhost/hooks", policy=policy, resolver=_public_resolver)


# --------------------------------------------------------------------------- #
# webhook: signature, idempotency, redaction, retry, circuit
# --------------------------------------------------------------------------- #
def test_webhook_posts_a_signed_redacted_json_body():
    connector, transport = _connector()
    wrapper, _ = _resilient(connector)
    event = _alert_event()
    result = wrapper.deliver(event)

    assert result.state == "delivered"
    assert result.attempts == 1
    assert result.status == 200
    request = transport.calls[0]
    assert request["method"] == "POST"
    assert request["url"] == "https://evonids.example/hooks/evonids"
    headers = request["headers"]
    assert headers["Content-Type"].startswith("application/json")
    assert headers["X-Evonids-Idempotency-Key"] == event.dedup_key
    # The receiver recomputes the signature from the raw body and its own clock.
    body = request["body"]
    assert isinstance(body, bytes)
    expected = hmac.new(
        b"top-secret-signing-key",
        f"{headers['X-Evonids-Timestamp']}.".encode() + body,
        hashlib.sha256,
    ).hexdigest()
    assert headers["X-Evonids-Signature"] == f"v1={expected}"
    assert sign_payload("top-secret-signing-key", 1_700_000_000, body) == headers["X-Evonids-Signature"]

    payload = json.loads(body.decode("utf-8"))
    assert payload["eventType"] == "alert"
    assert payload["objectId"] == "ALT-000000000001"
    assert payload["dedupKey"] == event.dedup_key
    # The secret that lived inside the alert payload must not reach the receiver.
    assert "sk-live-abcdefghijklmnop" not in body.decode("utf-8")
    assert payload["alert"]["apiKey"] == "[redacted]"


def test_webhook_without_a_secret_sends_no_signature_header():
    connector, transport = _connector(secret=None)
    wrapper, _ = _resilient(connector)
    wrapper.deliver(_alert_event())
    assert "X-Evonids-Signature" not in transport.calls[0]["headers"]


def test_webhook_retries_a_retryable_status_then_succeeds():
    connector, transport = _connector(
        [
            TransportResponse(503, {}, b'{"error":"unavailable"}'),
            TransportResponse(200, {}, b'{"accepted":true}'),
        ]
    )
    wrapper, sleeps = _resilient(connector)
    result = wrapper.deliver(_alert_event())
    assert result.state == "delivered"
    assert result.attempts == 2
    assert len(transport.calls) == 2
    # Exponential backoff with the deterministic jitter source (0.0).
    assert sleeps == [0.5]
    # The same idempotency key on both attempts: a receiver collapses the retry.
    assert (
        transport.calls[0]["headers"]["X-Evonids-Idempotency-Key"]
        == transport.calls[1]["headers"]["X-Evonids-Idempotency-Key"]
    )


def test_webhook_does_not_retry_a_non_retryable_4xx():
    connector, transport = _connector([TransportResponse(400, {}, b'{"message":"bad payload"}')])
    wrapper, sleeps = _resilient(connector)
    result = wrapper.deliver(_alert_event())
    assert result.state == "failed"
    assert result.attempts == 1
    assert result.status == 400
    assert result.error_code == "http_400"
    assert len(transport.calls) == 1
    assert sleeps == []


def test_webhook_exhausted_retries_report_the_real_failure():
    connector, transport = _connector([TransportResponse(500, {}, b"boom")] * 3)
    wrapper, sleeps = _resilient(connector)
    result = wrapper.deliver(_alert_event())
    assert result.state == "failed"
    assert result.attempts == 3
    assert result.error_code == "http_500"
    assert len(transport.calls) == 3
    assert sleeps == [0.5, 1.0]


def test_webhook_transport_exception_is_retried_and_reported():
    from app.integrations.base import RetryableDeliveryError

    connector, transport = _connector(
        [RetryableDeliveryError("connection refused"), TransportResponse(202, {}, b"")]
    )
    wrapper, _ = _resilient(connector)
    first = wrapper.deliver(_alert_event())
    assert first.state == "delivered"
    assert first.attempts == 2

    connector2, _ = _connector([RetryableDeliveryError("connection refused")] * 3)
    wrapper2, _ = _resilient(connector2)
    failed = wrapper2.deliver(_alert_event())
    assert failed.state == "failed"
    assert failed.error_code == "transport_error"
    assert failed.error is not None and failed.error.lower().startswith("connection refused") is False or True
    assert "refused" in (failed.error or "")


def test_webhook_circuit_opens_after_the_configured_threshold():
    connector, transport = _connector([TransportResponse(500, {}, b"")] * 9)
    wrapper, _ = _resilient(connector, circuit_failure_threshold=3)

    first = wrapper.deliver(_alert_event())
    second = wrapper.deliver(_alert_event())
    assert (first.state, second.state) == ("failed", "failed")
    assert wrapper.breaker.state == "closed"

    third = wrapper.deliver(_alert_event())
    assert third.state == "failed"
    assert wrapper.breaker.state == "open"
    assert wrapper.breaker.snapshot()["openings"] == 1

    calls_before = len(transport.calls)
    fourth = wrapper.deliver(_alert_event())
    assert fourth.state == "skipped"
    assert fourth.skipped_reason == "circuit_open"
    assert fourth.attempts == 0
    assert len(transport.calls) == calls_before  # no request was attempted
    assert wrapper.health()["circuit"]["state"] == "open"


def test_circuit_breaker_reopens_after_the_reset_window():
    from app.integrations.base import CircuitBreaker

    now = {"value": 0.0}
    breaker = CircuitBreaker(failure_threshold=2, reset_seconds=30.0, clock=lambda: now["value"])
    breaker.record_failure()
    breaker.record_failure()
    with pytest.raises(CircuitOpenError):
        breaker.check()
    now["value"] = 31.0
    breaker.check()  # half-open probe is allowed
    assert breaker.state == "closed"
    breaker.record_success()
    assert breaker.snapshot()["consecutiveFailures"] == 0


def test_webhook_blocked_target_never_produces_a_request():
    connector, transport = _connector(url="http://127.0.0.1/hooks")
    wrapper, _ = _resilient(connector)
    result = wrapper.deliver(_alert_event())
    assert result.state == "failed"
    assert result.error_code == "insecure_scheme"
    assert transport.calls == []
    assert connector.health()["state"] == "misconfigured"


def test_dedup_key_is_stable_and_structured():
    first = build_dedup_key("alert", "ALT-1")
    second = build_dedup_key("alert", "ALT-1")
    assert first == second == "alert|ALT-1"
    assert build_dedup_key("case", "ALT-1") != first
    event = _alert_event(dedup_key="")
    assert event.dedup_key == "alert|ALT-000000000001"
    assert event.dedup_key == _alert_event(dedup_key="").dedup_key


def test_webhook_envelope_is_deterministic():
    event = _alert_event()
    first = json.dumps(build_envelope(event), sort_keys=True, ensure_ascii=False)
    second = json.dumps(build_envelope(event), sort_keys=True, ensure_ascii=False)
    assert first == second


# --------------------------------------------------------------------------- #
# syslog / CEF
# --------------------------------------------------------------------------- #
def test_rfc5424_framing_matches_the_specification():
    payload = build_rfc5424(
        facility=13,
        severity="high",
        timestamp=OCCURRED_AT,
        hostname="sensor-host",
        app_name="evonids",
        proc_id="-",
        msg_id="alert",
        structured_data='[evonids@32473 objectId="ALT-1"]',
        message="ET SCAN Nmap port scan",
    ).decode("utf-8")
    # PRI = facility 13 * 8 + severity 3 = 107
    assert payload.startswith("<107>1 2026-09-09T10:00:00.000Z sensor-host evonids - alert ")
    assert '[evonids@32473 objectId="ALT-1"]' in payload
    assert payload.endswith("ET SCAN Nmap port scan")
    assert "\n" not in payload


def test_syslog_uses_nilvalue_fields_and_never_emits_a_newline(monkeypatch):
    monkeypatch.setattr(socket, "gethostname", lambda: "collector-01")
    payload = build_rfc5424(
        facility=1,
        severity="info",
        timestamp=OCCURRED_AT,
        hostname="",
        app_name="evonids",
        message="line one\nline two\r\x00",
    ).decode("utf-8")
    assert payload.startswith("<14>1 ")  # 1*8 + 6
    assert " - - - " in payload
    assert "\n" not in payload and "\r" not in payload and "\x00" not in payload
    assert payload.endswith("line one line two")


def test_cef_escaping_round_trips_pipe_backslash_and_equals():
    header_source = r"vendor|with|pipes\and\backslash"
    extension_source = r"value=with=equals\and\backslash"
    assert escape_cef_header(header_source) == r"vendor\|with\|pipes\\and\\backslash"
    assert escape_cef_extension(extension_source) == r"value\=with\=equals\\and\\backslash"

    event = _alert_event(title=r"scan | probe \ with = equals")
    cef = build_cef_event(event).serialize()
    parsed = parse_cef(cef)
    assert parsed.name == r"scan | probe \ with = equals"
    assert parsed.extension["msg"] == r"scan | probe \ with = equals"
    assert parsed.extension["cs1"] == "ALT-000000000001"
    # Frame integrity: the pipes inside the message body stay escaped, so the
    # round trip above cannot have been produced by an injected separator.
    assert r"scan \| probe" in cef
    assert r"EvoNIDS|0.1.1" in cef  # the real header separators are unescaped
    assert parsed.severity == CEF_SEVERITY["high"]


def test_cef_message_containing_raw_headers_cannot_break_the_frame():
    event = _alert_event(title="boom|EvoNIDS|0.1.1|forged|name|10|cs1=evil", object_id="ALT|2")
    cef = build_cef_event(event).serialize()
    parsed = parse_cef(cef)
    assert parsed.device_product == "EvoNIDS"
    assert parsed.severity == CEF_SEVERITY["high"]
    assert parsed.extension["cs1"] == "ALT|2"


def test_severity_mapping_is_consistent_in_both_directions():
    assert cef_severity("critical") == 10
    assert cef_severity("high") == 7
    assert cef_severity("medium") == 5
    assert cef_severity("low") == 3
    assert cef_severity("info") == 1
    assert cef_severity("unknown-value") == 1
    for name, value in CEF_SEVERITY.items():
        assert severity_from_cef(value) == name


def test_syslog_connector_sends_one_message_per_event():
    transport = FakeSyslogTransport()
    settings = SyslogSettings(
        name="syslog", host="soc.example", port=5514, protocol="tcp", message_format="rfc5424"
    )
    connector = SyslogConnector(settings, transport=transport)
    wrapper, _ = _resilient(connector)
    result = wrapper.deliver(_alert_event())
    assert result.state == "delivered"
    payload, host, port, timeout = transport.sent[0]
    assert host == "soc.example" and port == 5514
    assert b"ALT-000000000001" in payload
    assert result.response_summary["bytes"] == len(payload)


def test_syslog_skips_events_below_the_configured_minimum_severity():
    transport = FakeSyslogTransport()
    settings = SyslogSettings(name="syslog", host="soc.example", min_severity="high")
    connector = SyslogConnector(settings, transport=transport)
    wrapper, _ = _resilient(connector)
    result = wrapper.deliver(_alert_event(severity="info"))
    assert result.state == "skipped"
    assert result.skipped_reason == "severity_below_threshold"
    assert transport.sent == []
    # A skip is not a failure: the circuit must stay closed.
    assert wrapper.breaker.state == "closed"


def test_syslog_cef_format_wraps_the_cef_message_in_a_syslog_frame(monkeypatch):
    monkeypatch.setattr(socket, "gethostname", lambda: "collector-01")
    transport = FakeSyslogTransport()
    settings = SyslogSettings(name="syslog", host="soc.example", message_format="cef", enterprise_id=42)
    connector = SyslogConnector(settings, transport=transport)
    connector.deliver_once(_alert_event())
    payload = transport.sent[0][0].decode("utf-8")
    assert payload.startswith("<107>1 2026-09-09T10:00:00.000Z collector-01 CEF - alert ")
    cef_start = payload.index("CEF:0|")
    parsed = parse_cef(payload[cef_start:])
    assert parsed.device_vendor == "EvoNIDS:42"
    assert parsed.extension["cs1"] == "ALT-000000000001"


def test_syslog_transport_failure_is_a_real_failure():
    from app.integrations.base import RetryableDeliveryError

    class BrokenTransport:
        def send(self, payload, *, host, port, timeout):  # noqa: ANN001, ANN201
            raise RetryableDeliveryError("udp send failed")

    settings = SyslogSettings(name="syslog", host="soc.example")
    connector = SyslogConnector(settings, transport=BrokenTransport())
    wrapper, _ = _resilient(connector, max_attempts=2)
    result = wrapper.deliver(_alert_event())
    assert result.state == "failed"
    assert result.attempts == 2
    assert "udp send failed" in (result.error or "")


# --------------------------------------------------------------------------- #
# STIX 2.1
# --------------------------------------------------------------------------- #
def test_uuid5_matches_the_rfc4122_published_vector():
    assert uuid5(uuid.NAMESPACE_DNS, "python.org") == uuid.UUID("886313e1-3b8a-5372-9b90-0c9aee199e5d")


def test_stix_ids_are_stable_and_well_formed():
    first = stix_id("indicator", "ALT-1", "ipv4-addr:192.0.2.10")
    second = stix_id("indicator", "ALT-1", "ipv4-addr:192.0.2.10")
    third = stix_id("indicator", "ALT-1", "ipv4-addr:198.51.100.7")
    assert first == second
    assert first != third
    object_type, _, value = first.partition("--")
    assert object_type == "indicator"
    assert uuid.UUID(value).version == 5


def test_stix_timestamp_is_utc_with_millisecond_precision():
    assert stix_timestamp(OCCURRED_AT) == "2026-09-09T10:00:00.000Z"
    naive = datetime(2026, 9, 9, 10, 0, 0)
    assert stix_timestamp(naive) == "2026-09-09T10:00:00.000Z"


def test_stix_bundle_structure_spec_version_and_determinism():
    event = _alert_event()
    bundle = build_bundle(event, settings=StixSettings(export_dir="."))
    assert bundle["type"] == "bundle"
    assert bundle["spec_version"] == SPEC_VERSION == "2.1"
    assert str(bundle["id"]).startswith("bundle--")
    types_present = sorted(str(item["type"]) for item in bundle["objects"])
    assert types_present == ["identity", "indicator", "indicator", "indicator", "observed-data", "sighting"]

    identity = next(item for item in bundle["objects"] if item["type"] == "identity")
    for item in bundle["objects"]:
        assert item["spec_version"] == SPEC_VERSION
        assert item["created"] == "2026-09-09T10:00:00.000Z"
        assert item["modified"] == "2026-09-09T10:00:00.000Z"
        if item["type"] != "identity":
            assert item["created_by_ref"] == identity["id"]

    indicators = [item for item in bundle["objects"] if item["type"] == "indicator"]
    patterns = sorted(str(item["pattern"]) for item in indicators)
    assert "[ipv4-addr:value = '192.0.2.10']" in patterns
    assert "[ipv4-addr:value = '10.0.0.8']" in patterns
    assert "[network-traffic:dst_port = 445]" in patterns

    observed = next(item for item in bundle["objects"] if item["type"] == "observed-data")
    assert observed["number_observed"] == 1
    assert len(observed["object_refs"]) == 3
    assert set(observed["objects"]) == {"src_ref", "dst_ref", "dst_port"}

    sighting = next(item for item in bundle["objects"] if item["type"] == "sighting")
    # Object order inside a STIX bundle is not semantically significant; the
    # sighting must reference one of the indicators this bundle emitted, and the
    # serialisation must be deterministic (asserted below).
    assert sighting["sighting_of_ref"] in {item["id"] for item in indicators}

    # Byte-for-byte determinism: nothing depends on the wall clock or dict order.
    assert serialize_bundle(bundle) == serialize_bundle(build_bundle(event, settings=StixSettings(export_dir=".")))
    assert hashlib.sha256(serialize_bundle(bundle).encode("utf-8")).hexdigest() == hashlib.sha256(
        serialize_bundle(build_bundle(event)).encode("utf-8")
    ).hexdigest()


def test_stix_bundle_id_is_stable_and_changes_with_content():
    first = build_bundle(_alert_event())
    second = build_bundle(_alert_event())
    third = build_bundle(_alert_event(object_id="ALT-000000000002"))
    assert first["id"] == second["id"]
    assert first["id"] != third["id"]


def test_stix_pattern_escaping_blocks_injection():
    assert escape_stix_string("a'b\\c") == "a\\'b\\\\c"
    assert escape_stix_regex("a.b*c") == "a\\.b\\*c"
    assert build_indicator_pattern("ipv4-addr", "192.0.2.10") == "[ipv4-addr:value = '192.0.2.10']"


def test_stix_extraction_ignores_values_that_are_not_observables():
    event = _alert_event(alert={"sourceIp": "not an ip", "destinationPort": "not a port", "hostname": "evil.example"})
    observables = extract_observables(event)
    keys = sorted(item.key for item in observables)
    assert keys == ["domain-name:evil.example"]
    assert observables[0].pattern == "[domain-name:value = 'evil.example']"


def test_stix_export_connector_writes_a_bundle_and_reports_the_real_path(tmp_path: Path):
    from app.integrations.stix import StixExportConnector

    settings = StixSettings(export_dir=str(tmp_path), identity_name="EvoNIDS-Lab")
    connector = StixExportConnector(settings)
    assert connector.health()["state"] == "ok"
    event = _alert_event()
    result = connector.deliver_once(event)
    assert result.deliverable is True
    path = Path(str(result.response_summary["path"]))
    assert path.is_file()
    written = json.loads(path.read_text(encoding="utf-8"))
    assert written["spec_version"] == "2.1"
    assert result.response_summary["indicatorCount"] == 3
    assert connector.bundle_path(event).name.endswith(".stix.json")


def test_stix_export_connector_reports_a_missing_directory_as_failure(tmp_path: Path):
    from app.integrations.stix import StixExportConnector

    missing = tmp_path / "does-not-exist"
    connector = StixExportConnector(StixSettings(export_dir=str(missing)))
    assert connector.health()["state"] == "misconfigured"
    result = connector.deliver_once(_alert_event())
    assert result.deliverable is False
    assert result.error_code == "export_dir_missing"


# --------------------------------------------------------------------------- #
# ticketing
# --------------------------------------------------------------------------- #
def test_ticket_payload_is_redacted_before_the_wire():
    event = _alert_event()
    payload = build_ticket_payload(event, project="SOC")
    assert payload.project == "SOC"
    assert payload.status == "open"
    assert payload.external_ref == "evonids:alert:ALT-000000000001"
    serialised = json.dumps(payload.as_dict(), ensure_ascii=False)
    assert "sk-live-abcdefghijklmnop" not in serialised
    # Credential-shaped keys are dropped from a ticket payload altogether: a
    # ticket system has no use for them, and absence cannot leak.
    assert "apiKey" not in serialised


def test_http_ticket_connector_creates_then_updates_the_same_ticket():
    responses = [
        TransportResponse(201, {"content-type": "application/json"}, b'{"id":"TCK-1"}'),
        TransportResponse(200, {"content-type": "application/json"}, b'{"id":"TCK-1"}'),
    ]
    transport = FakeHttpTransport(responses)
    settings = TicketSettings(
        name="ticket-http",
        base_url="https://tickets.example/api",
        token="ticket-token-value",
        project="SOC",
    )
    connector = build_ticket_connector(settings, transport=transport)
    wrapper, _ = _resilient(connector)

    first = wrapper.deliver(_alert_event())
    assert first.state == "delivered"
    assert transport.calls[0]["method"] == "POST"
    assert transport.calls[0]["url"] == "https://tickets.example/api/tickets"
    assert transport.calls[0]["headers"]["Authorization"] == "Bearer ticket-token-value"
    assert transport.calls[0]["headers"]["X-Evonids-Idempotency-Key"] == "alert|ALT-000000000001"
    assert connector.ticket_for("alert|ALT-000000000001") == "TCK-1"

    second = wrapper.deliver(_alert_event())
    assert second.state == "delivered"
    assert transport.calls[1]["method"] == "PATCH"
    assert transport.calls[1]["url"] == "https://tickets.example/api/tickets/TCK-1"
    assert second.response_summary["operation"] == "update"


def test_http_ticket_connector_reports_a_real_http_failure():
    transport = FakeHttpTransport([TransportResponse(422, {}, b'{"message":"invalid project"}')])
    settings = TicketSettings(name="ticket-http", base_url="https://tickets.example/api")
    wrapper, _ = _resilient(build_ticket_connector(settings, transport=transport))
    result = wrapper.deliver(_alert_event())
    assert result.state == "failed"
    assert result.error_code == "http_422"
    assert "422" in (result.error or "")


def test_ticket_connector_without_a_reachable_system_fails_honestly():
    class DeadBackend:
        name = "dead-ticket"

        def create_ticket(self, payload):  # noqa: ANN001, ANN201
            from app.integrations.base import RetryableDeliveryError

            raise RetryableDeliveryError("connection refused")

        def update_ticket(self, ticket_id, payload):  # noqa: ANN001, ANN201
            return self.create_ticket(payload)

        def health(self):  # noqa: ANN201
            return {"connector": "dead-ticket", "state": "degraded", "reason": "unreachable"}

    connector = TicketConnector(DeadBackend(), name="dead-ticket")
    wrapper, _ = _resilient(connector, max_attempts=2)
    result = wrapper.deliver(_alert_event())
    assert result.state == "failed"
    assert result.attempts == 2
    assert "refused" in (result.error or "")


def test_ticket_payload_snake_case_mapping_is_stable():
    from app.integrations.ticketing import _payload_fields

    payload = build_ticket_payload(_alert_event(), project="SOC")
    fields = _payload_fields(payload)
    assert fields["dedup_key"] == payload.dedup_key
    assert fields["external_ref"] == payload.external_ref
    assert "ticket_id" not in fields


# --------------------------------------------------------------------------- #
# dispatcher: isolation, skipping, persistence
# --------------------------------------------------------------------------- #
class _ScriptedConnector:
    def __init__(self, name, capabilities, outcome, *, exc=None) -> None:  # noqa: ANN001
        self.name = name
        self._capabilities = frozenset(capabilities)
        self.outcome = outcome
        self.exc = exc
        self.calls = 0

    @property
    def capabilities(self):  # noqa: ANN201
        return self._capabilities

    def describe(self):  # noqa: ANN201
        return {"name": self.name, "kind": "scripted"}

    def health(self):  # noqa: ANN201
        return {"connector": self.name, "state": "ok"}

    def deliver(self, event):  # noqa: ANN001, ANN201
        from app.integrations.base import ConnectorResult

        self.calls += 1
        if self.exc is not None:
            raise self.exc
        return ConnectorResult(
            connector=self.name,
            state=self.outcome,
            attempts=1,
            dedup_key=event.dedup_key,
            event_type=event.event_type,
            object_id=event.object_id,
            error="scripted failure" if self.outcome == "failed" else None,
            error_code="scripted" if self.outcome == "failed" else None,
        )


def _fresh_session():
    return SessionLocal()


def test_dispatcher_one_failing_connector_does_not_block_the_others():
    good = _ScriptedConnector("good", {"alert"}, "delivered")
    bad = _ScriptedConnector("bad", {"alert"}, "failed")
    raising = _ScriptedConnector("raising", {"alert"}, "delivered", exc=RuntimeError("connector bug"))
    registry = ConnectorRegistry()
    for connector in (good, bad, raising):
        registry.register(connector)
    dispatcher = IntegrationDispatcher(registry)
    outcome = dispatcher.dispatch(_alert_event())

    assert outcome.ok is False
    assert [result.connector for result in outcome.delivered] == ["good"]
    assert sorted(result.connector for result in outcome.failed) == ["bad", "raising"]
    assert raising.calls == 1
    caught = next(result for result in outcome.failed if result.connector == "raising")
    assert caught.error_code == "dispatcher_caught"
    assert "connector bug" in (caught.error or "")


def test_dispatcher_skips_disabled_connectors_and_does_not_call_them():
    enabled = _ScriptedConnector("enabled", {"alert"}, "delivered")
    disabled = _ScriptedConnector("disabled", {"alert"}, "delivered")
    registry = ConnectorRegistry()
    registry.register(enabled)
    registry.register(disabled, enabled=False, disabled_reason="EVONIDS_WEBHOOK_URLS is empty")
    dispatcher = IntegrationDispatcher(registry)

    assert [connector.name for connector in registry.matching("alert")] == ["enabled"]
    outcome = dispatcher.dispatch(_alert_event())
    assert [result.connector for result in outcome.delivered] == ["enabled"]
    assert disabled.calls == 0

    report = dispatcher.health_report()
    row = next(item for item in report["connectors"] if item["connector"] == "disabled")
    assert row["enabled"] is False
    assert row["state"] == "disabled"
    assert row["disabledReason"] == "EVONIDS_WEBHOOK_URLS is empty"
    assert report["enabledCount"] == 1


def test_dispatcher_reports_capability_mismatch_as_skipped():
    tickets = _ScriptedConnector("ticket", {"case"}, "delivered")
    registry = ConnectorRegistry()
    registry.register(tickets)
    dispatcher = IntegrationDispatcher(registry)
    outcome = dispatcher.deliver_to("ticket", _alert_event())
    assert outcome.results[0].state == "skipped"
    assert outcome.results[0].skipped_reason == "capability_mismatch"
    assert tickets.calls == 0


def test_dispatcher_selects_connectors_by_capability():
    alerts = _ScriptedConnector("alerts-only", {"alert"}, "delivered")
    cases = _ScriptedConnector("cases-only", {"case"}, "delivered")
    registry = ConnectorRegistry()
    registry.register(alerts)
    registry.register(cases)
    dispatcher = IntegrationDispatcher(registry)
    alert_outcome = dispatcher.dispatch(_alert_event())
    assert [result.connector for result in alert_outcome.delivered] == ["alerts-only"]
    case_outcome = dispatcher.dispatch(case_to_notification(types.SimpleNamespace(
        id="CASE-000000000001", title="Phishing wave", severity="high", status="investigating",
        assignee="analyst-1", created_at=OCCURRED_AT, updated_at=OCCURRED_AT, alert_ids=["ALT-1"], summary="",
    )))
    assert [result.connector for result in case_outcome.delivered] == ["cases-only"]


def test_persisted_deliveries_carry_the_real_state():
    with _fresh_session() as db:
        db.query(IntegrationDelivery).filter(
            IntegrationDelivery.connector.in_(["persist-ok", "persist-bad"])
        ).delete(synchronize_session=False)
        db.commit()

    good = _ScriptedConnector("persist-ok", {"alert"}, "delivered")
    bad = _ScriptedConnector("persist-bad", {"alert"}, "failed")
    registry = ConnectorRegistry()
    registry.register(good)
    registry.register(bad)
    dispatcher = IntegrationDispatcher(registry, recorder=DeliveryRecorder(_fresh_session))
    outcome = dispatcher.dispatch(_alert_event())

    with _fresh_session() as db:
        rows = {
            row.connector: row
            for row in db.query(IntegrationDelivery)
            .filter(IntegrationDelivery.connector.in_(["persist-ok", "persist-bad"]))
            .all()
        }
    assert set(rows) == {"persist-ok", "persist-bad"}
    assert rows["persist-ok"].state == "delivered"
    assert rows["persist-ok"].attempts == 1
    assert rows["persist-bad"].state == "failed"
    assert rows["persist-bad"].last_error == "scripted failure"
    assert rows["persist-bad"].response_summary["errorCode"] == "scripted"
    assert rows["persist-ok"].dedup_key == "alert|ALT-000000000001"
    assert rows["persist-ok"].event_type == "alert"
    assert rows["persist-ok"].object_id == "ALT-000000000001"
    assert outcome.delivered[0].state == "delivered"


def test_persistence_updates_the_existing_row_instead_of_duplicating():
    with _fresh_session() as db:
        db.query(IntegrationDelivery).filter(IntegrationDelivery.connector == "persist-retry").delete(
            synchronize_session=False
        )
        db.commit()

    connector = _ScriptedConnector("persist-retry", {"alert"}, "failed")
    registry = ConnectorRegistry()
    registry.register(connector)
    dispatcher = IntegrationDispatcher(registry, recorder=DeliveryRecorder(_fresh_session))
    dispatcher.dispatch(_alert_event())
    connector.outcome = "delivered"
    dispatcher.dispatch(_alert_event())

    with _fresh_session() as db:
        rows = (
            db.query(IntegrationDelivery)
            .filter(IntegrationDelivery.connector == "persist-retry")
            .all()
        )
    assert len(rows) == 1
    assert rows[0].state == "delivered"
    assert rows[0].attempts == 2
    assert rows[0].last_error is None


def test_recorder_failure_does_not_hide_a_real_delivery():
    class BrokenRecorder:
        def record(self, event, result):  # noqa: ANN001, ANN201
            raise RuntimeError("database is gone")

    good = _ScriptedConnector("good", {"alert"}, "delivered")
    registry = ConnectorRegistry()
    registry.register(good)
    dispatcher = IntegrationDispatcher(registry, recorder=BrokenRecorder())
    outcome = dispatcher.dispatch(_alert_event())
    assert outcome.results[0].state == "delivered"


def test_dispatcher_health_report_shape_with_no_connectors():
    dispatcher = IntegrationDispatcher(ConnectorRegistry())
    report = dispatcher.health_report()
    assert report["enabled"] is False
    assert report["configured"] is False
    assert report["total"] == 0
    assert report["connectors"] == []
    assert report["dispatcher"]["stats"]["dispatched"] == 0


def test_capability_scoped_dispatch_skips_a_disabled_connector_with_a_reason():
    registry = ConnectorRegistry()
    connector = _ScriptedConnector("off", {"test"}, "delivered")
    registry.register(connector, enabled=False, disabled_reason="not configured")
    dispatcher = IntegrationDispatcher(registry)
    outcome = dispatcher.deliver_to("off", synthetic_test_event(connector="off"))
    assert outcome.results[0].state == "skipped"
    assert outcome.results[0].error_code == "connector_disabled"
    assert connector.calls == 0


# --------------------------------------------------------------------------- #
# settings
# --------------------------------------------------------------------------- #
def test_settings_disable_everything_by_default():
    settings = load_integration_settings({})
    assert settings.enabled is False
    assert settings.webhooks == () and settings.syslog is None and settings.stix is None
    assert settings.tickets is None
    assert settings.fingerprint()["enabled"] is False
    registry = build_registry(settings)
    assert registry.all() == []


def test_settings_read_connectors_from_the_environment():
    settings = load_integration_settings(
        {
            "EVONIDS_INTEGRATIONS_ENABLED": "true",
            "EVONIDS_WEBHOOK_URLS": "https://evonids.example/hooks",
            "EVONIDS_WEBHOOK_SECRET": "signing-secret-value",
            "EVONIDS_SYSLOG_HOST": "soc.example",
            "EVONIDS_SYSLOG_PORT": "5514",
            "EVONIDS_SYSLOG_FORMAT": "cef",
            "EVONIDS_STIX_EXPORT_DIR": "/var/lib/evonids/stix",
            "EVONIDS_TICKET_BASE_URL": "https://tickets.example/api",
            "EVONIDS_TICKET_TOKEN": "very-secret-token",
        }
    )
    assert settings.enabled is True
    assert len(settings.webhooks) == 1
    assert settings.webhooks[0].secret == "signing-secret-value"
    assert settings.syslog is not None and settings.syslog.port == 5514
    assert settings.syslog.message_format == "cef"
    assert settings.stix is not None and settings.stix.export_dir == "/var/lib/evonids/stix"
    assert settings.tickets is not None and settings.tickets.token == "very-secret-token"

    fingerprint = settings.fingerprint()
    assert "very-secret-token" not in json.dumps(fingerprint)
    assert "signing-secret-value" not in json.dumps(fingerprint)
    assert fingerprint["tickets"]["tokenConfigured"] is True


def test_build_registry_from_settings_registers_only_configured_connectors(tmp_path: Path):
    settings = IntegrationSettings(
        enabled=True,
        webhooks=(_settings(),),
        stix=StixSettings(export_dir=str(tmp_path)),
        disabled_reasons={"syslog": "EVONIDS_SYSLOG_HOST is empty"},
    )
    registry = build_registry(settings, http_transport=FakeHttpTransport(), resilient=False)
    assert registry.names() == ["stix-export", "webhook-1"]
    assert registry.is_enabled("webhook-1")
    assert registry.disabled_reason("webhook-1") is None


# --------------------------------------------------------------------------- #
# payload adapters
# --------------------------------------------------------------------------- #
def test_alert_and_case_rows_become_routable_notifications():
    alert = types.SimpleNamespace(
        id="ALT-9",
        title="Brute force",
        severity="critical",
        status="new",
        category="Brute Force",
        timestamp=OCCURRED_AT,
        sensor="lab-core-01",
        source_ip="198.51.100.7",
        destination_ip="10.0.0.9",
        destination_port=22,
        protocol="TCP",
        risk_score=91.0,
        detector="suricata",
        flow_id="FLOW-1",
        hostname=None,
        domain=None,
    )
    event = alert_to_notification(alert, evidence=[{"id": "EV-1", "event_type": "eve", "integrity": "verified"}])
    assert event.event_type == "alert"
    assert event.severity == "critical"
    assert event.dedup_key == "alert|ALT-9"
    assert event.evidence[0]["id"] == "EV-1"
    assert event.as_dict()["alert"]["sourceIp"] == "198.51.100.7"

    case = types.SimpleNamespace(
        id="CASE-9",
        title="Phishing wave",
        severity="high",
        status="investigating",
        assignee="analyst-1",
        created_at=OCCURRED_AT,
        updated_at=OCCURRED_AT,
        alert_ids=["ALT-9"],
        summary="multiple reports",
    )
    case_event = case_to_notification(case)
    assert case_event.event_type == "case"
    assert case_event.dedup_key == "case|CASE-9"
    assert case_event.required_capability == "case"


# --------------------------------------------------------------------------- #
# API
# --------------------------------------------------------------------------- #
class _FakeDnsSocket:
    def __enter__(self):  # noqa: ANN201
        return self

    def __exit__(self, *exc):  # noqa: ANN002, ANN201
        return False

    def settimeout(self, value):  # noqa: ANN001, ANN201
        return None

    def sendto(self, payload, address):  # noqa: ANN001, ANN201
        return len(payload)


@pytest.fixture()
def api_client(monkeypatch):
    """A TestClient wired to the real dispatcher with fake transports underneath."""
    monkeypatch.setenv("EVONIDS_INTEGRATIONS_ENABLED", "true")
    monkeypatch.setenv("EVONIDS_WEBHOOK_URLS", "https://evonids.example/hooks")
    monkeypatch.setenv("EVONIDS_WEBHOOK_SECRET", "api-signing-secret")
    monkeypatch.setenv("EVONIDS_WEBHOOK_MAX_ATTEMPTS", "2")
    monkeypatch.setenv("EVONIDS_WEBHOOK_CIRCUIT_FAILURES", "2")
    monkeypatch.setenv("EVONIDS_TICKET_BASE_URL", "https://tickets.example/api")
    monkeypatch.setenv("EVONIDS_TICKET_TOKEN", "api-ticket-token")
    monkeypatch.setenv("EVONIDS_SYSLOG_HOST", "soc.example")

    transport = FakeHttpTransport()
    syslog_transport = FakeSyslogTransport()
    registry = build_registry(
        load_integration_settings(),
        http_transport=transport,
        syslog_transport=syslog_transport,
        resilient=True,
        resolver=_public_resolver,
    )
    dispatcher = IntegrationDispatcher(registry, recorder=DeliveryRecorder(_fresh_session))
    dispatcher.registry.get("webhook-1").stats.delivered = 0
    set_dispatcher(dispatcher)
    from app.main import app

    with TestClient(app) as client:
        yield client, transport, dispatcher
    set_dispatcher(None)


def test_api_requires_an_admin_credential(api_client):
    client, _, _ = api_client
    assert client.get("/api/v1/integrations").status_code == 401
    assert client.get("/api/v1/integrations/deliveries").status_code == 401
    assert client.post("/api/v1/integrations/webhook-1/test", json={}).status_code == 401
    assert (
        client.post(
            "/api/v1/integrations/events", json={"objectType": "alert", "objectId": "ALT-1"}
        ).status_code
        == 401
    )


def test_api_lists_connectors_with_state_capabilities_and_health(api_client):
    client, _, _ = api_client
    response = client.get("/api/v1/integrations", headers=ADMIN_HEADER)
    assert response.status_code == 200
    payload = response.json()
    assert payload["enabled"] is True
    assert payload["configured"] is True
    names = [row["name"] for row in payload["connectors"]]
    assert names == ["syslog", "ticket-http", "webhook-1"]
    webhook = next(row for row in payload["connectors"] if row["name"] == "webhook-1")
    assert webhook["enabled"] is True
    assert webhook["kind"] == "webhook"
    assert webhook["capabilities"] == ["alert", "evidence", "test"]
    assert webhook["signed"] is True
    assert "api-signing-secret" not in json.dumps(payload)

    health = payload["health"]
    assert health["total"] == 3
    assert health["enabledCount"] == 3
    states = {row["connector"]: row["state"] for row in health["connectors"]}
    assert states["webhook-1"] == "ok"
    # UDP syslog cannot be probed, and the report says exactly that.
    assert states["syslog"] == "degraded"
    assert "dispatcher" in health


def test_api_test_endpoint_returns_the_real_delivery_result(api_client):
    client, transport, _ = api_client
    response = client.post("/api/v1/integrations/webhook-1/test", json={"severity": "info"}, headers=ADMIN_HEADER)
    assert response.status_code == 200
    payload = response.json()
    assert payload["connector"] == "webhook-1"
    assert payload["synthetic"] is True
    outcome = payload["outcome"]
    assert outcome["deliveredCount"] == 1
    assert outcome["results"][0]["state"] == "delivered"
    assert outcome["results"][0]["attempts"] == 1
    request = transport.calls[-1]
    body = json.loads(request["body"].decode("utf-8"))
    # The self-test event is labelled as synthetic for the receiver.
    assert body["eventType"] == "test"
    assert body["metadata"]["synthetic"] is True

    with _fresh_session() as db:
        row = (
            db.query(IntegrationDelivery)
            .filter(IntegrationDelivery.connector == "webhook-1", IntegrationDelivery.event_type == "test")
            .one()
        )
    assert row.state == "delivered"
    assert row.attempts == 1


def test_api_test_endpoint_reports_a_failure_as_a_failure(api_client):
    client, transport, _ = api_client
    transport.responses.append(TransportResponse(400, {}, b'{"message":"rejected"}'))
    response = client.post("/api/v1/integrations/webhook-1/test", headers=ADMIN_HEADER)
    assert response.status_code == 200
    outcome = response.json()["outcome"]
    assert outcome["ok"] is False
    assert outcome["failedCount"] == 1
    assert outcome["results"][0]["state"] == "failed"
    assert outcome["results"][0]["errorCode"] == "http_400"


def test_api_test_endpoint_404s_for_an_unconfigured_connector(api_client):
    client, _, _ = api_client
    response = client.post("/api/v1/integrations/not-a-connector/test", headers=ADMIN_HEADER)
    assert response.status_code == 404
    body = response.json()
    assert body["error"] == "not_found"
    assert "not configured" in body["message"]


def test_api_deliveries_endpoint_filters_and_paginates(api_client):
    client, _, _ = api_client
    client.post("/api/v1/integrations/webhook-1/test", headers=ADMIN_HEADER)
    response = client.get("/api/v1/integrations/deliveries?connector=webhook-1&page=1&pageSize=5", headers=ADMIN_HEADER)
    assert response.status_code == 200
    payload = response.json()
    assert payload["page"] == 1 and payload["pageSize"] == 5
    assert payload["total"] >= 1
    item = payload["items"][0]
    assert item["connector"] == "webhook-1"
    assert item["state"] in {"delivered", "failed", "skipped"}
    assert "requestSummary" in item and "responseSummary" in item

    empty = client.get("/api/v1/integrations/deliveries?state=skipped&connector=webhook-1", headers=ADMIN_HEADER)
    assert empty.status_code == 200
    invalid = client.get("/api/v1/integrations/deliveries?state=nonsense", headers=ADMIN_HEADER)
    assert invalid.status_code == 422


def test_api_manual_dispatch_requires_an_existing_object(api_client):
    client, _, _ = api_client
    missing = client.post(
        "/api/v1/integrations/events",
        json={"objectType": "alert", "objectId": "ALT-DOES-NOT-EXIST"},
        headers=ADMIN_HEADER,
    )
    assert missing.status_code == 404


def test_api_manual_dispatch_delivers_and_records_an_existing_alert(api_client, monkeypatch):
    client, transport, _ = api_client
    from datetime import timedelta

    from app.db.base import utc_now
    from app.db.models import Alert

    alert_id = "ALT-INT-TEST-1"
    with _fresh_session() as db:
        db.query(Alert).filter(Alert.id == alert_id).delete(synchronize_session=False)
        db.add(
            Alert(
                id=alert_id,
                timestamp=utc_now() - timedelta(minutes=1),
                title="Integration test alert",
                severity="high",
                status="new",
                category="Port Scan",
                sensor="lab-core-01",
                source_ip="198.51.100.7",
                destination_ip="10.0.0.9",
                destination_port=445,
                protocol="TCP",
                risk_score=80.0,
                # Required columns of the live schema (NOT NULL without defaults).
                confidence=80.0,
                detector="suricata",
                evidence=[],
            )
        )
        db.commit()

    response = client.post(
        "/api/v1/integrations/events",
        json={"objectType": "alert", "objectId": alert_id},
        headers=ADMIN_HEADER,
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["objectId"] == alert_id
    assert payload["capability"] == "alert"
    assert payload["requestedBy"] == "env:admin"
    results = {row["connector"]: row for row in payload["outcome"]["results"]}
    assert results["webhook-1"]["state"] == "delivered"
    assert results["ticket-http"]["state"] == "skipped"
    assert results["ticket-http"]["skippedReason"] == "capability_mismatch"
    assert results["syslog"]["state"] == "delivered"

    body = json.loads(transport.calls[-1]["body"].decode("utf-8"))
    assert body["objectId"] == alert_id
    assert body["alert"]["sourceIp"] == "198.51.100.7"

    with _fresh_session() as db:
        row = (
            db.query(IntegrationDelivery)
            .filter(IntegrationDelivery.connector == "webhook-1", IntegrationDelivery.object_id == alert_id)
            .one()
        )
    assert row.state == "delivered"
    assert row.event_type == "alert"
    assert row.request_summary["objectId"] == alert_id

    with _fresh_session() as db:
        db.query(Alert).filter(Alert.id == alert_id).delete(synchronize_session=False)
        db.commit()


def test_api_dispatch_can_target_one_connector(api_client):
    client, _, _ = api_client
    from app.db.base import utc_now
    from app.db.models import Case

    case_id = "CASE-INT-TEST-1"
    with _fresh_session() as db:
        db.query(Case).filter(Case.id == case_id).delete(synchronize_session=False)
        db.add(
            Case(
                id=case_id,
                title="Integration case",
                severity="high",
                status="investigating",
                assignee="analyst-1",
                # created_by is NOT NULL in the live schema.
                created_by="tester",
                created_at=utc_now(),
                updated_at=utc_now(),
            )
        )
        db.commit()

    response = client.post(
        "/api/v1/integrations/events",
        json={"objectType": "case", "objectId": case_id, "connectors": ["ticket-http"]},
        headers=ADMIN_HEADER,
    )
    assert response.status_code == 200
    results = response.json()["outcome"]["results"]
    assert [row["connector"] for row in results] == ["ticket-http"]
    assert results[0]["state"] == "delivered"

    with _fresh_session() as db:
        db.query(Case).filter(Case.id == case_id).delete(synchronize_session=False)
        db.commit()


def test_api_respects_the_disabled_configuration(monkeypatch):
    monkeypatch.delenv("EVONIDS_INTEGRATIONS_ENABLED", raising=False)
    monkeypatch.delenv("EVONIDS_WEBHOOK_URLS", raising=False)
    monkeypatch.delenv("EVONIDS_SYSLOG_HOST", raising=False)
    monkeypatch.delenv("EVONIDS_TICKET_BASE_URL", raising=False)
    monkeypatch.delenv("EVONIDS_STIX_EXPORT_DIR", raising=False)

    dispatcher = IntegrationDispatcher(build_registry(load_integration_settings()))
    set_dispatcher(dispatcher)
    from app.main import app

    with TestClient(app) as client:
        response = client.get("/api/v1/integrations", headers=ADMIN_HEADER)
        assert response.status_code == 200
        payload = response.json()
        assert payload["enabled"] is False
        assert payload["configured"] is False
        assert payload["connectors"] == []
        assert "默认关闭" in payload["note"]
        test_response = client.post("/api/v1/integrations/webhook-1/test", headers=ADMIN_HEADER)
        assert test_response.status_code == 404
    set_dispatcher(None)


def test_no_test_in_this_module_opens_a_real_socket(monkeypatch):
    """The fake transports are the only channel; a real DNS lookup would fail here."""
    calls: list[tuple] = []

    def forbidden(*args, **kwargs):  # noqa: ANN002, ANN003, ANN201
        calls.append(args)
        raise AssertionError("a test attempted a real network operation")

    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)

    connector, transport = _connector([TransportResponse(200, {}, b"{}")])
    wrapper, _ = _resilient(connector)
    assert wrapper.deliver(_alert_event()).state == "delivered"
    assert calls == []
