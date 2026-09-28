"""Syslog (RFC 5424) and CEF senders.

Two independent concerns live here:

1. **Framing** — RFC 5424 ``<PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID
   STRUCTURED-DATA MSG`` is built byte-for-byte; the payload is sent over UDP,
   TCP or TLS through an injectable transport so tests never open a socket.
2. **CEF formatting** — the ArcSight Common Event Format is built with the
   escaping rules the format actually defines:
   * header fields escape ``\\`` and ``|``;
   * extension values escape ``\\`` and ``=``;
   * the syslog newline is never emitted inside a message.

Severity is mapped once, explicitly, in both directions
(:func:`cen_severity` / :func:`severity_from_cef`) so a receiver and the platform
agree on what "high" means.
"""

from __future__ import annotations

import re
import socket
import ssl
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Protocol

from app.integrations.base import (
    DeliveryAttempt,
    Notification,
    RetryableDeliveryError,
    Severity,
    summarise_request,
)
from app.integrations.settings import SyslogSettings

# Syslog severities (RFC 5424 §6.2.1, smallest is most severe).
SYSLOG_SEVERITY: dict[str, int] = {
    "critical": 2,  # critical
    "high": 3,  # error
    "medium": 4,  # warning
    "low": 5,  # notice
    "info": 6,  # informational
}
SEVERITY_RANK: dict[str, int] = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
# CEF 0-10 severity scale (ArcSight convention).
CEF_SEVERITY: dict[str, int] = {
    "critical": 10,
    "high": 7,
    "medium": 5,
    "low": 3,
    "info": 1,
}
CEF_SEVERITY_THRESHOLDS: tuple[tuple[int, str], ...] = (
    (9, "critical"),
    (6, "high"),
    (4, "medium"),
    (2, "low"),
    (0, "info"),
)

NILVALUE = "-"
MAX_MESSAGE_BYTES = 8_192


def cef_severity(severity: str) -> int:
    """Map a platform severity onto the CEF 0-10 scale."""
    return CEF_SEVERITY.get(severity.strip().lower(), CEF_SEVERITY["info"])


def severity_from_cef(value: int) -> str:
    """Inverse of :func:`cef_severity` for the canonical CEF levels."""
    for threshold, name in CEF_SEVERITY_THRESHOLDS:
        if value >= threshold:
            return name
    return "info"


def syslog_severity(severity: str) -> int:
    """Map a platform severity onto the RFC 5424 numeric severity."""
    return SYSLOG_SEVERITY.get(severity.strip().lower(), SYSLOG_SEVERITY["info"])


def escape_cef_header(value: str) -> str:
    """Escape a CEF *prefix* field: backslash first, then pipe."""
    return value.replace("\\", "\\\\").replace("|", "\\|")


def unescape_cef_header(value: str) -> str:
    """Inverse of :func:`escape_cef_header` (used by the round-trip tests)."""
    return _unescape(value, stop_at=frozenset())


def escape_cef_extension(value: str) -> str:
    """Escape a CEF *extension* value: backslash first, then equals."""
    return value.replace("\\", "\\\\").replace("=", "\\=")


def unescape_cef_extension(value: str) -> str:
    """Inverse of :func:`escape_cef_extension`."""
    return _unescape(value, stop_at=frozenset())


def _unescape(value: str, *, stop_at: frozenset[str]) -> str:
    out: list[str] = []
    index = 0
    while index < len(value):
        char = value[index]
        if char == "\\" and index + 1 < len(value):
            nxt = value[index + 1]
            if nxt in ("\\", "|", "=") and nxt not in stop_at:
                out.append(nxt)
                index += 2
                continue
            out.append(char)
            index += 1
            continue
        out.append(char)
        index += 1
    return "".join(out)


def _sanitize(value: str) -> str:
    """CEF/syslog messages must never carry a raw newline or NUL."""
    return value.replace("\r", " ").replace("\n", " ").replace("\x00", "")


@dataclass(frozen=True, slots=True)
class CefEvent:
    """The fields a CEF receiver can rely on."""

    device_vendor: str
    device_product: str
    device_version: str
    signature_id: str
    name: str
    severity: int
    extension: dict[str, str]

    def serialize(self) -> str:
        header = "|".join(
            [
                escape_cef_header(self.device_vendor),
                escape_cef_header(self.device_product),
                escape_cef_header(self.device_version),
                escape_cef_header(self.signature_id),
                escape_cef_header(self.name),
                str(self.severity),
            ]
        )
        pairs = [
            f"{key}={escape_cef_extension(_sanitize(str(value)))}"
            for key, value in self.extension.items()
        ]
        message = f"CEF:0|{header}|" + " ".join(pairs)
        return _sanitize(message)


def parse_cef(message: str) -> CefEvent:
    """Parse a serialized CEF message back into its fields (round-trip support)."""
    if not message.startswith("CEF:"):
        raise ValueError("not a CEF message")
    body = message[len("CEF:") :]
    version, _, remainder = body.partition("|")
    if version != "0":
        raise ValueError(f"unsupported CEF version {version!r}")
    header_parts: list[str] = []
    cursor = 0
    while len(header_parts) < 5:
        start = cursor
        escaped = False
        while cursor < len(remainder):
            char = remainder[cursor]
            if escaped:
                escaped = False
                cursor += 1
                continue
            if char == "\\":
                escaped = True
                cursor += 1
                continue
            if char == "|":
                break
            cursor += 1
        if cursor >= len(remainder):
            raise ValueError("CEF header is truncated")
        header_parts.append(unescape_cef_header(remainder[start:cursor]))
        cursor += 1
    severity_text, _, extension_text = remainder[cursor:].partition("|")
    extension: dict[str, str] = {}
    for token in _split_extension(extension_text):
        key, _, value = token.partition("=")
        extension[key] = unescape_cef_extension(value)
    return CefEvent(
        device_vendor=header_parts[0],
        device_product=header_parts[1],
        device_version=header_parts[2],
        signature_id=header_parts[3],
        name=header_parts[4],
        severity=int(severity_text),
        extension=extension,
    )


def _split_extension(text: str) -> list[str]:
    """Split a CEF extension into ``key=value`` tokens.

    CEF extension values routinely contain spaces and pipes (a signature name is
    the normal case), so a value runs until the next ``key=`` boundary. Splitting
    on whitespace truncates every message at its first space, which silently loses
    the alert title.
    """
    tokens: list[str] = []
    current: list[str] = []
    index = 0
    while index < len(text):
        char = text[index]
        if char == "\\" and index + 1 < len(text) and text[index + 1] in ("\\", "="):
            current.append(text[index])
            current.append(text[index + 1])
            index += 2
            continue
        if char == " " and current and _starts_new_pair(text, index + 1):
            tokens.append("".join(current))
            current = []
            index += 1
            continue
        current.append(char)
        index += 1
    if current:
        tokens.append("".join(current))
    return tokens


def _starts_new_pair(text: str, position: int) -> bool:
    """True when ``text[position:]`` begins a CEF ``key=`` token."""
    return re.match(r"[A-Za-z][A-Za-z0-9_]*=", text[position:]) is not None


def build_cef_event(
    event: Notification,
    *,
    enterprise_id: int = 0,
    device_product: str = "EvoNIDS",
    device_version: str = "0.2.0",
    host: str = "",
) -> CefEvent:
    """Turn a :class:`Notification` into a CEF event (values pre-redacted)."""
    severity = event.severity if event.severity in CEF_SEVERITY else "info"
    extension: dict[str, str] = {
        "externalId": event.dedup_key,
        "rt": event.occurred_at_iso(),
        "cat": event.event_type,
        "msg": event.title,
        "cs1Label": "objectId",
        "cs1": event.object_id,
        "cs2Label": "dedupKey",
        "cs2": event.dedup_key,
        "cs3Label": "severity",
        "cs3": event.severity,
    }
    if host:
        extension["dvchost"] = host
    alert = event.alert or {}
    for key, cef_key in (
        ("sourceIp", "src"),
        ("destinationIp", "dst"),
        ("sourcePort", "spt"),
        ("destinationPort", "dpt"),
        ("protocol", "proto"),
        ("category", "cat"),
        ("sensor", "dvchost"),
    ):
        value = alert.get(key)
        if value not in (None, ""):
            extension[cef_key] = str(value)
    for index, tag in enumerate(event.tags[:8], start=1):
        extension[f"cs{index + 3}Label"] = f"tag{index}"
        extension[f"cs{index + 3}"] = str(tag)
    if event.case:
        case_id = event.case.get("id") or event.case.get("caseId")
        if case_id:
            extension["cs5Label"] = "caseId"
            extension["cs5"] = str(case_id)
    return CefEvent(
        device_vendor=f"EvoNIDS:{enterprise_id}" if enterprise_id else "EvoNIDS",
        device_product=device_product,
        device_version=device_version,
        signature_id=f"evonids-{event.event_type}",
        name=event.title,
        severity=cef_severity(severity),
        extension=extension,
    )


def build_rfc5424(
    *,
    facility: int,
    severity: str,
    timestamp: datetime,
    hostname: str,
    app_name: str,
    proc_id: str = NILVALUE,
    msg_id: str = NILVALUE,
    structured_data: str = NILVALUE,
    message: str = "",
) -> bytes:
    """Build one RFC 5424 syslog record as UTF-8 bytes."""
    pri = max(0, min(191, facility * 8 + syslog_severity(severity)))
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)
    stamp = timestamp.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    header = " ".join(
        [
            f"<{pri}>1",
            stamp,
            _rfc5424_field(hostname) or NILVALUE,
            _rfc5424_field(app_name) or NILVALUE,
            _rfc5424_field(proc_id) or NILVALUE,
            _rfc5424_field(msg_id) or NILVALUE,
            structured_data or NILVALUE,
        ]
    )
    body = _sanitize(message).strip()
    return (header + (" " + body if body else "")).encode("utf-8")


def _rfc5424_field(value: str) -> str:
    """RFC 5424 header fields are printable US-ASCII without spaces."""
    if value == NILVALUE:
        return NILVALUE
    cleaned = "".join(char for char in _sanitize(value) if 33 <= ord(char) <= 126)
    return cleaned[:48]


class SyslogTransport(Protocol):
    def send(self, payload: bytes, *, host: str, port: int, timeout: float) -> None: ...


class UdpSyslogTransport:
    def send(self, payload: bytes, *, host: str, port: int, timeout: float) -> None:
        # Truncate to the UDP datagram limit instead of letting the OS drop it silently.
        datagram = payload[:65_507]
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(datagram, (host, port))


class TcpSyslogTransport:
    """TCP (optionally TLS) syslog with RFC 6587 octet counting."""

    def __init__(self, *, use_tls: bool = False, server_hostname: str | None = None) -> None:
        self.use_tls = use_tls
        self.server_hostname = server_hostname

    def send(self, payload: bytes, *, host: str, port: int, timeout: float) -> None:
        framed = f"{len(payload)} ".encode("ascii") + payload
        try:
            with socket.create_connection((host, port), timeout=timeout) as raw:
                stream: Any = raw
                if self.use_tls:
                    context = ssl.create_default_context()
                    stream = context.wrap_socket(raw, server_hostname=self.server_hostname or host)
                stream.sendall(framed)
        except OSError as error:
            raise RetryableDeliveryError(f"syslog transport error: {error}"[:255]) from error


def default_syslog_transport(protocol: str) -> SyslogTransport:
    if protocol == "tcp":
        return TcpSyslogTransport()
    if protocol == "tls":
        return TcpSyslogTransport(use_tls=True)
    return UdpSyslogTransport()


class SyslogConnector:
    """RFC 5424 / CEF sender. One ``deliver_once`` call sends one message."""

    def __init__(
        self,
        settings: SyslogSettings,
        *,
        transport: SyslogTransport | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.settings = settings
        self.name = settings.name
        self._transport = transport
        self._clock = clock
        self.sent: list[bytes] = []

    @property
    def capabilities(self) -> frozenset[str]:
        return frozenset(self.settings.capabilities)

    @property
    def transport(self) -> SyslogTransport:
        if self._transport is None:
            self._transport = default_syslog_transport(self.settings.protocol)
        return self._transport

    def describe(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "kind": "syslog",
            "target": f"{self.settings.protocol}://{self.settings.host}:{self.settings.port}",
            "format": self.settings.message_format,
            "facility": self.settings.facility,
            "appName": self.settings.app_name,
            "minSeverity": self.settings.min_severity,
        }

    def health(self) -> dict[str, Any]:
        if not self.settings.host:
            return {
                "connector": self.name,
                "kind": "syslog",
                "state": "misconfigured",
                "reason": "no syslog host configured",
                "probe": "not_attempted",
            }
        protocol = self.settings.protocol
        if protocol not in {"udp", "tcp", "tls"}:
            return {
                "connector": self.name,
                "kind": "syslog",
                "state": "misconfigured",
                "reason": f"unsupported syslog protocol {protocol!r}",
                "probe": "not_attempted",
            }
        if protocol == "udp":
            return {
                "connector": self.name,
                "kind": "syslog",
                "state": "degraded",
                "reason": "UDP syslog cannot be probed or acknowledged; delivery is fire-and-forget",
                "probe": "not_attempted",
            }
        return {
            "connector": self.name,
            "kind": "syslog",
            "state": "ok",
            "probe": "not_attempted",
            "note": "仅在真实发送时才会建立连接；health 不主动探测。",
        }

    def format_message(self, event: Notification) -> bytes:
        if self.settings.message_format == "cef":
            cef = build_cef_event(
                event, enterprise_id=self.settings.enterprise_id, host=self.settings.host
            ).serialize()
            return build_rfc5424(
                facility=self.settings.facility,
                severity=event.severity,
                timestamp=event.occurred_at,
                hostname=_local_hostname(),
                app_name="CEF",
                msg_id=event.event_type,
                message=cef,
            )
        structured = (
            f'[evonids@32473 eventType="{_sd_value(event.event_type)}" '
            f'objectId="{_sd_value(event.object_id)}" '
            f'dedupKey="{_sd_value(event.dedup_key)}" '
            f'severity="{_sd_value(event.severity)}"]'
        )
        return build_rfc5424(
            facility=self.settings.facility,
            severity=event.severity,
            timestamp=event.occurred_at,
            hostname=_local_hostname(),
            app_name=self.settings.app_name,
            msg_id=event.event_type,
            structured_data=structured,
            message=event.title,
        )

    def deliver_once(self, event: Notification) -> DeliveryAttempt:
        threshold = SEVERITY_RANK.get(self.settings.min_severity, SEVERITY_RANK["info"])
        if SEVERITY_RANK.get(event.severity, SEVERITY_RANK["info"]) > threshold:
            return DeliveryAttempt(
                deliverable=False,
                skipped=True,
                skipped_reason="severity_below_threshold",
                error=(
                    f"event severity {event.severity!r} is below the configured minimum "
                    f"{self.settings.min_severity!r}"
                ),
                error_code="severity_below_threshold",
                request_summary=summarise_request(event),
            )
        payload = self.format_message(event)
        if len(payload) > MAX_MESSAGE_BYTES:
            return DeliveryAttempt(
                deliverable=False,
                error=f"syslog message of {len(payload)} bytes exceeds the {MAX_MESSAGE_BYTES} limit",
                error_code="message_too_large",
                request_summary=summarise_request(event),
            )
        self.sent.append(payload)
        self.transport.send(
            payload,
            host=self.settings.host,
            port=self.settings.port,
            timeout=self.settings.timeout_seconds,
        )
        return DeliveryAttempt(
            request_summary=summarise_request(event),
            response_summary={
                "protocol": self.settings.protocol,
                "bytes": len(payload),
                "format": self.settings.message_format,
            },
            deliverable=True,
        )


def _sd_value(value: str) -> str:
    """RFC 5424 SD-PARAM escaping: ``"``, ``\\`` and ``]``."""
    return _sanitize(str(value)).replace("\\", "\\\\").replace('"', '\\"').replace("]", "\\]")


def _local_hostname() -> str:
    import socket as _socket

    try:
        return _socket.gethostname() or NILVALUE
    except OSError:
        return NILVALUE


def severity_gte(left: Severity | str, right: Severity | str) -> bool:
    """True when ``left`` is at least as severe as ``right``."""
    return SEVERITY_RANK.get(str(left), 4) <= SEVERITY_RANK.get(str(right), 4)
