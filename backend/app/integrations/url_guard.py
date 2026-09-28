"""Outbound target validation (SSRF guard) and small HTTP transport types.

Every connector that talks to a URL — webhook, ticketing/SIEM HTTP adapter —
validates the target through :func:`validate_target_url` *before* the first byte
leaves the process. The guard is deny-by-default:

* only ``https`` is allowed unless the operator explicitly opts into ``http``
  (``EVONIDS_*_ALLOW_HTTP=true``), and plaintext is refused for loopback and
  private targets even then;
* loopback, link-local (including the cloud metadata address
  ``169.254.169.254``), private/RFC1918, carrier-grade NAT, unique-local IPv6,
  multicast, reserved and unspecified addresses are refused;
* when a host allow-list is configured it is authoritative;
* when no allow-list is configured the hostname is resolved and **every**
  resulting address must pass the same checks, so a DNS name that points at
  ``127.0.0.1`` cannot smuggle a request to the local platform.

The guard cannot pin the resolved address for the subsequent connect (that would
require a custom socket factory in the transport). This is documented as a
residual risk in ``docs/integrations.md``; the allow-list is the mitigation an
operator should use for high-assurance deployments.
"""

from __future__ import annotations

import ipaddress
import json
import socket
from dataclasses import dataclass
from typing import Any, Protocol
from urllib.parse import urlsplit

from app.integrations.base import DeliveryBlockedError


class TransportResponse:
    """One HTTP response, transport-agnostic and JSON-decodable."""

    __slots__ = ("status", "headers", "body")

    def __init__(self, status: int, headers: dict[str, str] | None = None, body: bytes = b"") -> None:
        self.status = status
        self.headers = dict(headers or {})
        self.body = body

    def json(self) -> Any:
        try:
            return json.loads(self.body.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            return None

    def text(self, limit: int = 500) -> str:
        try:
            return self.body.decode("utf-8", errors="replace")[:limit]
        except Exception:  # noqa: BLE001 - decoding must never raise
            return ""


class HttpTransport(Protocol):
    """Same shape as ``app.services.llm_gateway.HttpTransport`` (injectable)."""

    def send(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str],
        body: bytes | None = None,
        timeout: float = 10.0,
    ) -> TransportResponse: ...


class HttpxTransport:
    """Real transport. Only constructed when a connector is actually enabled."""

    def __init__(self) -> None:
        import httpx

        self._httpx = httpx
        # Redirects are never followed: a 302 to 127.0.0.1 would defeat the guard.
        self._client = httpx.Client(follow_redirects=False)

    def send(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str],
        body: bytes | None = None,
        timeout: float = 10.0,
    ) -> TransportResponse:
        try:
            response = self._client.request(method, url, headers=headers, content=body, timeout=timeout)
        except self._httpx.HTTPError as error:
            from app.integrations.base import RetryableDeliveryError

            raise RetryableDeliveryError(f"transport error: {error}"[:255], code="transport_error") from error
        return TransportResponse(
            status=response.status_code,
            headers={str(key).lower(): str(value) for key, value in response.headers.items()},
            body=response.content,
        )

    def close(self) -> None:
        self._client.close()


@dataclass(frozen=True, slots=True)
class TargetPolicy:
    """What a connector is allowed to talk to."""

    allowed_hosts: tuple[str, ...] = ()
    allow_http: bool = False
    allow_private: bool = False
    allowed_schemes: tuple[str, ...] = ("https", "http")


@dataclass(frozen=True, slots=True)
class ValidatedTarget:
    url: str
    scheme: str
    host: str
    port: int
    addresses: tuple[str, ...]


def _is_blocked_address(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str | None:
    if address.is_loopback:
        return "loopback address"
    if address.is_link_local:
        return "link-local address"
    if address.is_private:
        return "private address"
    if address.is_multicast:
        return "multicast address"
    if address.is_reserved:
        return "reserved address"
    if address.is_unspecified:
        return "unspecified address"
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return _is_blocked_address(address.ipv4_mapped)
    return None


def _resolve(host: str, port: int) -> tuple[str, ...]:
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror as error:
        raise DeliveryBlockedError(f"cannot resolve host {host!r}: {error}", code="unresolvable_host") from error
    addresses: list[str] = []
    for info in infos:
        address = str(info[4][0])
        if address not in addresses:
            addresses.append(address)
    return tuple(addresses)


def validate_target_url(
    url: str,
    *,
    policy: TargetPolicy | None = None,
    resolver: Any = _resolve,
) -> ValidatedTarget:
    """Validate one outbound URL, raising :class:`DeliveryBlockedError` if refused.

    ``resolver`` is injectable so tests never touch DNS.
    """
    active = policy or TargetPolicy()
    if not url or not url.strip():
        raise DeliveryBlockedError("delivery target URL is empty", code="empty_target")
    parts = urlsplit(url.strip())
    scheme = parts.scheme.lower()
    if scheme not in {item.lower() for item in active.allowed_schemes}:
        raise DeliveryBlockedError(f"url scheme {scheme or '(none)'!r} is not allowed", code="blocked_scheme")
    if scheme != "https" and not active.allow_http:
        raise DeliveryBlockedError(
            "plaintext http is refused; set the connector's ALLOW_HTTP flag to opt in",
            code="insecure_scheme",
        )
    host = (parts.hostname or "").lower().rstrip(".")
    if not host:
        raise DeliveryBlockedError("delivery target URL has no host", code="missing_host")
    try:
        port = parts.port or (443 if scheme == "https" else 80)
    except ValueError as error:
        raise DeliveryBlockedError(f"delivery target port is invalid: {error}", code="invalid_port") from error

    allowlist = tuple(item.lower().rstrip(".") for item in active.allowed_hosts if item.strip())
    if allowlist and host not in allowlist:
        raise DeliveryBlockedError(
            f"host {host!r} is not in the configured allow-list", code="host_not_allowed"
        )

    local_name = host in {"localhost", "localhost.localdomain", "ip6-localhost"} or host.endswith(
        (".localhost", ".local", ".internal")
    )
    literal: ipaddress.IPv4Address | ipaddress.IPv6Address | None = None
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None

    if literal is not None:
        reason = _is_blocked_address(literal)
        if reason and not active.allow_private:
            raise DeliveryBlockedError(f"target {host} is a {reason}", code="blocked_address")
        addresses: tuple[str, ...] = (str(literal),)
    elif allowlist:
        # An explicit allow-list entry is trusted as written; resolving it would
        # make the allow-list dependent on DNS being reachable at request time.
        # Plaintext to a local name is refused regardless: an allow-list entry is
        # not a reason to send credentials to the host running the platform.
        if local_name and scheme != "https" and not active.allow_private:
            raise DeliveryBlockedError(
                "plaintext http to a local host is refused", code="insecure_scheme"
            )
        addresses = ()
    else:
        if local_name:
            raise DeliveryBlockedError(f"host {host!r} is a local name", code="blocked_host")
        addresses = tuple(resolver(host, port))
        if not addresses:
            raise DeliveryBlockedError(f"host {host!r} resolved to no address", code="unresolvable_host")
        for address in addresses:
            parsed = ipaddress.ip_address(address)
            reason = _is_blocked_address(parsed)
            if reason:
                raise DeliveryBlockedError(
                    f"host {host!r} resolves to {address}, a {reason}", code="blocked_address"
                )
    return ValidatedTarget(url=url.strip(), scheme=scheme, host=host, port=port, addresses=addresses)
