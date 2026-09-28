"""HTTP transport abstraction for the collector.

The transport is injected so the collector's retry/spool/backoff behaviour can be
unit tested without a network, and so an operator can swap in an mTLS-configured
client without touching the batching logic.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from email.utils import parsedate_to_datetime
from typing import Any, Protocol


@dataclass(frozen=True, slots=True)
class TransportResponse:
    status: int
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""

    def json(self) -> Any:
        import json

        if not self.body:
            return None
        try:
            return json.loads(self.body.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            return None

    def server_time_epoch(self) -> float | None:
        """Parse the HTTP ``Date`` header (second resolution) as a skew reference."""
        raw = self.headers.get("date") or self.headers.get("Date")
        if not raw:
            return None
        try:
            return parsedate_to_datetime(raw).timestamp()
        except (TypeError, ValueError):
            return None


class Transport(Protocol):
    def send(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str],
        body: bytes | None = None,
        timeout: float = 15.0,
    ) -> TransportResponse: ...


class TransportError(RuntimeError):
    """Network-level failure (connection reset, DNS, timeout)."""


class HttpTransport:
    """httpx-based transport; the only component that touches the network."""

    def __init__(self, *, client_cert: str | None = None, client_key: str | None = None, verify: bool = True) -> None:
        import httpx

        self._httpx = httpx
        self._client = httpx.Client(
            cert=(client_cert, client_key) if client_cert and client_key else None,
            verify=verify,
            follow_redirects=False,
        )

    def send(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str],
        body: bytes | None = None,
        timeout: float = 15.0,
    ) -> TransportResponse:
        try:
            response = self._client.request(method, url, headers=headers, content=body, timeout=timeout)
        except self._httpx.HTTPError as exc:  # pragma: no cover - depends on real network
            raise TransportError(str(exc)) from exc
        return TransportResponse(
            status=response.status_code,
            headers={key.lower(): value for key, value in response.headers.items()},
            body=response.content,
        )

    def close(self) -> None:
        self._client.close()
