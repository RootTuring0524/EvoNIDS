"""HTTP hardening: security headers, body-size guard and per-principal rate limits.

The rate limiter is in-process and deliberately simple: it protects a single API
process against accidental floods and runaway clients. It is **not** a
distributed limiter - with multiple replicas each replica keeps its own budget -
and that limitation is documented in ``docs/deployment.md``.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse, Response

SECURITY_HEADERS: dict[str, str] = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
    "Cross-Origin-Resource-Policy": "same-site",
    # The API only ever returns JSON; a restrictive CSP keeps a browser from
    # treating an error payload as a document.
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
    "Cache-Control": "no-store",
}
HSTS_HEADER = "max-age=31536000; includeSubDomains"

# Paths whose bodies are event batches rather than JSON control payloads.
INGEST_PATH_MARKERS = ("/ingestion/",)
WRITE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


@dataclass
class TokenBucket:
    capacity: float
    refill_per_second: float
    clock: Callable[[], float] = time.monotonic
    tokens: float = field(init=False)
    updated_at: float = field(init=False)

    def __post_init__(self) -> None:
        self.tokens = self.capacity
        self.updated_at = self.clock()

    def consume(self, amount: float = 1.0) -> tuple[bool, float]:
        now = self.clock()
        elapsed = max(now - self.updated_at, 0.0)
        self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_per_second)
        self.updated_at = now
        if self.tokens >= amount:
            self.tokens -= amount
            return True, 0.0
        missing = amount - self.tokens
        retry_after = missing / self.refill_per_second if self.refill_per_second > 0 else 1.0
        return False, round(max(retry_after, 0.001), 3)


class RateLimiter:
    """Per-key token bucket with bounded memory (stale buckets are evicted)."""

    def __init__(
        self,
        *,
        per_minute: int,
        burst: int | None = None,
        clock: Callable[[], float] = time.monotonic,
        max_keys: int = 10_000,
    ) -> None:
        self.per_minute = max(per_minute, 1)
        self.capacity = float(burst if burst is not None else max(per_minute // 4, 5))
        self.clock = clock
        self.max_keys = max_keys
        self._buckets: dict[str, TokenBucket] = {}

    def check(self, key: str, *, amount: float = 1.0) -> tuple[bool, float]:
        bucket = self._buckets.get(key)
        if bucket is None:
            if len(self._buckets) >= self.max_keys:
                self._evict()
            bucket = TokenBucket(
                capacity=self.capacity,
                refill_per_second=self.per_minute / 60.0,
                clock=self.clock,
            )
            self._buckets[key] = bucket
        return bucket.consume(amount)

    def _evict(self) -> None:
        stale = [key for key, bucket in self._buckets.items() if bucket.tokens >= self.capacity]
        for key in stale[: max(len(stale) // 2, 1)]:
            self._buckets.pop(key, None)
        if len(self._buckets) >= self.max_keys:
            self._buckets.clear()

    def reset(self) -> None:
        """Drop every bucket. Used by tests to isolate per-case budgets."""
        self._buckets.clear()


def client_key(request: Request) -> str:
    principal = getattr(request.state, "principal", None)
    display = getattr(principal, "display", None)
    if display:
        return f"principal:{display}"
    if request.client is not None and request.client.host:
        return f"ip:{request.client.host}"
    return "anonymous"


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, *, hsts: bool = False) -> None:  # noqa: ANN001 - ASGI app
        super().__init__(app)
        self.hsts = hsts

    async def dispatch(self, request: Request, call_next) -> Response:  # noqa: ANN001
        response = await call_next(request)
        for header, value in SECURITY_HEADERS.items():
            response.headers.setdefault(header, value)
        if self.hsts:
            response.headers.setdefault("Strict-Transport-Security", HSTS_HEADER)
        return response


class GuardMiddleware(BaseHTTPMiddleware):
    """Body-size limit plus rate limiting for state-changing requests."""

    def __init__(
        self,
        app,  # noqa: ANN001
        *,
        write_limiter: RateLimiter,
        ingest_limiter: RateLimiter,
        max_json_body_bytes: int,
        enabled: bool = True,
    ) -> None:
        super().__init__(app)
        self.write_limiter = write_limiter
        self.ingest_limiter = ingest_limiter
        self.max_json_body_bytes = max_json_body_bytes
        self.enabled = enabled

    async def dispatch(self, request: Request, call_next) -> Response:  # noqa: ANN001
        if self.enabled and request.method in WRITE_METHODS:
            is_ingest = any(marker in request.url.path for marker in INGEST_PATH_MARKERS)
            limiter = self.ingest_limiter if is_ingest else self.write_limiter
            allowed, retry_after = limiter.check(client_key(request))
            if not allowed:
                return JSONResponse(
                    status_code=429,
                    content={
                        "error": "rate_limited",
                        "message": (
                            f"request rate exceeded for {client_key(request)}; "
                            f"retry after {retry_after} seconds"
                        ),
                        "requestId": getattr(request.state, "request_id", None),
                    },
                    headers={"Retry-After": f"{retry_after:.0f}"},
                )
            if not is_ingest:
                declared = request.headers.get("content-length")
                if declared and declared.isdigit() and int(declared) > self.max_json_body_bytes:
                    return JSONResponse(
                        status_code=413,
                        content={
                            "error": "payload_too_large",
                            "message": (
                                f"JSON body exceeds the {self.max_json_body_bytes} byte limit"
                            ),
                            "requestId": getattr(request.state, "request_id", None),
                        },
                    )
        return await call_next(request)
