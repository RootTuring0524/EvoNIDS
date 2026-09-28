"""HTTP hardening: security headers, rate limiting and body-size guard."""
import os
import tempfile
import time
from pathlib import Path

database_path = Path(tempfile.gettempdir()) / "evonids-http-hardening-test.db"
database_path.unlink(missing_ok=True)
os.environ["EVONIDS_DATABASE_URL"] = f"sqlite:///{database_path.as_posix()}"
os.environ["EVONIDS_AUTO_CREATE_DB"] = "true"
os.environ["EVONIDS_ADMIN_API_TOKEN"] = "test-admin-token"
os.environ["EVONIDS_SENSOR_INGEST_TOKEN"] = "test-sensor-token"
os.environ["EVONIDS_ENVIRONMENT"] = "development"

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.core.security import SECURITY_HEADERS, RateLimiter, TokenBucket  # noqa: E402
from app.main import app  # noqa: E402

ADMIN_HEADER = {"x-evonids-admin-token": "test-admin-token"}


def test_token_bucket_refills_over_time():
    now = {"value": 0.0}
    bucket = TokenBucket(capacity=2, refill_per_second=1.0, clock=lambda: now["value"])
    assert bucket.consume()[0] is True
    assert bucket.consume()[0] is True
    allowed, retry_after = bucket.consume()
    assert allowed is False
    assert retry_after == pytest.approx(1.0, abs=0.01)
    now["value"] = 1.5
    assert bucket.consume()[0] is True


def test_rate_limiter_is_per_key_and_bounded():
    limiter = RateLimiter(per_minute=60, burst=2, max_keys=2)
    assert limiter.check("a")[0] is True
    assert limiter.check("a")[0] is True
    assert limiter.check("a")[0] is False
    assert limiter.check("b")[0] is True
    limiter.check("c")
    assert len(limiter._buckets) <= 2


def test_every_response_carries_hardening_headers():
    with TestClient(app) as client:
        response = client.get("/api/v1/health")
        assert response.status_code == 200
        for header, value in SECURITY_HEADERS.items():
            assert response.headers.get(header) == value, header
        assert "Strict-Transport-Security" not in response.headers  # development is not TLS


def test_security_headers_are_present_on_error_responses_too():
    with TestClient(app) as client:
        response = client.get("/api/v1/does-not-exist")
        assert response.status_code == 404
        assert response.headers["X-Content-Type-Options"] == "nosniff"
        assert response.json()["error"] == "not_found"


def test_oversized_json_body_is_rejected_before_validation():
    with TestClient(app) as client:
        payload = {"structured": {"ruleId": "x", "ruleName": "y", "description": "z" * 3_000_000}}
        response = client.post(
            "/api/v1/rules", json=payload, headers=ADMIN_HEADER
        )
        assert response.status_code in (413, 422)
        if response.status_code == 413:
            assert response.json()["error"] == "payload_too_large"


def _guarded_app(*, per_minute: int, burst: int, max_body: int):
    from fastapi import FastAPI

    from app.core.security import GuardMiddleware, RateLimiter

    guarded = FastAPI()
    guarded.add_middleware(
        GuardMiddleware,
        write_limiter=RateLimiter(per_minute=per_minute, burst=burst, clock=lambda: 0.0),
        ingest_limiter=RateLimiter(per_minute=1000, burst=1000),
        max_json_body_bytes=max_body,
        enabled=True,
    )

    @guarded.post("/api/v1/cases")
    def _create() -> dict[str, bool]:
        return {"ok": True}

    @guarded.post("/api/v1/ingestion/eve")
    def _ingest() -> dict[str, bool]:
        return {"ok": True}

    return guarded


def test_rate_limit_returns_429_with_retry_after():
    with TestClient(_guarded_app(per_minute=60, burst=1, max_body=1024)) as client:
        assert client.post("/api/v1/cases").status_code == 200
        blocked = client.post("/api/v1/cases")
        assert blocked.status_code == 429
        assert blocked.json()["error"] == "rate_limited"
        assert blocked.headers.get("Retry-After")
        # The ingestion path uses its own, more generous budget.
        assert client.post("/api/v1/ingestion/eve").status_code == 200


def test_json_body_limit_applies_to_control_plane_but_not_ingestion():
    with TestClient(_guarded_app(per_minute=1000, burst=1000, max_body=64)) as client:
        oversized = client.post("/api/v1/cases", content=b"{" + b"a" * 200 + b"}")
        assert oversized.status_code == 413
        assert oversized.json()["error"] == "payload_too_large"
        # Event batches are bounded by the ingestion-specific limit instead.
        assert client.post("/api/v1/ingestion/eve", content=b"x" * 200).status_code == 200


def test_rate_limiter_survives_clock_jumps():
    now = {"value": 0.0}
    limiter = RateLimiter(per_minute=60, burst=1, clock=lambda: now["value"])
    assert limiter.check("k")[0] is True
    now["value"] = -10.0  # clock went backwards; must not grant unlimited tokens
    assert limiter.check("k")[0] is False
    now["value"] = 5.0
    time.sleep(0)
    assert limiter.check("k")[0] is True
