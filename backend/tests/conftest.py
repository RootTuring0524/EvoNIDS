"""Shared fixtures for the backend test suite.

Rate limiting is keyed by principal and lives in the application process, so a
suite that shares one process also shares one token bucket per principal. That
is right in production — each caller keeps its own budget — but wrong across
test cases: a fast machine issues writes quickly enough to drain the bucket,
and every later write in the run answers 429. That is exactly how the backend
job failed on CI (11 tests asserting 200/202/404 but seeing 429) while the same
suite passed on a slower local machine.

Clearing the buckets between cases gives each test a full budget without
weakening the limiter itself; the dedicated rate-limit tests still exercise the
real code path because they spend their own budget within a single case.
"""

import pytest


@pytest.fixture(autouse=True)
def _reset_rate_limiters():
    from app.main import ingest_limiter, write_limiter

    write_limiter.reset()
    ingest_limiter.reset()
    yield
    write_limiter.reset()
    ingest_limiter.reset()
