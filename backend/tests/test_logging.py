"""Tests for structured JSON-line logging."""
import json
import logging

from app.core.logging import JsonFormatter, configure_logging


class CaptureHandler(logging.Handler):
    def __init__(self) -> None:
        super().__init__()
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


def test_configure_logging_is_idempotent():
    json_handlers = lambda: [  # noqa: E731
        h for h in logging.getLogger().handlers if isinstance(h.formatter, JsonFormatter)
    ]
    configure_logging("INFO")
    assert len(json_handlers()) >= 1
    configure_logging("INFO")  # must not add duplicate JSON handlers
    assert len(json_handlers()) == 1


def test_json_formatter_emits_flat_json_with_extras():
    record = logging.LogRecord(
        name="evonids.access",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="request complete",
        args=(),
        exc_info=None,
    )
    record.request_id = "req-123"
    record.principal = "env:admin"
    record.status_code = 200
    record.duration_ms = 7
    line = JsonFormatter().format(record)
    payload = json.loads(line)
    assert payload["message"] == "request complete"
    assert payload["level"] == "INFO"
    assert payload["logger"] == "evonids.access"
    assert payload["request_id"] == "req-123"
    assert payload["principal"] == "env:admin"
    assert payload["status_code"] == 200
    assert payload["duration_ms"] == 7


def test_access_log_records_request_fields():
    import os
    import tempfile
    from pathlib import Path

    database_path = Path(tempfile.gettempdir()) / "evonids-logging-test.db"
    database_path.unlink(missing_ok=True)
    os.environ["EVONIDS_DATABASE_URL"] = f"sqlite:///{database_path.as_posix()}"
    os.environ["EVONIDS_AUTO_CREATE_DB"] = "true"
    os.environ["EVONIDS_ADMIN_API_TOKEN"] = "test-admin-token"
    os.environ["EVONIDS_ENVIRONMENT"] = "development"

    from fastapi.testclient import TestClient

    from app.main import app

    capture = CaptureHandler()
    logger = logging.getLogger("evonids.access")
    logger.addHandler(capture)
    try:
        with TestClient(app) as client:
            response = client.get("/api/v1/health", headers={"x-request-id": "req-abc"})
            assert response.status_code == 200
            assert response.headers.get("x-request-id") == "req-abc"
        assert capture.records, "expected at least one access log record"
        record = capture.records[-1]
        assert record.request_id == "req-abc"
        assert record.path == "/api/v1/health"
        assert record.status_code == 200
        assert record.duration_ms >= 0
    finally:
        logger.removeHandler(capture)
