"""Structured (JSON-line) logging for the EvoNIDS API service.

Every record is emitted as one JSON object per line with a stable field set:
timestamp, level, logger, message plus any structured context the caller attached
(``request_id``, ``principal``, ``duration_ms``, ``status_code``, ``method``,
``path``...). Context fields are attached with ``logger.info("...", extra={
"request_id": ..., "principal": ...})`` and rendered by the formatter regardless
of whether a particular handler template lists them.
"""
from __future__ import annotations

import json
import logging
import sys
import time
from typing import Any

RESERVED = {
    # fields the formatter renders itself or that belong to the logging
    # machinery rather than application context
    "message", "asctime", "levelname", "name", "taskName", "process", "thread",
    "msg", "args", "levelno", "pathname", "filename", "module", "exc_info",
    "exc_text", "stack_info", "lineno", "funcName", "created", "msecs",
    "relativeCreated", "threadName", "processName", "stackLevel",
}


class JsonFormatter(logging.Formatter):
    """Render a LogRecord as a single JSON object per line."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        for key, value in record.__dict__.items():
            if key not in RESERVED and not key.startswith("_"):
                try:
                    json.dumps(value)
                    payload[key] = value
                except (TypeError, ValueError):
                    payload[key] = str(value)
        try:
            return json.dumps(payload, ensure_ascii=False, default=str)
        except (TypeError, ValueError):
            return json.dumps({"level": record.levelname, "message": str(record.getMessage())})


def configure_logging(level: str = "INFO") -> None:
    """Install a single JSON-line handler on the root logger (idempotent)."""
    root = logging.getLogger()
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    if any(isinstance(handler.formatter, JsonFormatter) for handler in root.handlers):
        return
    for handler in list(root.handlers):
        root.removeHandler(handler)
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    root.addHandler(handler)


class Timer:
    """Tiny helper for the access log (not a stopwatch substitute)."""

    __slots__ = ("_started",)

    def __init__(self) -> None:
        self._started = time.perf_counter()

    def elapsed_ms(self) -> int:
        return max(0, round((time.perf_counter() - self._started) * 1000))
