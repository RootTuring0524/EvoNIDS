from __future__ import annotations

import logging
import threading
import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.api.router import api_router
from app.core.config import get_settings, validate_production_settings
from app.core.errors import (
    http_exception_handler,
    unhandled_exception_handler,
    validation_exception_handler,
)
from app.core.logging import Timer, configure_logging
from app.core.security import GuardMiddleware, RateLimiter, SecurityHeadersMiddleware
from app.services.observability import (
    continue_or_start_trace,
    request_finished,
    request_started,
    route_label,
)
from app.db.base import Base
from app.db.session import SessionLocal, engine
from app.services.investigation_worker import investigation_worker_loop
from app.services.training import recover_interrupted_training_runs
from app.services.training_worker import SHUTDOWN_GRACE_SECONDS, training_worker_loop

settings = get_settings()
configure_logging(settings.log_level)
access_logger = logging.getLogger("evonids.access")


@asynccontextmanager
async def lifespan(_: FastAPI):
    # Refuse to serve an insecure production instance before binding any socket.
    validate_production_settings(settings)
    if settings.auto_create_db:
        Base.metadata.create_all(bind=engine)
    with SessionLocal() as db:
        recovered = recover_interrupted_training_runs(db)
    if recovered:
        logging.getLogger("evonids.training").warning(
            "Marked %s interrupted training run(s) as failed during startup",
            recovered,
        )
    # Single in-process training worker: the request path only queues rows
    # (state "queued"); the worker executes them sequentially. On shutdown we
    # wait up to the grace window for the current run; if it is still running
    # the next boot marks it failed with an audit event (see ADR 0004).
    stop_event = threading.Event()
    worker = threading.Thread(
        target=training_worker_loop,
        args=(stop_event,),
        name="evonids-training-worker",
        daemon=True,
    )
    worker.start()
    # Second in-process worker: AI investigations are queued as rows and executed
    # here, so an LLM call never blocks an HTTP request (see ADR-0011).
    investigation_worker = threading.Thread(
        target=investigation_worker_loop,
        args=(stop_event,),
        name="evonids-investigation-worker",
        daemon=True,
    )
    investigation_worker.start()
    try:
        yield
    finally:
        stop_event.set()
        worker.join(timeout=SHUTDOWN_GRACE_SECONDS)
        investigation_worker.join(timeout=SHUTDOWN_GRACE_SECONDS)


app = FastAPI(
    title=settings.app_name,
    version="0.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
    allow_headers=[
        "Authorization",
        "Content-Type",
        "X-Request-ID",
        "X-EvoNIDS-Admin-Token",
        "X-EvoNIDS-Sensor-Token",
        "X-Evonids-Batch-Id",
        "X-Evonids-Encoding",
        "X-Evonids-Event-Count",
        "X-Evonids-Clock-Skew-Seconds",
        "X-Evonids-Agent-Version",
    ],
)
# HSTS is only meaningful behind TLS, which production requires.
app.add_middleware(SecurityHeadersMiddleware, hsts=settings.environment == "production")
app.add_middleware(
    GuardMiddleware,
    write_limiter=RateLimiter(per_minute=settings.rate_limit_write_per_minute),
    ingest_limiter=RateLimiter(per_minute=settings.rate_limit_ingest_per_minute, burst=200),
    max_json_body_bytes=settings.max_json_body_bytes,
    enabled=settings.rate_limit_enabled,
)


@app.middleware("http")
async def request_context(request: Request, call_next):
    request_id = request.headers.get("x-request-id") or str(uuid.uuid4())
    request.state.request_id = request_id
    # W3C trace propagation: continue an upstream trace when present, otherwise
    # start one, and always echo the trace id back for correlation.
    trace = continue_or_start_trace(request.headers.get("traceparent"))
    request.state.trace_id = trace.trace_id
    request.state.span_id = trace.span_id
    started = request_started()
    timer = Timer()
    try:
        response = await call_next(request)
    except Exception:
        # Exception handlers run after the middleware stack unwinds, so the
        # failure itself is logged by app.core.errors.unhandled_exception_handler;
        # here we only record the access line before re-raising.
        access_logger.info(
            "request failed",
            extra={
                "request_id": request_id,
                "method": request.method,
                "path": request.url.path,
                "status_code": 500,
                "duration_ms": timer.elapsed_ms(),
            },
        )
        raise
    status_code = response.status_code
    principal = getattr(request.state, "principal", None)
    request_finished(
        method=request.method, route=route_label(request), status=status_code, started=started
    )
    access_logger.info(
        "request complete",
        extra={
            "request_id": request_id,
            "trace_id": trace.trace_id,
            "span_id": trace.span_id,
            "method": request.method,
            "path": request.url.path,
            "status_code": status_code,
            "duration_ms": timer.elapsed_ms(),
            "principal": getattr(principal, "display", None),
        },
    )
    response.headers["X-Request-ID"] = request_id
    response.headers["X-Trace-ID"] = trace.trace_id
    return response


# Uniform error envelope for every failure surface: explicit HTTPException raises,
# FastAPI request validation, routing 404/405 and unhandled exceptions.
app.add_exception_handler(StarletteHTTPException, http_exception_handler)
app.add_exception_handler(RequestValidationError, validation_exception_handler)
app.add_exception_handler(Exception, unhandled_exception_handler)

app.include_router(api_router, prefix="/api/v1")
