"""Uniform API error contract for EvoNIDS.

Every handled failure answers with the same JSON envelope:

    {"error": "<machine code>", "message": "<human readable>", "requestId": "<request id>"}

plus an optional ``details`` key when structured detail is available (for example
request validation errors). HTTP status codes keep their standard meaning; the
machine ``error`` code derives from the status code unless a more specific code
is supplied. Machine codes are stable for programmatic consumers; messages are
for humans and may change without notice.
"""
from __future__ import annotations

import logging
from typing import Any

from fastapi import Request
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

logger = logging.getLogger("evonids.api")

CODE_BY_STATUS: dict[int, str] = {
    400: "bad_request",
    401: "unauthorized",
    403: "forbidden",
    404: "not_found",
    405: "method_not_allowed",
    409: "conflict",
    413: "payload_too_large",
    415: "unsupported_media_type",
    422: "validation_error",
    429: "rate_limited",
    500: "internal_error",
    502: "bad_gateway",
    503: "service_unavailable",
    504: "gateway_timeout",
}

MESSAGE_BY_STATUS: dict[int, str] = {
    400: "The request could not be processed.",
    401: "Authentication is required.",
    403: "You do not have permission to perform this action.",
    404: "The requested resource was not found.",
    405: "The requested method is not allowed.",
    409: "The request conflicts with the current state.",
    413: "The request payload is too large.",
    415: "The request media type is not supported.",
    422: "The request failed validation.",
    429: "Too many requests. Please retry later.",
    500: "The service could not complete the request.",
    502: "An upstream service returned an invalid response.",
    503: "The service is unavailable. Please retry later.",
    504: "An upstream service timed out.",
}


def code_for_status(status_code: int) -> str:
    """Map an HTTP status code to its stable machine error code."""
    return CODE_BY_STATUS.get(status_code, "internal_error")


def message_for_status(status_code: int) -> str:
    """Return the default human message for a status code."""
    return MESSAGE_BY_STATUS.get(status_code, "The service could not complete the request.")


def error_envelope(
    request: Request,
    status_code: int,
    *,
    message: str | None = None,
    code: str | None = None,
    details: Any = None,
    headers: dict[str, str] | None = None,
) -> JSONResponse:
    """Build the uniform error JSON response."""
    body: dict[str, Any] = {
        "error": code or code_for_status(status_code),
        "message": message or message_for_status(status_code),
        "requestId": getattr(request.state, "request_id", None),
    }
    if details is not None:
        body["details"] = jsonable_encoder(details)
    request_id = getattr(request.state, "request_id", None)
    response_headers = dict(headers or {})
    # Unhandled errors bypass the request-context middleware on the way out, so
    # the envelope itself must carry the request id header.
    if request_id is not None:
        response_headers.setdefault("X-Request-ID", request_id)
    return JSONResponse(status_code=status_code, content=body, headers=response_headers)


async def http_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Normalize explicit HTTPException raises (and Starlette 404/405) to the envelope."""
    if not isinstance(exc, StarletteHTTPException):
        raise TypeError("http_exception_handler is registered for HTTP exceptions only")
    message = exc.detail if isinstance(exc.detail, str) else None
    details = exc.detail if not isinstance(exc.detail, str) else None
    return error_envelope(
        request,
        exc.status_code,
        message=message,
        details=details,
        headers=getattr(exc, "headers", None),
    )


async def validation_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Normalize request validation failures to the envelope with structured details."""
    if not isinstance(exc, RequestValidationError):
        raise TypeError("validation_exception_handler is registered for RequestValidationError only")
    errors = jsonable_encoder(exc.errors())
    first = str(errors[0].get("msg", "")) if errors else ""
    summary = "Request validation failed" + (f": {first}" if first else "")
    return error_envelope(request, 422, message=summary, details=errors)


async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Last-resort handler: log the real failure, answer with the generic envelope only."""
    logger.error(
        "Unhandled request failure",
        exc_info=exc,
        extra={"request_id": getattr(request.state, "request_id", None)},
    )
    return error_envelope(request, 500)
