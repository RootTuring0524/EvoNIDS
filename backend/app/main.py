from __future__ import annotations

import logging
import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.router import api_router
from app.core.config import get_settings
from app.db.base import Base
from app.db.session import SessionLocal, engine
from app.services.training import recover_interrupted_training_runs


settings = get_settings()
logging.basicConfig(
    level=getattr(logging, settings.log_level.upper(), logging.INFO),
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)


@asynccontextmanager
async def lifespan(_: FastAPI):
    if settings.auto_create_db:
        Base.metadata.create_all(bind=engine)
    with SessionLocal() as db:
        recovered = recover_interrupted_training_runs(db)
    if recovered:
        logging.getLogger("evonids.training").warning(
            "Marked %s interrupted training run(s) as failed during startup",
            recovered,
        )
    yield


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
    ],
)


@app.middleware("http")
async def request_context(request: Request, call_next):
    request_id = request.headers.get("x-request-id") or str(uuid.uuid4())
    request.state.request_id = request_id
    response = await call_next(request)
    response.headers["X-Request-ID"] = request_id
    return response


@app.exception_handler(Exception)
async def unhandled_error(request: Request, exc: Exception):
    logging.getLogger("evonids.api").exception(
        "Unhandled request failure",
        extra={"request_id": getattr(request.state, "request_id", None)},
    )
    return JSONResponse(
        status_code=500,
        content={
            "error": "internal_server_error",
            "message": "The service could not complete the request.",
            "requestId": getattr(request.state, "request_id", None),
        },
    )


app.include_router(api_router, prefix="/api/v1")
