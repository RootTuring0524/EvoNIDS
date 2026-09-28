"""Durable background worker for AI investigations.

Invocations are queued as ``InvestigationRun`` rows and executed outside the API
request process, exactly like training runs (ADR-0004): an LLM call must never
block an HTTP request, and a restart must not lose a queued investigation.
"""

from __future__ import annotations

import logging
import threading
from datetime import timedelta

from sqlalchemy import select

from app.core.config import get_settings
from app.db.base import utc_now
from app.db.models import InvestigationRun
from app.db.session import SessionLocal
from app.services.investigation import execute_run, next_queued_run_id
from app.services.llm_gateway import get_gateway

POLL_SECONDS = 1.0
STUCK_RUN_SECONDS = 600

logger = logging.getLogger("evonids.investigation.worker")


def recover_interrupted_runs() -> int:
    """Requeue runs that were interrupted by a restart mid-execution."""
    cutoff = utc_now() - timedelta(seconds=STUCK_RUN_SECONDS)
    with SessionLocal() as db:
        rows = db.scalars(
            select(InvestigationRun).where(
                InvestigationRun.state == "running",
                InvestigationRun.updated_at < cutoff,
            )
        ).all()
        for row in rows:
            row.state = "queued"
            row.degraded_reasons = list(dict.fromkeys([*(row.degraded_reasons or []), "requeued_after_restart"]))
        db.commit()
        return len(rows)


def investigation_worker_loop(stop_event: threading.Event) -> None:
    logger.info("investigation worker started")
    try:
        recovered = recover_interrupted_runs()
        if recovered:
            logger.info("requeued interrupted investigations", extra={"count": recovered})
        while not stop_event.wait(POLL_SECONDS):
            with SessionLocal() as db:
                run_id = next_queued_run_id(db)
            if run_id is None:
                continue
            settings = get_settings()
            gateway = get_gateway(settings)
            with SessionLocal() as db:
                try:
                    execute_run(db, run_id, gateway=gateway)
                except Exception:  # noqa: BLE001 - the worker must survive any run failure
                    logger.exception("investigation run failed", extra={"run_id": run_id})
                    run = db.get(InvestigationRun, run_id)
                    if run is not None and run.state in {"queued", "running"}:
                        run.state = "failed"
                        run.summary = "调查执行过程中出现未处理异常，已记录并跳过。"
                        run.degraded_reasons = list(
                            dict.fromkeys([*(run.degraded_reasons or []), "worker_exception"])
                        )
                        run.completed_at = utc_now()
                        db.commit()
    finally:
        logger.info("investigation worker stopped")
