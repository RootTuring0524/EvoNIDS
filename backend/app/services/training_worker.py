"""In-process training worker for the EvoNIDS API process.

``TrainingRun`` rows in state ``queued`` are the durable queue: the API request
path only inserts the row and returns ``202``, and a single worker thread
started by the API lifespan claims queued runs sequentially and executes them
outside the request path.

Restart semantics stay honest: a job still ``running`` when the process dies is
marked ``failed`` with an audit event on the next boot
(``recover_interrupted_training_runs``) and must be retried manually. A durable
job broker with automatic retry, backoff and distributed workers is a Phase 3
item (see docs/adr/0004-in-process-training-worker.md).
"""
from __future__ import annotations

import logging
import threading

from sqlalchemy import select

from app.db.models import TrainingRun
from app.db.session import SessionLocal
from app.services.training import execute_training_run

logger = logging.getLogger("evonids.training.worker")

POLL_SECONDS = 2.0
SHUTDOWN_GRACE_SECONDS = 8.0


def _next_queued_run_id() -> str | None:
    with SessionLocal() as db:
        row = db.scalar(
            select(TrainingRun)
            .where(TrainingRun.state == "queued")
            .order_by(TrainingRun.created_at.asc(), TrainingRun.id.asc())
            .limit(1)
        )
        return row.id if row is not None else None


def training_worker_loop(stop_event: threading.Event) -> None:
    """Claim and execute queued training runs until the stop event is set."""
    logger.info("training worker started")
    try:
        while not stop_event.is_set():
            run_id = _next_queued_run_id()
            if run_id is None:
                stop_event.wait(POLL_SECONDS)
                continue
            logger.info("training worker picked up queued run %s", run_id)
            try:
                execute_training_run(run_id)
            except Exception:  # execute_training_run persists failures itself
                logger.exception("training worker failed while executing run %s", run_id)
    finally:
        logger.info("training worker stopped")
