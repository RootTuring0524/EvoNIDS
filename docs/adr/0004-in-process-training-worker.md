# ADR 0004 — In-process training worker now, durable job broker in Phase 3

- **Status:** Accepted
- **Date:** 2026-09-07
- **Deciders:** EvoNIDS maintainers

## Context

Training runs were executed on Starlette `BackgroundTasks` attached to the request that
queued them: the request path implicitly executed the job, recovery semantics were the
only durability story, and there was no separation between "the API serving traffic" and
"the thing that trains models". The production target requires API/worker separation with
a persistent task queue and resumable training and replay jobs.

## Decision

1. **TrainingRun rows are the durable queue.** The request path now only inserts a row in
   state `queued` and returns `202`; it never executes the job.
2. **A dedicated in-process worker thread** (`app/services/training_worker.py`) started by
   the API lifespan claims queued rows (oldest first) and executes them sequentially
   through the existing `execute_training_run` (which persists running/succeeded/failed
   state, metrics, artifacts and audit events).
3. **Crash semantics stay honest.** On boot, `recover_interrupted_training_runs` marks
   rows still `running` as `failed` with an audit event; they must be retried manually.
   On graceful shutdown the worker waits up to 8 seconds for the current run; a run
   interrupted beyond that is failed by the next boot, never silently dropped.
4. **A durable broker is deferred to Phase 3** (together with the collection plane, where
   NATS JetStream arrives for event streams). Adoption criteria for the broker:
   multiple API replicas, training or replay jobs longer than a few minutes at volume,
   scheduled retry/backoff, or queue inspection without paging the database. Until then
   the single-worker model is documented and load-tested (see tests).

## Alternatives considered

- A generic `jobs` table + polling loop now: rejected — the `training_runs` table already
  carries job state, metrics, lineage and audit; a second table would duplicate it.
- Celery/arq with a broker now: rejected — adds infrastructure and operational surface
  before the collection plane justifies it (Phase 3), and the brief requires ADR +
  load-test evidence before new components.

## Migration / rollback

No schema change. Rollback: restore `background_tasks.add_task(execute_training_run, ...)`
in the training route and stop starting the worker.

## Cost

One worker module (~60 lines), lifespan wiring in `main.py`, route simplification,
one integration test updated to poll for the terminal state.
