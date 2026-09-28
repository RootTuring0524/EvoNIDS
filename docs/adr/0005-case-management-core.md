# ADR 0005 — Case management core (cases / case_alerts / case_timeline_events)

- **Status:** Accepted
- **Date:** 2026-09-07
- **Deciders:** EvoNIDS maintainers

## Context

Alerts carried status and disposition but there was no investigation container: analysts
could not group related alerts into a unit of work, track a lifecycle with a note-based
history, or review what had been attached and decided. The audit log is append-only but is
not a case-scoped workbench view.

## Decision

1. **`cases`** is the analyst-facing investigation unit: title, summary, severity
   (`critical|high|medium|low`), lifecycle status
   (`open|investigating|contained|closed|archived`), assignee, creator, maintained
   counters (`alert_count`, `highest_risk_score`), timestamps.
2. **`case_alerts`** is a unique (case, alert) link table; attaching/detaching updates the
   case counters and writes both an immutable audit event (`case.*`) and a
   `case_timeline_events` row — the latter is explicitly a case-scoped, human-readable
   mirror of the audit log, not a second record of truth.
3. **Status transitions are guarded** by an explicit map; `contained|closed|archived`
   require a note of at least 10 characters. Alert aggregation is explicit (manual
   create + attach/detach) in this iteration; automatic correlation (rule + asset +
   time-window grouping) is a later iteration and will be recorded here.
4. **API**: `/api/v1/cases` (list/create/get/patch) and
   `/api/v1/cases/{id}/alerts` (attach/detach). All mutations require an admin
   credential; the audit actor is the server-resolved principal (never client-supplied).
5. Deletion is intentionally absent: cases move to `archived` (retention policy comes
   later).

## Alternatives considered

- Generic `evidence`/`entity` tables in the same migration: deferred — the full evidence
  registry needs the ingestion-side hashing design (Phase 2, next iteration); keeping this
  migration to the case core keeps it reviewable and reversible.
- Deriving timelines purely from audit queries: rejected for the workbench read path —
  `case_timeline_events` is a cheap indexed projection written by the same transaction.

## Migration / rollback

`alembic upgrade head` (revision `20260907_0008`). Rollback: `alembic downgrade
20260907_0007` drops the three tables; no data migration is required.

## Cost

Three tables, one service module, one router, one migration, four integration tests, OpenAPI
snapshot refresh.
