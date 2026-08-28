# ADR 0001 — Keep the backend/ + project/ layout for v0.1

- **Status:** Accepted
- **Date:** 2026-08-28
- **Deciders:** EvoNIDS maintainers

## Context

EvoNIDS currently has two top-level application directories:

- `backend/` — the FastAPI service (SQLAlchemy models, Alembic migrations, training and
  extraction scripts, dataset and artifact roots, pytest suite, its own `README.md` and
  Dockerfile).
- `project/` — the Nuxt 3 console (pages, server-only API proxy routes, mock mode).

An open-source monorepo convention such as `apps/api` + `apps/web` + `packages/*` would
align the repository with common tooling expectations. However, at v0.1 the codebase is a
small, fast-moving, mostly single-author research project: the README, `start-demo.ps1`,
`stop-demo.ps1`, `docker-compose.yml`, CI workflows, backend docs and all published
walkthroughs already reference `backend/` and `project/` paths, and the two apps have not
yet extracted any shared code that would justify a packages layer.

## Decision

For v0.1, EvoNIDS **keeps the existing `backend/` + `project/` top-level layout** and does
not restructure into an `apps/` + `packages/` monorepo.

Rationale:

1. **Continuity of verified documentation.** MODEL_CARD, DATA_CARD, architecture docs,
   READMEs and the demo scripts cite concrete paths; a layout migration would invalidate
   them all at once for zero functional gain.
2. **Low contributor onboarding cost.** Two obviously named directories — a Python service
   and a Nuxt console — are easier to explain than a tooling-driven workspace taxonomy.
3. **No shared-code pressure yet.** There are no shared Python/TypeScript packages; the
   only cross-boundary contract is the REST API plus proxy routes, which a directory move
   would not improve.
4. **Reproducibility first.** Effort in v0.2 goes to the Flow Transformer benchmark and
   dataset reproducibility, not to import-path churn.

## Consequences

- All scripts, docs, CI paths and the demo entry points remain valid; nothing needs a
  migration commit.
- New contributors must read the root README to learn the two-directory convention; the
  root README and `docs/architecture.md` state it explicitly.
- Path strings like `backend/datasets` and `EVONIDS_DATASET_ROOT` defaults stay
  environment-coupled; any future move must preserve or migrate those settings.
- The repository will not automatically benefit from monorepo tooling (workspace-wide
  versioning, shared lint configs, generated client packages) until restructured.

## When to revisit

Re-evaluate this decision when any of the following becomes true:

1. A **third deployable component** lands (for example the Flow Transformer training
   service or a durable job-queue worker being split out of the FastAPI process), making
   "apps" plural in fact.
2. **Shared code emerges** — Python or TypeScript packages consumed by more than one
   component (shared API schemas, generated clients, common evaluation tooling).
3. **CI or release complexity** grows enough that per-app ownership, path filters or
   independent versioning would materially reduce friction.
4. **Community growth** makes the two-directory convention a repeated source of
   contributor confusion (issues, PRs landing in the wrong tree).
5. The backend outgrows the single `app/` package such that an internal package split is
   required anyway; restructuring can be coordinated in the same migration.
