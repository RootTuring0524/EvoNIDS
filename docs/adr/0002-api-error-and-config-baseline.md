# ADR 0002 — Uniform API error envelope and production configuration baseline

- **Status:** Accepted
- **Date:** 2026-09-07
- **Deciders:** EvoNIDS maintainers

## Context

Error responses were inconsistent: explicit `HTTPException` raises returned FastAPI's
default `{"detail": ...}` body, request-validation failures returned the framework
`{"detail": [{loc, msg, type, ...}]}` array, unknown routes returned plain text, and the
unhandled-exception path returned a custom `{"error", "message", "requestId"}` envelope.
Programmatic consumers could not rely on a stable error contract.

Configuration was similarly loose: `EVONIDS_ENVIRONMENT` accepted arbitrary strings and a
boot tagged `production` could start without any administrative/sensor secrets, or on a
SQLite database, with no startup feedback.

## Decision

1. **One error envelope for every failure surface.** Every handled failure answers
   `{"error": <stable machine code>, "message": <human text>, "requestId": <uuid>}` plus
   an optional `details` array for structured validation errors. Machine codes are
   registered by HTTP status in `backend/app/core/errors.py` (`not_found`, `unauthorized`,
   `conflict`, `validation_error`, `internal_error`, ...). Status codes keep their standard
   meaning. The Nuxt BFF already translates backend errors to its own generic messages, so
   the frontend contract is unaffected by this change.
2. **Registered exception handlers in `main.py`** for Starlette `HTTPException` (covers
   FastAPI raises plus routing 404/405), `RequestValidationError` (422 with structured
   `details`) and a last-resort `Exception` handler that logs the real error server-side
   and answers with the generic envelope (no internals leaked).
3. **Environment whitelist.** `EVONIDS_ENVIRONMENT` must be one of `development`,
   `staging`, `production` (normalized lowercase). Empty token strings are treated as
   unset.
4. **Fail-fast production boot.** `validate_production_settings()` runs in the FastAPI
   lifespan before the server accepts traffic: in `production` the boot refuses when
   `EVONIDS_ADMIN_API_TOKEN` or `EVONIDS_SENSOR_INGEST_TOKEN` are missing or the database
   URL is not PostgreSQL.

## Alternatives considered

- Keeping FastAPI's default `detail` bodies and documenting them: rejected — the
  framework shape varies by error class and is not a stable contract.
- A full custom exception hierarchy with typed exceptions per domain: deferred — the
  registry of machine codes by status keeps the change small; typed domain exceptions can
  be layered on top later without changing the envelope.

## Migration

Backward compatible for the Nuxt console (BFF does not read backend error bodies) and for
the in-repo test-suite (no test asserted on the old `detail` shape). External consumers of
the raw API that read `detail` must switch to `message`.

## Rollback

Revert the handlers in `main.py` and `core/errors.py`; the envelope disappears and default
framework bodies return.

## Cost

One new module (`core/errors.py`), handler wiring in `main.py`, config validation in
`core/config.py`, plus a dedicated `tests/test_errors.py` (9 tests) — no schema or database
migration required.
