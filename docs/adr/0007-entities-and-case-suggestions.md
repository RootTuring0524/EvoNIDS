# ADR 0007 — Entity discovery, relations and case correlation suggestions

- **Status:** Accepted
- **Date:** 2026-09-09
- **Deciders:** EvoNIDS maintainers

## Context

Alerts and flows were rows with IP addresses but no aggregate graph: analysts could not
browse "everything 192.0.2.77 talked to" and had no machine help when deciding whether a
new alert belongs to an existing case.

## Decision

1. **`entities`** aggregates observed IP endpoints (type `ip`) across sensors:
   first/last seen, event count, observed sensors. Values are deterministic ids
   (`sha256(type|value)`), never hand-curated; rows are created/updated in the same
   transaction as the accepted event.
2. **`entity_relations`** aggregates the communication between a pair of entities into
   one undirected row (`communicates_with`, canonical entity ordering), with first/last
   seen and event count.
3. **Discovery is automatic at ingestion** (alerts and flows with both endpoints,
   excluding `0.0.0.0`/self-pairs). Two-phase upsert with an explicit flush keeps the
   unique constraints safe inside one multi-event transaction.
4. **Case correlation is a *suggestion*, never an auto-create**: an analyst opens
   `GET /api/v1/cases/suggestions?alertId=...` and receives open/investigating cases that
   share at least one endpoint with attached alerts, including the shared IPs and the
   concrete matching alert ids, so the reason for each suggestion is inspectable.
   Auto-correlation rules (rule + asset + time window, with suppression and thresholds)
   remain a later iteration behind explicit policy.
5. **API**: `GET /api/v1/entities` (search/type/pagination) and
   `GET /api/v1/entities/{id}` (with aggregated relations); mutations never exist on the
   entity API because facts come from events only.

## Alternatives considered

- Directed relations (src→dst): rejected for v1 — the analyst question ("who talked to
  whom") is symmetric; direction is preserved in the originating alerts/evidence.
- Auto-creating cases from correlation hits: rejected — creates alert floods and
  un-auditable case sprawl; suggestions keep a human in the loop, matching the
  deployment/approval principles for high-impact actions.

## Migration / rollback

`alembic upgrade head` (revision `20260909_0010`). Rollback: `alembic downgrade
20260907_0009` drops both tables. Pre-existing rows are not backfilled (entities are only
discovered for events ingested after this migration — honest lineage).

## Cost

Two tables, one service module, one router, ingestion hooks, suggestion service + route,
two integration tests, OpenAPI snapshot refresh.
