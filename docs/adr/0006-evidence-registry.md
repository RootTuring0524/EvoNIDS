# ADR 0006 — Generic evidence registry with ingestion-side content hashing

- **Status:** Accepted
- **Date:** 2026-09-07
- **Deciders:** EvoNIDS maintainers

## Context

Alerts carried a free-form string array named "evidence" but no object recorded *the
original fact*: raw EVE lines were parsed, transformed into flow/alert rows and then
discarded. There was no content hash, no observation/receipt separation, no parser
identity, no integrity or missing-data marker, and no way for cases or an AI
investigation to reference the exact original event behind a derived alert.

## Decision

1. **`evidence_records`** is the generic evidence registry: one row per accepted raw
   event with `source_type` (`suricata_eve` today), sensor id, event/external ids,
   `observed_at` (event timestamp) vs `received_at` (ingest time), `content_sha256` of
   the raw line, integrity (`complete`/`partial`), data-missing marker (`none`/
   `artifact_truncated`), parser version, redaction flag, `source_ref_type`/`id`
   pointing at the derived flow/alert row, artifact size, and an extracted-fields JSON
   object. Original facts and derived detections stay separate.
2. **`evidence_artifacts`** stores the raw line (bounded: events above 1 MiB keep the
   registry row with `integrity=partial` and no artifact).
3. **Ingestion writes evidence in the same transaction** as flow/alert creation.
   Evidence ids are deterministic (sensor + event type + external id + timestamp), so
   retried uploads never duplicate registry rows; duplicate *events* never touch the
   registry at all.
4. **API**: `GET /api/v1/evidence` (open, filterable by sensor/event/external id/
   content hash, paginated) and `GET /api/v1/evidence/{id}` (admin-only detail with the
   raw artifact text, because the raw object may contain sensitive payloads).
5. Alert-to-evidence navigation uses `source_ref_id`; case attachment still operates on
   alerts, and evidence→case links arrive with the investigation iteration.

## Alternatives considered

- Storing raw lines inside `flows`/`alerts` columns: rejected — evidence must be
  source-agnostic (Zeek, replay, NetFlow later) and independent of derived rows.
- External object storage now: deferred to the collection plane (Phase 3/MinIO), where
  PCAP and bulk evidence move out of the database.

## Migration / rollback

`alembic upgrade head` (revision `20260907_0009`). Rollback: `alembic downgrade
20260907_0008` drops the two tables. Backfill of pre-existing rows is intentionally not
performed: only events ingested after this migration carry registry rows (documented,
honest lineage).
