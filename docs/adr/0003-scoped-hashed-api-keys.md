# ADR 0003 — Scoped, hashed API keys with environment-token compatibility

- **Status:** Accepted
- **Date:** 2026-09-07
- **Deciders:** EvoNIDS maintainers

## Context

The API authenticated callers with two shared environment secrets
(`EVONIDS_ADMIN_API_TOKEN`, `EVONIDS_SENSOR_INGEST_TOKEN`). All administrative callers
shared one credential, there was no per-machine identity, no scope separation, no rotation
path, and secrets sat in plaintext in the environment of every replica.

## Decision

1. **Machine identities become database rows.** A new `api_keys` table (Alembic
   `20260907_0007`) stores only a salted SHA-256 digest of each secret
   (`sha256$<salt>$<digest>`); the raw secret is returned exactly once at creation and can
   never be read back.
2. **Scopes.** Each key carries exactly one scope: `admin`, `sensor` or `analyst`.
   Dependencies resolve the caller's scope (`require_admin_token`,
   `require_sensor_token`, `require_analyst_token`) and attach an `ApiKeyPrincipal`
   (`kind`, `scope`, `key_id`, `name`) to `request.state.principal` for downstream
   audit naming.
3. **Management API.** `GET/POST /api/v1/admin/api-keys` and
   `POST /api/v1/admin/api-keys/{id}/revoke` create, list and revoke keys; creation and
   revocation write audit events (`apikey.created`, `apikey.revoked`).
4. **Legacy compatibility.** Environment tokens remain valid and keep their exact
   semantics (constant-time comparison; no database round-trip; the development sensor
   bypass is unchanged). A credential family is "unconfigured" (503) only when neither the
   environment token nor any enabled key of that scope exists, so the environment token
   remains the bootstrap path for creating the first database keys.
5. **Operational detail.** `last_used_at` refreshes at most every five minutes per key to
   avoid a write per request.

## Alternatives considered

- Users/RBAC tables with OIDC: deferred to the identity phase that introduces human
  sessions; machine identities and human identities are separate concerns and this ADR
  only covers machines (sensors, consoles, integrations).
- Encrypted key storage: plaintext-equivalent server-side encryption adds a key-management
  dependency without raising the bar over salted hashes for single-purpose machine keys.

## Migration

`alembic upgrade head` creates the table. Existing environment tokens keep working without
any change. Rollback: `alembic downgrade 20260723_0006`.

## Cost

One migration, one service module, one admin router, principal plumbing in the three
existing auth dependencies, eight integration/unit tests.
