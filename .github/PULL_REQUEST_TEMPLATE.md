<!-- Suggested title format: type(scope): summary — e.g. feat(rules): guard approve transition -->

## Purpose

<!-- Why is this change needed? Link related issues with "Fixes #123" or "Refs #123". -->

## Changes

<!-- Summarize the concrete changes. One bullet per logical change. -->

## Tests

<!-- Check only the commands you actually ran locally. -->

- [ ] `cd backend && pip install -e ".[dev,ml]"`
- [ ] `cd backend && ruff check .`
- [ ] `cd backend && pytest -q`
- [ ] `cd project && pnpm install --frozen-lockfile`
- [ ] `cd project && pnpm lint`
- [ ] `cd project && pnpm test`
- [ ] `cd project && pnpm typecheck`
- [ ] `cd project && pnpm build` (with `NUXT_PUBLIC_USE_MOCK_API=true`)
- [ ] No new tests needed — explain why in Changes

## Screenshots

<!-- Required for any console/UI change. Paste before/after screenshots. -->

- [ ] UI changed — screenshots attached below
- [ ] No UI change

## Data or model impact

<!-- Does this PR touch data contracts (dataset registration, profiling, SHA-256 lineage, label columns) or model metrics (training, evaluation, replay)? -->

- [ ] No data contract or model metric impact
- [ ] Data contract touched — migration notes attached
- [ ] Model metrics touched — regression comparison attached (same dataset identity, same split protocol)

Details:

## Security impact

<!-- Consider: secrets, token scopes, prompt-injection surface, ingestion boundary. -->

- [ ] No new secrets or tokens introduced
- [ ] No change to token scopes or permission boundaries (admin/sensor tokens, audit log)
- [ ] No new prompt-injection surface (knowledge evidence, Agent inputs)
- [ ] Ingestion boundary unchanged (EVE JSON size limits, malformed-line handling, dedup)

Details:

## Rollback

<!-- How to revert safely: DB migrations to roll back, artifacts/datasets to invalidate, feature flags to flip. -->

---

> **Maintainer review required:** PRs that touch data contracts, model metrics, rule lifecycle transitions or permission boundaries need item-by-item maintainer review before merge.
