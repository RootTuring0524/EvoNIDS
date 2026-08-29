# Changelog

All notable changes to EvoNIDS are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-08-28

Initial public release. The detection channels shipped in this version are the
HistGradientBoosting CPU baseline and the PyTorch AutoEncoder anomaly channel;
the Flow Transformer is intentionally **not** part of this release and is
planned for 0.2.0, where it must beat the CPU baseline under the same dataset
identity and split protocol.

### Added

#### Backend

- FastAPI application with SQLAlchemy persistence for sensors, flows, model
  versions, inferences, alerts, rules, rule versions, validations, dataset
  registrations, knowledge evidence and audit events; SQLite for local
  development, PostgreSQL as the target container runtime, and an Alembic
  migration entry point.
- Request IDs, controlled error responses, health checks
  (`GET /api/v1/health`) and a non-secret readiness checklist
  (`GET /api/v1/readiness`) covering database access, non-placeholder
  credentials, administrative/sensor authentication, collection health, ML
  dependencies, training executor durability, writable artifact storage and
  runtime mode.
- Sensor registry with heartbeat ingestion, derived online/degraded/offline
  health and accumulated ingest-quality counters, aggregated into persisted
  operations-overview metrics for alerts, flows, rules and collection health.
- Suricata EVE JSON/NDJSON ingestion endpoint accepting files up to 10 MiB,
  rejecting malformed lines individually and deduplicating repeated flow and
  alert events by external IDs; sensor-token authentication is mandatory
  outside development.
- Administrative write protection via `EVONIDS_ADMIN_API_TOKEN` for alert
  disposition, rule lifecycle actions, dataset registration, knowledge writes
  and sensor updates, all recorded in the audit log.

#### Detection & Models

- Dataset registry that accepts only relative CSV/CSV.GZ paths under
  `EVONIDS_DATASET_ROOT` and profiles registered files in the background:
  real SHA-256 digest, row count, feature count, missing values and label
  distribution. No dataset rows or evaluation scores are created
  automatically; absolute paths and path traversal are rejected; deleting a
  registration removes only the database record, never the source file.
- Known-attack classification channel: persistent, auditable
  `HistGradientBoostingClassifier` CPU baseline training runs that re-hash the
  complete source file before fitting, scan the full CSV, take a deterministic
  bounded sample with per-class priority reservoirs, exclude identifier and
  leakage-prone columns, persist independent validation/test metrics including
  per-class metrics and confusion matrices, and write a local model artifact
  with its own SHA-256 linked to the run config, feature list, split sizes,
  metrics and Python/NumPy/pandas/scikit-learn/joblib versions in the database
  and audit log.
- Immutable dataset lineage: once a dataset has a linked training run, its
  content digest becomes immutable and the registration is protected from
  deletion; changed content must be registered as a new version. Training jobs
  interrupted by a prior process exit are marked failed at API startup with an
  audit event instead of staying stuck in a false running state.
- Anomaly channel: PyTorch CPU AutoEncoder training on normal flows, persisted
  as a versioned model artifact, with reconstruction-error threshold evaluation
  over the labeled flow table.
- Dual-channel inference backfill script that scores labeled replay flows with
  both the HGB baseline and the AutoEncoder and persists per-flow inference and
  fusion evidence.
- Reproducible CICIDS2017 PCAP research scripts for flow extraction, baseline
  bootstrap, labeled replay import and an idempotent demo seed containing
  trusted, review-only and prompt-injection-like evidence.

#### Rule governance

- Pure-Python structured rule interpreter over versioned feature definitions,
  plus a lifecycle transition guard.
- Rule lifecycle state machine with creation, validation, rejection,
  confirmation, deployment, remediation and deprecation transitions, every
  action persisted with audit events.
- Labeled-flow rule replay validation with measured precision, recall, F1 and
  false-positive rate; validations run as explicit start/complete steps and the
  measured replay metrics must be reviewed before confirmation and deployment.

#### Knowledge & Agent

- Persisted knowledge evidence with source, authorization, agent-usage
  permission and prompt-injection risk fields; keyword retrieval that honestly
  reports `keyword_fallback` (vector candidates and scores stay at zero until
  an embedding pipeline is implemented).
- Trust filtering and prompt-injection quarantine: common injection markers
  force suspicious evidence into the blocked review path; blocked records stay
  visible for review but are never sent to the Agent.
- Alert-detail evidence retrieval behind a strict boundary that only passes
  trusted evidence to the Agent contract.
- Admin-token protected knowledge writes through `POST /api/v1/rag/evidence`.
- DeepSeek Agent alert analysis with candidate rule proposals, proxied through
  the Nuxt server: credentials live only in the server runtime config, the
  connection test really requests the upstream `/models` endpoint with an
  8-second timeout, and the API key, real base URL and upstream response body
  are never returned to the browser.

#### Frontend

- Nuxt 4 console with 11 pages: overview, traffic, sensors, alerts, alert
  detail, rules, rule detail, knowledge, models, audit and settings.
- Mock/real dual mode: `NUXT_PUBLIC_USE_MOCK_API=true` runs the deterministic
  UI demo with no backend; `false` proxies alert, flow and rule requests
  through the Nuxt BFF to FastAPI.
- Nuxt BFF (Nitro) server routes for alerts, datasets, flows, ingestion,
  models, overview, rag, rules, sensors, audit, settings, training and agent
  analysis, with server-only clients so the DeepSeek API key never leaves the
  server runtime.
- Console workflows: collection-plane page reporting registered sensors,
  derived health, ingest quality and bounded EVE file import; model operations
  page for dataset registration, profiling review and CPU baseline training
  runs; alert evidence panel with trust filtering; shared zod schema and
  TypeScript contract layer between app and server.

#### Delivery

- Docker Compose stack (FastAPI, PostgreSQL, Nuxt) with the backend datasets
  mounted read-only, generated model artifacts kept in the managed
  `evonids-models` volume, and administrator/sensor/DeepSeek credentials passed
  only as server environment variables from the uncommitted root `.env`.
- GitHub Actions CI with per-job path filtering: a backend job (ruff + pytest
  on Python 3.11 with the dev and ml extras) and a frontend job
  (frozen-lockfile pnpm install, ESLint, Vitest and a mock-mode Nuxt build on
  Node 22).
- One-command local demonstration scripts (`start-demo.ps1` /
  `stop-demo.ps1`) that start the real SQLite-backed API and Nuxt frontend with
  an ephemeral in-memory administrator/sensor token that is never written to
  disk.

[unreleased]: https://github.com/RootTuring0524/EvoNIDS/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/RootTuring0524/EvoNIDS/releases/tag/v0.1.0
