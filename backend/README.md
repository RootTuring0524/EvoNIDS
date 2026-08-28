# EvoNIDS Backend

This directory is the real backend foundation for the existing Nuxt console.

## Local development

```powershell
cd backend
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev,ml]"
Copy-Item .env.example .env
alembic upgrade head
uvicorn app.main:app --reload
```

Open `http://127.0.0.1:8000/docs` for OpenAPI.

The default SQLite database is only for local learning and tests. Docker Compose uses PostgreSQL.

## Seed the explicit local demo

The real backend starts empty by design. To load one labeled attack flow, one normal flow, one
Suricata alert, one candidate rule and a mixed-trust knowledge set:

```powershell
python .\scripts\seed_demo.py
```

The command is idempotent and never runs automatically. Open the candidate rule in the console,
submit validation twice (start and complete), review the measured replay metrics, confirm it, and
then approve deployment. Every step is persisted in the audit log.

## Implemented foundation

- request IDs, controlled errors and health checks;
- SQLAlchemy models for sensors, flows, model versions, inferences, alerts, rules, rule versions,
  validations and audit events;
- paginated alert, flow, rule and audit APIs matching the current Nuxt contracts;
- persisted alert assignment/disposition and rule lifecycle actions with audit events;
- labeled-flow rule replay with measured precision, recall, F1 and false-positive rate;
- versioned feature definitions;
- Suricata EVE JSON parser and idempotent flow/alert ingestion API;
- sensor registry, heartbeat endpoint, derived online/degraded/offline health and accumulated ingest
  quality counters;
- persisted operations overview metrics for alerts, flows, rules and collection health;
- persistent, auditable CPU baseline training runs with dataset identity verification, stratified
  train/validation/test evaluation and SHA-256-verified local artifacts;
- persisted knowledge evidence with keyword retrieval, trust filtering and prompt-injection
  quarantine;
- alert-detail evidence retrieval and a strict boundary that only passes trusted evidence to the
  Agent contract;
- pure Python structured rule evaluator and lifecycle transition guard;
- Alembic migration entry point.

## Knowledge evidence security

Evidence reads are available from `GET /api/v1/rag?query=...`. The current implementation reports
`keyword_fallback` honestly: vector candidates and vector scores stay at zero until an embedding
pipeline is implemented.

API writes are disabled unless `EVONIDS_ADMIN_API_TOKEN` is configured. When enabled, use:

```powershell
curl.exe -X POST "http://127.0.0.1:8000/api/v1/rag/evidence" `
  -H "Content-Type: application/json" `
  -H "X-EvoNIDS-Admin-Token: YOUR_LOCAL_ADMIN_TOKEN" `
  --data-binary "@evidence.json"
```

The server detects common prompt-injection markers and forces suspicious evidence into the blocked
review path. The demo seed writes directly through the service and therefore does not require an
HTTP admin token.

## Import Suricata EVE JSON

With the backend running, import an EVE JSON/NDJSON file:

```powershell
curl.exe -X POST `
  "http://127.0.0.1:8000/api/v1/ingestion/eve?sensorId=lab-core-01" `
  -H "Content-Type: application/x-ndjson" `
  -H "X-EvoNIDS-Sensor-Token: YOUR_SENSOR_TOKEN" `
  --data-binary "@C:\path\to\eve.json"
```

The endpoint currently accepts files up to 10 MiB, rejects malformed lines individually, and
deduplicates repeated flow and alert events. Imported records are available from `/api/v1/flows`
and `/api/v1/alerts`. In development only, ingestion remains available when no sensor token is
configured. Outside development, `EVONIDS_SENSOR_INGEST_TOKEN` is mandatory. The Nuxt server can
forward it from the server-only `NUXT_SENSOR_INGEST_TOKEN` setting; it is never returned to the
browser.

Sensor inventory is available from `GET /api/v1/sensors`, heartbeats from
`POST /api/v1/sensors/{sensorId}/heartbeat`, and the operations aggregate from
`GET /api/v1/overview`. Administrative sensor updates require `EVONIDS_ADMIN_API_TOKEN` and are
recorded in the audit log.

`GET /api/v1/readiness` returns a non-secret deployment checklist covering database access,
PostgreSQL/non-placeholder credentials, administrative and sensor authentication, collection
health, ML dependencies, training executor durability, writable artifact storage, model artifacts
and runtime mode.
Warnings remain visible in development instead of falsely reporting production readiness.

Flow Transformer and AutoEncoder training, online model inference, real-time packet capture, vector
embeddings and persisted Agent runs remain separate future services.

## Register real training datasets

Dataset metadata is not seeded. Put an actual `.csv` or `.csv.gz` file inside the configured
`EVONIDS_DATASET_ROOT` (defaults to `backend/datasets` for local development), then register its
relative path through `POST /api/v1/datasets` with the administrator token. The API returns `202`
and profiles the file in the background. It calculates a SHA-256 digest and reads every CSV row to
derive the real row count, feature count, missing-value count and label distribution. It never
modifies or deletes the source file.

Example request body:

```json
{
  "id": "DS-CIC-2017",
  "name": "CICIDS2017",
  "version": "original-csv",
  "relativePath": "CICIDS2017/Friday-WorkingHours.csv",
  "sourceUri": "https://www.unb.ca/cic/datasets/ids-2017.html",
  "labelColumn": "Label",
  "normalLabels": ["BENIGN"],
  "mainTrainingSet": true,
  "unknownHoldout": true,
  "ruleReplay": true
}
```

Absolute paths, path traversal and files outside the configured root are rejected. Removing a
dataset registration only removes its database record; it never deletes the dataset file.

## Train the real known-attack CPU baseline

After a registered dataset reaches `ready`, start a run through `POST /api/v1/training/runs` or the
model operations page. The endpoint requires `EVONIDS_ADMIN_API_TOKEN`. The worker re-hashes the
complete source file before fitting, scans the complete CSV, takes a deterministic bounded sample,
uses only sufficiently numeric non-constant features, and persists independent validation and test
metrics. Artifacts are written below `EVONIDS_MODEL_ARTIFACT_ROOT`; the dataset digest, run config,
feature list, split sizes, metrics, Python/NumPy/pandas/scikit-learn/joblib versions and artifact digest
remain linked in the database and audit log.
Sampling uses per-class priority reservoirs based on the profiled full-file label distribution, so
long-tail classes are retained instead of being accidentally erased by a uniform sample. Obvious
identifiers, timestamps, IP columns and alternate target columns are excluded to reduce leakage.
Once a dataset has a linked training run, its content digest becomes immutable lineage: reprofile
may verify the same file, but changed content must be registered as a new dataset version. The
referenced registration also cannot be deleted.

Example request body:

```json
{
  "datasetId": "DS-CIC-2017",
  "algorithm": "hist_gradient_boosting",
  "maxRows": 250000,
  "randomSeed": 42,
  "maxIter": 200,
  "learningRate": 0.08,
  "maxLeafNodes": 31,
  "l2Regularization": 0.1,
  "actor": "local-ml-operator"
}
```

This is deliberately a `HistGradientBoostingClassifier` baseline, not the locked Flow Transformer.
It establishes a reproducible benchmark that the later Transformer must beat under the same dataset
identity and split protocol. Set `EVONIDS_TRAINING_CPU_THREADS=0` to let the runtime use the machine
default, or a positive integer to cap CPU worker threads. Training runs execute in the FastAPI
process today; a production deployment should move them to a durable job queue before accepting
concurrent or multi-hour workloads. Until that queue exists, API startup explicitly marks jobs
interrupted by a prior process exit as failed and records an audit event instead of leaving them
stuck in a false running state.
