# Operations Guide

Practical, task-oriented reference for running the real backend and console. For concepts and architecture see [architecture.md](architecture.md).

## Modes

Mock mode (default) keeps the deterministic product demo:

```dotenv
NUXT_PUBLIC_USE_MOCK_API=true
```

Real backend mode sends alert, flow and rule requests through the Nuxt server to FastAPI:

```dotenv
NUXT_PUBLIC_USE_MOCK_API=false
NUXT_BACKEND_API_BASE=http://127.0.0.1:8000/api/v1
NUXT_SENSOR_INGEST_TOKEN=use-the-same-value-as-the-backend-sensor-token
NUXT_BACKEND_ADMIN_TOKEN=use-the-same-value-as-the-backend-admin-token
```

DeepSeek credentials remain server-only. Never commit `.env` or paste a key into source code.

### Console authentication

Console login is optional. Set a password to enable it:

```dotenv
NUXT_CONSOLE_PASSWORD=use-a-long-random-password
NUXT_CONSOLE_SESSION_HOURS=24
```

- When `NUXT_CONSOLE_PASSWORD` is set, every console page and `/api/**` BFF route requires login (the login page itself is the only exception): `POST /api/auth/login` exchanges the password for a signed HttpOnly session cookie, `POST /api/auth/logout` clears it, and `GET /api/auth/status` returns `{required, authenticated}`.
- `NUXT_CONSOLE_SESSION_HOURS` sets the session lifetime in hours and defaults to 24.
- Leave `NUXT_CONSOLE_PASSWORD` empty to keep the console open — the intended mode for local development and demos. This is a minimal gate, not a replacement for a TLS-terminating reverse proxy in real deployments.
- Forgot the password? There is no recovery flow: update `NUXT_CONSOLE_PASSWORD` in the uncommitted `.env` and restart the console.

## One-command local demonstration (Windows)

`start-demo.ps1` starts the SQLite-backed API and the Nuxt console with one ephemeral in-memory administrator/sensor token. The token is not written to disk. The script imports only `NUXT_DEEPSEEK_API_BASE`, `NUXT_DEEPSEEK_API_KEY` and `NUXT_DEEPSEEK_MODEL` from the uncommitted root `.env`:

```powershell
Set-Location "<repo-root>"   # or your clone location
.\start-demo.ps1               # open http://127.0.0.1:3000/overview
.\stop-demo.ps1
```

If PowerShell blocks local scripts: `Set-ExecutionPolicy -Scope Process Bypass` first.

## Import real Suricata events

```powershell
curl.exe -X POST `
  "http://127.0.0.1:8000/api/v1/ingestion/eve?sensorId=lab-core-01" `
  -H "Content-Type: application/x-ndjson" `
  -H "X-EvoNIDS-Sensor-Token: YOUR_SENSOR_TOKEN" `
  --data-binary "@C:\path\to\eve.json"
```

Files up to 10 MiB are accepted; malformed lines are rejected individually; repeated flow/alert events deduplicate. Imported records appear in `/api/v1/flows`, `/api/v1/alerts` and the console in real mode. In development only, ingestion remains available without a sensor token; outside development `EVONIDS_SENSOR_INGEST_TOKEN` is mandatory.

Sensor inventory: `GET /api/v1/sensors` · heartbeats: `POST /api/v1/sensors/{sensorId}/heartbeat` · operations aggregate: `GET /api/v1/overview` · deployment checklist: `GET /api/v1/readiness`.

## Knowledge evidence

Reads: `GET /api/v1/rag?query=...` — reports `keyword_fallback` honestly; vector candidates stay at zero until an embedding pipeline exists.

Writes through `POST /api/v1/rag/evidence` are disabled until `EVONIDS_ADMIN_API_TOKEN` is configured; send the same value in `X-EvoNIDS-Admin-Token`. The server detects common prompt-injection markers and forces suspicious evidence into the blocked review path. The demo seed writes through the service directly and therefore does not require the HTTP admin token.

## Register real training datasets

Dataset metadata is never seeded. Place an actual `.csv`/`.csv.gz` under `EVONIDS_DATASET_ROOT` (defaults to `backend/datasets` locally), then register its **relative** path:

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

`POST /api/v1/datasets` (admin token required) returns `202` and profiles the file in the background: SHA-256, row count, feature count, missing values and label distribution. Absolute paths, path traversal and files outside the root are rejected. Deleting a registration never deletes the file. Once a dataset has a linked training run, its content digest becomes immutable lineage.

## Train the known-attack baseline

After a dataset reaches `ready`:

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

`POST /api/v1/training/runs` (admin token). The worker re-hashes the full source file, takes a deterministic per-class priority reservoir sample, fits only sufficiently numeric non-constant features, persists independent validation/test metrics, and writes a SHA-256-verified artifact under `EVONIDS_MODEL_ARTIFACT_ROOT` with dataset digest, config, feature list, split sizes, metrics and library versions linked in the database and audit log.

This is deliberately a `HistGradientBoostingClassifier` baseline — the benchmark the planned Flow Transformer must beat under the same dataset identity and split protocol. `EVONIDS_TRAINING_CPU_THREADS=0` uses the runtime default; a positive integer caps worker threads. Training executes in the FastAPI process today; startup marks jobs interrupted by a prior process exit as failed instead of leaving them stuck in a false running state.

## Reproduce the CICIDS2017 PCAP baseline

The released repository does not include the SQLite database or the 235 MB dataset. `seed_demo.py` loads a small demo; to reproduce the full July 2026 baseline, extract the dataset from the official PCAPs (see DATA_CARD.md) and rerun the pipeline:

```powershell
Set-Location "<repo-root>\backend"
.\.venv\Scripts\Activate.ps1

python .\scripts\extract_cicids2017_flows.py `
  --input-root "C:\path\to\CICIDS2017" `
  --output ".\datasets\CICIDS2017\cicids2017_pcap_flow_research_v1.csv.gz" `
  --benign-sample-rate 0.05

python .\scripts\bootstrap_cicids2017_baseline.py `
  --max-rows 250000 `
  --max-iter 160 `
  --random-seed 20260728

python .\scripts\import_cicids2017_replay.py
```

The derived flow table is a reproducible EvoNIDS research asset, not a byte-for-byte copy of the official CICFlowMeter CSV. See [DATA_CARD.md](../DATA_CARD.md) and [MODEL_CARD.md](../MODEL_CARD.md).

## Local demo seed

```powershell
Set-Location "<repo-root>\backend"
.\.venv\Scripts\Activate.ps1
python .\scripts\seed_demo.py
```

Idempotent; loads one labeled attack flow, one normal flow, one Suricata alert, one candidate rule and a mixed-trust knowledge set (trusted, review-only and prompt-injection-like evidence) so the knowledge page and alert evidence panel demonstrate the filtering policy without pretending a vector model ran. Open the candidate rule in the console, submit validation twice (start and complete), review the measured replay metrics, confirm it, then approve deployment — every step is persisted in the audit log.

## AutoEncoder channel

Training, threshold evaluation and dual-channel backfill scoring of replay flows (HGB + AE fusion evidence persisted to the `inferences` table):

```powershell
python .\scripts\train_autoencoder.py --help
python .\scripts\evaluate_autoencoder_thresholds.py --help
python .\scripts\backfill_dual_channel_inference.py --help
python .\scripts\ae_operating_points.py --help
```

## Container stack

```powershell
Copy-Item .env.example .env
docker compose up --build
```

The stack mounts `backend/datasets` read-only, keeps model artifacts in the managed `evonids-models` volume, and passes credentials only as server environment variables from the uncommitted root `.env`. Exposed: Nuxt `http://localhost:3000`, FastAPI docs `http://localhost:8000/docs`, health `http://localhost:8000/api/v1/health`.
