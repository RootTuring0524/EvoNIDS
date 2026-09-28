# EvoNIDS Helm Chart

Kubernetes/Helm deployment of the EvoNIDS stack that the root
`docker-compose.yml` + `docker-compose.prod.yml` describe:

| Component | Image family | Role |
|---|---|---|
| `api` | FastAPI/uvicorn (`backend/`, port 8000) | `/api/v1/health`, `/api/v1/readiness`, EVE ingestion, training worker |
| `web` | Nuxt 4 console/BFF (`project/`, port 3000) | console UI + `/api/**` BFF routes |
| `postgres` | `pgvector/pgvector:pg17` | single primary, database `evonids` |
| `migration` | api image (`alembic upgrade head`) | Helm hook `pre-install,pre-upgrade` |

> **Validation status (honest):** this chart was authored on a machine without
> Docker, Helm or kubectl. It has **not** been rendered with `helm template`,
> linted with `helm lint`, or applied to a cluster. Do a full dry-run + staging
> deployment and read `docs/runbooks/backup-restore-drill.md` before any
> production use.

## 1. Prerequisites

- Kubernetes ≥ 1.26, Helm ≥ 3.12.
- The api/web images are **not published**: build them from this repository
  and push them to a registry the cluster can pull from.

```bash
cd <repo-root>
cp .env.example .env            # only needed for compose; chart takes --set values
docker compose -f docker-compose.yml build api web
docker tag <compose-image-api>  <registry>/evonids/api:0.1.0
docker tag <compose-image-web>  <registry>/evonids/web:0.1.0
docker push <registry>/evonids/api:0.1.0
docker push <registry>/evonids/web:0.1.0
```

## 2. Install

All credentials are values-driven. Choose one source:

1. `--set`/private values file (simplest; nothing committed):
   ```bash
   helm upgrade --install evonids deploy/helm/evonids \
     --namespace evonids --create-namespace --wait --timeout 10m \
     --set secrets.adminApiToken='<long-random>' \
     --set secrets.sensorIngestToken='<long-random>' \
     --set secrets.postgresPassword='<strong-password>' \
     --set secrets.consolePassword='<console-login-password>' \
     --set image.registry='<registry>' \
     --set ingress.host='console.example.com'
   ```
2. external-secrets / pre-created Secret: create a Secret containing the
   canonical keys documented in `templates/secret.yaml`
   (`admin-token`, `sensor-token`, `analyst-token`, `postgres-password`,
   `console-password`, `deepseek-api-key`) and install with
   `--set secrets.existingSecret=<name>` (the chart then renders no Secret).

Production example: `values-production.yaml` (no secrets inside).

### What happens at install/upgrade

1. Pre-install/pre-upgrade hook Job `evonids-migration` runs
   `alembic upgrade head` (api image, working dir `/app`). The hook Job is
   self-contained — its env is rendered inline from values (Helm runs hooks
   before the release's own ConfigMap/Secret exist); with
   `secrets.existingSecret` the password comes from that existing Secret via
   `secretKeyRef`.
2. Migrations read `EVONIDS_DATABASE_URL` which the chart composes at runtime
   from `POSTGRES_*` env vars:
   `postgresql+psycopg://<user>:<password>@<postgres-svc>:5432/<database>`.
   Override with `api.env.databaseUrlOverride` when pointing at an external
   database.
3. The api image itself also runs `alembic upgrade head` at boot
   (`backend/Dockerfile`); once the hook finished it is an idempotent no-op.
4. Deployments start only when probes pass:
   - api: startup/liveness `GET /api/v1/health`; readiness `GET /api/v1/readiness`
   - web: startup/readiness/liveness `GET /api/auth/status`
   - postgres: `pg_isready -U evonids -d evonids`

## 3. Verify

```bash
helm test evonids -n evonids          # connectivity test pod
kubectl -n evonids get pods,pvc,svc
curl -fsS https://console.example.com/api/v1/health   # via ingress (exposeApi)
curl -fsS http://<web-svc>/api/auth/status
kubectl -n evonids logs deploy/evonids-migration --tail=50   # or job logs
kubectl -n evonids get events --sort-by=.lastTimestamp
```

## 4. Configuration highlights (`values.yaml`)

- **Env names** are copied from `docker-compose(.prod).yml`,
  `backend/app/core/config.py` (`EVONIDS_*`), `backend/.env.example`,
  `project/.env.example`, `project/nuxt.config.ts` (`NUXT_*`); nothing invented.
- **Non-secret config**: one ConfigMap (`<release>-config`) consumed by every
  workload. Pods carry `checksum/config` + `checksum/secret` annotations so
  ConfigMap/Secret changes roll Deployments/StatefulSet.
- **Secrets**: canonical key Secret described in `templates/secret.yaml`;
  `secrets.existingSecret` for external-secrets flows. Rotating an *external*
  Secret afterwards needs `kubectl rollout restart` (checksum cannot observe
  out-of-band edits).
- **Storage**:
  - postgres → PVC `<release>-postgres` (`postgres.persistence.*`).
  - datasets + trained model artifacts → PVC `<release>-data`
    (`api.dataVolume.*`). The api pod seeds the sub-directories at startup;
    upload your dataset CSVs into that volume (paths relative to
    `EVONIDS_DATASET_ROOT`, i.e. the `datasets/` sub-path) before registering
    them. Compose keeps datasets on the host (`./backend/datasets`) — mirror
    those files into the volume.
- **HPA**: `web.autoscaling` is safe to enable (stateless). `api.autoscaling`
  is **disabled by default**: the training worker is a per-pod in-process loop
  that claims `queued` TrainingRun rows without row locks
  (`docs/adr/0004-in-process-training-worker.md`), and the data PVC defaults
  to ReadWriteOnce. Scaling api > 1 needs a ReadWriteMany volume and operator
  awareness that duplicate workers can race on queued runs.
- **PDB**: postgres has `minAvailable: 1` by default — it protects the single
  primary but also blocks node drains while the pod is healthy; disable during
  maintenance.
- **NetworkPolicy**: default-deny ingress+egress with explicit allows
  (web←ingress-controller, web→api, api→postgres, migration→postgres, DNS).
  When `ingress.exposeApi: true`, the ingress controller may reach api:8000
  directly (`/api/v1`). Outbound LLM calls from web require
  `networkPolicy.allowWebExternalEgress: true`.
- **Non-root / read-only**: api/web/migration run as uid 10001 with
  `readOnlyRootFilesystem: true` (emptyDir `/tmp`); postgres runs as the
  official image uid 999 with a writable root (entrypoint/runtime needs),
  data on its own PVC.

## 5. Upgrade / rollback / uninstall

```bash
# upgrade (migration hook runs first)
helm upgrade evonids deploy/helm/evonids -n evonids -f values-production.yaml --set secrets... 

# rollback (DB-migration-safe: restore a pg_dump first when downgrading code)
helm rollback evonids <revision> -n evonids

# uninstall WITHOUT deleting data: PVCs are kept unless you delete them
helm uninstall evonids -n evonids
kubectl -n evonids delete pvc evonids-postgres evonids-data   # data loss!
```

## 6. Backup / restore in-cluster

The repo backup scripts (`scripts/backup/`) target the Compose path
(host pg_dump/psql). For the in-cluster PostgreSQL use the same scripts with
`PGHOST`/`PGPORT` pointing at a `kubectl port-forward` of
`svc/evonids-postgres`, or use volume snapshots of `evonids-postgres` and
`evonids-data`. Model artifacts + datasets live on `evonids-data`; dataset
registration metadata lives inside the database dump. See
`scripts/backup/README.md` and `docs/runbooks/backup-restore-drill.md`.

## 7. Layout

```
deploy/helm/evonids/
├── Chart.yaml  values.yaml  values.schema.json  values-production.yaml
├── .helmignore  README.md
└── templates/
    ├── _helpers.tpl  namespace.yaml  configmap.yaml  secret.yaml
    ├── api-deployment.yaml  api-service.yaml
    ├── web-deployment.yaml  web-service.yaml
    ├── postgres-statefulset.yaml  postgres-service.yaml  postgres-pvc.yaml
    ├── data-pvc.yaml             # api datasets/model-artifacts volume
    ├── migration-job.yaml  ingress.yaml  networkpolicy.yaml
    ├── poddisruptionbudget.yaml  hpa.yaml
    ├── serviceaccount.yaml  rbac.yaml  NOTES.txt
    └── tests/connection-test.yaml
```
