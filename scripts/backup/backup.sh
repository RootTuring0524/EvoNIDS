#!/usr/bin/env bash
#
# EvoNIDS backup.sh — PostgreSQL logical backup (pg_dump -Fc) with
# checksummed, timestamped artifacts, plus model artifacts and dataset
# metadata. Retention-prunes old backups.
#
# Environment (required):
#   PGHOST PGPORT(optional, 5432) PGUSER PGPASSWORD PGDATABASE
#   The script refuses to run when these PG* variables are missing.
#   Optional: EVONIDS_BACKUP_DIR, EVONIDS_MODEL_ARTIFACT_DIR,
#   EVONIDS_DATASETS_DIR, EVONIDS_BACKUP_RETENTION_DAYS,
#   EVONIDS_BACKUP_KEEP_LATEST
#
# Repository paths (relative to <repo-root>/scripts/backup):
#   ../..                    -> repo root
#   ../../backend/model-artifacts  -> trained artifacts (local default)
#   ../../backend/datasets         -> registered dataset files (optional)
#
# Compatible with both the Docker Compose deployment (port-forward the
# postgres port or run from a host with network access to it) and a local
# PostgreSQL. NOT a substitute for WAL/volume backups of an HA cluster.
#
# NOTE: authored on a machine without bash; run `bash -n backup.sh` on a
# POSIX host before first use (see scripts/backup/README.md).

set -euo pipefail

# ---------------------------------------------------------------------------
# Locate repo root (this script lives at <repo>/scripts/backup/backup.sh)
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# ---------------------------------------------------------------------------
# Defaults (env-overridable)
# ---------------------------------------------------------------------------
BACKUP_DIR="${EVONIDS_BACKUP_DIR:-${REPO_ROOT}/backups}"
MODEL_DIR="${EVONIDS_MODEL_ARTIFACT_DIR:-${REPO_ROOT}/backend/model-artifacts}"
DATASETS_DIR="${EVONIDS_DATASETS_DIR:-${REPO_ROOT}/backend/datasets}"
RETENTION_DAYS="${EVONIDS_BACKUP_RETENTION_DAYS:-30}"
KEEP_LATEST="${EVONIDS_BACKUP_KEEP_LATEST:-14}"
INCLUDE_DATASETS=0
ENV_FILE=""

usage() {
  cat <<'EOF'
Usage: backup.sh [options]

  --env-file FILE     source FILE (e.g. the root .env) and map POSTGRES_*
                      variables into PG* when the PG* ones are absent
  --backup-dir DIR    target root directory (default: $EVONIDS_BACKUP_DIR
                      or <repo>/backups)
  --include-datasets  also archive the dataset CSV/CSV.GZ files under
                      EVONIDS_DATASETS_DIR (large; datasets metadata is always
                      exported from the database)
  --retention-days N  prune backups older than N days (default 30; 0=off)
  --keep-latest N     always keep the N newest backups (default 14)
  -h, --help          show this help

Required environment: PGHOST, PGUSER, PGPASSWORD, PGDATABASE (PGPORT
defaults to 5432). The script refuses to run without them.
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --env-file)
      ENV_FILE="${2:?--env-file requires a path}"
      shift 2
      ;;
    --backup-dir)
      BACKUP_DIR="${2:?--backup-dir requires a path}"
      shift 2
      ;;
    --include-datasets)
      INCLUDE_DATASETS=1
      shift
      ;;
    --retention-days)
      RETENTION_DAYS="${2:?--retention-days requires a number}"
      shift 2
      ;;
    --keep-latest)
      KEEP_LATEST="${2:?--keep-latest requires a number}"
      shift 2
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      echo "backup.sh: unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

# ---------------------------------------------------------------------------
# Tool availability
# ---------------------------------------------------------------------------
for tool in pg_dump sha256sum tar gzip date; do
  if ! command -v "${tool}" >/dev/null 2>&1; then
    echo "backup.sh: required tool missing: ${tool}" >&2
    exit 1
  fi
done

# ---------------------------------------------------------------------------
# Load --env-file and map POSTGRES_* -> PG*
# ---------------------------------------------------------------------------
if [ -n "${ENV_FILE}" ]; then
  if [ ! -f "${ENV_FILE}" ]; then
    echo "backup.sh: --env-file not found: ${ENV_FILE}" >&2
    exit 1
  fi
  # shellcheck disable=SC1090
  set -a
  # Safe sourcing: only KEY=VALUE lines are meaningful to us. Trim CR so a
  # Windows-edited .env keeps values clean.
  while IFS='=' read -r key value; do
    value="${value%$'\r'}"
    case "${key}" in
      POSTGRES_DB|POSTGRES_USER|POSTGRES_PASSWORD|POSTGRES_PORT|EVONIDS_BACKUP_DIR|\
      EVONIDS_MODEL_ARTIFACT_DIR|EVONIDS_DATASETS_DIR|EVONIDS_BACKUP_RETENTION_DAYS|\
      EVONIDS_BACKUP_KEEP_LATEST)
        export "${key}=${value}"
        ;;
    esac
  done < <(grep -E '^[A-Za-z_][A-Za-z0-9_]*=' "${ENV_FILE}" | sed 's/\r$//' || true)
  set +a
fi

export PGHOST="${PGHOST:-127.0.0.1}"
export PGPORT="${PGPORT:-5432}"
if [ -z "${PGUSER:-}" ] && [ -n "${POSTGRES_USER:-}" ]; then
  export PGUSER="${POSTGRES_USER}"
fi
if [ -z "${PGPASSWORD:-}" ] && [ -n "${POSTGRES_PASSWORD:-}" ]; then
  export PGPASSWORD="${POSTGRES_PASSWORD}"
fi
if [ -z "${PGDATABASE:-}" ] && [ -n "${POSTGRES_DB:-}" ]; then
  export PGDATABASE="${POSTGRES_DB}"
fi

# ---------------------------------------------------------------------------
# Refuse without PG* env
# ---------------------------------------------------------------------------
MISSING=""
for var in PGHOST PGUSER PGPASSWORD PGDATABASE; do
  if [ -z "${!var:-}" ]; then
    MISSING="${MISSING} ${var}"
  fi
done
if [ -n "${MISSING}" ]; then
  echo "backup.sh: refusing to run: required PG* environment variable(s) unset:${MISSING}" >&2
  echo "Set PGHOST PGPORT PGUSER PGPASSWORD PGDATABASE (or pass --env-file with POSTGRES_*) and retry." >&2
  exit 1
fi

mkdir -p "${BACKUP_DIR}"
TS="$(date +%Y%m%d-%H%M%S)"
DEST="${BACKUP_DIR}/evonids-${TS}"
mkdir -p "${DEST}"

DB_FILE="evonids-db-${TS}.dump"
MANIFEST_FILE="datasets-manifest-${TS}.txt"
MODELS_FILE="model-artifacts-${TS}.tar.gz"
DATASETS_FILE="datasets-files-${TS}.tar.gz"
CHECKSUM_FILE="SHA256SUMS.txt"
META_FILE="backup.json"

echo "==> EvoNIDS backup: ${DEST}"

# ---------------------------------------------------------------------------
# 1. PostgreSQL logical dump (custom format)
# ---------------------------------------------------------------------------
echo "==> pg_dump ${PGHOST}:${PGPORT}/${PGDATABASE} as ${PGUSER}"
pg_dump -Fc --no-owner --no-privileges \
  -h "${PGHOST}" -p "${PGPORT}" -U "${PGUSER}" -d "${PGDATABASE}" \
  -f "${DEST}/${DB_FILE}"

# ---------------------------------------------------------------------------
# 2. Dataset metadata manifest (registration records live in the dump too;
#    this is a human-readable sidecar). psql is optional: its absence only
#    skips the sidecar.
# ---------------------------------------------------------------------------
if command -v psql >/dev/null 2>&1; then
  echo "==> exporting dataset metadata manifest"
  psql -h "${PGHOST}" -p "${PGPORT}" -U "${PGUSER}" -d "${PGDATABASE}" \
    -At -F '|' -c \
    "SELECT id, name, version, relative_path, state, COALESCE(sha256, '')
       FROM dataset_assets
      ORDER BY id;" > "${DEST}/${MANIFEST_FILE}" || {
      echo "backup.sh: WARN: dataset manifest export failed (continuing)" >&2
      rm -f "${DEST}/${MANIFEST_FILE}"
    }
else
  echo "backup.sh: WARN: psql not found; dataset metadata sidecar skipped (records are inside the DB dump)" >&2
fi

# ---------------------------------------------------------------------------
# 3. Model artifacts archive (trained joblib models under EVONIDS_MODEL_ARTIFACT_ROOT)
# ---------------------------------------------------------------------------
if [ -d "${MODEL_DIR}" ]; then
  echo "==> archiving model artifacts: ${MODEL_DIR}"
  tar -czf "${DEST}/${MODELS_FILE}" -C "$(dirname "${MODEL_DIR}")" \
    "$(basename "${MODEL_DIR}")"
else
  echo "backup.sh: WARN: model artifact directory not found (skipped): ${MODEL_DIR}" >&2
fi

# ---------------------------------------------------------------------------
# 4. Dataset CSV/CSV.GZ files (optional, opt-in: may be large)
# ---------------------------------------------------------------------------
if [ "${INCLUDE_DATASETS}" -eq 1 ]; then
  if [ -d "${DATASETS_DIR}" ]; then
    echo "==> archiving dataset files: ${DATASETS_DIR}"
    tar -czf "${DEST}/${DATASETS_FILE}" -C "$(dirname "${DATASETS_DIR}")" \
      "$(basename "${DATASETS_DIR}")"
  else
    echo "backup.sh: WARN: datasets directory not found (skipped): ${DATASETS_DIR}" >&2
  fi
fi

# ---------------------------------------------------------------------------
# 5. Checksums + metadata + immediate verify
# ---------------------------------------------------------------------------
echo "==> checksumming artifacts"
(
  cd "${DEST}"
  for f in *; do
    [ -f "${f}" ] && sha256sum "${f}" >> "${CHECKSUM_FILE}"
  done
)

cat > "${DEST}/${META_FILE}" <<EOF
{
  "tool": "scripts/backup/backup.sh",
  "created_at": "${TS}",
  "database": {"host": "${PGHOST}", "port": "${PGPORT}", "name": "${PGDATABASE}", "user": "${PGUSER}"},
  "dump_format": "custom (pg_restore)",
  "pg_dump_version": "$(pg_dump --version 2>/dev/null || echo unknown)"
}
EOF

echo "==> verifying checksums"
( cd "${DEST}" && sha256sum -c "${CHECKSUM_FILE}" )

# ---------------------------------------------------------------------------
# 6. Retention pruning
# ---------------------------------------------------------------------------
prune_old() {
  local base="$1" days="$2" keep="$3"
  if [ "${days}" -le 0 ]; then
    echo "==> retention by age disabled (--retention-days 0)"
    return 0
  fi
  local cutoff
  cutoff="$(date -d "${days} days ago" +%Y%m%d-%H%M%S 2>/dev/null || date -v-${days}d +%Y%m%d-%H%M%S)"
  # map: date prefix -> dir (only evonids-<ts> dirs)
  mapfile -t dirs < <(find "${base}" -maxdepth 1 -type d -name 'evonids-*' | sort -r)
  local kept=0 dir ts
  for dir in "${dirs[@]:-}"; do
    ts="$(basename "${dir}" | sed 's/^evonids-//')"
    if [ "${kept}" -lt "${keep}" ]; then
      kept=$((kept + 1))
      continue
    fi
    if [ "${ts}" \< "${cutoff}" ]; then
      echo "==> pruning ${dir}"
      rm -rf "${dir}"
    fi
  done
}

prune_old "${BACKUP_DIR}" "${RETENTION_DAYS}" "${KEEP_LATEST}"

# ---------------------------------------------------------------------------
# 7. Summary
# ---------------------------------------------------------------------------
echo ""
echo "==> backup complete: ${DEST}"
( cd "${DEST}" && ls -la )
echo ""
echo "Validate with:  scripts/backup/verify-backup.sh ${DEST}"
