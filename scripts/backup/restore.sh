#!/usr/bin/env bash
#
# EvoNIDS restore.sh — restore a backup directory produced by backup.sh.
#
# Safety rules:
#   * verifies every SHA-256 checksum before touching anything;
#   * --dry-run prints the plan without writing to the database or disk;
#   * real execution requires the explicit --confirm flag.
#
# Environment: PGHOST PGPORT(optional) PGUSER PGPASSWORD PGDATABASE of the
# DESTINATION database (the same PG* rules as backup.sh).
#
# NOTE: authored on a machine without bash; run `bash -n restore.sh` on a
# POSIX host before first use (see scripts/backup/README.md).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

BACKUP_DIR="${EVONIDS_BACKUP_DIR:-${REPO_ROOT}/backups}"
BACKUP_PATH=""
DRY_RUN=0
CONFIRM=0
RESTORE_FILES=0
TARGET_MODEL_DIR="${EVONIDS_MODEL_ARTIFACT_DIR:-${REPO_ROOT}/backend/model-artifacts}"
ENV_FILE=""

usage() {
  cat <<'EOF'
Usage: restore.sh [options] [BACKUP_PATH]

  BACKUP_PATH          backup directory created by backup.sh (default: the
                       newest evonids-* under the backup dir)

  --env-file FILE      source FILE (root .env) and map POSTGRES_* -> PG*
  --backup-dir DIR     where backups live (default: $EVONIDS_BACKUP_DIR
                       or <repo>/backups)
  --dry-run            verify checksums and print the restore plan only
  --restore-files      also restore model-artifact archives into
                       EVONIDS_MODEL_ARTIFACT_DIR (only together with
                       --confirm; not with --dry-run? dry-run prints plan)
  --confirm            explicitly acknowledge destructive restore
  -h, --help           show this help

Required environment: PGHOST, PGUSER, PGPASSWORD, PGDATABASE. The script
refuses to run without them, and refuses to restore without --confirm.
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
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    --restore-files)
      RESTORE_FILES=1
      shift
      ;;
    --confirm)
      CONFIRM=1
      shift
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    -*)
      echo "restore.sh: unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
    *)
      if [ -n "${BACKUP_PATH}" ]; then
        echo "restore.sh: unexpected extra argument: $1" >&2
        exit 2
      fi
      BACKUP_PATH="$1"
      shift
      ;;
  esac
done

for tool in sha256sum pg_restore; do
  if ! command -v "${tool}" >/dev/null 2>&1; then
    echo "restore.sh: required tool missing: ${tool}" >&2
    exit 1
  fi
done

if [ -n "${ENV_FILE}" ]; then
  if [ ! -f "${ENV_FILE}" ]; then
    echo "restore.sh: --env-file not found: ${ENV_FILE}" >&2
    exit 1
  fi
  set -a
  while IFS='=' read -r key value; do
    value="${value%$'\r'}"
    case "${key}" in
      POSTGRES_DB|POSTGRES_USER|POSTGRES_PASSWORD|POSTGRES_PORT|\
      EVONIDS_BACKUP_DIR|EVONIDS_MODEL_ARTIFACT_DIR)
        export "${key}=${value}"
        ;;
    esac
  done < <(grep -E '^[A-Za-z_][A-Za-z0-9_]*=' "${ENV_FILE}" || true)
  set +a
fi

export PGHOST="${PGHOST:-127.0.0.1}"
export PGPORT="${PGPORT:-5432}"
[ -n "${PGUSER:-}" ] || PGUSER="${POSTGRES_USER:-}"
[ -n "${PGPASSWORD:-}" ] || PGPASSWORD="${POSTGRES_PASSWORD:-}"
[ -n "${PGDATABASE:-}" ] || PGDATABASE="${POSTGRES_DB:-}"
export PGUSER PGPASSWORD PGDATABASE

MISSING=""
for var in PGHOST PGUSER PGPASSWORD PGDATABASE; do
  if [ -z "${!var:-}" ]; then
    MISSING="${MISSING} ${var}"
  fi
done
if [ -n "${MISSING}" ]; then
  echo "restore.sh: refusing to run: required PG* variable(s) unset:${MISSING}" >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# Resolve backup path
# ---------------------------------------------------------------------------
if [ -z "${BACKUP_PATH}" ]; then
  BACKUP_PATH="$(find "${BACKUP_DIR}" -maxdepth 1 -type d -name 'evonids-*' | sort | tail -n 1)"
  if [ -z "${BACKUP_PATH}" ]; then
    echo "restore.sh: no backup directory found under ${BACKUP_DIR}" >&2
    exit 1
  fi
fi
if [ ! -d "${BACKUP_PATH}" ]; then
  echo "restore.sh: backup directory not found: ${BACKUP_PATH}" >&2
  exit 1
fi

echo "==> backup to restore: ${BACKUP_PATH}"

# ---------------------------------------------------------------------------
# Checksum verification (always, even for --dry-run)
# ---------------------------------------------------------------------------
CHECKSUM_FILE="${BACKUP_PATH}/SHA256SUMS.txt"
if [ ! -f "${CHECKSUM_FILE}" ]; then
  echo "restore.sh: missing ${CHECKSUM_FILE}; refusing to restore an unverified backup" >&2
  exit 1
fi
echo "==> verifying checksums"
( cd "${BACKUP_PATH}" && sha256sum -c "${CHECKSUM_FILE}" )

DB_FILE="$(find "${BACKUP_PATH}" -maxdepth 1 -name 'evonids-db-*.dump' | head -n 1)"
if [ -z "${DB_FILE}" ]; then
  echo "restore.sh: no evonids-db-*.dump found in ${BACKUP_PATH}" >&2
  exit 1
fi
DB_FILE="$(cd "${BACKUP_PATH}" && pwd)/$(basename "${DB_FILE}")"

# ---------------------------------------------------------------------------
# Sanity: pg_restore --list on the archive (no server contact)
# ---------------------------------------------------------------------------
echo "==> sanity: pg_restore --list"
pg_restore --list "${DB_FILE}" >/dev/null

cat <<EOF

Restore plan:
  database : ${PGHOST}:${PGPORT}/${PGDATABASE} (user ${PGUSER})
  archive  : ${DB_FILE}
  command  : pg_restore --clean --if-exists --no-owner --no-privileges
             -h ${PGHOST} -p ${PGPORT} -U ${PGUSER} -d ${PGDATABASE} ${DB_FILE}
EOF

if [ "${RESTORE_FILES}" -eq 1 ]; then
  echo "  files    : restore model-artifact archives into ${TARGET_MODEL_DIR}"
fi

if [ "${DRY_RUN}" -eq 1 ]; then
  echo ""
  echo "==> dry-run finished: nothing was written. Re-run without --dry-run and with --confirm to restore."
  exit 0
fi

if [ "${CONFIRM}" -ne 1 ]; then
  echo ""
  echo "restore.sh: refusing to restore without --confirm. Review the plan above (use --dry-run first)." >&2
  exit 1
fi

echo "==> restoring database (this REPLACES current objects in ${PGDATABASE})"
pg_restore --clean --if-exists --no-owner --no-privileges \
  -h "${PGHOST}" -p "${PGPORT}" -U "${PGUSER}" -d "${PGDATABASE}" \
  "${DB_FILE}"

if [ "${RESTORE_FILES}" -eq 1 ]; then
  mkdir -p "${TARGET_MODEL_DIR}"
  for tarball in "${BACKUP_PATH}"/model-artifacts-*.tar.gz; do
    [ -e "${tarball}" ] || continue
    echo "==> restoring files: ${tarball}"
    tar -xzf "${tarball}" -C "$(dirname "${TARGET_MODEL_DIR}")"
  done
fi

echo ""
echo "==> restore complete. Run scripts/backup/verify-backup.sh ${BACKUP_PATH} and smoke-test the app."
