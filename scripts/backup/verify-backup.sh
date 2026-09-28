#!/usr/bin/env bash
#
# EvoNIDS verify-backup.sh — verify a backup directory produced by backup.sh:
#   1. SHA-256 checksum verification (sha256sum -c)
#   2. archive sanity for the PostgreSQL dump (pg_restore --list — reads the
#      dump file only, never contacts a server)
#   3. gzip/tar sanity for any model-artifact / dataset archives
#
# Usage: verify-backup.sh [BACKUP_PATH]   (default: newest evonids-* dir)
#
# Exit codes: 0 = verified, 1 = verification failed, 2 = tooling unavailable
# or bad usage.
#
# NOTE: authored on a machine without bash; run `bash -n verify-backup.sh` on
# a POSIX host before first use (see scripts/backup/README.md).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
BACKUP_DIR="${EVONIDS_BACKUP_DIR:-${REPO_ROOT}/backups}"
BACKUP_PATH="${1:-}"

for tool in sha256sum pg_restore gzip tar; do
  if ! command -v "${tool}" >/dev/null 2>&1; then
    echo "verify-backup.sh: required tool missing: ${tool}" >&2
    exit 2
  fi
done

if [ -z "${BACKUP_PATH}" ]; then
  BACKUP_PATH="$(find "${BACKUP_DIR}" -maxdepth 1 -type d -name 'evonids-*' | sort | tail -n 1)"
fi
if [ -z "${BACKUP_PATH}" ] || [ ! -d "${BACKUP_PATH}" ]; then
  echo "verify-backup.sh: backup directory not found: ${BACKUP_PATH:-<none>}" >&2
  exit 2
fi
echo "==> verifying backup: ${BACKUP_PATH}"
FAILED=0

# --- 1. checksums -----------------------------------------------------------
CHECKSUM_FILE="${BACKUP_PATH}/SHA256SUMS.txt"
if [ ! -f "${CHECKSUM_FILE}" ]; then
  echo "ERROR: ${CHECKSUM_FILE} not found" >&2
  exit 1
fi
echo "==> sha256sum -c"
if ! ( cd "${BACKUP_PATH}" && sha256sum -c "${CHECKSUM_FILE}" ); then
  FAILED=1
fi

# --- 2. pg_restore --list sanity --------------------------------------------
DB_FILE="$(find "${BACKUP_PATH}" -maxdepth 1 -name 'evonids-db-*.dump' | head -n 1)"
if [ -n "${DB_FILE}" ]; then
  echo "==> pg_restore --list ${DB_FILE}"
  if pg_restore --list "${DB_FILE}" >/dev/null 2>&1; then
    echo "      TOC entries: $(pg_restore --list "${DB_FILE}" | grep -vc '^;')"
  else
    echo "ERROR: pg_restore --list failed on ${DB_FILE}" >&2
    FAILED=1
  fi
else
  echo "WARN: no evonids-db-*.dump found in ${BACKUP_PATH}" >&2
fi

# --- 3. gzip/tar sanity ------------------------------------------------------
for tarball in "${BACKUP_PATH}"/*.tar.gz; do
  [ -e "${tarball}" ] || continue
  echo "==> gzip -t + tar -tzf ${tarball}"
  if ! gzip -t "${tarball}" || ! tar -tzf "${tarball}" >/dev/null; then
    echo "ERROR: archive corrupt: ${tarball}" >&2
    FAILED=1
  fi
done

if [ "${FAILED}" -eq 0 ]; then
  echo ""
  echo "==> verification PASSED: ${BACKUP_PATH}"
  exit 0
fi
echo ""
echo "==> verification FAILED: ${BACKUP_PATH}" >&2
exit 1
