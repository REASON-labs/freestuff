#!/usr/bin/env bash
# FreeStuff backup script.
#
# Backs up the SQLite database (with WAL checkpoint for consistency) and the
# uploads directory into a timestamped tarball.
#
# Usage:
#   ./backup.sh                      # default: DATA_DIR/data
#   ./backup.sh /mnt/backup          # destination dir
#   DATA_DIR=/path ./backup.sh       # custom data dir via env
#
# Intended to be run from cron (e.g. daily at 03:00):
#   0 3 * * *  /path/to/freestuff/backup.sh /path/to/backup/rotate 2>&1 | logger -t freestuff-backup
#
# Retention: the caller (e.g. rsync to a remote host, or a wrapper script)
# should rotate old backups. This script does not delete anything — it only
# creates.

set -euo pipefail

DATA_DIR="${DATA_DIR:-data}"
DEST="${1:-.}"
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
DB_FILE="${DATA_DIR}/freestuff.db"
UPLOADS_DIR="${DATA_DIR}/uploads"
BACKUP_NAME="freestuff-${TIMESTAMP}.tar.gz"

# Ensure destination exists
mkdir -p "${DEST}"

# Verify data directory exists
if [ ! -d "${DATA_DIR}" ]; then
    echo "ERROR: DATA_DIR '${DATA_DIR}' does not exist" >&2
    exit 1
fi

# Checkpoint WAL so the backup is consistent
if [ -f "${DB_FILE}" ]; then
    python3 -c "
import sqlite3, sys
con = sqlite3.connect('${DB_FILE}')
con.execute('PRAGMA journal_mode=WAL')
con.execute('PRAGMA wal_checkpoint(TRUNCATE)')
con.close()
" || { echo "ERROR: WAL checkpoint failed" >&2; exit 1; }
fi

# Build the tarball — include the DB and uploads, omit .env and temp files
cd "${DATA_DIR}"
tar czf "${DEST}/${BACKUP_NAME}" \
    --exclude='*.db-wal' --exclude='*.db-shm' \
    --exclude='.env' \
    freestuff.db \
    ${UPLOADS_DIR:+uploads/} \
    2>/dev/null || {
    # If uploads dir doesn't exist, just back up the DB
    tar czf "${DEST}/${BACKUP_NAME}" \
        --exclude='*.db-wal' --exclude='*.db-shm' \
        --exclude='.env' \
        freestuff.db
}

cd - > /dev/null
echo "Backup created: ${DEST}/${BACKUP_NAME}"
