# Backup Strategy

FreeStuff's entire data is the SQLite database (`data/freestuff.db`) plus
uploaded images (`data/uploads/`). This document describes how to back them up
and restore from them.

## What to back up

| Path | Contents |
|---|---|
| `data/freestuff.db` | Items, claims, blocked dates |
| `data/freestuff.db-wal` | WAL file (auto-recovered on restore; not needed) |
| `data/uploads/` | Uploaded images (one per item) |

## Automated backups

A backup script is included: `backup.sh`. It:

1. Checkpoints the SQLite WAL so the backup is consistent.
2. Creates a timestamped `freestuff-YYYYMMDD-HHMMSS.tar.gz` containing the DB
   and uploads directory.
3. Excludes `.env` and WAL/shm temp files.

### Cron example

Daily at 03:00, writing to a rotating backup directory:

```
0 3 * * *  /path/to/freestuff/backup.sh /path/to/backups/rotate 2>&1 | logger -t freestuff-backup
```

The script does **not** delete old backups — implement retention separately
(e.g. `find /path/to/backups -name 'freestuff-*.tar.gz' -mtime +30 -delete`).

### Docker / Compose

If using `docker-compose.yml`, mount a backup volume:

```yaml
volumes:
  - ./data:/app/data
  - ./backups:/app/backups
```

Then run the backup script inside the container:

```bash
docker compose exec freestuff /app/backup.sh /app/backups
```

## Manual backup

```bash
cd /path/to/freestuff
./backup.sh /wherever/you/store/backups/
```

## Restore

```bash
# Stop the app first (if running)
# Extract the tarball
tar xzf freestuff-20260101-030000.tar.gz -C /path/to/freestuff/data/
# Start the app — it will use the restored database
```

## Recovery testing

At minimum, verify that restored data is readable:

```bash
python3 -c "
import sqlite3
con = sqlite3.connect('data/freestuff.db')
print('Items:', con.execute('SELECT count(*) FROM items').fetchone()[0])
print('Claims:', con.execute('SELECT count(*) FROM claims').fetchone()[0])
"
```
