# freestuff — Give-it-away board

## What this is
Tiny self-hosted board for giving things away to friends. Public browse + claim (with waitlist), admin add/edit/delete, claim management.

## Stack
- **Flask 3.x** (Python 3.12) — single-file app (`app.py`, 1057 lines)
- **SQLite** — data stored in `data/freestuff.db`
- **Pillow** + **pillow-heif** — image upload with HEIC→JPEG conversion
- **Gunicorn** — production serving
- **Docker** deployment
- **hardening.py** — rate limiting module

## Key features
- Items: browse available, claim (or join waitlist)
- Admin: add/edit/delete items, see queue, mark given away, remove claims
- Rate limiting: claim_burst (3/2min), claim_sustained (10/hr), claim_item (2/hr/item), login_failed (5/15min)
- Image upload: PNG/JPG/GIF/WEBP direct, HEIC/HEIF converted to JPEG
- Anti-abuse: rate limiter, disposable email blocking (optional), max 50MP image guard
- Authentication: ADMIN_PASSWORD_HASH (preferred) or ADMIN_PASSWORD fallback
- Timezone-aware pickup dates (default empty = server TZ)
- Proxy-aware: TRUSTED_PROXIES for X-Forwarded-For (Traefik/nginx/Cloudflare)

## Config env vars
- `DATA_DIR` — data directory (default: `data/`)
- `SITE_NAME` / `SITE_TAGLINE` — site identity
- `ADMIN_PASSWORD_HASH` — werkzeug hash (preferred)
- `ADMIN_PASSWORD` — plaintext fallback
- `SECRET_KEY` — session security (auto-generated if missing)
- `MAX_UPLOAD_MB` — max upload size (default 8)
- `MAX_IMAGE_PIXELS` — decompression guard (default 50M)
- `TRUSTED_PROXIES` — reverse proxy count (default 0)
- `BLOCK_DISPOSABLE_EMAIL` — block throwaway emails (default off)
- `TIMEZONE` — timezone for pickup dates
- `SECURE_COOKIES` — HTTPS cookie flag

## Notes
- Single-file architecture — all routes, models, templates in one file
- Templates in `templates/`, static assets in `static/`
- Tests in `tests/`
- Sibling app to `rentstuff` (similar Flask pattern, different domain)
