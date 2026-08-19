# FreeStuff

A tiny, self-hostable board for giving things away to friends. Post an item, let
people claim it, and keep an orderly waitlist for everyone after the first.

![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)
![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)

![The public board](docs/screenshot-board.png)

Flask + SQLite, no external services and no CDN calls. Runs as a single
container, so it's happy on a small VPS, a home server, or a Raspberry Pi.

## Features

- **Public board** — browse available items, claim one, or join its waitlist by
  leaving a name, contact, pickup date, and an optional estimated pickup time.
- **Ordered waitlist** — the first person to claim an item is the recipient;
  everyone after joins a waitlist and moves up automatically if someone drops.
- **Admin panel** — add, edit, and delete items (with photo upload), see the
  full queue with everyone's contact details, and mark items as given away.
- **Blackout dates** — block days when pickups can't happen (holidays, travel);
  they're steered away from on the form and enforced on the server.
- **iPhone photos just work** — HEIC uploads are converted to JPEG on the way in
  (which also strips GPS metadata, a nice privacy bonus).
- **Privacy first** — claimant contact details are only ever shown to the admin.
  Public pages just show *Available* / *Claimed · N waiting* / *Given away*.
- **Built-in safety** — CSRF protection, upload validation, autoescaped
  templates, and a private per-claim link people can use to withdraw themselves.
- **Light & dark themes** — follows the visitor's system setting by default; the
  header toggle cycles System → Light → Dark and remembers the choice. No JS
  required for the system default.

![Claiming an item](docs/screenshot-claim.png)

## How the claim / waitlist logic works

Each item has a queue of claims ordered by time. The **first active claim is the
recipient**; everyone after is the **waitlist**. This is computed live, so
there's nothing to get out of sync:

- First person to claim an available item → **first in line**.
- Anyone who claims after that → joins the **waitlist**.
- Admin removes the recipient (they flaked) → the next person **moves up
  automatically**.
- Admin clicks **Mark given away** → the item closes and drops off the board.

## Quick start (Docker Compose)

```bash
git clone https://github.com/<your-username>/freestuff.git
cd freestuff
cp .env.example .env

# generate a session secret and append it
python3 -c "import secrets; print('SECRET_KEY=' + secrets.token_hex(32))" >> .env
# then edit .env and set ADMIN_PASSWORD (and optionally SITE_NAME / SITE_TAGLINE)

docker compose up -d --build
```

The app listens on `127.0.0.1:8000`. Sign in at `/admin/login`. Data (the SQLite
database and uploaded photos) lives in the `freestuff_data` Docker volume, so it
survives restarts and rebuilds.

## Running locally (no Docker)

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

export ADMIN_PASSWORD='pick-something'
export SECRET_KEY="$(python3 -c 'import secrets;print(secrets.token_hex(32))')"
python3 app.py        # http://localhost:8000
```

## Configuration

All configuration is via environment variables (see `.env.example`):

| Variable | Default | Purpose |
|---|---|---|
| `ADMIN_PASSWORD_HASH` | — | Hashed password for `/admin/login`. **Preferred.** Generate with `python app.py hash-password`. |
| `ADMIN_PASSWORD` | `changeme` | Plaintext fallback, still honoured so existing deployments keep working. Set the hash instead. |
| `SECRET_KEY` | random per start | Signs session cookies and claim-form stamps. **Set this** so logins survive restarts / multiple workers. |
| `SITE_NAME` | `Free Stuff` | Name shown in the header and page titles. |
| `SITE_TAGLINE` | `Take what you'll love.` | The line at the top of the public homepage. |
| `MAX_UPLOAD_MB` | `8` | Max photo upload size. |
| `MAX_IMAGE_PIXELS` | `50000000` | Refuse to decode images above this pixel count (decompression-bomb guard). |
| `DATA_DIR` | `/data` (Docker) / `data` | Where the database and uploads are stored. |
| `TIMEZONE` | server local | Zone used to decide what "today" is when validating pickup dates, e.g. `America/Los_Angeles`. |
| `SECURE_COOKIES` | off | Set to `1` when serving over HTTPS so the session cookie is HTTPS-only. |
| `TRUSTED_PROXIES` | `0` | How many reverse proxies sit in front of the app. **Set this if you use one** — see below. |
| `BLOCK_DISPOSABLE_EMAIL` | off | Set to `1` to turn away contact addresses on known throwaway-mail domains. |
| `HOST` | `127.0.0.1` | Bind address for `python app.py` (the dev server only). |
| `PORT` | `8000` | Port for `python app.py`. |
| `FLASK_DEBUG` | off | Set to `1` for the Werkzeug debugger. **Never in production** — it is a remote shell. |

### Setting the admin password

```bash
python app.py hash-password     # prompts twice, prints ADMIN_PASSWORD_HASH=...
```

Put the result in `.env` and remove `ADMIN_PASSWORD`. The plaintext variable
still works if you'd rather not migrate, but it is visible to anyone who can run
`docker inspect` or read the compose file, and the app logs a warning on boot.

## Putting it behind HTTPS

The compose file binds the app to `127.0.0.1`, so it isn't exposed directly.
Point a reverse proxy at it. [Caddy](https://caddyserver.com/) is the least fuss
— it handles Let's Encrypt certificates automatically:

```
give.yourdomain.com {
    reverse_proxy 127.0.0.1:8000
}
```

Or with nginx (certificates via certbot):

```nginx
server {
    server_name give.yourdomain.com;
    client_max_body_size 10M;          # allow photo uploads
    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

**Whichever proxy you use, set `TRUSTED_PROXIES=1`.** Without it every visitor
appears to the app as the proxy's own address, so the rate limiter sees the
whole board as one client and the first spammer locks everyone out. Set it to
the number of proxies actually in the chain — count Cloudflare if it's in front
of your own. Setting it higher than the real number is the opposite mistake: a
client can then forge `X-Forwarded-For` and skip the limiter entirely.

## Backups

Everything lives in one place — the data volume:

```bash
docker run --rm -v freestuff_data:/data -v "$PWD":/backup alpine \
    tar czf /backup/freestuff-backup-$(date +%F).tar.gz -C /data .
```

The SQLite file is `freestuff.db`; uploaded photos are under `uploads/`.

## Development

```bash
pip install -r requirements.txt -r requirements-dev.txt
python -m pytest
```

CI runs the test suite on Python 3.9, 3.11, and 3.12.

## Project layout

```
app.py               # the whole application (routes, auth, claim logic)
hardening.py         # anti-abuse core: rate limiter, form stamps, validation
schema.sql           # database schema
templates/           # Jinja2 templates
static/style.css     # styling + light/dark design tokens
static/theme.js      # theme toggle (system / light / dark)
static/app.js        # shared behaviours (confirmation prompts)
tests/               # pytest suite
Dockerfile
docker-compose.yml
```

## Anti-abuse

The public claim form is the one place strangers can write to the database, so
it is defended in layers. None of these is strong alone; together they stop the
form-flooding pattern that hit the sibling RentStuff board (21 near-identical
submissions in 20 seconds) without putting a CAPTCHA in front of your friends.

| Layer | What it does |
|---|---|
| CSRF token | Session-scoped token on every form, verified on POST. |
| Signed form stamp | Hidden, signed issue-time. Rejects submissions faster than 3s (scripted) or older than 6h (scraped and replayed). |
| Honeypots | Two off-screen decoy fields. Anything that fills one is automated. |
| Rate limits | Per IP: 3 claims / 2 min, 10 / hour, and 2 / hour on any one item. |
| Field validation | Contact must be an actual email address or phone number; names and notes reject links; control characters stripped. |
| Duplicate detection | A second claim from the same contact returns your existing place in line instead of taking a second slot. |
| Login throttle | 5 failed admin passwords per IP per 15 minutes, then HTTP 429. |
| Structured logs | One JSON line per outcome on stdout. |

Deliberately **not** included: a CAPTCHA (an external script on every page, and
a real accessibility cost, for a board a few dozen people use), and gibberish
or entropy scoring on names — it flags real names like *Szczepanski* far more
often than it catches a bot that can just as easily generate *Sarah Miller*.
Both stay on the table if spam gets past the layers above.

### Watching for trouble

Rejections are logged as JSON on stdout, so `docker compose logs` is the whole
observability story:

```bash
# what got turned away, and why
docker compose logs freestuff | grep claim_rejected | jq -r .reason | sort | uniq -c

# addresses hitting the rate limiter
docker compose logs freestuff | grep rate_limited | jq -r .ip | sort | uniq -c | sort -rn
```

No claimant name, contact detail or note text is ever logged. Contacts appear
only as a truncated hash, which is enough to correlate a repeat offender across
entries without the log becoming a second copy of the claims table.

### A note on scale

The rate limiter holds its counters in process memory rather than Redis, which
keeps the deploy at one container. The tradeoff: each gunicorn worker counts
separately, so with the default 2 workers a client gets roughly twice the listed
allowance before being throttled. The thresholds above are set with that in
mind. If you raise `--workers`, lower the limits in `RATE_LIMITS` to match.

## Scope & notes

Built deliberately small for a friends-and-family use case:

- Admin is a single shared password — fine behind HTTPS for a private board.
  Per-user admin accounts would be the natural next step.
- There is no Content-Security-Policy yet. The pre-paint theme script has to be
  inline to avoid a flash of light mode, so a strict policy needs a per-request
  nonce first. Everything else in the header set is in place.
- No email/SMS notifications; the admin sees contacts in the queue and reaches
  out directly.

Contributions welcome — see [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[MIT](LICENSE)
