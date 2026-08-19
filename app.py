"""
FreeStuff — a tiny self-hosted board for giving things away to friends.

Public side:  browse available items, claim one (or join its waitlist).
Admin side:   add / edit / delete items, see the queue and contact details,
              mark items given away, remove claims (which promotes the next
              person in line automatically).

Single-file Flask app backed by SQLite. No external services, no CDN calls.
"""

import os
import re
import sys
import hmac
import secrets
import sqlite3
from datetime import date, datetime
from functools import wraps
from pathlib import Path

try:  # Python 3.9+
    from zoneinfo import ZoneInfo
except ImportError:  # pragma: no cover - only on very old Pythons
    ZoneInfo = None

from flask import (
    Flask, g, request, session, redirect, url_for,
    render_template, abort, flash, send_from_directory,
)
from werkzeug.utils import secure_filename
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash

import hardening
from hardening import RateLimiter

# HEIC/HEIF support (iPhone photos). Registering the opener lets Pillow read
# .heic files so we can convert them to browser-friendly JPEG on upload.
from PIL import Image, ImageOps
try:
    import pillow_heif
    pillow_heif.register_heif_opener()
    HEIF_SUPPORTED = True
except Exception:  # pragma: no cover - only if the optional dep is missing
    HEIF_SUPPORTED = False

# --------------------------------------------------------------------------- #
# Configuration (all overridable via environment variables)
# --------------------------------------------------------------------------- #
DATA_DIR = Path(os.environ.get("DATA_DIR", "data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)

UPLOAD_DIR = DATA_DIR / "uploads"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

DB_PATH = DATA_DIR / "freestuff.db"

SITE_NAME = os.environ.get("SITE_NAME", "Free Stuff")
SITE_TAGLINE = os.environ.get(
    "SITE_TAGLINE", "Take what you'll love."
)

# Preferred: ADMIN_PASSWORD_HASH, a werkzeug hash produced by
#   python app.py hash-password
# so the plaintext never sits in an env file, a compose file or `docker inspect`
# output. ADMIN_PASSWORD is still honoured for existing deployments, with a
# warning, so upgrading doesn't lock anyone out of their own board.
ADMIN_PASSWORD_HASH = os.environ.get("ADMIN_PASSWORD_HASH", "").strip()
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "" if ADMIN_PASSWORD_HASH else "changeme")

# Formats stored as-is. GIFs pass through untouched so animation is preserved.
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp"}
# Formats we convert to JPEG on the way in (browsers can't display HEIC).
CONVERT_EXTENSIONS = {"heic", "heif"}
MAX_UPLOAD_MB = int(os.environ.get("MAX_UPLOAD_MB", "8"))

# Refuse to decode an image larger than this many pixels. A 100MB PNG can
# decompress to tens of gigabytes of bitmap; Pillow's own guard is off by
# default above a much higher threshold. 50MP is ~8000x6000 — comfortably more
# than any phone camera produces.
MAX_IMAGE_PIXELS = int(os.environ.get("MAX_IMAGE_PIXELS", str(50_000_000)))
Image.MAX_IMAGE_PIXELS = MAX_IMAGE_PIXELS

# Number of reverse proxies in front of the app (Traefik, nginx, Cloudflare...).
# This MUST be right: set it too low and every visitor shares the proxy's IP, so
# one spammer rate-limits the whole board; set it too high and a client can
# forge X-Forwarded-For and dodge the limiter entirely. 0 = no proxy.
TRUSTED_PROXIES = int(os.environ.get("TRUSTED_PROXIES", "0"))

# Reject contact addresses on known throwaway-mail domains. Off by default:
# on a board for friends, wrongly turning away a real person costs more than
# one spam row in the claims table.
BLOCK_DISPOSABLE_EMAIL = os.environ.get("BLOCK_DISPOSABLE_EMAIL", "") == "1"

# Pickup dates are "today" from the giver's point of view, not the server's.
# Without this a board hosted in UTC starts rejecting *today* as a past date
# from 5pm onwards on the US west coast.
TIMEZONE = os.environ.get("TIMEZONE", "")

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_MB * 1024 * 1024
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY") or secrets.token_hex(32)

# Session cookie hardening. SameSite=Lax alone blocks the cross-site form POSTs
# that CSRF depends on; the token check below is the belt to its braces.
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
# Set SECURE_COOKIES=1 when serving over HTTPS (the normal production case).
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("SECURE_COOKIES", "") == "1"

if TRUSTED_PROXIES > 0:
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=TRUSTED_PROXIES, x_proto=TRUSTED_PROXIES)

if not os.environ.get("SECRET_KEY"):
    app.logger.warning(
        "SECRET_KEY not set — using a random key. Sessions reset on restart. "
        "Set SECRET_KEY in the environment for production."
    )
if ADMIN_PASSWORD == "changeme":
    app.logger.warning(
        "ADMIN_PASSWORD is still the default 'changeme'. Set a real one."
    )
elif ADMIN_PASSWORD and not ADMIN_PASSWORD_HASH:
    app.logger.warning(
        "ADMIN_PASSWORD is stored in plaintext. Generate a hash with "
        "`python app.py hash-password` and set ADMIN_PASSWORD_HASH instead."
    )


# --------------------------------------------------------------------------- #
# Anti-abuse plumbing
# --------------------------------------------------------------------------- #
limiter = RateLimiter()

# (limit, window_seconds). Two gunicorn workers each keep their own counters,
# so real-world allowances are roughly double these — the numbers below are
# halved from what we actually want to permit. The August 18 attack on the
# sibling app was 21 submissions in 20 seconds; anything here stops that dead
# while leaving room for a family of four claiming things off one home IP.
RATE_LIMITS = {
    # key                 limit  window
    "claim_burst":        (3,    120),     # 3 claims / 2 min
    "claim_sustained":    (10,   3600),    # 10 claims / hour
    "claim_item":         (2,    3600),    # 2 claims / hour on ONE item
    "login_failed":       (5,    900),     # 5 bad passwords / 15 min
}


def client_ip():
    """Best available client address, honouring ProxyFix when configured."""
    return request.remote_addr or "unknown"


def audit(event, **fields):
    """One structured JSON line per interesting request outcome.

    Deliberately excludes claimant names, contact details and note text — the
    log is for spotting attack shapes, not for keeping a second copy of the
    claims table. The contact fingerprint is a hash, so repeat offenders are
    still correlatable across entries.
    """
    fields.setdefault("ip", client_ip())
    fields.setdefault("ua", (request.headers.get("User-Agent") or "")[:200])
    fields.setdefault("path", request.path)
    hardening.log_event(sys.stdout, event, **fields)


def rate_limited(bucket, suffix=""):
    """Check one of the RATE_LIMITS buckets for this client.

    Returns (allowed, retry_after).
    """
    limit, window = RATE_LIMITS[bucket]
    key = f"{bucket}:{client_ip()}"
    if suffix:
        key = f"{key}:{suffix}"
    return limiter.check(key, limit, window)


def form_stamp():
    """Signed issue-time for the claim form (see hardening.sign_form_stamp)."""
    return hardening.sign_form_stamp(app.config["SECRET_KEY"])


@app.after_request
def security_headers(response):
    """Cheap, universally-safe response headers.

    No Content-Security-Policy yet: base.html carries an inline pre-paint theme
    script that a strict policy would block, and item.html inlines the
    blocked-dates hint. Both need a per-request nonce before CSP can go on
    without breaking the page — tracked separately rather than shipped half-done.
    """
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault(
        "Permissions-Policy", "geolocation=(), camera=(), microphone=(), interest-cohort=()"
    )
    # Uploaded files are attacker-influenced content served from our own origin.
    # nosniff plus a hard sandbox stops a crafted "image" from ever executing
    # in the board's origin if a browser is talked into treating it as HTML.
    if request.path.startswith("/uploads/"):
        response.headers["Content-Security-Policy"] = "sandbox; default-src 'none'"
    return response


# --------------------------------------------------------------------------- #
# Database helpers
# --------------------------------------------------------------------------- #
def today_str():
    """Today's date where the board lives, as YYYY-MM-DD."""
    if TIMEZONE and ZoneInfo is not None:
        try:
            return datetime.now(ZoneInfo(TIMEZONE)).date().isoformat()
        except Exception:  # unknown zone name — fall back rather than 500
            app.logger.warning("Unknown TIMEZONE %r — using server local time.", TIMEZONE)
    return date.today().isoformat()


def configure_connection(con):
    """Pragmas every connection needs.

    WAL lets a reader and a writer work at the same time, and busy_timeout
    makes a blocked writer wait rather than immediately raising
    "database is locked" — both matter once gunicorn runs more than one worker.
    """
    con.execute("PRAGMA foreign_keys = ON")
    con.execute("PRAGMA journal_mode = WAL")
    con.execute("PRAGMA busy_timeout = 5000")
    con.execute("PRAGMA synchronous = NORMAL")


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        configure_connection(g.db)
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    schema = (Path(__file__).parent / "schema.sql").read_text()
    con = sqlite3.connect(DB_PATH)
    configure_connection(con)
    con.executescript(schema)
    # Migration: add pickup_time to claims tables created before this column existed.
    columns = [row[1] for row in con.execute("PRAGMA table_info(claims)")]
    if "pickup_time" not in columns:
        con.execute("ALTER TABLE claims ADD COLUMN pickup_time TEXT NOT NULL DEFAULT ''")
    con.commit()
    con.close()


def get_blocked_dates(db, upcoming_only=False):
    """Return the list of blacked-out pickup dates (YYYY-MM-DD strings)."""
    rows = db.execute(
        "SELECT id, date, reason FROM blocked_dates ORDER BY date"
    ).fetchall()
    if upcoming_only:
        today = today_str()
        rows = [r for r in rows if r["date"] >= today]
    return rows


def claim_queue(db, item_id):
    """Return (recipient, waitlist) for an item.

    The recipient is the earliest active claim; everyone after is the waitlist.
    """
    active = db.execute(
        "SELECT * FROM claims WHERE item_id = ? AND status = 'active' "
        "ORDER BY created_at, id",
        (item_id,),
    ).fetchall()
    recipient = active[0] if active else None
    waitlist = active[1:]
    return recipient, waitlist


def item_public_status(item, recipient, waitlist):
    """Human-readable status for the public view."""
    if item["status"] == "gone":
        return "gone", "Given away"
    if recipient is None:
        return "available", "Available"
    n = len(waitlist)
    if n == 0:
        return "claimed", "Claimed"
    return "claimed", f"Claimed · {n} waiting"


# --------------------------------------------------------------------------- #
# CSRF protection (lightweight, session-token based)
# --------------------------------------------------------------------------- #
def get_csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(16)
    return session["csrf_token"]


def secure_equals(a, b):
    """Constant-time compare that survives non-ASCII input.

    hmac.compare_digest raises TypeError on strings with non-ASCII characters,
    which turned a wrong password (or a mangled form token) into a 500.
    Comparing the UTF-8 bytes has no such restriction.
    """
    return hmac.compare_digest(str(a).encode("utf-8"), str(b).encode("utf-8"))


@app.before_request
def csrf_protect():
    if request.method == "POST":
        expected = session.get("csrf_token", "")
        sent = request.form.get("csrf_token", "")
        # An empty expected token must never match: without this, a POST from a
        # session that had never rendered a form passed the check outright,
        # because "" == "".
        if not expected or not secure_equals(sent, expected):
            abort(400, "Invalid or missing form token. Please reload and retry.")


@app.context_processor
def inject_globals():
    return {
        "csrf_token": get_csrf_token,
        "form_stamp": form_stamp,
        "honeypot_fields": hardening.HONEYPOT_FIELDS,
        "site_name": SITE_NAME,
        "site_tagline": SITE_TAGLINE,
        "is_admin": session.get("is_admin", False),
        "today": today_str(),
    }


# --------------------------------------------------------------------------- #
# Auth
# --------------------------------------------------------------------------- #
def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("is_admin"):
            return redirect(url_for("admin_login", next=request.path))
        return view(*args, **kwargs)

    return wrapped


# --------------------------------------------------------------------------- #
# Uploads
# --------------------------------------------------------------------------- #
def save_upload(file_storage):
    """Validate and store an uploaded image; return the served URL or ''.

    HEIC/HEIF photos (the iPhone default) are converted to JPEG so they display
    in every browser. Converting also drops the original EXIF, which strips GPS
    location data as a privacy bonus.
    """
    if not file_storage or not file_storage.filename:
        return ""
    original = secure_filename(file_storage.filename)
    ext = original.rsplit(".", 1)[-1].lower() if "." in original else ""

    if ext in CONVERT_EXTENSIONS:
        if not HEIF_SUPPORTED:
            raise ValueError("HEIC support isn't available on the server.")
        try:
            image = Image.open(file_storage.stream)
            _reject_oversized(image)
            image = ImageOps.exif_transpose(image).convert("RGB")
        except ValueError:
            raise
        except Exception:
            raise ValueError("Couldn't read that HEIC photo. Try a JPG or PNG.")
        name = f"{secrets.token_hex(8)}.jpg"
        image.save(UPLOAD_DIR / name, format="JPEG", quality=85)
        return url_for("uploaded_file", filename=name)

    if ext not in ALLOWED_EXTENSIONS:
        raise ValueError("Unsupported image type. Use HEIC, PNG, JPG, GIF, or WEBP.")

    real_format = verify_image(file_storage.stream, ext)
    name = f"{secrets.token_hex(8)}.{real_format}"
    file_storage.stream.seek(0)
    file_storage.save(UPLOAD_DIR / name)
    return url_for("uploaded_file", filename=name)


# Pillow's format name -> the extension we store it under. The stored extension
# is derived from what the bytes actually *are*, never from what the uploader
# called the file, so a .png full of HTML can't be served back as image/png.
FORMAT_EXTENSION = {
    "PNG": "png", "JPEG": "jpg", "MPO": "jpg", "GIF": "gif", "WEBP": "webp",
}


def verify_image(stream, claimed_ext):
    """Confirm an upload really is a supported image; return its true extension.

    Extension checks alone are cosmetic — the previous version stored whatever
    bytes arrived under a trusted-looking name. Uploads are admin-only, so this
    was hardening rather than an open hole, but "the admin pasted the wrong
    file" is a much more likely failure than an attack and this catches that too.

    verify() must run on a fresh Image object and invalidates it, so the file is
    opened twice: once to check integrity, once to read the dimensions.
    """
    stream.seek(0)
    try:
        probe = Image.open(stream)
        detected = probe.format
        probe.verify()
    except ValueError:
        raise
    except Exception:
        raise ValueError("That file isn't a readable image.")

    if detected not in FORMAT_EXTENSION:
        raise ValueError("Unsupported image type. Use HEIC, PNG, JPG, GIF, or WEBP.")

    stream.seek(0)
    try:
        _reject_oversized(Image.open(stream))
    except ValueError:
        raise
    except Exception:
        raise ValueError("That file isn't a readable image.")

    return FORMAT_EXTENSION[detected]


def _reject_oversized(image):
    width, height = image.size
    if width * height > MAX_IMAGE_PIXELS:
        raise ValueError(
            f"That image is too large to process ({width}x{height} pixels)."
        )


def delete_upload(image_url):
    """Remove a previously uploaded file, if the URL points at one of ours.

    Pasted external URLs and empty values are ignored. Without this, replacing
    or deleting an item left its photo on disk forever.
    """
    if not image_url:
        return
    prefix = url_for("uploaded_file", filename="")
    if not image_url.startswith(prefix):
        return
    name = Path(image_url[len(prefix):]).name  # basename only — no traversal
    if not name:
        return
    try:
        (UPLOAD_DIR / name).unlink()
    except FileNotFoundError:
        pass
    except OSError as exc:  # pragma: no cover - permissions, etc.
        app.logger.warning("Couldn't delete upload %s: %s", name, exc)


@app.route("/uploads/<path:filename>")
def uploaded_file(filename):
    return send_from_directory(UPLOAD_DIR, filename)


# --------------------------------------------------------------------------- #
# Validation helpers
# --------------------------------------------------------------------------- #
def clean(text, limit):
    return (text or "").strip()[:limit]


def safe_image_url(value):
    """Accept only URLs that are safe to drop into src= and CSS url().

    Anything that isn't an http(s) URL or one of our own /uploads/ paths is
    rejected, which rules out javascript: and data: URLs. Quotes, parentheses
    and whitespace are rejected too: image_url is interpolated into a
    background-image: url('…') declaration on the board, and those characters
    would let it escape the declaration.
    """
    value = (value or "").strip()
    if not value:
        return ""
    if any(ch in value for ch in "'\"()<>\\ \t\r\n"):
        raise ValueError("That image URL contains characters we can't use.")
    if value.startswith("/uploads/"):
        return value
    if re.match(r"^https?://", value, re.IGNORECASE):
        return value
    raise ValueError("Image URLs need to start with http:// or https://.")


def valid_date(value):
    if not value:
        return False
    try:
        datetime.strptime(value, "%Y-%m-%d")
        return True
    except ValueError:
        return False


def valid_time(value):
    """Accept what <input type="time"> sends: HH:MM, or HH:MM:SS with seconds."""
    if not value:
        return False
    for fmt in ("%H:%M", "%H:%M:%S"):
        try:
            datetime.strptime(value, fmt)
            return True
        except ValueError:
            continue
    return False


# --------------------------------------------------------------------------- #
# Public routes
# --------------------------------------------------------------------------- #
@app.route("/")
def index():
    db = get_db()
    items = db.execute("SELECT * FROM items ORDER BY status, created_at DESC").fetchall()

    live, given = [], []
    for item in items:
        recipient, waitlist = claim_queue(db, item["id"])
        state, label = item_public_status(item, recipient, waitlist)
        record = {"item": item, "state": state, "label": label,
                  "waiting": len(waitlist), "claimed": recipient is not None}
        (given if state == "gone" else live).append(record)

    return render_template("index.html", live=live, given=given)


@app.route("/item/<int:item_id>")
def item_detail(item_id):
    db = get_db()
    item = db.execute("SELECT * FROM items WHERE id = ?", (item_id,)).fetchone()
    if item is None:
        abort(404)
    recipient, waitlist = claim_queue(db, item["id"])
    state, label = item_public_status(item, recipient, waitlist)
    return render_template(
        "item.html", item=item, state=state, label=label,
        claimed=recipient is not None, waiting=len(waitlist),
        blocked=get_blocked_dates(db, upcoming_only=True),
    )


GENERIC_REJECTION = (
    "We couldn't accept that just now. Please reload the page and try again."
)


@app.route("/item/<int:item_id>/claim", methods=["POST"])
def claim(item_id):
    db = get_db()
    item = db.execute("SELECT * FROM items WHERE id = ?", (item_id,)).fetchone()
    if item is None:
        abort(404)
    if item["status"] != "available":
        flash("Sorry, this item is no longer available.", "error")
        return redirect(url_for("item_detail", item_id=item_id))

    def reject(reason, message, **extra):
        """Refuse a claim, log why, and tell the visitor as little as useful.

        Bot-detection failures get a deliberately vague message: naming the
        control that caught them ("you filled the honeypot") is free tuning
        feedback for whoever is probing the form. Validation failures get a
        specific message, because those are overwhelmingly real people making
        real mistakes and a vague error there is just cruel.
        """
        audit("claim_rejected", reason=reason, item_id=item_id, **extra)
        flash(message, "error")
        return redirect(url_for("item_detail", item_id=item_id))

    # --- Category 1: is this submission plausibly from a person on our page? --
    if hardening.honeypot_tripped(request.form):
        return reject("honeypot", GENERIC_REJECTION)

    stamp_ok, stamp_reason = hardening.check_form_stamp(
        app.config["SECRET_KEY"], request.form.get("form_stamp", "")
    )
    if not stamp_ok:
        if stamp_reason == "stamp_expired":
            # A real person who left the tab open overnight. Say so plainly.
            return reject(stamp_reason,
                          "This page went stale. Please reload and claim again.")
        return reject(stamp_reason, GENERIC_REJECTION)

    # --- Category 2: rate limiting -------------------------------------------
    for bucket, suffix in (("claim_burst", ""),
                           ("claim_sustained", ""),
                           ("claim_item", str(item_id))):
        allowed, retry_after = rate_limited(bucket, suffix)
        if not allowed:
            audit("rate_limited", bucket=bucket, item_id=item_id,
                  retry_after=retry_after)
            flash(
                "That's a lot of claims in a short time. Please wait a few "
                "minutes and try again.", "error",
            )
            response = redirect(url_for("item_detail", item_id=item_id))
            response.headers["Retry-After"] = str(retry_after)
            return response

    # --- Category 3: input validation ----------------------------------------
    name = hardening.clean_text(request.form.get("name"), hardening.NAME_MAX)
    contact = hardening.clean_text(request.form.get("contact"), hardening.CONTACT_MAX)
    pickup_date = clean(request.form.get("pickup_date"), 20)
    pickup_time = clean(request.form.get("pickup_time"), 40)
    note = hardening.clean_text(request.form.get("note"), hardening.NOTE_MAX,
                                collapse_whitespace=False)

    # Validation errors are collected rather than returned on the first miss:
    # someone who left two fields wrong should be told about both, not sent
    # round the loop once per mistake. (The bot checks above deliberately do
    # fail fast — there is nobody there to help.)
    disposable = hardening.DISPOSABLE_DOMAINS if BLOCK_DISPOSABLE_EMAIL else None
    blocked = {r["date"] for r in get_blocked_dates(db)}

    checks = [
        hardening.check_name(name),
        hardening.check_contact(contact, disposable),
        hardening.check_note(note),
    ]
    if not valid_date(pickup_date):
        checks.append((False, "date_invalid", "Please choose a valid pickup date."))
    elif pickup_date < today_str():
        checks.append((False, "date_past", "Pickup date can't be in the past."))
    elif pickup_date in blocked:
        checks.append((False, "date_blocked",
                       "That date isn't available for pickup. Please choose another."))
    if pickup_time and not valid_time(pickup_time):
        checks.append((False, "time_invalid", "Please choose a valid pickup time."))

    failures = [(reason, message) for ok, reason, message in checks if not ok]
    if failures:
        audit("claim_rejected", item_id=item_id,
              reason=",".join(reason for reason, _ in failures))
        for _, message in failures:
            flash(message, "error")
        return redirect(url_for("item_detail", item_id=item_id))

    # --- Duplicate claims -----------------------------------------------------
    # The observed attack was 21 near-identical submissions to one item. Even
    # setting spam aside, the same person claiming twice quietly occupies two
    # waitlist slots and pushes a real person down the queue.
    fingerprint = hardening.contact_fingerprint(contact)
    if fingerprint:
        existing = db.execute(
            "SELECT token, contact FROM claims "
            "WHERE item_id = ? AND status = 'active' ORDER BY created_at, id",
            (item_id,),
        ).fetchall()
        for row in existing:
            if hardening.contact_fingerprint(row["contact"]) == fingerprint:
                audit("claim_duplicate", item_id=item_id,
                      contact_fp=fingerprint[:12])
                flash("You're already in line for this one — here's where you stand.",
                      "ok")
                return redirect(url_for("claim_success", token=row["token"]))

    token = secrets.token_urlsafe(16)
    db.execute(
        "INSERT INTO claims (item_id, name, contact, pickup_date, pickup_time, note, token) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (item_id, name, contact, pickup_date, pickup_time, note, token),
    )
    db.commit()

    audit("claim_accepted", item_id=item_id, contact_fp=fingerprint[:12] or None)

    # claim_success recomputes the queue position from the token, so there's
    # nothing to pass along here.
    return redirect(url_for("claim_success", token=token))


@app.route("/claim/<token>")
def claim_success(token):
    db = get_db()
    row = db.execute("SELECT * FROM claims WHERE token = ?", (token,)).fetchone()
    if row is None:
        abort(404)
    item = db.execute("SELECT * FROM items WHERE id = ?", (row["item_id"],)).fetchone()

    recipient, waitlist = claim_queue(db, row["item_id"])
    if row["status"] == "cancelled":
        position = None
    elif row["status"] == "fulfilled" or (recipient and recipient["token"] == token):
        position = 0
    else:
        position = next(
            (i + 1 for i, c in enumerate(waitlist) if c["token"] == token), None
        )

    return render_template(
        "claim_success.html", claim=row, item=item, position=position,
    )


@app.route("/claim/<token>/cancel", methods=["POST"])
def claim_cancel(token):
    db = get_db()
    row = db.execute("SELECT * FROM claims WHERE token = ?", (token,)).fetchone()
    if row is None:
        abort(404)
    if row["status"] == "active":
        db.execute("UPDATE claims SET status = 'cancelled' WHERE token = ?", (token,))
        db.commit()
        flash("Your claim was withdrawn. Thanks for letting us know!", "ok")
    return redirect(url_for("claim_success", token=token))


# --------------------------------------------------------------------------- #
# Admin routes
# --------------------------------------------------------------------------- #
def password_matches(candidate):
    """Check a submitted admin password against whichever form is configured.

    Prefers ADMIN_PASSWORD_HASH. Falls back to the plaintext ADMIN_PASSWORD so
    existing deployments keep working across the upgrade, and refuses outright
    if neither is set rather than letting an empty password in.
    """
    if ADMIN_PASSWORD_HASH:
        try:
            return check_password_hash(ADMIN_PASSWORD_HASH, candidate)
        except Exception:
            app.logger.error("ADMIN_PASSWORD_HASH is not a valid werkzeug hash.")
            return False
    if not ADMIN_PASSWORD:
        return False
    return secure_equals(candidate, ADMIN_PASSWORD)


@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        # Only *failed* attempts are counted, so a busy admin signing in from
        # several devices is never locked out by their own success. The limiter
        # is checked before the comparison runs, which also caps how much CPU a
        # brute-forcer can spend on password hashing.
        limit, window = RATE_LIMITS["login_failed"]
        key = f"login_failed:{client_ip()}"
        allowed, retry_after = limiter.peek(key, limit, window)
        if not allowed:
            audit("login_throttled", retry_after=retry_after)
            flash(
                f"Too many failed sign-in attempts. Try again in "
                f"{max(1, retry_after // 60)} minute(s).", "error",
            )
            response = render_template("admin_login.html")
            return response, 429, {"Retry-After": str(retry_after)}

        password = request.form.get("password", "")
        if password_matches(password):
            limiter.reset(key)
            audit("login_ok")
            session.clear()  # new privilege level, new session identifiers
            session["is_admin"] = True
            dest = request.args.get("next", "")
            # Must be a same-site absolute path: "//evil.example" is a valid
            # protocol-relative URL that startswith("/admin") would never see,
            # but "/admin" alone isn't enough of a guard to rely on by luck.
            if dest.startswith("/admin/") or dest == "/admin":
                return redirect(dest)
            return redirect(url_for("admin_dashboard"))

        limiter.check(key, limit, window)
        audit("login_failed")
        flash("That password didn't match.", "error")
    return render_template("admin_login.html")


@app.route("/admin/logout", methods=["POST"])
def admin_logout():
    session.pop("is_admin", None)
    flash("Signed out.", "ok")
    return redirect(url_for("index"))


@app.route("/admin")
@login_required
def admin_dashboard():
    db = get_db()
    items = db.execute("SELECT * FROM items ORDER BY status, created_at DESC").fetchall()
    rows = []
    for item in items:
        recipient, waitlist = claim_queue(db, item["id"])
        rows.append({
            "item": item,
            "recipient": recipient,
            "waiting": len(waitlist),
        })
    upcoming_blocked = len(get_blocked_dates(db, upcoming_only=True))
    return render_template("admin_dashboard.html", rows=rows,
                           upcoming_blocked=upcoming_blocked)


@app.route("/admin/dates", methods=["GET", "POST"])
@login_required
def admin_dates():
    db = get_db()
    if request.method == "POST":
        block_date = clean(request.form.get("date"), 20)
        reason = clean(request.form.get("reason"), 120)
        if not valid_date(block_date):
            flash("Please choose a valid date to block.", "error")
        elif block_date < today_str():
            # The form carries min="{{ today }}", but that's a client-side hint
            # only — the handler used to accept any date that parsed, so a past
            # date could be blocked and then sat in the list forever.
            flash("That date has already passed. Pick today or later.", "error")
        else:
            try:
                db.execute(
                    "INSERT INTO blocked_dates (date, reason) VALUES (?, ?)",
                    (block_date, reason),
                )
                db.commit()
                flash("Date blocked. No one can pick that day for pickup.", "ok")
            except sqlite3.IntegrityError:
                flash("That date is already blocked.", "error")
        return redirect(url_for("admin_dates"))

    blocked = get_blocked_dates(db)
    today = today_str()
    return render_template("admin_dates.html", blocked=blocked, today=today)


@app.route("/admin/dates/<int:date_id>/delete", methods=["POST"])
@login_required
def admin_dates_delete(date_id):
    db = get_db()
    db.execute("DELETE FROM blocked_dates WHERE id = ?", (date_id,))
    db.commit()
    flash("Date reopened for pickups.", "ok")
    return redirect(url_for("admin_dates"))


@app.route("/admin/item/new", methods=["GET", "POST"])
@login_required
def admin_item_new():
    if request.method == "POST":
        title = clean(request.form.get("title"), 120)
        description = clean(request.form.get("description"), 2000)
        image_url = clean(request.form.get("image_url"), 500)
        if not title:
            flash("An item needs a title.", "error")
            return render_template("admin_item_form.html", item=None,
                                   form=request.form)
        try:
            image_url = safe_image_url(image_url)
            uploaded = save_upload(request.files.get("image_file"))
        except ValueError as exc:
            flash(str(exc), "error")
            return render_template("admin_item_form.html", item=None,
                                   form=request.form)
        db = get_db()
        db.execute(
            "INSERT INTO items (title, description, image_url) VALUES (?, ?, ?)",
            (title, description, uploaded or image_url),
        )
        db.commit()
        flash("Item added.", "ok")
        return redirect(url_for("admin_dashboard"))
    return render_template("admin_item_form.html", item=None, form={})


@app.route("/admin/item/<int:item_id>/edit", methods=["GET", "POST"])
@login_required
def admin_item_edit(item_id):
    db = get_db()
    item = db.execute("SELECT * FROM items WHERE id = ?", (item_id,)).fetchone()
    if item is None:
        abort(404)
    if request.method == "POST":
        title = clean(request.form.get("title"), 120)
        description = clean(request.form.get("description"), 2000)
        image_url = clean(request.form.get("image_url"), 500)
        status = request.form.get("status", "available")
        status = status if status in ("available", "gone") else "available"
        if not title:
            flash("An item needs a title.", "error")
            return render_template("admin_item_form.html", item=item,
                                   form=request.form)
        try:
            image_url = safe_image_url(image_url)
            uploaded = save_upload(request.files.get("image_file"))
        except ValueError as exc:
            flash(str(exc), "error")
            return render_template("admin_item_form.html", item=item,
                                   form=request.form)
        new_image = uploaded or image_url
        db.execute(
            "UPDATE items SET title = ?, description = ?, image_url = ?, status = ? "
            "WHERE id = ?",
            (title, description, new_image, status, item_id),
        )
        db.commit()
        if new_image != item["image_url"]:
            delete_upload(item["image_url"])
        flash("Changes saved.", "ok")
        return redirect(url_for("admin_item_manage", item_id=item_id))
    return render_template("admin_item_form.html", item=item, form=item)


@app.route("/admin/item/<int:item_id>")
@login_required
def admin_item_manage(item_id):
    db = get_db()
    item = db.execute("SELECT * FROM items WHERE id = ?", (item_id,)).fetchone()
    if item is None:
        abort(404)
    recipient, waitlist = claim_queue(db, item_id)
    history = db.execute(
        "SELECT * FROM claims WHERE item_id = ? AND status != 'active' "
        "ORDER BY created_at DESC",
        (item_id,),
    ).fetchall()
    blocked_set = {r["date"] for r in get_blocked_dates(db)}
    return render_template(
        "admin_item_manage.html", item=item, recipient=recipient,
        waitlist=waitlist, history=history, blocked_set=blocked_set,
    )


@app.route("/admin/item/<int:item_id>/delete", methods=["POST"])
@login_required
def admin_item_delete(item_id):
    db = get_db()
    item = db.execute("SELECT * FROM items WHERE id = ?", (item_id,)).fetchone()
    if item is None:
        abort(404)
    db.execute("DELETE FROM items WHERE id = ?", (item_id,))
    db.commit()
    delete_upload(item["image_url"])
    flash("Item deleted.", "ok")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/item/<int:item_id>/given", methods=["POST"])
@login_required
def admin_item_given(item_id):
    """Mark the current recipient as fulfilled and close the item."""
    db = get_db()
    recipient, _ = claim_queue(db, item_id)
    if recipient is not None:
        db.execute("UPDATE claims SET status = 'fulfilled' WHERE id = ?",
                   (recipient["id"],))
    db.execute("UPDATE items SET status = 'gone' WHERE id = ?", (item_id,))
    db.commit()
    flash("Marked as given away.", "ok")
    return redirect(url_for("admin_item_manage", item_id=item_id))


@app.route("/admin/item/<int:item_id>/reopen", methods=["POST"])
@login_required
def admin_item_reopen(item_id):
    db = get_db()
    db.execute("UPDATE items SET status = 'available' WHERE id = ?", (item_id,))
    db.commit()
    flash("Item is back on the board.", "ok")
    return redirect(url_for("admin_item_manage", item_id=item_id))


@app.route("/admin/claim/<int:claim_id>/remove", methods=["POST"])
@login_required
def admin_claim_remove(claim_id):
    """Cancel a claim. If it was the recipient, the next person is promoted
    automatically because the recipient is always the earliest active claim."""
    db = get_db()
    row = db.execute("SELECT * FROM claims WHERE id = ?", (claim_id,)).fetchone()
    if row is None:
        abort(404)
    db.execute("UPDATE claims SET status = 'cancelled' WHERE id = ?", (claim_id,))
    db.commit()
    flash("Claim removed. Next person in line is now first.", "ok")
    return redirect(url_for("admin_item_manage", item_id=row["item_id"]))


# --------------------------------------------------------------------------- #
# Error pages
# --------------------------------------------------------------------------- #
@app.errorhandler(404)
def not_found(_e):
    return render_template("error.html", code=404,
                           message="We couldn't find that."), 404


@app.errorhandler(400)
def bad_request(e):
    return render_template("error.html", code=400,
                           message=getattr(e, "description", "Bad request.")), 400


@app.errorhandler(413)
def too_large(_e):
    return render_template(
        "error.html", code=413,
        message=f"That image is too big (limit {MAX_UPLOAD_MB} MB)."), 413


@app.errorhandler(429)
def too_many(_e):
    return render_template(
        "error.html", code=429,
        message="Too many requests. Please wait a moment and try again."), 429


@app.route("/healthz")
def healthz():
    """Liveness probe: proves the process is up *and* the database answers."""
    try:
        get_db().execute("SELECT 1").fetchone()
    except Exception as exc:  # pragma: no cover - only on a broken volume
        app.logger.error("Health check failed: %s", exc)
        return {"status": "error"}, 503
    return {"status": "ok"}, 200


# --------------------------------------------------------------------------- #
init_db()

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "hash-password":
        # Generates the value for ADMIN_PASSWORD_HASH. Read from a prompt rather
        # than argv so the password never lands in shell history or `ps` output.
        import getpass
        entered = getpass.getpass("New admin password: ")
        if entered != getpass.getpass("Confirm: "):
            sys.exit("Passwords didn't match.")
        if len(entered) < 12:
            sys.exit("Please use at least 12 characters.")
        print("\nAdd this to your .env (and remove ADMIN_PASSWORD):\n")
        print(f"ADMIN_PASSWORD_HASH={generate_password_hash(entered)}")
        sys.exit(0)

    # Debug mode exposes the Werkzeug console — opt in explicitly with
    # FLASK_DEBUG=1 rather than shipping it on by default.
    app.run(
        host=os.environ.get("HOST", "127.0.0.1"),
        port=int(os.environ.get("PORT", "8000")),
        debug=os.environ.get("FLASK_DEBUG", "") == "1",
    )
