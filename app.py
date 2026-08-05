"""
FreeShare — a tiny self-hosted board for giving things away to friends.

Public side:  browse available items, claim one (or join its waitlist).
Admin side:   add / edit / delete items, see the queue and contact details,
              mark items given away, remove claims (which promotes the next
              person in line automatically).

Single-file Flask app backed by SQLite. No external services, no CDN calls.
"""

import os
import re
import hmac
import secrets
import sqlite3
from datetime import date, datetime
from functools import wraps
from pathlib import Path

from flask import (
    Flask, g, request, session, redirect, url_for,
    render_template, abort, flash, send_from_directory,
)
from werkzeug.utils import secure_filename

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

DB_PATH = DATA_DIR / "freeshare.db"

SITE_NAME = os.environ.get("SITE_NAME", "Free Stuff")
SITE_TAGLINE = os.environ.get(
    "SITE_TAGLINE", "Take what you'll love."
)

ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "changeme")

# Formats stored as-is. GIFs pass through untouched so animation is preserved.
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp"}
# Formats we convert to JPEG on the way in (browsers can't display HEIC).
CONVERT_EXTENSIONS = {"heic", "heif"}
MAX_UPLOAD_MB = int(os.environ.get("MAX_UPLOAD_MB", "8"))

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_MB * 1024 * 1024
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY") or secrets.token_hex(32)

if not os.environ.get("SECRET_KEY"):
    app.logger.warning(
        "SECRET_KEY not set — using a random key. Sessions reset on restart. "
        "Set SECRET_KEY in the environment for production."
    )
if ADMIN_PASSWORD == "changeme":
    app.logger.warning(
        "ADMIN_PASSWORD is still the default 'changeme'. Set a real one."
    )


# --------------------------------------------------------------------------- #
# Database helpers
# --------------------------------------------------------------------------- #
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    schema = (Path(__file__).parent / "schema.sql").read_text()
    con = sqlite3.connect(DB_PATH)
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
        today = date.today().isoformat()
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


@app.before_request
def csrf_protect():
    if request.method == "POST":
        sent = request.form.get("csrf_token", "")
        if not hmac.compare_digest(sent, session.get("csrf_token", "")):
            abort(400, "Invalid or missing form token. Please reload and retry.")


@app.context_processor
def inject_globals():
    return {
        "csrf_token": get_csrf_token,
        "site_name": SITE_NAME,
        "site_tagline": SITE_TAGLINE,
        "is_admin": session.get("is_admin", False),
        "today": date.today().isoformat(),
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
            image = ImageOps.exif_transpose(image).convert("RGB")
        except Exception:
            raise ValueError("Couldn't read that HEIC photo. Try a JPG or PNG.")
        name = f"{secrets.token_hex(8)}.jpg"
        image.save(UPLOAD_DIR / name, format="JPEG", quality=85)
        return url_for("uploaded_file", filename=name)

    if ext not in ALLOWED_EXTENSIONS:
        raise ValueError("Unsupported image type. Use HEIC, PNG, JPG, GIF, or WEBP.")
    name = f"{secrets.token_hex(8)}.{ext}"
    file_storage.save(UPLOAD_DIR / name)
    return url_for("uploaded_file", filename=name)


@app.route("/uploads/<path:filename>")
def uploaded_file(filename):
    return send_from_directory(UPLOAD_DIR, filename)


# --------------------------------------------------------------------------- #
# Validation helpers
# --------------------------------------------------------------------------- #
def clean(text, limit):
    return (text or "").strip()[:limit]


def valid_date(value):
    if not value:
        return False
    try:
        datetime.strptime(value, "%Y-%m-%d")
        return True
    except ValueError:
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


@app.route("/item/<int:item_id>/claim", methods=["POST"])
def claim(item_id):
    db = get_db()
    item = db.execute("SELECT * FROM items WHERE id = ?", (item_id,)).fetchone()
    if item is None:
        abort(404)
    if item["status"] != "available":
        flash("Sorry, this item is no longer available.", "error")
        return redirect(url_for("item_detail", item_id=item_id))

    name = clean(request.form.get("name"), 120)
    contact = clean(request.form.get("contact"), 200)
    pickup_date = clean(request.form.get("pickup_date"), 20)
    pickup_time = clean(request.form.get("pickup_time"), 40)
    note = clean(request.form.get("note"), 500)

    blocked = {r["date"] for r in get_blocked_dates(db)}

    errors = []
    if not name:
        errors.append("Please add your name.")
    if not contact:
        errors.append("Please add a way to reach you (email or phone).")
    if not valid_date(pickup_date):
        errors.append("Please choose a valid pickup date.")
    elif pickup_date < date.today().isoformat():
        errors.append("Pickup date can't be in the past.")
    elif pickup_date in blocked:
        errors.append("That date isn't available for pickup. Please choose another.")

    if errors:
        for e in errors:
            flash(e, "error")
        return redirect(url_for("item_detail", item_id=item_id))

    token = secrets.token_urlsafe(16)
    db.execute(
        "INSERT INTO claims (item_id, name, contact, pickup_date, pickup_time, note, token) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (item_id, name, contact, pickup_date, pickup_time, note, token),
    )
    db.commit()

    # Position among active claims (0 = recipient).
    recipient, waitlist = claim_queue(db, item_id)
    position = 0 if recipient and recipient["token"] == token else \
        next((i + 1 for i, c in enumerate(waitlist) if c["token"] == token), 0)

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
@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        password = request.form.get("password", "")
        if hmac.compare_digest(password, ADMIN_PASSWORD):
            session["is_admin"] = True
            dest = request.args.get("next", "")
            if dest.startswith("/admin"):
                return redirect(dest)
            return redirect(url_for("admin_dashboard"))
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
    today = date.today().isoformat()
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
            uploaded = save_upload(request.files.get("image_file"))
        except ValueError as exc:
            flash(str(exc), "error")
            return render_template("admin_item_form.html", item=item,
                                   form=request.form)
        db.execute(
            "UPDATE items SET title = ?, description = ?, image_url = ?, status = ? "
            "WHERE id = ?",
            (title, description, uploaded or image_url, status, item_id),
        )
        db.commit()
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
    db.execute("DELETE FROM items WHERE id = ?", (item_id,))
    db.commit()
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


# --------------------------------------------------------------------------- #
init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "8000")), debug=True)
