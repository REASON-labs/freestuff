"""Test suite for FreeStuff.

Run with:  python -m pytest
"""
import io
import os
import re
import sqlite3
import tempfile

import pytest

# Configure a throwaway data directory BEFORE importing the app, since the app
# reads its configuration and initialises the database at import time.
_TMP = tempfile.mkdtemp(prefix="freestuff-test-")
os.environ["DATA_DIR"] = _TMP
os.environ["ADMIN_PASSWORD"] = "test-pass"
os.environ["SECRET_KEY"] = "test-secret"

import app as fs  # noqa: E402


# --------------------------------------------------------------------------- #
# Fixtures & helpers
# --------------------------------------------------------------------------- #
@pytest.fixture
def client():
    """A test client backed by a fresh database for each test."""
    if fs.DB_PATH.exists():
        fs.DB_PATH.unlink()
    fs.init_db()
    fs.app.config["TESTING"] = True
    with fs.app.test_client() as c:
        yield c


def csrf(html):
    return re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)


def login(c):
    token = csrf(c.get("/admin/login").get_data(as_text=True))
    c.post("/admin/login", data={"password": "test-pass", "csrf_token": token})


def add_item(c, title="Blue armchair", description="Comfy", image_url=""):
    token = csrf(c.get("/admin/item/new").get_data(as_text=True))
    return c.post(
        "/admin/item/new",
        data={"title": title, "description": description,
              "image_url": image_url, "csrf_token": token},
        follow_redirects=True,
    )


def claim_item(c, item_id, **fields):
    data = {"name": "Ana", "contact": "ana@example.com",
            "pickup_date": "2099-01-01", "pickup_time": "", "note": ""}
    data.update(fields)
    data["csrf_token"] = csrf(c.get(f"/item/{item_id}").get_data(as_text=True))
    return c.post(f"/item/{item_id}/claim", data=data, follow_redirects=True)


def db():
    con = sqlite3.connect(fs.DB_PATH)
    con.row_factory = sqlite3.Row
    return con


# --------------------------------------------------------------------------- #
# Public + admin basics
# --------------------------------------------------------------------------- #
def test_homepage_empty(client):
    r = client.get("/")
    assert r.status_code == 200
    assert b"Nothing on the board" in r.data


def test_admin_requires_login(client):
    r = client.get("/admin")
    assert r.status_code == 302
    assert "/admin/login" in r.location


def test_login_rejects_wrong_password(client):
    token = csrf(client.get("/admin/login").get_data(as_text=True))
    r = client.post("/admin/login",
                    data={"password": "nope", "csrf_token": token})
    assert b"match" in r.data


def test_missing_csrf_is_rejected(client):
    login(client)
    r = client.post("/admin/item/1/reopen", data={})
    assert r.status_code == 400


# --------------------------------------------------------------------------- #
# Claim + waitlist flow
# --------------------------------------------------------------------------- #
def test_first_claim_is_recipient(client):
    login(client)
    add_item(client)
    r = claim_item(client, 1)
    assert b"first in line" in r.data


def test_second_claim_goes_to_waitlist(client):
    login(client)
    add_item(client)
    claim_item(client, 1, name="Ana")
    r = claim_item(client, 1, name="Ben", contact="555")
    assert b"on the waitlist" in r.data


def test_public_page_hides_claimant_contacts(client):
    login(client)
    add_item(client)
    claim_item(client, 1, name="Ana", contact="secret@ana.com")
    page = client.get("/item/1").get_data(as_text=True)
    assert "secret@ana.com" not in page


def test_removing_recipient_promotes_next(client):
    login(client)
    add_item(client)
    claim_item(client, 1, name="Ana")
    claim_item(client, 1, name="Ben", contact="555")
    con = db()
    ana_id = con.execute("SELECT id FROM claims WHERE name='Ana'").fetchone()["id"]
    token = csrf(client.get("/admin/item/1").get_data(as_text=True))
    r = client.post(f"/admin/claim/{ana_id}/remove",
                    data={"csrf_token": token}, follow_redirects=True)
    assert b"Ben" in r.data and b"1st" in r.data


def test_mark_given_away_closes_item(client):
    login(client)
    add_item(client)
    claim_item(client, 1)
    token = csrf(client.get("/admin/item/1").get_data(as_text=True))
    client.post("/admin/item/1/given",
                data={"csrf_token": token}, follow_redirects=True)
    assert b"Recently given away" in client.get("/").data


# --------------------------------------------------------------------------- #
# Validation
# --------------------------------------------------------------------------- #
def test_claim_rejects_past_date_and_empty_fields(client):
    login(client)
    add_item(client)
    r = claim_item(client, 1, name="", contact="", pickup_date="2000-01-01")
    assert b"add your name" in r.data
    assert b"past" in r.data


# --------------------------------------------------------------------------- #
# Blocked dates
# --------------------------------------------------------------------------- #
def test_admin_can_block_and_unblock_dates(client):
    login(client)
    token = csrf(client.get("/admin/dates").get_data(as_text=True))
    r = client.post("/admin/dates",
                    data={"date": "2099-12-25", "reason": "Holiday",
                          "csrf_token": token}, follow_redirects=True)
    assert b"Date blocked" in r.data

    # duplicate rejected
    token = csrf(client.get("/admin/dates").get_data(as_text=True))
    r = client.post("/admin/dates",
                    data={"date": "2099-12-25", "reason": "",
                          "csrf_token": token}, follow_redirects=True)
    assert b"already blocked" in r.data


def test_claim_on_blocked_date_is_rejected_server_side(client):
    login(client)
    add_item(client)
    token = csrf(client.get("/admin/dates").get_data(as_text=True))
    client.post("/admin/dates",
                data={"date": "2099-12-25", "reason": "", "csrf_token": token},
                follow_redirects=True)
    r = claim_item(client, 1, pickup_date="2099-12-25")
    assert b"available for pickup" in r.data
    assert db().execute("SELECT COUNT(*) FROM claims").fetchone()[0] == 0


def test_blocked_date_shown_on_item_page(client):
    login(client)
    add_item(client)
    token = csrf(client.get("/admin/dates").get_data(as_text=True))
    client.post("/admin/dates",
                data={"date": "2099-12-25", "reason": "Holiday",
                      "csrf_token": token}, follow_redirects=True)
    page = client.get("/item/1").get_data(as_text=True)
    assert "2099-12-25" in page and "Holiday" in page


# --------------------------------------------------------------------------- #
# Pickup time
# --------------------------------------------------------------------------- #
def test_pickup_time_is_saved_and_shown(client):
    login(client)
    add_item(client)
    r = claim_item(client, 1, pickup_time="15:30")
    assert b"15:30" in r.data
    row = db().execute("SELECT pickup_time FROM claims").fetchone()
    assert row["pickup_time"] == "15:30"


# --------------------------------------------------------------------------- #
# HEIC conversion
# --------------------------------------------------------------------------- #
def test_heic_upload_is_converted_to_jpeg(client):
    pillow_heif = pytest.importorskip("pillow_heif")
    from PIL import Image
    pillow_heif.register_heif_opener()

    buf = io.BytesIO()
    Image.new("RGB", (800, 600), (224, 149, 46)).save(buf, format="HEIF")

    login(client)
    token = csrf(client.get("/admin/item/new").get_data(as_text=True))
    r = client.post("/admin/item/new", data={
        "title": "Desk", "description": "", "image_url": "",
        "csrf_token": token,
        "image_file": (io.BytesIO(buf.getvalue()), "IMG_1.HEIC"),
    }, content_type="multipart/form-data", follow_redirects=True)
    assert b"Item added" in r.data

    url = db().execute("SELECT image_url FROM items").fetchone()["image_url"]
    assert url.endswith(".jpg")
    served = client.get(url)
    assert served.status_code == 200
    assert served.data[:3] == b"\xff\xd8\xff"  # JPEG magic bytes


def test_bad_upload_type_is_rejected(client):
    login(client)
    token = csrf(client.get("/admin/item/new").get_data(as_text=True))
    r = client.post("/admin/item/new", data={
        "title": "Bad", "description": "", "image_url": "",
        "csrf_token": token,
        "image_file": (io.BytesIO(b"nope"), "malware.exe"),
    }, content_type="multipart/form-data", follow_redirects=True)
    assert b"Unsupported image type" in r.data


# --------------------------------------------------------------------------- #
# Migration from an older database
# --------------------------------------------------------------------------- #
def test_migration_adds_pickup_time_to_old_db():
    """A database created before pickup_time existed should be upgraded in place
    without losing data."""
    tmp = tempfile.mkdtemp(prefix="freestuff-migrate-")
    old_db = os.path.join(tmp, "old.db")
    con = sqlite3.connect(old_db)
    con.executescript("""
        CREATE TABLE items (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL,
          description TEXT NOT NULL DEFAULT '', image_url TEXT NOT NULL DEFAULT '',
          status TEXT NOT NULL DEFAULT 'available',
          created_at TEXT NOT NULL DEFAULT (datetime('now')));
        CREATE TABLE claims (id INTEGER PRIMARY KEY AUTOINCREMENT, item_id INTEGER NOT NULL,
          name TEXT NOT NULL, contact TEXT NOT NULL, pickup_date TEXT NOT NULL DEFAULT '',
          note TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'active',
          token TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT (datetime('now')));
        INSERT INTO items (title) VALUES ('Old couch');
    """)
    con.commit()
    con.close()

    # Point the app's schema loader at this old DB and migrate it.
    original = fs.DB_PATH
    try:
        fs.DB_PATH = __import__("pathlib").Path(old_db)
        fs.init_db()
        con = sqlite3.connect(old_db)
        cols = [r[1] for r in con.execute("PRAGMA table_info(claims)")]
        tables = [r[0] for r in con.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")]
        assert "pickup_time" in cols
        assert "blocked_dates" in tables
        assert con.execute("SELECT COUNT(*) FROM items").fetchone()[0] == 1
        con.close()
    finally:
        fs.DB_PATH = original
