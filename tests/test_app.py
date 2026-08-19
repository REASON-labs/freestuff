"""Test suite for FreeStuff.

Run with:  python -m pytest
"""
import io
import json
import os
import re
import sqlite3
import tempfile
import time

import pytest

# Configure a throwaway data directory BEFORE importing the app, since the app
# reads its configuration and initialises the database at import time.
_TMP = tempfile.mkdtemp(prefix="freestuff-test-")
os.environ["DATA_DIR"] = _TMP
os.environ["ADMIN_PASSWORD"] = "test-pass"
os.environ["SECRET_KEY"] = "test-secret"

import app as fs  # noqa: E402
import hardening  # noqa: E402


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
    # The rate limiter lives in process memory, so without this every test after
    # the third claim would inherit the previous test's counters.
    fs.limiter = hardening.RateLimiter()
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


def fresh_stamp(seconds_ago=10):
    """A validly-signed form stamp, aged to look like a human filling a form.

    Tests can't use the stamp the page actually renders: it is issued "now", and
    the server rejects anything submitted faster than MIN_FILL_SECONDS. Minting
    a backdated one exercises the real signature path while standing in for the
    ten seconds a person would have spent typing.
    """
    return hardening.sign_form_stamp(
        fs.app.config["SECRET_KEY"], issued_at=time.time() - seconds_ago
    )


def claim_item(c, item_id, **fields):
    data = {"name": "Ana", "contact": "ana@example.com",
            "pickup_date": "2099-01-01", "pickup_time": "", "note": "",
            "form_stamp": fresh_stamp()}
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
    r = claim_item(client, 1, name="Ben", contact="555-0142-990")
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
    claim_item(client, 1, name="Ben", contact="555-0142-990")
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


# --------------------------------------------------------------------------- #
# Regression tests for the security / correctness pass
# --------------------------------------------------------------------------- #
def test_post_without_any_session_token_is_rejected(client):
    """A POST from a session that never rendered a form must not pass CSRF.

    The old check compared the submitted token with session.get(..., "") — so
    an empty submitted token matched an absent session token and sailed through.
    """
    login(client)
    add_item(client)
    fresh = fs.app.test_client()          # never loaded a page, so no token
    resp = fresh.post("/item/1/claim", data={
        "name": "Mallory", "contact": "m@example.com", "pickup_date": "2099-01-01",
    })
    assert resp.status_code == 400
    assert db().execute("SELECT COUNT(*) c FROM claims").fetchone()["c"] == 0


def test_non_ascii_password_does_not_500(client):
    """hmac.compare_digest raises TypeError on non-ASCII strings."""
    token = csrf(client.get("/admin/login").get_data(as_text=True))
    resp = client.post("/admin/login",
                       data={"password": "hünter2", "csrf_token": token})
    assert resp.status_code == 200
    assert b"didn&#39;t match" in resp.data or b"didn't match" in resp.data


def test_non_ascii_csrf_token_is_rejected_not_500(client):
    login(client)
    add_item(client)
    client.get("/item/1")                 # establish a session token
    resp = client.post("/item/1/claim", data={
        "name": "Ana", "contact": "a@example.com",
        "pickup_date": "2099-01-01", "csrf_token": "café",
    })
    assert resp.status_code == 400


def test_claimant_name_cannot_inject_script_into_admin_page(client):
    """Names are rendered into a data-confirm attribute, never a JS string."""
    login(client)
    add_item(client)
    payload = "Bob'+(window.pwned=1)+'"
    claim_item(client, 1, name=payload)
    html = client.get("/admin/item/1").get_data(as_text=True)
    # No inline handler anywhere, so there is no JavaScript string literal for
    # the name to break out of...
    assert "onsubmit" not in html
    # ...and the name survives only as escaped text inside a data attribute.
    assert 'data-confirm="Remove Bob&#39;+(window.pwned=1)+&#39;?' in html
    assert "confirm('Remove Bob'" not in html


def test_deleting_an_item_removes_its_uploaded_photo(client):
    login(client)
    upload = fs.UPLOAD_DIR / "deadbeef.png"
    upload.write_bytes(b"not really a png")
    token = csrf(client.get("/admin/item/new").get_data(as_text=True))
    client.post("/admin/item/new", data={
        "title": "Lamp", "image_url": "/uploads/deadbeef.png",
        "csrf_token": token,
    }, follow_redirects=True)
    assert upload.exists()
    token = csrf(client.get("/admin/item/1/edit").get_data(as_text=True))
    client.post("/admin/item/1/delete", data={"csrf_token": token},
                follow_redirects=True)
    assert not upload.exists()


def test_external_image_urls_are_left_alone_on_delete(client):
    """Only our own /uploads/ files get unlinked."""
    login(client)
    add_item(client, image_url="https://example.com/chair.jpg")
    token = csrf(client.get("/admin/item/1/edit").get_data(as_text=True))
    resp = client.post("/admin/item/1/delete", data={"csrf_token": token},
                       follow_redirects=True)
    assert resp.status_code == 200


def test_dangerous_image_urls_are_rejected(client):
    login(client)
    for bad in ("javascript:alert(1)",
                "data:text/html,<script>alert(1)</script>",
                "https://x.test/a.png');background:url('evil"):
        resp = add_item(client, title="Bad", image_url=bad)
        assert resp.status_code == 200
    assert db().execute("SELECT COUNT(*) c FROM items").fetchone()["c"] == 0


def test_valid_image_urls_still_work(client):
    login(client)
    add_item(client, image_url="https://example.com/chair.jpg")
    row = db().execute("SELECT image_url FROM items").fetchone()
    assert row["image_url"] == "https://example.com/chair.jpg"


def test_timezone_setting_controls_today(monkeypatch):
    monkeypatch.setattr(fs, "TIMEZONE", "Pacific/Kiritimati")   # UTC+14
    ahead = fs.today_str()
    monkeypatch.setattr(fs, "TIMEZONE", "Pacific/Midway")       # UTC-11
    behind = fs.today_str()
    assert ahead >= behind


def test_unknown_timezone_falls_back_instead_of_crashing(monkeypatch):
    monkeypatch.setattr(fs, "TIMEZONE", "Mars/Olympus_Mons")
    assert re.match(r"^\d{4}-\d{2}-\d{2}$", fs.today_str())


def test_login_rotates_the_session(client):
    """A pre-login session token must not survive the privilege change."""
    before = csrf(client.get("/admin/login").get_data(as_text=True))
    client.post("/admin/login",
                data={"password": "test-pass", "csrf_token": before})
    after = csrf(client.get("/admin").get_data(as_text=True))
    assert after != before


def test_wal_mode_is_enabled(client):
    con = db()
    assert con.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"


# --------------------------------------------------------------------------- #
# Hardening — pure helpers (hardening.py, no request context needed)
# --------------------------------------------------------------------------- #
def test_rate_limiter_allows_up_to_the_limit_then_blocks():
    clock = [1000.0]
    rl = hardening.RateLimiter(clock=lambda: clock[0])
    for _ in range(3):
        assert rl.check("ip", 3, 60)[0] is True
    allowed, retry_after = rl.check("ip", 3, 60)
    assert allowed is False
    assert 0 < retry_after <= 61


def test_rate_limiter_window_slides_open_again():
    clock = [1000.0]
    rl = hardening.RateLimiter(clock=lambda: clock[0])
    for _ in range(3):
        rl.check("ip", 3, 60)
    assert rl.check("ip", 3, 60)[0] is False
    clock[0] += 61
    assert rl.check("ip", 3, 60)[0] is True


def test_rate_limiter_rejection_does_not_extend_the_penalty():
    """A blocked client that keeps hammering must still recover on schedule.

    If a rejected hit were recorded, every retry would push the window forward
    and the client could never get back in — which also means one accidental
    double-click could lock a real person out for good.
    """
    clock = [1000.0]
    rl = hardening.RateLimiter(clock=lambda: clock[0])
    for _ in range(2):
        rl.check("ip", 2, 60)
    for _ in range(10):          # hammering while blocked
        clock[0] += 1
        assert rl.check("ip", 2, 60)[0] is False
    clock[0] = 1061              # 60s after the FIRST hit
    assert rl.check("ip", 2, 60)[0] is True


def test_rate_limiter_keys_are_independent():
    rl = hardening.RateLimiter()
    assert rl.check("a", 1, 60)[0] is True
    assert rl.check("a", 1, 60)[0] is False
    assert rl.check("b", 1, 60)[0] is True


def test_form_stamp_roundtrips():
    stamp = hardening.sign_form_stamp("secret", issued_at=1000)
    assert hardening.check_form_stamp("secret", stamp, now=1010) == (True, "")


def test_form_stamp_rejects_instant_submission():
    stamp = hardening.sign_form_stamp("secret", issued_at=1000)
    ok, reason = hardening.check_form_stamp("secret", stamp, now=1000)
    assert (ok, reason) == (False, "stamp_too_fast")


def test_form_stamp_rejects_stale_and_forged():
    stamp = hardening.sign_form_stamp("secret", issued_at=1000)
    assert hardening.check_form_stamp("secret", stamp, now=10**9)[1] == "stamp_expired"
    # Signed with a different key — i.e. minted by someone who isn't us.
    assert hardening.check_form_stamp(
        "secret", hardening.sign_form_stamp("other", issued_at=1000), now=1010
    )[1] == "stamp_bad_signature"
    # Timestamp edited to look recent, signature left alone.
    tampered = "9999999999." + stamp.split(".")[1]
    assert hardening.check_form_stamp("secret", tampered, now=1010)[0] is False
    assert hardening.check_form_stamp("secret", "")[1] == "stamp_missing"


def test_form_stamp_rejects_future_timestamps():
    """A forged stamp dated in the future must not read as 'old enough'."""
    stamp = hardening.sign_form_stamp("secret", issued_at=2000)
    assert hardening.check_form_stamp("secret", stamp, now=1000)[0] is False


def test_contact_requires_an_email_or_a_phone_number():
    # The exact shape used in the August 18 attack on the sibling app.
    assert hardening.check_contact("tyoyiosrzf")[1] == "contact_unreachable"
    assert hardening.check_contact("ana@example.com")[0] is True
    assert hardening.check_contact("555-123-4567")[0] is True
    assert hardening.check_contact("+1 (555) 123 4567")[0] is True
    # Free text around a real address still passes — people write like this.
    assert hardening.check_contact("email me at ana@example.com")[0] is True
    assert hardening.check_contact("ana@example.com or 555-123-4567")[0] is True


def test_contact_disposable_domains_only_when_enabled():
    throwaway = "jewflgkv@mailinator.com"
    assert hardening.check_contact(throwaway)[0] is True          # off by default
    ok, reason, _ = hardening.check_contact(throwaway, hardening.DISPOSABLE_DOMAINS)
    assert (ok, reason) == (False, "contact_disposable")
    # A subdomain of a throwaway provider is caught by the parent-domain check.
    assert hardening.check_contact(
        "x@mail.mailinator.com", hardening.DISPOSABLE_DOMAINS
    )[1] == "contact_disposable"


def test_name_rules():
    assert hardening.check_name("Ana")[0] is True
    assert hardening.check_name("A")[1] == "name_too_short"
    assert hardening.check_name("12345")[1] == "name_no_letters"
    assert hardening.check_name("Buy now http://spam.example")[1] == "name_has_link"
    # Real names that a gibberish heuristic would wrongly reject must pass.
    for name in ("Szczepanski", "Ng", "Þórunn", "O'Brien-Smith", "李明"):
        assert hardening.check_name(name)[0] is True, name


def test_note_allows_a_link_but_not_a_link_farm():
    assert hardening.check_note("see http://example.com for the manual")[0] is True
    spam = " ".join(f"http://spam{i}.example" for i in range(4))
    assert hardening.check_note(spam)[1] == "note_link_spam"


def test_clean_text_strips_control_characters_and_normalises():
    assert hardening.clean_text("An\x00a\x07", 50) == "Ana"
    assert hardening.clean_text("  Ana   Lee  ", 50) == "Ana Lee"
    # NFC normalisation, so "e + combining acute" and "é" are the same person.
    assert hardening.clean_text("Renée", 50) == hardening.clean_text("Renée", 50)
    assert hardening.clean_text("x" * 100, 10) == "x" * 10


def test_contact_fingerprint_collapses_equivalent_forms():
    fp = hardening.contact_fingerprint
    assert fp("Ana@Example.com ") == fp("ana@example.com")
    assert fp("555-123-4567") == fp("(555) 123 4567") == fp("+1 555 123 4567")
    assert fp("ana@example.com") != fp("ben@example.com")
    assert fp("") == ""


def test_honeypot_detects_a_filled_decoy():
    assert hardening.honeypot_tripped({}) is False
    assert hardening.honeypot_tripped({"website": "   "}) is False
    assert hardening.honeypot_tripped({"website": "http://spam"}) is True
    assert hardening.honeypot_tripped({"confirm_email": "x@y.com"}) is True


# --------------------------------------------------------------------------- #
# Hardening — end to end through the claim form
# --------------------------------------------------------------------------- #
def test_claim_form_serves_a_stamp_and_honeypots(client):
    login(client)
    add_item(client)
    page = client.get("/item/1").get_data(as_text=True)
    assert 'name="form_stamp"' in page
    for field in hardening.HONEYPOT_FIELDS:
        assert f'name="{field}"' in page
    # The decoys must never be reachable by keyboard or announced aloud.
    assert 'tabindex="-1"' in page and 'aria-hidden="true"' in page


def test_claim_without_a_stamp_is_rejected(client):
    """A direct POST that never loaded the page — the attack's actual shape."""
    login(client)
    add_item(client)
    token = csrf(client.get("/item/1").get_data(as_text=True))
    r = client.post("/item/1/claim", data={
        "name": "Ana", "contact": "ana@example.com",
        "pickup_date": "2099-01-01", "csrf_token": token,
    }, follow_redirects=True)
    assert b"couldn&#39;t accept that" in r.data
    assert db().execute("SELECT COUNT(*) FROM claims").fetchone()[0] == 0


def test_claim_submitted_instantly_is_rejected(client):
    login(client)
    add_item(client)
    r = claim_item(client, 1, form_stamp=fresh_stamp(seconds_ago=0))
    assert db().execute("SELECT COUNT(*) FROM claims").fetchone()[0] == 0
    # Vague on purpose: naming the control that caught it is free tuning
    # feedback for whoever is probing the form.
    assert b"honeypot" not in r.data.lower() and b"too fast" not in r.data.lower()


def test_stale_form_gets_a_helpful_message_not_a_vague_one(client):
    """A person who left the tab open overnight is not an attacker."""
    login(client)
    add_item(client)
    r = claim_item(client, 1, form_stamp=fresh_stamp(seconds_ago=60 * 60 * 24))
    assert b"went stale" in r.data


def test_filling_a_honeypot_is_rejected(client):
    login(client)
    add_item(client)
    r = claim_item(client, 1, website="http://spam.example")
    assert db().execute("SELECT COUNT(*) FROM claims").fetchone()[0] == 0
    assert b"couldn&#39;t accept that" in r.data


def test_claim_flood_is_rate_limited(client):
    """Replays the August 18 attack shape: many claims, back to back."""
    login(client)
    add_item(client, title="Truck")
    add_item(client, title="Chair")
    accepted = 0
    for i in range(21):
        r = claim_item(client, 1 if i % 2 else 2,
                       name=f"Bot {i}", contact=f"bot{i}@example.com")
        if b"lot of claims" not in r.data:
            accepted += 1
    limit = fs.RATE_LIMITS["claim_burst"][0]
    assert accepted == limit, f"{accepted} of 21 got through, expected {limit}"


def test_per_item_limit_stops_one_item_being_swamped(client):
    """Even under the burst limit, one item shouldn't collect a queue of bots."""
    login(client)
    add_item(client)
    for i in range(3):
        claim_item(client, 1, name=f"P{i}", contact=f"p{i}@example.com")
    assert db().execute(
        "SELECT COUNT(*) FROM claims"
    ).fetchone()[0] == fs.RATE_LIMITS["claim_item"][0]


def test_rate_limited_claim_is_logged(client, capsys):
    login(client)
    add_item(client)
    for i in range(5):
        claim_item(client, 1, name=f"P{i}", contact=f"p{i}@example.com")
    events = [json.loads(line) for line in capsys.readouterr().out.splitlines()
              if line.startswith("{")]
    kinds = {e["event"] for e in events}
    assert "claim_accepted" in kinds and "rate_limited" in kinds
    limited = next(e for e in events if e["event"] == "rate_limited")
    assert limited["ip"] and limited["retry_after"] > 0


def test_logs_never_contain_claimant_contact_details(client, capsys):
    login(client)
    add_item(client)
    claim_item(client, 1, name="Ana Secret", contact="ana@private.example",
               note="my address is 12 Elm St")
    out = capsys.readouterr().out
    assert "ana@private.example" not in out
    assert "Ana Secret" not in out
    assert "12 Elm St" not in out
    # ...but the hashed fingerprint is there, so repeat offenders correlate.
    accepted = next(json.loads(l) for l in out.splitlines()
                    if l.startswith("{") and "claim_accepted" in l)
    assert len(accepted["contact_fp"]) == 12


def test_duplicate_claim_returns_the_existing_place_in_line(client):
    """Claiming twice must not silently occupy two waitlist slots."""
    login(client)
    add_item(client)
    claim_item(client, 1, name="Ana", contact="ana@example.com")
    r = claim_item(client, 1, name="Ana Again", contact="ANA@example.com ")
    assert db().execute("SELECT COUNT(*) FROM claims").fetchone()[0] == 1
    assert b"already in line" in r.data
    assert b"first in line" in r.data          # sent to their real claim page


def test_duplicate_check_ignores_withdrawn_claims(client):
    """Withdrawing and claiming again is allowed — it's the same person, once."""
    login(client)
    add_item(client)
    claim_item(client, 1, contact="ana@example.com")
    token = db().execute("SELECT token FROM claims").fetchone()["token"]
    csrf_token = csrf(client.get(f"/claim/{token}").get_data(as_text=True))
    client.post(f"/claim/{token}/cancel", data={"csrf_token": csrf_token},
                follow_redirects=True)
    claim_item(client, 1, contact="ana@example.com")
    assert db().execute(
        "SELECT COUNT(*) FROM claims WHERE status='active'"
    ).fetchone()[0] == 1


def test_gibberish_fields_from_the_attack_are_rejected(client):
    """The literal payload from the August 18 flood."""
    login(client)
    add_item(client)
    claim_item(client, 1, name="vhnnhidmrs", contact="tyoyiosrzf",
               note="ntlqmqdloteirnupseoqgueyrswvqm")
    assert db().execute("SELECT COUNT(*) FROM claims").fetchone()[0] == 0


def test_a_normal_claim_still_sails_through(client):
    """The false-positive guard: none of the above may block a real person."""
    login(client)
    add_item(client)
    r = claim_item(
        client, 1,
        name="Ana O'Brien-Szczepanski",
        contact="ana.obrien+freestuff@example.co.uk",
        pickup_date="2099-03-04", pickup_time="15:30",
        note="Thanks! I can come by after 5 — see http://example.com/map",
    )
    assert b"first in line" in r.data
    assert db().execute("SELECT COUNT(*) FROM claims").fetchone()[0] == 1


# --------------------------------------------------------------------------- #
# Admin auth hardening
# --------------------------------------------------------------------------- #
def test_admin_login_is_rate_limited(client):
    limit = fs.RATE_LIMITS["login_failed"][0]
    for _ in range(limit):
        token = csrf(client.get("/admin/login").get_data(as_text=True))
        r = client.post("/admin/login",
                        data={"password": "wrong", "csrf_token": token})
        assert b"match" in r.data
    token = csrf(client.get("/admin/login").get_data(as_text=True))
    r = client.post("/admin/login", data={"password": "wrong", "csrf_token": token})
    assert r.status_code == 429
    assert "Retry-After" in r.headers
    # And the throttle holds even once the password is right, so a brute-forcer
    # who lands on it during the lockout still doesn't get in on that request.
    token = csrf(client.get("/admin/login").get_data(as_text=True))
    r = client.post("/admin/login", data={"password": "test-pass",
                                          "csrf_token": token})
    assert r.status_code == 429


def test_successful_login_clears_the_failure_counter(client):
    """A typo or two must not put a real admin near the lockout threshold."""
    for _ in range(3):
        token = csrf(client.get("/admin/login").get_data(as_text=True))
        client.post("/admin/login", data={"password": "wrong", "csrf_token": token})
    login(client)
    assert client.get("/admin").status_code == 200
    for _ in range(4):   # would exceed the limit if the counter had persisted
        token = csrf(client.get("/admin/login").get_data(as_text=True))
        r = client.post("/admin/login", data={"password": "wrong",
                                              "csrf_token": token})
    assert r.status_code == 200


def test_hashed_admin_password_is_accepted(client, monkeypatch):
    from werkzeug.security import generate_password_hash
    monkeypatch.setattr(fs, "ADMIN_PASSWORD_HASH",
                        generate_password_hash("hashed-pass"))
    monkeypatch.setattr(fs, "ADMIN_PASSWORD", "plaintext-pass")
    assert fs.password_matches("hashed-pass") is True
    # The hash wins outright — a stale plaintext left in .env can't also work.
    assert fs.password_matches("plaintext-pass") is False


def test_empty_admin_password_never_matches(monkeypatch):
    monkeypatch.setattr(fs, "ADMIN_PASSWORD_HASH", "")
    monkeypatch.setattr(fs, "ADMIN_PASSWORD", "")
    assert fs.password_matches("") is False
    assert fs.password_matches("anything") is False


def test_login_next_cannot_redirect_off_site(client):
    """"//evil.example" starts with "/" and is a valid off-site URL."""
    token = csrf(client.get("/admin/login").get_data(as_text=True))
    r = client.post("/admin/login?next=//evil.example/admin",
                    data={"password": "test-pass", "csrf_token": token})
    assert "evil.example" not in (r.location or "")


# --------------------------------------------------------------------------- #
# Uploads, headers, health
# --------------------------------------------------------------------------- #
def _png_bytes(size=(4, 4)):
    from PIL import Image as PILImage
    buf = io.BytesIO()
    PILImage.new("RGB", size, "red").save(buf, format="PNG")
    buf.seek(0)
    return buf


def test_upload_rejects_a_non_image_wearing_an_image_extension(client):
    login(client)
    token = csrf(client.get("/admin/item/new").get_data(as_text=True))
    r = client.post("/admin/item/new", data={
        "title": "Nope", "description": "", "image_url": "", "csrf_token": token,
        "image_file": (io.BytesIO(b"<html><script>alert(1)</script></html>"),
                       "evil.png"),
    }, content_type="multipart/form-data", follow_redirects=True)
    assert b"isn&#39;t a readable image" in r.data
    assert db().execute("SELECT COUNT(*) FROM items").fetchone()[0] == 0


def test_upload_stores_the_real_format_not_the_claimed_one(client):
    """A genuine PNG named .jpg must be stored as .png, so it's served right."""
    login(client)
    token = csrf(client.get("/admin/item/new").get_data(as_text=True))
    client.post("/admin/item/new", data={
        "title": "Chair", "description": "", "image_url": "", "csrf_token": token,
        "image_file": (_png_bytes(), "photo.jpg"),
    }, content_type="multipart/form-data", follow_redirects=True)
    stored = db().execute("SELECT image_url FROM items").fetchone()["image_url"]
    assert stored.endswith(".png")
    assert client.get(stored).status_code == 200


def test_upload_rejects_a_decompression_bomb(client, monkeypatch):
    monkeypatch.setattr(fs, "MAX_IMAGE_PIXELS", 100)
    login(client)
    token = csrf(client.get("/admin/item/new").get_data(as_text=True))
    r = client.post("/admin/item/new", data={
        "title": "Huge", "description": "", "image_url": "", "csrf_token": token,
        "image_file": (_png_bytes(size=(64, 64)), "big.png"),
    }, content_type="multipart/form-data", follow_redirects=True)
    assert b"too large to process" in r.data
    assert db().execute("SELECT COUNT(*) FROM items").fetchone()[0] == 0


def test_security_headers_are_present(client):
    r = client.get("/")
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert r.headers["X-Frame-Options"] == "DENY"
    assert r.headers["Referrer-Policy"] == "strict-origin-when-cross-origin"
    assert "Permissions-Policy" in r.headers


def test_uploads_are_served_sandboxed(client):
    """Attacker-influenced bytes on our own origin must not be able to execute."""
    login(client)
    token = csrf(client.get("/admin/item/new").get_data(as_text=True))
    client.post("/admin/item/new", data={
        "title": "Chair", "description": "", "image_url": "", "csrf_token": token,
        "image_file": (_png_bytes(), "photo.png"),
    }, content_type="multipart/form-data", follow_redirects=True)
    stored = db().execute("SELECT image_url FROM items").fetchone()["image_url"]
    csp = client.get(stored).headers["Content-Security-Policy"]
    assert "sandbox" in csp and "default-src 'none'" in csp


def test_healthz(client):
    r = client.get("/healthz")
    assert r.status_code == 200 and r.get_json()["status"] == "ok"


def test_admin_cannot_block_a_past_date(client):
    login(client)
    token = csrf(client.get("/admin/dates").get_data(as_text=True))
    r = client.post("/admin/dates",
                    data={"date": "2000-01-01", "reason": "", "csrf_token": token},
                    follow_redirects=True)
    assert b"already passed" in r.data
    assert db().execute("SELECT COUNT(*) FROM blocked_dates").fetchone()[0] == 0
