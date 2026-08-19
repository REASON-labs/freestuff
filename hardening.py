"""
FreeStuff — anti-abuse core.

Pure, dependency-light helpers for the mitigations described in the family
hardening spec. Everything here is a plain function or a small class with no
Flask imports, so the whole file is unit-testable without a request context.

Covers spec categories:
  1. Request origin & intent  -> sign_form_stamp / check_form_stamp, honeypot
  2. Rate limiting            -> RateLimiter
  3. Input validation         -> clean_text, check_name, check_contact, check_note
  5. Logging                  -> log_event

Category 4 (email/notification security) does not apply: FreeStuff has no mail
layer. The disposable-domain list here is used only to reject obviously
throwaway *contact* addresses, and is off unless explicitly enabled.
"""

import hmac
import json
import re
import sys
import threading
import time
import unicodedata
from collections import deque
from hashlib import sha256

# --------------------------------------------------------------------------- #
# Rate limiting
# --------------------------------------------------------------------------- #


class RateLimiter:
    """Sliding-window rate limiter held in process memory.

    Deliberately not Redis. FreeStuff is one container with a couple of gunicorn
    workers, and adding a second service to the deploy costs more than it buys
    at this scale. The tradeoff to know about: each worker keeps its own
    counters, so with N workers a determined client gets roughly N x the
    configured allowance before it is throttled. Thresholds below are set with
    that in mind — see RATE_LIMITS in app.py.
    """

    def __init__(self, clock=time.monotonic):
        self._hits = {}
        self._lock = threading.Lock()
        self._clock = clock
        self._last_sweep = clock()

    def check(self, key, limit, window):
        """Record a hit for `key` and report whether it is allowed.

        Returns (allowed, retry_after_seconds). A rejected hit is *not*
        recorded, so a client that backs off recovers on schedule instead of
        extending its own penalty forever.
        """
        now = self._clock()
        with self._lock:
            self._sweep(now)
            bucket = self._hits.setdefault(key, deque())
            cutoff = now - window
            while bucket and bucket[0] <= cutoff:
                bucket.popleft()
            if len(bucket) >= limit:
                retry_after = max(1, int(bucket[0] + window - now) + 1)
                return False, retry_after
            bucket.append(now)
            return True, 0

    def peek(self, key, limit, window):
        """Same question as check(), without recording a hit."""
        now = self._clock()
        with self._lock:
            bucket = self._hits.get(key)
            if not bucket:
                return True, 0
            cutoff = now - window
            while bucket and bucket[0] <= cutoff:
                bucket.popleft()
            if len(bucket) >= limit:
                return False, max(1, int(bucket[0] + window - now) + 1)
            return True, 0

    def reset(self, key):
        """Clear a key — used to forget failed logins after a good password."""
        with self._lock:
            self._hits.pop(key, None)

    def _sweep(self, now, max_age=3600):
        """Drop buckets nothing has touched in an hour.

        Without this the dict grows once per unique IP forever, which is a slow
        memory leak an attacker with a proxy pool could accelerate.
        """
        if now - self._last_sweep < 300:
            return
        self._last_sweep = now
        cutoff = now - max_age
        stale = [k for k, v in self._hits.items() if not v or v[-1] <= cutoff]
        for k in stale:
            del self._hits[k]


# --------------------------------------------------------------------------- #
# Form stamps — time-to-submit + form freshness
# --------------------------------------------------------------------------- #
#
# A signed timestamp is embedded in the claim form. It gives us two signals for
# the price of one hidden field:
#
#   * Submitted too fast  -> nothing types a name, a contact and a date in under
#                            a couple of seconds. Scripted POSTs are instant.
#   * Submitted too slow  -> the form was scraped once and replayed hours later.
#
# It is signed with SECRET_KEY so a bot can't mint its own plausible stamp, and
# it is stateless, so it survives multiple tabs and multiple gunicorn workers
# where a session-stored timestamp would not.

MIN_FILL_SECONDS = 3
MAX_FORM_AGE_SECONDS = 6 * 3600


def sign_form_stamp(secret, issued_at=None):
    issued_at = int(issued_at if issued_at is not None else time.time())
    payload = str(issued_at)
    return f"{payload}.{_sign(secret, payload)}"


def check_form_stamp(secret, stamp, now=None,
                     min_age=MIN_FILL_SECONDS, max_age=MAX_FORM_AGE_SECONDS):
    """Return (ok, reason). reason is a short machine-readable slug."""
    now = int(now if now is not None else time.time())
    if not stamp or "." not in str(stamp):
        return False, "stamp_missing"
    payload, _, signature = str(stamp).rpartition(".")
    if not hmac.compare_digest(signature, _sign(secret, payload)):
        return False, "stamp_bad_signature"
    try:
        issued_at = int(payload)
    except ValueError:
        return False, "stamp_malformed"
    age = now - issued_at
    if age < min_age:
        # Includes negative ages (clock skew or a forged-future stamp).
        return False, "stamp_too_fast"
    if age > max_age:
        return False, "stamp_expired"
    return True, ""


def _sign(secret, payload):
    key = secret.encode("utf-8") if isinstance(secret, str) else bytes(secret)
    return hmac.new(key, payload.encode("utf-8"), sha256).hexdigest()[:32]


# --------------------------------------------------------------------------- #
# Honeypot
# --------------------------------------------------------------------------- #
#
# Two decoys, because a bot that skips empty-looking fields still tends to fill
# anything that smells like a required contact field:
#
#   website  — visually hidden, must stay empty
#   confirm_email — visually hidden, must stay empty
#
# Both carry autocomplete="off" and tabindex="-1" so a keyboard user never lands
# on them, and aria-hidden so a screen reader never announces them. This is the
# weakest control in the stack (Selenium defeats it trivially) but it is free.

HONEYPOT_FIELDS = ("website", "confirm_email")


def honeypot_tripped(form):
    """True if any decoy field came back non-empty."""
    return any((form.get(field) or "").strip() for field in HONEYPOT_FIELDS)


# --------------------------------------------------------------------------- #
# Input validation
# --------------------------------------------------------------------------- #

# C0/C1 control characters, minus tab/newline/carriage-return which we fold to
# spaces instead. These have no business in a name or a contact field and are a
# reliable sign of a generated payload.
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")
_WHITESPACE_RUN = re.compile(r"\s+")
_URLISH = re.compile(
    r"(https?://|www\.|\b[a-z0-9-]+\.(?:com|net|org|ru|cn|info|xyz|top|biz|club|online|site)\b)",
    re.IGNORECASE,
)
_BBCODE = re.compile(r"\[/?(?:url|link|img|b|i)\b", re.IGNORECASE)
_DIGITS = re.compile(r"\d")


def clean_text(value, limit, collapse_whitespace=True):
    """Normalise a submitted string: NFC, strip controls, collapse runs, cap.

    Unicode normalisation matters because otherwise two visually identical names
    compare unequal, which would defeat the duplicate-claim check below.
    """
    text = "" if value is None else str(value)
    text = unicodedata.normalize("NFC", text)
    text = _CONTROL_CHARS.sub("", text)
    if collapse_whitespace:
        text = _WHITESPACE_RUN.sub(" ", text)
    else:
        # Keep paragraph breaks in the note, but cap runaway blank lines.
        text = re.sub(r"\n{3,}", "\n\n", text.replace("\r\n", "\n"))
        text = re.sub(r"[ \t]{2,}", " ", text)
    return text.strip()[:limit]


NAME_MIN = 2
NAME_MAX = 120
CONTACT_MIN = 5
CONTACT_MAX = 200
NOTE_MAX = 500


def check_name(name):
    """Return (ok, reason, message) for a claimant name.

    Note what this deliberately does *not* do: no gibberish/entropy heuristic.
    Consonant-run scoring flags real names (Szczepanski, Brzezinski, plenty of
    non-Latin transliterations) far more often than it catches a bot that can
    trivially generate "Sarah Miller" instead. The controls that actually stop
    the flood are rate limiting and dedupe; this function only enforces shape.
    """
    if len(name) < NAME_MIN:
        return False, "name_too_short", "Please add your name."
    if len(name) > NAME_MAX:
        return False, "name_too_long", "That name is too long."
    if _URLISH.search(name) or _BBCODE.search(name):
        return False, "name_has_link", "Names can't contain links."
    if not any(ch.isalpha() for ch in name):
        return False, "name_no_letters", "Please enter your name using letters."
    return True, "", ""


def check_contact(contact, disposable_domains=None):
    """Return (ok, reason, message) for the 'how do we reach you' field.

    The form asks for an email address or a phone number, so that is what we
    enforce: an '@' with something either side, or enough digits to be a phone
    number. This is the single cheapest filter against the observed attack —
    the August 18 flood used contact values like "tyoyiosrzf", pure letters with
    no address and no number, which nobody could have replied to anyway.
    """
    if len(contact) < CONTACT_MIN:
        return False, "contact_too_short", "Please add a way to reach you."
    if len(contact) > CONTACT_MAX:
        return False, "contact_too_long", "That contact detail is too long."
    if _BBCODE.search(contact):
        return False, "contact_has_markup", "Please enter just an email address or phone number."

    email = _extract_email(contact)
    digit_count = len(_DIGITS.findall(contact))

    if email is None and digit_count < 7:
        return (False, "contact_unreachable",
                "Please give an email address or a phone number so we can reach you.")

    if email is not None and disposable_domains:
        domain = email.rsplit("@", 1)[1].lower()
        if domain in disposable_domains or _parent_domain(domain) in disposable_domains:
            return (False, "contact_disposable",
                    "That looks like a temporary email address. Please use one you check.")

    return True, "", ""


def check_note(note):
    if len(note) > NOTE_MAX:
        return False, "note_too_long", "Please keep the note under 500 characters."
    # One link is a plausible "here's the listing I saw"; three is a spam post.
    if len(_URLISH.findall(note)) > 2:
        return False, "note_link_spam", "Please leave out the links."
    return True, "", ""


_EMAIL_RE = re.compile(r"[^\s@,;<>()\[\]]+@[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+",
                       re.IGNORECASE)


def _extract_email(value):
    """Find an email address inside a free-text contact field, or None.

    Free text because people write "email me at x@y.com" or "x@y.com / 555-1234"
    and rejecting those would be a worse failure than accepting them.
    """
    match = _EMAIL_RE.search(value or "")
    return match.group(0) if match else None


def _parent_domain(domain):
    parts = domain.split(".")
    return ".".join(parts[-2:]) if len(parts) > 2 else domain


def contact_fingerprint(contact):
    """A stable key for 'the same person claiming twice'.

    Lowercased, whitespace and punctuation-noise removed, so
    "Jay@Example.com" and "jay@example.com " collide, and "555-123-4567" and
    "(555) 123 4567" do too. Stored hashed so the dedupe index never becomes a
    second copy of everyone's contact details.
    """
    value = (contact or "").strip().lower()
    email = _extract_email(value)
    if email:
        basis = email
    else:
        digits = "".join(_DIGITS.findall(value))
        # Last 10 digits: tolerates +1 / 001 / leading-zero country prefixes.
        basis = digits[-10:] if len(digits) >= 7 else re.sub(r"[^a-z0-9]", "", value)
    if not basis:
        return ""
    return sha256(basis.encode("utf-8")).hexdigest()


# A deliberately small, hand-checked list. Nothing auto-fetched: a remote
# blocklist is a live dependency that can start rejecting your friends without
# a deploy. Off by default (BLOCK_DISPOSABLE_EMAIL), because on a board for
# friends the cost of a false rejection is higher than the cost of one spam row.
DISPOSABLE_DOMAINS = frozenset({
    "0-mail.com", "10minutemail.com", "20minutemail.com", "33mail.com",
    "anonbox.net", "byom.de", "dispostable.com", "dropmail.me",
    "emailondeck.com", "fakeinbox.com", "getairmail.com", "getnada.com",
    "guerrillamail.com", "guerrillamail.info", "harakirimail.com",
    "inboxbear.com", "jetable.org", "mailcatch.com", "maildrop.cc",
    "mailinator.com", "mailnesia.com", "mintemail.com", "mohmal.com",
    "moakt.com", "mytemp.email", "nowmymail.com", "sharklasers.com",
    "spam4.me", "spamgourmet.com", "temp-mail.org", "tempinbox.com",
    "tempmail.net", "tempmailo.com", "throwawaymail.com", "trashmail.com",
    "trashmail.de", "yopmail.com", "yopmail.fr",
})


# --------------------------------------------------------------------------- #
# Structured logging
# --------------------------------------------------------------------------- #
#
# One JSON object per line on stdout. That is the format Docker, journald and
# every hosted log service already understand, and it means "how many claims
# were rejected as too-fast last week" is a grep away instead of a schema
# migration. No values that identify a claimant are logged — the contact field
# is recorded as its fingerprint hash, never in the clear.


def log_event(stream, event, **fields):
    record = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "event": event}
    record.update({k: v for k, v in fields.items() if v is not None})
    try:
        stream.write(json.dumps(record, default=str, sort_keys=True) + "\n")
        stream.flush()
    except Exception:  # pragma: no cover - never let logging break a request
        pass


def stdout_logger(event, **fields):
    log_event(sys.stdout, event, **fields)
