-- FreeShare database schema

CREATE TABLE IF NOT EXISTS items (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    title       TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    image_url   TEXT NOT NULL DEFAULT '',
    -- 'available' = still on the board (may or may not have a claimant)
    -- 'gone'      = picked up / no longer offered
    status      TEXT NOT NULL DEFAULT 'available',
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS claims (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    item_id     INTEGER NOT NULL,
    name        TEXT NOT NULL,
    contact     TEXT NOT NULL,
    pickup_date TEXT NOT NULL DEFAULT '',
    pickup_time TEXT NOT NULL DEFAULT '',
    note        TEXT NOT NULL DEFAULT '',
    -- 'active'    = in the queue (first active claim = recipient, rest = waitlist)
    -- 'fulfilled' = this person picked it up
    -- 'cancelled' = withdrawn / removed by admin
    status      TEXT NOT NULL DEFAULT 'active',
    token       TEXT NOT NULL,
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (item_id) REFERENCES items(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_claims_item ON claims(item_id, status, created_at);

-- Dates the admin has blacked out for pickups (holidays, out of town, etc.)
CREATE TABLE IF NOT EXISTS blocked_dates (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    date        TEXT NOT NULL UNIQUE,   -- YYYY-MM-DD
    reason      TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);
