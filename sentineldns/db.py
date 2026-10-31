"""SQLite persistence for the control plane (WAL mode, parameterized SQL only)."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sources (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    url         TEXT NOT NULL UNIQUE,
    category    TEXT NOT NULL,
    enabled     INTEGER NOT NULL DEFAULT 1,
    last_sync   TEXT,
    last_status TEXT,
    last_count  INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS categories (
    name   TEXT PRIMARY KEY,
    action TEXT NOT NULL CHECK(action IN ('BLOCK', 'MONITOR', 'ALLOW'))
);
CREATE TABLE IF NOT EXISTS domain_rules (
    domain     TEXT PRIMARY KEY,
    category   TEXT NOT NULL,
    action     TEXT NOT NULL CHECK(action IN ('BLOCK', 'MONITOR', 'ALLOW')),
    note       TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS hit_events (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        TEXT NOT NULL,
    query     TEXT NOT NULL,
    matched   TEXT NOT NULL,
    category  TEXT NOT NULL,
    action    TEXT NOT NULL,
    client_ip TEXT NOT NULL,
    channel   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_hit_events_ts ON hit_events(ts);
CREATE TABLE IF NOT EXISTS reviews (
    matched     TEXT PRIMARY KEY,
    category    TEXT NOT NULL,
    action      TEXT NOT NULL,
    hit_count   INTEGER NOT NULL DEFAULT 0,
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    last_client TEXT NOT NULL,
    last_query  TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'PENDING'
                CHECK(status IN ('PENDING', 'CONFIRMED', 'ALLOWED', 'DISMISSED')),
    notified_at TEXT,
    reviewed_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_reviews_status ON reviews(status, last_seen);
"""

POLICY_VERSION = "policy_version"
LIST_VERSION = "list_version"
REVIEW_STATUSES = ("PENDING", "CONFIRMED", "ALLOWED", "DISMISSED")


def utc_now(offset_seconds: int = 0) -> str:
    """
    ISO-8601 UTC timestamp (lexicographically sortable), optionally offset.
    Complexity: Time O(1) | Space O(1)
    """
    # --- DATA ---
    moment = datetime.now(UTC) + timedelta(seconds=offset_seconds)

    # --- CONDITIONS ---
    # (none)

    # --- RETURNS ---
    return moment.isoformat(timespec="seconds")


def connect(db_path: str) -> sqlite3.Connection:
    """
    Opens a tuned SQLite connection (busy timeout, Row factory, NORMAL sync under WAL).
    Complexity: Time O(1) | Space O(1)
    """
    # --- DATA ---
    conn = sqlite3.connect(db_path, timeout=5.0, check_same_thread=True)

    # --- CONDITIONS ---
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout = 5000")
    conn.execute("PRAGMA synchronous = NORMAL")
    conn.execute("PRAGMA foreign_keys = ON")

    # --- RETURNS ---
    return conn


def init_database(db_path: str) -> bool:
    """
    Creates the schema and enables WAL so readers never block the single writer.
    Complexity: Time O(1) | Space O(1)
    """
    # --- DATA ---
    conn: sqlite3.Connection | None = None
    success = False

    # --- CONDITIONS ---
    if not db_path:
        return False

    try:
        conn = connect(db_path)
        conn.execute("PRAGMA journal_mode = WAL")
        conn.executescript(SCHEMA_SQL)
        for key in (POLICY_VERSION, LIST_VERSION):
            conn.execute("INSERT OR IGNORE INTO meta (key, value) VALUES (?, '0')", (key,))
        conn.commit()
        success = True
    except sqlite3.Error:
        success = False
    finally:
        if conn is not None:
            conn.close()

    # --- RETURNS ---
    return success


# ---------------------------------------------------------------------
# Versioning (cross-process change propagation)
# ---------------------------------------------------------------------
def get_versions(conn: sqlite3.Connection) -> tuple[int, int]:
    """
    Reads (policy_version, list_version). Polled cheaply by every process.
    Complexity: Time O(1) | Space O(1)
    """
    # --- DATA ---
    values = {POLICY_VERSION: 0, LIST_VERSION: 0}
    rows = conn.execute(
        "SELECT key, value FROM meta WHERE key IN (?, ?)", (POLICY_VERSION, LIST_VERSION)
    ).fetchall()

    # --- CONDITIONS ---
    for row in rows:
        values[row["key"]] = int(row["value"])

    # --- RETURNS ---
    return values[POLICY_VERSION], values[LIST_VERSION]


def bump_version(conn: sqlite3.Connection, key: str) -> None:
    """
    Atomically increments a version counter so other processes reload.
    Complexity: Time O(1) | Space O(1)
    """
    # --- DATA ---
    sql = "UPDATE meta SET value = CAST(value AS INTEGER) + 1 WHERE key = ?"

    # --- CONDITIONS ---
    if key not in (POLICY_VERSION, LIST_VERSION):
        raise ValueError(f"Unknown version key: {key}")
    conn.execute(sql, (key,))
    conn.commit()

    # --- RETURNS ---
    return None


# ---------------------------------------------------------------------
# Sources
# ---------------------------------------------------------------------
def seed_sources(conn: sqlite3.Connection, seeds: Iterable[tuple[str, str]]) -> int:
    """
    Inserts seed sources from configuration if they do not already exist.
    Complexity: Time O(S) | Space O(1)
    """
    # --- DATA ---
    inserted = 0
    sql = "INSERT OR IGNORE INTO sources (url, category) VALUES (?, ?)"

    # --- CONDITIONS ---
    for url, category in seeds:
        inserted += conn.execute(sql, (url, category)).rowcount
    conn.commit()

    # --- RETURNS ---
    return inserted


def list_sources(conn: sqlite3.Connection, enabled_only: bool = False) -> list[sqlite3.Row]:
    """
    Lists configured remote sources.
    Complexity: Time O(S) | Space O(S)
    """
    # --- DATA ---
    sql = "SELECT * FROM sources ORDER BY id"

    # --- CONDITIONS ---
    if enabled_only:
        sql = "SELECT * FROM sources WHERE enabled = 1 ORDER BY id"

    # --- RETURNS ---
    return conn.execute(sql).fetchall()


def add_source(conn: sqlite3.Connection, url: str, category: str) -> bool:
    """
    Adds a remote source (caller validates the URL first).
    Complexity: Time O(log S) | Space O(1)
    """
    # --- DATA ---
    added = False

    # --- CONDITIONS ---
    try:
        conn.execute("INSERT INTO sources (url, category) VALUES (?, ?)", (url, category))
        conn.commit()
        added = True
    except sqlite3.IntegrityError:
        added = False

    # --- RETURNS ---
    return added


def set_source_enabled(conn: sqlite3.Connection, source_id: int, enabled: bool) -> None:
    """
    Enables or disables a source.
    Complexity: Time O(log S) | Space O(1)
    """
    # --- DATA ---
    flag = 1 if enabled else 0

    # --- CONDITIONS ---
    conn.execute("UPDATE sources SET enabled = ? WHERE id = ?", (flag, source_id))
    conn.commit()

    # --- RETURNS ---
    return None


def delete_source(conn: sqlite3.Connection, source_id: int) -> None:
    """
    Deletes a source.
    Complexity: Time O(log S) | Space O(1)
    """
    # --- DATA ---
    sql = "DELETE FROM sources WHERE id = ?"

    # --- CONDITIONS ---
    conn.execute(sql, (source_id,))
    conn.commit()

    # --- RETURNS ---
    return None


def update_source_status(
    conn: sqlite3.Connection, url: str, status: str, count: int
) -> None:
    """
    Records the outcome of the latest sync for a source.
    Complexity: Time O(log S) | Space O(1)
    """
    # --- DATA ---
    sql = "UPDATE sources SET last_sync = ?, last_status = ?, last_count = ? WHERE url = ?"

    # --- CONDITIONS ---
    conn.execute(sql, (utc_now(), status[:500], count, url))
    conn.commit()

    # --- RETURNS ---
    return None


# ---------------------------------------------------------------------
# Categories & rules
# ---------------------------------------------------------------------
def ensure_categories(conn: sqlite3.Connection, names: Iterable[str], action: str) -> int:
    """
    Registers newly seen categories with the default action (idempotent).
    Complexity: Time O(C log C) | Space O(1)
    """
    # --- DATA ---
    inserted = 0
    sql = "INSERT OR IGNORE INTO categories (name, action) VALUES (?, ?)"

    # --- CONDITIONS ---
    for name in names:
        inserted += conn.execute(sql, (name, action)).rowcount
    conn.commit()

    # --- RETURNS ---
    return inserted


def category_actions(conn: sqlite3.Connection) -> dict[str, str]:
    """
    Returns {category: action}.
    Complexity: Time O(C) | Space O(C)
    """
    # --- DATA ---
    rows = conn.execute("SELECT name, action FROM categories ORDER BY name").fetchall()

    # --- CONDITIONS ---
    mapping = {row["name"]: row["action"] for row in rows}

    # --- RETURNS ---
    return mapping


def set_category_action(conn: sqlite3.Connection, name: str, action: str) -> None:
    """
    Upserts the action for a category.
    Complexity: Time O(log C) | Space O(1)
    """
    # --- DATA ---
    sql = (
        "INSERT INTO categories (name, action) VALUES (?, ?) "
        "ON CONFLICT(name) DO UPDATE SET action = excluded.action"
    )

    # --- CONDITIONS ---
    conn.execute(sql, (name, action))
    conn.commit()

    # --- RETURNS ---
    return None


def list_rules(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    """
    Lists admin domain rules.
    Complexity: Time O(R) | Space O(R)
    """
    # --- DATA ---
    sql = "SELECT * FROM domain_rules ORDER BY domain"

    # --- CONDITIONS ---
    # (none)

    # --- RETURNS ---
    return conn.execute(sql).fetchall()


def upsert_rule(
    conn: sqlite3.Connection, domain: str, category: str, action: str, note: str = ""
) -> None:
    """
    Creates or replaces an admin override rule for a domain (and its subdomains).
    Complexity: Time O(log R) | Space O(1)
    """
    # --- DATA ---
    sql = (
        "INSERT INTO domain_rules (domain, category, action, note, created_at) "
        "VALUES (?, ?, ?, ?, ?) ON CONFLICT(domain) DO UPDATE SET "
        "category = excluded.category, action = excluded.action, note = excluded.note"
    )

    # --- CONDITIONS ---
    conn.execute(sql, (domain, category, action, note[:200], utc_now()))
    conn.commit()

    # --- RETURNS ---
    return None


def delete_rule(conn: sqlite3.Connection, domain: str) -> None:
    """
    Removes an admin rule.
    Complexity: Time O(log R) | Space O(1)
    """
    # --- DATA ---
    sql = "DELETE FROM domain_rules WHERE domain = ?"

    # --- CONDITIONS ---
    conn.execute(sql, (domain,))
    conn.commit()

    # --- RETURNS ---
    return None


# ---------------------------------------------------------------------
# Hits & reviews
# ---------------------------------------------------------------------
def record_hits(conn: sqlite3.Connection, hits: list[tuple]) -> int:
    """
    Batch-inserts hit events and upserts the aggregated review queue in one transaction.
    Each hit tuple: (ts, query, matched, category, action, client_ip, channel).
    Complexity: Time O(H log R) | Space O(1)
    """
    # --- DATA ---
    event_sql = (
        "INSERT INTO hit_events (ts, query, matched, category, action, client_ip, channel) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)"
    )
    review_sql = (
        "INSERT INTO reviews (matched, category, action, hit_count, first_seen, last_seen, "
        "last_client, last_query) VALUES (?, ?, ?, 1, ?, ?, ?, ?) "
        "ON CONFLICT(matched) DO UPDATE SET hit_count = hit_count + 1, "
        "last_seen = excluded.last_seen, last_client = excluded.last_client, "
        "last_query = excluded.last_query, category = excluded.category, "
        "action = excluded.action"
    )

    # --- CONDITIONS ---
    if not hits:
        return 0

    with conn:
        conn.executemany(event_sql, hits)
        conn.executemany(
            review_sql,
            [(h[2], h[3], h[4], h[0], h[0], h[5], h[1]) for h in hits],
        )

    # --- RETURNS ---
    return len(hits)


def claim_notification(
    conn: sqlite3.Connection, matched: str, cooldown_seconds: int
) -> sqlite3.Row | None:
    """
    Atomically claims the right to email about a PENDING review (race-free across
    processes via UPDATE ... RETURNING). Returns the review row or None.
    Complexity: Time O(log R) | Space O(1)
    """
    # --- DATA ---
    now = utc_now()
    cutoff = utc_now(-cooldown_seconds)
    sql = (
        "UPDATE reviews SET notified_at = ? WHERE matched = ? AND status = 'PENDING' "
        "AND (notified_at IS NULL OR notified_at < ?) RETURNING *"
    )

    # --- CONDITIONS ---
    with conn:
        row = conn.execute(sql, (now, matched, cutoff)).fetchone()

    # --- RETURNS ---
    return row


def list_reviews(
    conn: sqlite3.Connection, status: str = "PENDING", limit: int = 100
) -> list[sqlite3.Row]:
    """
    Lists reviews by status, newest activity first.
    Complexity: Time O(log R + k) | Space O(k)
    """
    # --- DATA ---
    sql = "SELECT * FROM reviews WHERE status = ? ORDER BY last_seen DESC LIMIT ?"

    # --- CONDITIONS ---
    if status not in REVIEW_STATUSES:
        status = "PENDING"

    # --- RETURNS ---
    return conn.execute(sql, (status, max(1, min(limit, 1000)))).fetchall()


def set_review_status(conn: sqlite3.Connection, matched: str, status: str) -> bool:
    """
    Marks a review CONFIRMED / ALLOWED / DISMISSED.
    Complexity: Time O(log R) | Space O(1)
    """
    # --- DATA ---
    updated = False
    sql = "UPDATE reviews SET status = ?, reviewed_at = ? WHERE matched = ?"

    # --- CONDITIONS ---
    if status in REVIEW_STATUSES:
        updated = conn.execute(sql, (status, utc_now(), matched)).rowcount > 0
        conn.commit()

    # --- RETURNS ---
    return updated


def recent_events(conn: sqlite3.Connection, limit: int = 50) -> list[sqlite3.Row]:
    """
    Latest raw hit events.
    Complexity: Time O(k) via rowid order | Space O(k)
    """
    # --- DATA ---
    sql = "SELECT * FROM hit_events ORDER BY id DESC LIMIT ?"

    # --- CONDITIONS ---
    # (none)

    # --- RETURNS ---
    return conn.execute(sql, (max(1, min(limit, 500)),)).fetchall()


def dashboard_stats(conn: sqlite3.Connection) -> dict[str, int]:
    """
    Aggregate counters for the admin dashboard.
    Complexity: Time O(log E + e24) using the ts index | Space O(1)
    """
    # --- DATA ---
    since = utc_now(-86400)
    stats: dict[str, int] = {}

    # --- CONDITIONS ---
    stats["pending"] = conn.execute(
        "SELECT COUNT(*) FROM reviews WHERE status = 'PENDING'"
    ).fetchone()[0]
    stats["hits_24h"] = conn.execute(
        "SELECT COUNT(*) FROM hit_events WHERE ts >= ?", (since,)
    ).fetchone()[0]
    stats["blocked_24h"] = conn.execute(
        "SELECT COUNT(*) FROM hit_events WHERE ts >= ? AND action = 'BLOCK'", (since,)
    ).fetchone()[0]
    stats["rules"] = conn.execute("SELECT COUNT(*) FROM domain_rules").fetchone()[0]
    stats["sources"] = conn.execute("SELECT COUNT(*) FROM sources").fetchone()[0]

    # --- RETURNS ---
    return stats


def prune_events(conn: sqlite3.Connection, retention_days: int) -> int:
    """
    Deletes raw hit events older than the retention window (reviews are kept).
    Complexity: Time O(log E + d) using the ts index | Space O(1)
    """
    # --- DATA ---
    cutoff = utc_now(-retention_days * 86400)

    # --- CONDITIONS ---
    with conn:
        deleted = conn.execute("DELETE FROM hit_events WHERE ts < ?", (cutoff,)).rowcount

    # --- RETURNS ---
    return deleted
