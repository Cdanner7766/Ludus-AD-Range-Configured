"""
SQLite persistence layer for the scoring engine.
Schema:
  check_rounds   - one row per check cycle (timestamp)
  service_checks - one row per service per cycle (foreign key → check_rounds)
"""

import os
import sqlite3
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), "scores.db")


def _connect():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Create tables if they don't exist."""
    with _connect() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS check_rounds (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT    NOT NULL
            );

            CREATE TABLE IF NOT EXISTS service_checks (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                round_id   INTEGER NOT NULL,
                service_id TEXT    NOT NULL,
                up         INTEGER NOT NULL,   -- 1=UP, 0=DOWN
                message    TEXT,
                FOREIGN KEY (round_id) REFERENCES check_rounds(id)
            );

            CREATE TABLE IF NOT EXISTS service_credentials (
                service_id TEXT PRIMARY KEY,
                username   TEXT NOT NULL,
                password   TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_sc_round   ON service_checks(round_id);
            CREATE INDEX IF NOT EXISTS idx_sc_service ON service_checks(service_id);
        """)


def save_round(results):
    """
    Persist one complete check cycle.
    results: list of dicts with keys service_id, up, message
    """
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with _connect() as conn:
        cur = conn.execute(
            "INSERT INTO check_rounds (timestamp) VALUES (?)",
            (ts,),
        )
        round_id = cur.lastrowid
        conn.executemany(
            "INSERT INTO service_checks (round_id, service_id, up, message) VALUES (?, ?, ?, ?)",
            [
                (round_id, r["service_id"], 1 if r["up"] else 0, r["message"])
                for r in results
            ],
        )


def get_round_count():
    with _connect() as conn:
        row = conn.execute("SELECT COUNT(*) FROM check_rounds").fetchone()
        return row[0]


def get_recent_rounds(limit=20):
    """Return the most recent rounds, newest first."""
    with _connect() as conn:
        rows = conn.execute(
            "SELECT * FROM check_rounds ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]


def get_service_stats():
    """
    Aggregate per-service statistics across all rounds.
    Returns a dict keyed by service_id with: total_checks, up_count
    """
    with _connect() as conn:
        rows = conn.execute("""
            SELECT
                service_id,
                COUNT(*) AS total_checks,
                SUM(up)  AS up_count
            FROM service_checks
            GROUP BY service_id
        """).fetchall()
        return {r["service_id"]: dict(r) for r in rows}


def get_last_round_results():
    """
    Return service_checks rows for the most recent round,
    keyed by service_id.
    """
    with _connect() as conn:
        row = conn.execute(
            "SELECT id FROM check_rounds ORDER BY id DESC LIMIT 1"
        ).fetchone()
        if not row:
            return {}
        round_id = row["id"]
        rows = conn.execute(
            "SELECT * FROM service_checks WHERE round_id = ?", (round_id,)
        ).fetchall()
        return {r["service_id"]: dict(r) for r in rows}


def clear_all_checks():
    """Delete all check history from the database."""
    with _connect() as conn:
        conn.execute("DELETE FROM service_checks")
        conn.execute("DELETE FROM check_rounds")


# ---------------------------------------------------------------------------
# Credential management
# ---------------------------------------------------------------------------

def get_credential(svc_id):
    """Return (username, password) stored for svc_id, or (None, None) if unset."""
    with _connect() as conn:
        row = conn.execute(
            "SELECT username, password FROM service_credentials WHERE service_id = ?",
            (svc_id,),
        ).fetchone()
    return (row["username"], row["password"]) if row else (None, None)


def set_credential(svc_id, username, password):
    """Insert or update credentials for svc_id."""
    with _connect() as conn:
        conn.execute(
            """
            INSERT INTO service_credentials (service_id, username, password)
            VALUES (?, ?, ?)
            ON CONFLICT(service_id) DO UPDATE
              SET username = excluded.username,
                  password = excluded.password
            """,
            (svc_id, username, password),
        )
