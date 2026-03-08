"""
SQLite persistence layer for the scoring engine.
Schema:
  check_rounds   - one row per check cycle (timestamp, round score, max score)
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
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp   TEXT    NOT NULL,
                round_score INTEGER NOT NULL,
                max_score   INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS service_checks (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                round_id      INTEGER NOT NULL,
                service_id    TEXT    NOT NULL,
                up            INTEGER NOT NULL,   -- 1=UP, 0=DOWN
                points_earned INTEGER NOT NULL,
                message       TEXT,
                FOREIGN KEY (round_id) REFERENCES check_rounds(id)
            );

            CREATE INDEX IF NOT EXISTS idx_sc_round   ON service_checks(round_id);
            CREATE INDEX IF NOT EXISTS idx_sc_service ON service_checks(service_id);
        """)


def save_round(results, round_score, max_score):
    """
    Persist one complete check cycle.
    results: list of dicts with keys service_id, up, points_earned, message
    """
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with _connect() as conn:
        cur = conn.execute(
            "INSERT INTO check_rounds (timestamp, round_score, max_score) VALUES (?, ?, ?)",
            (ts, round_score, max_score),
        )
        round_id = cur.lastrowid
        conn.executemany(
            """INSERT INTO service_checks
               (round_id, service_id, up, points_earned, message)
               VALUES (?, ?, ?, ?, ?)""",
            [
                (round_id, r["service_id"], 1 if r["up"] else 0,
                 r["points_earned"], r["message"])
                for r in results
            ],
        )


def get_cumulative_score():
    """Sum of all round scores across the entire competition."""
    with _connect() as conn:
        row = conn.execute("SELECT COALESCE(SUM(round_score), 0) FROM check_rounds").fetchone()
        return row[0]


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
    Returns a dict keyed by service_id with:
      total_checks, up_count, total_points
    """
    with _connect() as conn:
        rows = conn.execute("""
            SELECT
                service_id,
                COUNT(*)        AS total_checks,
                SUM(up)         AS up_count,
                SUM(points_earned) AS total_points
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


def get_score_history(limit=30):
    """
    Return (timestamp, round_score, max_score) for the last N rounds,
    oldest first — suitable for Chart.js datasets.
    """
    with _connect() as conn:
        rows = conn.execute(
            """SELECT timestamp, round_score, max_score
               FROM check_rounds ORDER BY id DESC LIMIT ?""",
            (limit,),
        ).fetchall()
        return list(reversed([dict(r) for r in rows]))
