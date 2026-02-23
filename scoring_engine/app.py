"""
CCDC Blue Team Scoring Engine
Runs on Kali (red-team network) and checks whether blue-team services
are reachable from the outside.

Usage:
    python3 app.py
Dashboard: http://<kali-ip>:8080
"""

import logging
import threading
import time
from datetime import datetime

from flask import Flask, jsonify, render_template

import checks
import config
import database

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-5s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("scoring")

# ---------------------------------------------------------------------------
# Shared state (updated by the background thread)
# ---------------------------------------------------------------------------
_lock = threading.Lock()

_state = {
    "last_check_time": None,   # ISO string of last completed check
    "next_check_in": 0,        # seconds until next round
    "current_results": {},     # service_id → {up, points_earned, message}
    "round_score": 0,
    "is_checking": False,
}

# ---------------------------------------------------------------------------
# Background check loop
# ---------------------------------------------------------------------------

def _run_one_round():
    """Execute checks for every service and persist results."""
    results = []
    round_score = 0

    for svc in config.SERVICES:
        try:
            up, message = checks.run_check(svc)
        except Exception as exc:
            up = False
            message = f"Check exception: {exc}"

        pts = svc["points"] if up else 0
        round_score += pts
        result = {
            "service_id": svc["id"],
            "up": up,
            "points_earned": pts,
            "message": message,
        }
        results.append(result)
        log.info(
            "  %-4s  %-30s  +%-3d pts  %s",
            "UP" if up else "DOWN",
            svc["name"],
            pts,
            message[:70],
        )

    database.save_round(results, round_score, config.MAX_SCORE_PER_ROUND)

    with _lock:
        _state["last_check_time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        _state["round_score"] = round_score
        _state["current_results"] = {r["service_id"]: r for r in results}
        _state["is_checking"] = False

    log.info(
        "Round complete: %d/%d pts  |  cumulative: %d",
        round_score,
        config.MAX_SCORE_PER_ROUND,
        database.get_cumulative_score(),
    )


def _scheduler_loop():
    """Background thread: runs checks every CHECK_INTERVAL seconds."""
    # Run immediately on startup
    while True:
        with _lock:
            _state["is_checking"] = True
        log.info("=== Starting check round ===")
        try:
            _run_one_round()
        except Exception as exc:
            log.error("Unhandled error in check round: %s", exc)
            with _lock:
                _state["is_checking"] = False

        # Count down to next round, updating next_check_in each second
        for remaining in range(config.CHECK_INTERVAL, 0, -1):
            with _lock:
                _state["next_check_in"] = remaining
            time.sleep(1)
        with _lock:
            _state["next_check_in"] = 0


# ---------------------------------------------------------------------------
# Flask application
# ---------------------------------------------------------------------------
app = Flask(__name__)


def _build_services_display():
    """Merge config, live status, and historical stats into one list for the template."""
    stats = database.get_service_stats()

    with _lock:
        results = dict(_state["current_results"])

    display = []
    for svc in config.SERVICES:
        sid = svc["id"]
        last = results.get(sid, {})
        hist = stats.get(sid, {})

        total_checks = hist.get("total_checks", 0)
        up_count = hist.get("up_count", 0)
        uptime_pct = round(up_count / total_checks * 100, 1) if total_checks else 0.0

        display.append({
            "id": sid,
            "name": svc["name"],
            "machine": svc["machine"],
            "host": svc["host"],
            "port": svc["port"],
            "points_per_round": svc["points"],
            # None = not yet checked; True/False after first round
            "up": last.get("up"),
            "message": last.get("message", "No checks run yet"),
            "points_last_round": last.get("points_earned", 0),
            "total_points": hist.get("total_points", 0),
            "total_checks": total_checks,
            "uptime_pct": uptime_pct,
        })
    return display


@app.route("/")
def index():
    with _lock:
        state_snapshot = dict(_state)

    services = _build_services_display()
    recent_rounds = database.get_recent_rounds(15)
    score_history = database.get_score_history(30)

    # Build per-round service breakdown for the history table
    # (last_round results already in current_results; older rounds need per-round query)
    return render_template(
        "index.html",
        services=services,
        last_check_time=state_snapshot["last_check_time"],
        next_check_in=state_snapshot["next_check_in"],
        is_checking=state_snapshot["is_checking"],
        round_score=state_snapshot["round_score"],
        max_score_per_round=config.MAX_SCORE_PER_ROUND,
        cumulative_score=database.get_cumulative_score(),
        round_count=database.get_round_count(),
        check_interval=config.CHECK_INTERVAL,
        range_id=config.RANGE_ID,
        base_net=config.BASE_NET,
        recent_rounds=recent_rounds,
        score_history=score_history,
    )


@app.route("/api/status")
def api_status():
    """JSON endpoint — polled by the dashboard JS for live updates."""
    with _lock:
        state_snapshot = dict(_state)
        results = dict(_state["current_results"])

    services_out = {}
    for svc in config.SERVICES:
        sid = svc["id"]
        last = results.get(sid, {})
        services_out[sid] = {
            "name": svc["name"],
            "up": last.get("up"),
            "points_earned": last.get("points_earned", 0),
            "message": last.get("message", ""),
        }

    return jsonify({
        "last_check_time": state_snapshot["last_check_time"],
        "next_check_in": state_snapshot["next_check_in"],
        "is_checking": state_snapshot["is_checking"],
        "round_score": state_snapshot["round_score"],
        "max_score_per_round": config.MAX_SCORE_PER_ROUND,
        "cumulative_score": database.get_cumulative_score(),
        "round_count": database.get_round_count(),
        "services": services_out,
    })


@app.route("/api/history")
def api_history():
    """Score-per-round history for Chart.js."""
    return jsonify(database.get_score_history(30))


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    database.init_db()

    bg = threading.Thread(target=_scheduler_loop, daemon=True, name="scorer")
    bg.start()

    log.info(
        "Scoring engine starting — Range %d | Network %s.0/24 | Interval %ds",
        config.RANGE_ID,
        config.BASE_NET,
        config.CHECK_INTERVAL,
    )
    log.info("Dashboard: http://0.0.0.0:8080/")

    app.run(host="0.0.0.0", port=8080, debug=False, use_reloader=False)
