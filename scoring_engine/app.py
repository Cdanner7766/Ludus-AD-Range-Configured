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

from flask import Flask, jsonify, render_template, request

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
    "current_results": {},     # service_id → {up, message}
    "is_checking": False,
}

# ---------------------------------------------------------------------------
# Background check loop
# ---------------------------------------------------------------------------

def _run_one_round():
    """Execute checks for every service and persist results."""
    results = []

    for svc in config.SERVICES:
        # Merge DB credential overrides over config defaults for credentialed services
        effective_svc = dict(svc)
        if svc.get("has_credentials"):
            db_user, db_pass = database.get_credential(svc["id"])
            effective_svc["_user"] = db_user or svc.get("default_user", "")
            effective_svc["_pass"] = db_pass or svc.get("default_pass", "")
        try:
            up, message = checks.run_check(effective_svc)
        except Exception as exc:
            up = False
            message = f"Check exception: {exc}"

        result = {
            "service_id": svc["id"],
            "up": up,
            "message": message,
        }
        results.append(result)
        log.info(
            "  %-4s  %-30s  %s",
            "UP" if up else "DOWN",
            svc["name"],
            message[:70],
        )

    database.save_round(results)

    with _lock:
        _state["last_check_time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        _state["current_results"] = {r["service_id"]: r for r in results}
        _state["is_checking"] = False

    up_count = sum(1 for r in results if r["up"])
    log.info("Round complete: %d/%d services up", up_count, len(results))


def _scheduler_loop():
    """Background thread: runs checks every CHECK_INTERVAL seconds."""
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
            # None = not yet checked; True/False after first round
            "up": last.get("up"),
            "message": last.get("message", "No checks run yet"),
            "up_count": up_count,
            "total_checks": total_checks,
            "uptime_pct": uptime_pct,
            "has_credentials": svc.get("has_credentials", False),
        })
    return display


@app.route("/")
def index():
    with _lock:
        state_snapshot = dict(_state)

    services = _build_services_display()
    recent_rounds = database.get_recent_rounds(15)

    return render_template(
        "index.html",
        services=services,
        last_check_time=state_snapshot["last_check_time"],
        next_check_in=state_snapshot["next_check_in"],
        is_checking=state_snapshot["is_checking"],
        round_count=database.get_round_count(),
        check_interval=config.CHECK_INTERVAL,
        range_id=config.RANGE_ID,
        base_net=config.BASE_NET,
        recent_rounds=recent_rounds,
    )


@app.route("/api/status")
def api_status():
    """JSON endpoint — polled by the dashboard JS for live updates."""
    with _lock:
        state_snapshot = dict(_state)
        results = dict(_state["current_results"])

    stats = database.get_service_stats()

    services_out = {}
    for svc in config.SERVICES:
        sid = svc["id"]
        last = results.get(sid, {})
        hist = stats.get(sid, {})
        total_checks = hist.get("total_checks", 0)
        up_count = hist.get("up_count", 0)
        services_out[sid] = {
            "name": svc["name"],
            "up": last.get("up"),
            "message": last.get("message", ""),
            "up_count": up_count,
            "total_checks": total_checks,
            "uptime_pct": round(up_count / total_checks * 100, 1) if total_checks else 0.0,
        }

    return jsonify({
        "last_check_time": state_snapshot["last_check_time"],
        "next_check_in": state_snapshot["next_check_in"],
        "is_checking": state_snapshot["is_checking"],
        "round_count": database.get_round_count(),
        "services": services_out,
    })


@app.route("/api/credentials/<svc_id>", methods=["GET", "POST"])
def api_credentials(svc_id):
    """GET: return current username for a credentialed service (password never returned).
       POST: update credentials {username, password}."""
    svc = next(
        (s for s in config.SERVICES if s["id"] == svc_id and s.get("has_credentials")),
        None,
    )
    if not svc:
        return jsonify({"error": "Service not found or does not use credentials"}), 404

    if request.method == "GET":
        db_user, _ = database.get_credential(svc_id)
        return jsonify({"username": db_user or svc.get("default_user", "")})

    data = request.get_json(force=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    if not username or not password:
        return jsonify({"error": "Both username and password are required"}), 400
    database.set_credential(svc_id, username, password)
    log.info("Credentials updated for service '%s' (user=%s)", svc_id, username)
    return jsonify({"ok": True})


@app.route("/api/clear", methods=["POST"])
def api_clear():
    """Clear all check history and reset in-memory state."""
    database.clear_all_checks()
    with _lock:
        _state["current_results"] = {}
        _state["last_check_time"] = None
    log.info("Check history cleared by user request.")
    return jsonify({"ok": True})


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
