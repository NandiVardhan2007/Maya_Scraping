#!/usr/bin/env python3
"""
app.py - Maya API aggregator (requests-based)
Drop-in replacement for your Selenium-based backend.
"""

import os
import re
import json
import time
import pickle
import logging
import threading
from datetime import datetime, timedelta
from typing import Optional, Dict, Any

import certifi
import requests
from flask import Flask, request, jsonify, abort
from flask_cors import CORS
from logging.handlers import RotatingFileHandler
from dotenv import load_dotenv

load_dotenv()

# -------- Configuration --------
BASE = os.getenv("MAYA_BASE", "https://maya.technicalhub.io")
LOGIN_PATH = "/node/api/secure-login"
ENDPOINTS = {
    "problems_count": "/node/api/get-student-problems-count",
    "problems_count_dashboard": "/node/api/get-student-problems-count-dashboard",
    "every_day_counts": "/node/api/get-student-every-day-problems-count",
    "batch_ranks": "/node/api/get-batch-ranks",
    "user_by_id": "/node/api/get-user-by-id"  # append /<id>
}
CACHE_HOURS = float(os.getenv("CACHE_HOURS", "12"))
CACHE_TTL = timedelta(hours=CACHE_HOURS)
CACHE_DIR = os.path.join(os.path.dirname(__file__), "cache")
LOG_DIR = os.path.join(os.path.dirname(__file__), "logs")
CRON_KEY = os.getenv("CRON_KEY", "")
DISABLE_SSL_VERIFY = os.getenv("DISABLE_SSL_VERIFY", "false").lower() in ("1", "true", "yes")
REQUEST_TIMEOUT = int(os.getenv("REQUESTS_TIMEOUT", "30"))

os.makedirs(CACHE_DIR, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)

# -------- Logging --------
logger = logging.getLogger("maya-api")
logger.setLevel(logging.INFO)
handler = RotatingFileHandler(os.path.join(LOG_DIR, "maya-api.log"), maxBytes=5_000_000, backupCount=3)
handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
logger.addHandler(handler)
console = logging.StreamHandler()
console.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
logger.addHandler(console)

# -------- Flask --------
app = Flask(__name__)
CORS(app)

# -------- Utilities --------
def cache_path(roll_no: str) -> str:
    safe = re.sub(r"[^\w\-_\.]", "_", roll_no)
    return os.path.join(CACHE_DIR, f"{safe}.cache")

def save_cache(roll_no: str, data: Dict[str, Any]) -> None:
    payload = {"timestamp": datetime.utcnow(), "data": data}
    with open(cache_path(roll_no), "wb") as f:
        pickle.dump(payload, f)

def load_cache(roll_no: str) -> Optional[Dict[str, Any]]:
    fp = cache_path(roll_no)
    if not os.path.exists(fp):
        return None
    try:
        with open(fp, "rb") as f:
            payload = pickle.load(f)
        ts = payload.get("timestamp")
        if not isinstance(ts, datetime):
            return None
        if datetime.utcnow() - ts > CACHE_TTL:
            # expired
            try:
                os.remove(fp)
            except Exception:
                pass
            return None
        data = payload.get("data")
        if isinstance(data, dict):
            data["_cache_ts"] = ts.isoformat()
        return data
    except Exception as e:
        logger.exception("Failed to load cache for %s: %s", roll_no, e)
        return None

def clear_all_cache() -> None:
    for fn in os.listdir(CACHE_DIR):
        if fn.endswith(".cache"):
            try:
                os.remove(os.path.join(CACHE_DIR, fn))
            except Exception:
                pass

def build_session() -> requests.Session:
    s = requests.Session()
    s.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "Accept": "application/json, text/plain, */*",
        "Origin": BASE,
        "Referer": f"{BASE}/sign-in"
    })
    return s

def do_post(session: requests.Session, path: str, json_payload: dict, verify) -> Dict[str, Any]:
    url = BASE + path
    try:
        r = session.post(url, json=json_payload, timeout=REQUEST_TIMEOUT, verify=verify)
        try:
            return {"ok": True, "status_code": r.status_code, "json": r.json(), "text": r.text[:1000]}
        except Exception:
            return {"ok": True, "status_code": r.status_code, "json": None, "text": r.text[:1000]}
    except Exception as e:
        logger.exception("POST %s failed: %s", url, e)
        return {"ok": False, "error": str(e)}

def do_get(session: requests.Session, path: str, verify) -> Dict[str, Any]:
    url = BASE + path
    try:
        r = session.get(url, timeout=REQUEST_TIMEOUT, verify=verify)
        try:
            return {"ok": True, "status_code": r.status_code, "json": r.json(), "text": r.text[:1000], "url": r.url}
        except Exception:
            return {"ok": True, "status_code": r.status_code, "json": None, "text": r.text[:1000], "url": r.url}
    except Exception as e:
        logger.exception("GET %s failed: %s", url, e)
        return {"ok": False, "error": str(e)}

# -------- Core scraping logic (requests-based) --------
def login_and_aggregate(roll_no: str, password: str) -> Dict[str, Any]:
    verify = False if DISABLE_SSL_VERIFY else certifi.where()

    session = build_session()
    login_payload = {"roll_no": roll_no, "password": password, "forcelogin": True}
    logger.info("Logging in %s", roll_no)
    res_login = do_post(session, LOGIN_PATH, login_payload, verify)

    if not res_login.get("ok") or res_login.get("status_code") != 200:
        return {"ok": False, "stage": "login", "result": res_login}

    login_json = res_login.get("json") or {}
    student_id = login_json.get("student_id") or login_json.get("_id")

    out: Dict[str, Any] = {"ok": True, "roll_no": roll_no, "student_id": student_id, "login": {"status": res_login.get("status_code")}}

    # 1) problems_count
    out["problems_count"] = do_post(session, ENDPOINTS["problems_count"], {"roll_no": roll_no}, verify)

    # 2) problems_count_dashboard
    out["problems_count_dashboard"] = do_post(session, ENDPOINTS["problems_count_dashboard"], {"roll_no": roll_no}, verify)

    # 3) every day counts
    out["every_day_counts"] = do_post(session, ENDPOINTS["every_day_counts"], {"roll_no": roll_no}, verify)

    # 4) user_by_id (if available)
    if student_id:
        out["user_by_id"] = do_get(session, f"{ENDPOINTS['user_by_id']}/{student_id}", verify)
        # try extract batch if available
        batch_id = None
        if out["user_by_id"].get("json"):
            u = out["user_by_id"]["json"]
            cp = u.get("current_program") or u.get("current_courses") or u.get("current_program")
            if isinstance(cp, list) and cp:
                batch_id = cp[0].get("batch") or cp[0].get("batch_id")
        if batch_id:
            out["batch_ranks"] = do_post(session, ENDPOINTS["batch_ranks"], {"roll_no": roll_no, "batch": batch_id}, verify)
            out["batch_id_used"] = batch_id
    else:
        out["user_by_id"] = {"ok": False, "note": "student_id_missing"}

    out["_fetched_at"] = datetime.utcnow().isoformat()
    # Save to cache
    try:
        save_cache(roll_no, out)
    except Exception:
        logger.exception("Failed to cache results for %s", roll_no)

    return out

# -------- Flask endpoints --------
@app.route("/api/health", methods=["GET"])
def health():
    stats = {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}
    # cache summary
    cache_files = []
    total_size = 0
    for fn in os.listdir(CACHE_DIR):
        if fn.endswith(".cache"):
            p = os.path.join(CACHE_DIR, fn)
            total_size += os.path.getsize(p)
            cache_files.append(fn)
    stats["cache_stats"] = {"cache_files": cache_files, "total_cached_users": len(cache_files), "total_size_bytes": total_size}
    return jsonify(stats), 200

@app.route("/api/scrape", methods=["POST"])
def api_scrape():
    """
    POST body JSON:
      {
        "roll_no": "...",            # optional if env var set
        "password": "...",           # optional if env var set
        "use_cache": true|false      # optional (default true)
      }
    Returns aggregated data (cached or fresh).
    """
    data = request.get_json(silent=True) or {}
    roll = data.get("roll_no") or os.getenv("MAYA_USER")
    pwd = data.get("password") or os.getenv("MAYA_PASS")
    use_cache = data.get("use_cache", True)

    if not roll or not pwd:
        return jsonify({"ok": False, "error": "credentials_missing"}), 400

    if use_cache:
        cached = load_cache(roll)
        if cached:
            return jsonify({"ok": True, "cached": True, "result": cached}), 200

    result = login_and_aggregate(roll, pwd)
    if not result.get("ok"):
        return jsonify(result), 500
    return jsonify({"ok": True, "cached": False, "result": result}), 200

@app.route("/api/cron", methods=["POST"])
def api_cron():
    """
    Protected endpoint for cron-job.org or similar.
    Provide header X-CRON-KEY=<CRON_KEY> (or set CRON_KEY empty to disable protection).
    Body may include { "roll_no": "...", "password": "...", "use_cache": false } to override env defaults.
    """
    key = request.headers.get("X-CRON-KEY", "")
    if CRON_KEY and key != CRON_KEY:
        return jsonify({"ok": False, "error": "invalid_cron_key"}), 403

    data = request.get_json(silent=True) or {}
    roll = data.get("roll_no") or os.getenv("MAYA_USER")
    pwd = data.get("password") or os.getenv("MAYA_PASS")

    if not roll or not pwd:
        return jsonify({"ok": False, "error": "credentials_missing"}), 400

    # spawn background thread so cron provider gets quick 202
    def bg():
        try:
            logger.info("Background cron started for %s", roll)
            login_and_aggregate(roll, pwd)
            logger.info("Background cron finished for %s", roll)
        except Exception:
            logger.exception("Background cron failed for %s", roll)

    t = threading.Thread(target=bg, daemon=True)
    t.start()
    return jsonify({"ok": True, "status": "started"}), 202

@app.route("/api/cache_stats", methods=["GET"])
def api_cache_stats():
    stats = {"files": [], "total_size": 0, "total_cached": 0}
    for fn in os.listdir(CACHE_DIR):
        if fn.endswith(".cache"):
            p = os.path.join(CACHE_DIR, fn)
            size = os.path.getsize(p)
            stats["files"].append({"filename": fn, "size_bytes": size})
            stats["total_size"] += size
            stats["total_cached"] += 1
    return jsonify(stats), 200

@app.route("/api/cache_clear", methods=["POST"])
def api_cache_clear():
    data = request.get_json(silent=True) or {}
    roll = data.get("roll_no")
    if roll:
        fp = cache_path(roll)
        if os.path.exists(fp):
            try:
                os.remove(fp)
                return jsonify({"ok": True, "cleared": roll}), 200
            except Exception as e:
                return jsonify({"ok": False, "error": str(e)}), 500
        return jsonify({"ok": False, "error": "not_found"}), 404
    else:
        clear_all_cache()
        return jsonify({"ok": True, "cleared_all": True}), 200

# ---- run server ----
if __name__ == "__main__":
    port = int(os.getenv("PORT", "5000"))
    app.run(host="0.0.0.0", port=port)
