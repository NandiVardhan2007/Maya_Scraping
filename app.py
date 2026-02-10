#!/usr/bin/env python3
"""
app.py - Maya API aggregator (requests-based)
Returns clean, structured student stats:
  Easy, Medium, Hard, Total, Score, Rank, Programming Languages, Total Streak
"""

import os
import re
import json
import pickle
import logging
import threading
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List

import certifi
import requests
from flask import Flask, request, jsonify
from flask_cors import CORS
from logging.handlers import RotatingFileHandler
from dotenv import load_dotenv

load_dotenv()

# -------- Configuration --------
BASE            = os.getenv("MAYA_BASE", "https://maya.technicalhub.io")
LOGIN_PATH      = "/node/api/secure-login"
ENDPOINTS = {
    "problems_count":           "/node/api/get-student-problems-count",
    "problems_count_dashboard": "/node/api/get-student-problems-count-dashboard",
    "every_day_counts":         "/node/api/get-student-every-day-problems-count",
    "batch_ranks":              "/node/api/get-batch-ranks",
    "user_by_id":               "/node/api/get-user-by-id",   # append /<id>
}
CACHE_HOURS         = float(os.getenv("CACHE_HOURS", "12"))
CACHE_TTL           = timedelta(hours=CACHE_HOURS)
CACHE_DIR           = os.path.join(os.path.dirname(__file__), "cache")
LOG_DIR             = os.path.join(os.path.dirname(__file__), "logs")
CRON_KEY            = os.getenv("CRON_KEY", "")
DISABLE_SSL_VERIFY  = os.getenv("DISABLE_SSL_VERIFY", "false").lower() in ("1", "true", "yes")
REQUEST_TIMEOUT     = int(os.getenv("REQUESTS_TIMEOUT", "30"))

os.makedirs(CACHE_DIR, exist_ok=True)
os.makedirs(LOG_DIR,   exist_ok=True)

# -------- Logging --------
logger = logging.getLogger("maya-api")
logger.setLevel(logging.INFO)
_fh = RotatingFileHandler(os.path.join(LOG_DIR, "maya-api.log"), maxBytes=5_000_000, backupCount=3)
_fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
logger.addHandler(_fh)
_ch = logging.StreamHandler()
_ch.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
logger.addHandler(_ch)

# -------- Flask --------
app = Flask(__name__)
CORS(app)

# ─────────────────────────────────────────────
# Cache helpers
# ─────────────────────────────────────────────
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

# ─────────────────────────────────────────────
# HTTP helpers
# ─────────────────────────────────────────────
def build_session() -> requests.Session:
    s = requests.Session()
    s.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "Accept":     "application/json, text/plain, */*",
        "Origin":     BASE,
        "Referer":    f"{BASE}/sign-in",
    })
    return s

def do_post(session: requests.Session, path: str, json_payload: dict, verify) -> Dict[str, Any]:
    url = BASE + path
    try:
        r = session.post(url, json=json_payload, timeout=REQUEST_TIMEOUT, verify=verify)
        try:
            return {"ok": True, "status_code": r.status_code, "json": r.json()}
        except Exception:
            return {"ok": True, "status_code": r.status_code, "json": None, "text": r.text[:500]}
    except Exception as e:
        logger.exception("POST %s failed: %s", url, e)
        return {"ok": False, "error": str(e)}

def do_get(session: requests.Session, path: str, verify) -> Dict[str, Any]:
    url = BASE + path
    try:
        r = session.get(url, timeout=REQUEST_TIMEOUT, verify=verify)
        try:
            return {"ok": True, "status_code": r.status_code, "json": r.json()}
        except Exception:
            return {"ok": True, "status_code": r.status_code, "json": None, "text": r.text[:500]}
    except Exception as e:
        logger.exception("GET %s failed: %s", url, e)
        return {"ok": False, "error": str(e)}

# ─────────────────────────────────────────────
# Extraction helpers — written to match exact
# Maya API response shapes confirmed from debug
# ─────────────────────────────────────────────

def _extract_from_batch_current_user(batch_ranks_json: Any, roll_no: str) -> Dict[str, Any]:
    """
    batch-ranks returns:
      {
        "top5": [ ... ],
        "current_user": [
          {
            "roll_no": "24P31A1224",
            "problems_count": { "easy": 309, "medium": 59, "hard": 12 },
            "score": 9260,
            "rank": 55
          }
        ]
      }
    We read directly from current_user[0].
    """
    empty = {"easy": 0, "medium": 0, "hard": 0, "score": None, "rank": None}
    if not batch_ranks_json or not isinstance(batch_ranks_json, dict):
        return empty

    current_user_list = batch_ranks_json.get("current_user", [])
    if not isinstance(current_user_list, list) or not current_user_list:
        return empty

    cu = current_user_list[0]
    if not isinstance(cu, dict):
        return empty

    pc = cu.get("problems_count", {})
    return {
        "easy":   int(pc.get("easy",   0) or 0),
        "medium": int(pc.get("medium", 0) or 0),
        "hard":   int(pc.get("hard",   0) or 0),
        "score":  int(cu.get("score",  0) or 0),
        "rank":   int(cu.get("rank",   0) or 0),
    }


def _extract_programming_languages(pc_json: Any) -> Dict[str, int]:
    """
    get-student-problems-count returns:
      { "programmingLanguages": { "java": 76, "c": 169, "sql": 121 } }
    """
    if not pc_json or not isinstance(pc_json, dict):
        return {}
    langs = pc_json.get("programmingLanguages", {})
    if not isinstance(langs, dict):
        return {}
    return {lang: int(cnt or 0) for lang, cnt in langs.items()}


def _extract_streak_and_submissions(every_day_json: Any) -> Dict[str, Any]:
    """
    get-student-every-day-problems-count returns:
      {
        "formattedCounts": [
          { "10-02-2026": 4 },
          { "09-02-2026": 1 },
          ...
        ],
        "submissions": {
          "per_last_year":  67,
          "per_last_month": 134,
          "per_last_week":  9
        }
      }

    Each item in formattedCounts is a single-key dict:
      key   = "DD-MM-YYYY"
      value = problem count for that day

    Streak = longest unbroken run of consecutive days ending at
             the most recent active date (≤ today).
    """
    result = {
        "current_streak":  0,
        "per_last_week":   0,
        "per_last_month":  0,
        "per_last_year":   0,
    }

    if not every_day_json or not isinstance(every_day_json, dict):
        return result

    # ── Submissions summary ───────────────────────────────────────────────────
    subs = every_day_json.get("submissions", {})
    if isinstance(subs, dict):
        result["per_last_week"]  = int(subs.get("per_last_week",  0) or 0)
        result["per_last_month"] = int(subs.get("per_last_month", 0) or 0)
        result["per_last_year"]  = int(subs.get("per_last_year",  0) or 0)

    # ── Build active-date set from formattedCounts ────────────────────────────
    formatted = every_day_json.get("formattedCounts", [])
    if not isinstance(formatted, list):
        return result

    active_dates: set = set()
    for entry in formatted:
        if not isinstance(entry, dict):
            continue
        # Each entry has exactly one key: "DD-MM-YYYY" → count
        for date_str, count in entry.items():
            try:
                cnt = int(count or 0)
            except (TypeError, ValueError):
                continue
            if cnt <= 0:
                continue
            try:
                # Parse "DD-MM-YYYY"
                day, month, year = date_str.split("-")
                d = datetime(int(year), int(month), int(day)).date()
                active_dates.add(d)
            except (ValueError, AttributeError):
                continue

    if not active_dates:
        return result

    # ── Walk backwards from most-recent active date ≤ today ──────────────────
    today       = datetime.utcnow().date()
    most_recent = max(d for d in active_dates if d <= today) if any(d <= today for d in active_dates) else None

    if most_recent is None:
        return result

    streak = 0
    check  = most_recent
    while check in active_dates:
        streak += 1
        check  -= timedelta(days=1)

    result["current_streak"] = streak
    return result


# ─────────────────────────────────────────────
# Core: login + aggregate → clean summary
# ─────────────────────────────────────────────
def login_and_aggregate(roll_no: str, password: str) -> Dict[str, Any]:
    verify = False if DISABLE_SSL_VERIFY else certifi.where()

    session = build_session()
    logger.info("Logging in %s", roll_no)
    res_login = do_post(session, LOGIN_PATH,
                        {"roll_no": roll_no, "password": password, "forcelogin": True},
                        verify)

    if not res_login.get("ok") or res_login.get("status_code") != 200:
        return {"ok": False, "stage": "login", "detail": res_login}

    login_json  = res_login.get("json") or {}
    student_id  = login_json.get("student_id") or login_json.get("_id")

    # ── fetch all endpoints ──────────────────────────────────────────────────
    r_pc        = do_post(session, ENDPOINTS["problems_count"],           {"roll_no": roll_no}, verify)
    r_pcd       = do_post(session, ENDPOINTS["problems_count_dashboard"], {"roll_no": roll_no}, verify)
    r_edc       = do_post(session, ENDPOINTS["every_day_counts"],         {"roll_no": roll_no}, verify)

    r_user      = {"ok": False, "note": "student_id_missing"}
    r_ranks     = None
    batch_id    = None

    if student_id:
        r_user  = do_get(session, f"{ENDPOINTS['user_by_id']}/{student_id}", verify)
        u       = (r_user.get("json") or {})
        cp      = u.get("current_program") or u.get("current_courses") or []
        if isinstance(cp, list) and cp:
            batch_id = cp[0].get("batch") or cp[0].get("batch_id")

    if batch_id:
        r_ranks = do_post(session, ENDPOINTS["batch_ranks"],
                          {"roll_no": roll_no, "batch": batch_id}, verify)

    # ── extract from batch_ranks → current_user (authoritative source) ───────
    batch_data = _extract_from_batch_current_user(
        r_ranks.get("json") if r_ranks else None, roll_no
    )
    easy   = batch_data["easy"]
    medium = batch_data["medium"]
    hard   = batch_data["hard"]
    total  = easy + medium + hard
    score  = batch_data["score"]
    rank   = batch_data["rank"] or None

    # ── extract programming languages from get-student-problems-count ─────────
    prog_langs = _extract_programming_languages(r_pc.get("json"))

    # ── extract streak + submission stats from every-day-counts ──────────────
    streak_data = _extract_streak_and_submissions(r_edc.get("json"))

    # ── assemble clean output ────────────────────────────────────────────────
    summary = {
        "ok":         True,
        "roll_no":    roll_no,
        "student_id": student_id,
        "batch_id":   batch_id,
        "name":       (r_user.get("json") or {}).get("first_name", ""),
        "college":    (r_user.get("json") or {}).get("college", ""),
        # ─── problem stats (from batch_ranks → current_user) ──────────────
        "problems": {
            "easy":   easy,
            "medium": medium,
            "hard":   hard,
            "total":  total,
        },
        "score": score,
        "rank":  rank,
        # ─── languages (from get-student-problems-count) ──────────────────
        "programmingLanguages": prog_langs,
        # ─── streak + submissions (from every-day-counts) ─────────────────
        "streak": {
            "current_streak":  streak_data["current_streak"],
            "per_last_week":   streak_data["per_last_week"],
            "per_last_month":  streak_data["per_last_month"],
            "per_last_year":   streak_data["per_last_year"],
        },
        "_fetched_at": datetime.utcnow().isoformat(),
    }

    # Cache & return
    try:
        save_cache(roll_no, summary)
    except Exception:
        logger.exception("Failed to cache results for %s", roll_no)

    return summary


# ─────────────────────────────────────────────
# Flask routes
# ─────────────────────────────────────────────

@app.route("/api/health", methods=["GET"])
def health():
    cache_files = [f for f in os.listdir(CACHE_DIR) if f.endswith(".cache")]
    total_size  = sum(os.path.getsize(os.path.join(CACHE_DIR, f)) for f in cache_files)
    return jsonify({
        "status":    "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "cache": {
            "total_cached_users": len(cache_files),
            "total_size_bytes":   total_size,
        }
    }), 200


@app.route("/api/scrape", methods=["POST"])
def api_scrape():
    """
    POST body JSON:
      {
        "roll_no":   "24P31A1224",   # or set MAYA_USER env var
        "password":  "...",          # or set MAYA_PASS env var
        "use_cache": true            # default true
      }

    Response:
      {
        "ok": true,
        "cached": false,
        "result": {
          "roll_no":   "24P31A1224",
          "problems":  { "easy": 12, "medium": 8, "hard": 3, "total": 23 },
          "score":     450,
          "rank":      5,
          "programmingLanguages": { "java": 76, "c": 169, "sql": 121 },
          "streak":    { "current_streak": 7 },
          "_fetched_at": "2024-05-20T10:30:00"
        }
      }
    """
    body = request.get_json(silent=True) or {}
    roll = body.get("roll_no")  or os.getenv("MAYA_USER")
    pwd  = body.get("password") or os.getenv("MAYA_PASS")
    use_cache = body.get("use_cache", True)

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
    Protected cron endpoint.  Supply header: X-CRON-KEY: <CRON_KEY>
    Returns 202 immediately; scraping runs in background.
    """
    key = request.headers.get("X-CRON-KEY", "")
    if CRON_KEY and key != CRON_KEY:
        return jsonify({"ok": False, "error": "invalid_cron_key"}), 403

    body = request.get_json(silent=True) or {}
    roll = body.get("roll_no")  or os.getenv("MAYA_USER")
    pwd  = body.get("password") or os.getenv("MAYA_PASS")

    if not roll or not pwd:
        return jsonify({"ok": False, "error": "credentials_missing"}), 400

    def bg():
        try:
            logger.info("Cron background start: %s", roll)
            login_and_aggregate(roll, pwd)
            logger.info("Cron background done:  %s", roll)
        except Exception:
            logger.exception("Cron background error: %s", roll)

    threading.Thread(target=bg, daemon=True).start()
    return jsonify({"ok": True, "status": "started"}), 202


@app.route("/api/cache_stats", methods=["GET"])
def api_cache_stats():
    files = []
    total = 0
    for fn in os.listdir(CACHE_DIR):
        if fn.endswith(".cache"):
            p    = os.path.join(CACHE_DIR, fn)
            size = os.path.getsize(p)
            files.append({"filename": fn, "size_bytes": size})
            total += size
    return jsonify({"total_cached": len(files), "total_size_bytes": total, "files": files}), 200


@app.route("/api/cache_clear", methods=["POST"])
def api_cache_clear():
    body = request.get_json(silent=True) or {}
    roll = body.get("roll_no")
    if roll:
        fp = cache_path(roll)
        if not os.path.exists(fp):
            return jsonify({"ok": False, "error": "not_found"}), 404
        try:
            os.remove(fp)
            return jsonify({"ok": True, "cleared": roll}), 200
        except Exception as e:
            return jsonify({"ok": False, "error": str(e)}), 500
    clear_all_cache()
    return jsonify({"ok": True, "cleared_all": True}), 200


@app.route("/api/debug", methods=["POST"])
def api_debug():
    """
    Returns the RAW JSON from every Maya endpoint.
    Use this to inspect exact field names for streak / rank.

    POST: { "roll_no": "24P31A1224", "password": "..." }
    """
    body = request.get_json(silent=True) or {}
    roll = body.get("roll_no")  or os.getenv("MAYA_USER")
    pwd  = body.get("password") or os.getenv("MAYA_PASS")

    if not roll or not pwd:
        return jsonify({"ok": False, "error": "credentials_missing"}), 400

    verify  = False if DISABLE_SSL_VERIFY else certifi.where()
    session = build_session()

    res_login = do_post(session, LOGIN_PATH,
                        {"roll_no": roll, "password": pwd, "forcelogin": True},
                        verify)
    if not res_login.get("ok") or res_login.get("status_code") != 200:
        return jsonify({"ok": False, "stage": "login", "detail": res_login}), 500

    login_json = res_login.get("json") or {}
    student_id = login_json.get("student_id") or login_json.get("_id")

    raw = {
        "student_id":               student_id,
        "problems_count":           do_post(session, ENDPOINTS["problems_count"],           {"roll_no": roll}, verify).get("json"),
        "problems_count_dashboard": do_post(session, ENDPOINTS["problems_count_dashboard"], {"roll_no": roll}, verify).get("json"),
        "every_day_counts":         do_post(session, ENDPOINTS["every_day_counts"],         {"roll_no": roll}, verify).get("json"),
    }

    if student_id:
        r_user            = do_get(session, f"{ENDPOINTS['user_by_id']}/{student_id}", verify)
        raw["user_by_id"] = r_user.get("json")

        u        = r_user.get("json") or {}
        cp       = u.get("current_program") or u.get("current_courses") or []
        batch_id = None
        if isinstance(cp, list) and cp:
            batch_id = cp[0].get("batch") or cp[0].get("batch_id")

        if batch_id:
            raw["batch_ranks"]   = do_post(session, ENDPOINTS["batch_ranks"],
                                           {"roll_no": roll, "batch": batch_id}, verify).get("json")
            raw["batch_id_used"] = batch_id

    return jsonify({"ok": True, "raw": raw}), 200


# ─────────────────────────────────────────────
if __name__ == "__main__":
    port = int(os.getenv("PORT", "5000"))
    app.run(host="0.0.0.0", port=port)