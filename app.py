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
# Extraction helpers  (adapt field names here if
# the API ever changes its key names)
# ─────────────────────────────────────────────

def _extract_difficulty_counts(pc_json: Any) -> Dict[str, int]:
    """
    Tries several common shapes that Maya /get-student-problems-count
    or /get-student-problems-count-dashboard might return:
      { easy, medium, hard }
      { easyCount, mediumCount, hardCount }
      { data: { easy, medium, hard } }
      list of { difficulty, count } objects
    Returns a dict with keys: easy, medium, hard
    """
    result = {"easy": 0, "medium": 0, "hard": 0}
    if not pc_json or not isinstance(pc_json, (dict, list)):
        return result

    # Unwrap common wrappers
    if isinstance(pc_json, dict):
        if "data" in pc_json and isinstance(pc_json["data"], (dict, list)):
            pc_json = pc_json["data"]

    if isinstance(pc_json, list):
        for item in pc_json:
            if not isinstance(item, dict):
                continue
            diff = str(item.get("difficulty", item.get("level", ""))).lower()
            cnt  = int(item.get("count", item.get("solved", item.get("total", 0))) or 0)
            if diff in result:
                result[diff] = cnt
        return result

    if isinstance(pc_json, dict):
        # Try plain keys first
        for key, alias in [("easy", ["easy", "easyCount", "Easy", "EASY"]),
                           ("medium", ["medium", "mediumCount", "Medium", "MEDIUM"]),
                           ("hard", ["hard", "hardCount", "Hard", "HARD"])]:
            for a in alias:
                if a in pc_json:
                    result[key] = int(pc_json[a] or 0)
                    break

    return result


def _extract_score(source: Any) -> Optional[int]:
    """Look for a score / total_score / points field in various shapes."""
    if isinstance(source, dict):
        for k in ("score", "total_score", "totalScore", "points", "total_points"):
            if k in source:
                return int(source[k] or 0)
        if "data" in source and isinstance(source["data"], dict):
            return _extract_score(source["data"])
    return None


def _extract_rank(batch_ranks_json: Any, roll_no: str) -> Optional[int]:
    """
    batch_ranks response is typically a list of student objects.
    Find the entry matching roll_no and return its rank (index+1 or explicit rank field).
    """
    if not batch_ranks_json:
        return None

    data = batch_ranks_json
    if isinstance(data, dict):
        data = data.get("data") or data.get("ranks") or data.get("students") or []

    if not isinstance(data, list):
        return None

    # Sort by score descending if no explicit rank field
    explicit_rank = any("rank" in (item if isinstance(item, dict) else {}) for item in data)

    for idx, item in enumerate(data):
        if not isinstance(item, dict):
            continue
        rn = item.get("roll_no") or item.get("rollNo") or item.get("roll_number") or ""
        if str(rn).strip().lower() == roll_no.strip().lower():
            if explicit_rank:
                return int(item.get("rank", idx + 1))
            return idx + 1          # position in the list (assumed sorted by score)

    return None


def _extract_problem_count_from_batch(batch_ranks_json: Any, roll_no: str) -> Dict[str, int]:
    """
    Some Maya setups store per-student difficulty breakdown inside the batch-ranks list.
    """
    result = {"easy": 0, "medium": 0, "hard": 0}
    if not batch_ranks_json:
        return result

    data = batch_ranks_json
    if isinstance(data, dict):
        data = data.get("data") or data.get("ranks") or data.get("students") or []

    if not isinstance(data, list):
        return result

    for item in data:
        if not isinstance(item, dict):
            continue
        rn = item.get("roll_no") or item.get("rollNo") or item.get("roll_number") or ""
        if str(rn).strip().lower() == roll_no.strip().lower():
            result["easy"]   = int(item.get("easy",   item.get("easyCount",   0)) or 0)
            result["medium"] = int(item.get("medium", item.get("mediumCount", 0)) or 0)
            result["hard"]   = int(item.get("hard",   item.get("hardCount",   0)) or 0)
            break

    return result


def _extract_programming_languages(source_json: Any) -> Dict[str, int]:
    """
    Looks for a programmingLanguages / programming_languages dict.
    Searches both top-level and inside common wrappers.
    """
    if not source_json:
        return {}

    def _find(obj):
        if isinstance(obj, dict):
            for k in ("programmingLanguages", "programming_languages", "languages", "languageCounts"):
                if k in obj and isinstance(obj[k], dict):
                    return {lang: int(cnt or 0) for lang, cnt in obj[k].items()}
            # recurse one level into common wrappers
            for k in ("data", "student", "result"):
                if k in obj:
                    found = _find(obj[k])
                    if found:
                        return found
        return {}

    return _find(source_json)


def _extract_streak(every_day_json: Any) -> int:
    """
    Computes the current streak from get-student-every-day-problems-count.

    Strategy:
      1. Parse every entry into (date, count) pairs.
      2. Keep only dates where count > 0  →  these are "active days".
      3. Sort active dates descending (newest first).
      4. Walk backwards day-by-day: as long as each next expected date is
         present in the active-date set, increment the streak.
      5. Allow today to be missing (student may not have solved yet today)
         so we start from the most recent active date ≤ today.
    """
    if not every_day_json:
        return 0

    # Unwrap common response wrappers
    data = every_day_json
    if isinstance(data, dict):
        # Try explicit streak field first
        for k in ("streak", "currentStreak", "current_streak"):
            if k in data:
                return int(data[k] or 0)
        data = data.get("data") or data.get("counts") or data.get("days") or []

    if not isinstance(data, list) or not data:
        return 0

    # ── Build a set of active dates (count > 0) ──────────────────────────────
    active_dates = set()
    for item in data:
        if not isinstance(item, dict):
            continue

        # Date field: "date" | "day" | "_id" | "createdAt"
        raw_date = (item.get("date") or item.get("day") or
                    item.get("_id")  or item.get("createdAt") or "")
        # Count field: "count" | "solved" | "total" | "problemCount"
        raw_count = (item.get("count") or item.get("solved") or
                     item.get("total") or item.get("problemCount") or 0)

        try:
            count = int(raw_count)
        except (TypeError, ValueError):
            count = 0

        if count <= 0:
            continue

        # Parse date – handles "2024-05-20", "2024-05-20T00:00:00.000Z", timestamps
        try:
            d = datetime.fromisoformat(str(raw_date)[:10]).date()
            active_dates.add(d)
        except (ValueError, TypeError):
            continue

    if not active_dates:
        return 0

    # ── Walk backwards from most-recent active date ≤ today ─────────────────
    today         = datetime.utcnow().date()
    most_recent   = max(active_dates)

    # If the most recent activity is in the future (timezone edge), clamp to today
    if most_recent > today:
        most_recent = today

    # Start counting from the most recent active day
    streak   = 0
    check    = most_recent

    while check in active_dates:
        streak += 1
        check  -= timedelta(days=1)   # step one day back

    return streak


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

    # ── extract difficulty counts ────────────────────────────────────────────
    # Priority: batch_ranks (has per-student breakdown) > problems_count_dashboard > problems_count
    diff = {"easy": 0, "medium": 0, "hard": 0}

    if r_ranks and r_ranks.get("json"):
        diff_from_batch = _extract_problem_count_from_batch(r_ranks["json"], roll_no)
        if any(diff_from_batch.values()):
            diff = diff_from_batch

    if not any(diff.values()) and r_pcd.get("json"):
        diff = _extract_difficulty_counts(r_pcd["json"])

    if not any(diff.values()) and r_pc.get("json"):
        diff = _extract_difficulty_counts(r_pc["json"])

    easy   = diff["easy"]
    medium = diff["medium"]
    hard   = diff["hard"]
    total  = easy + medium + hard

    # ── extract score ────────────────────────────────────────────────────────
    score = None
    for src in [r_pcd.get("json"), r_pc.get("json"), r_user.get("json")]:
        score = _extract_score(src)
        if score is not None:
            break

    # Also try finding this student's score inside batch_ranks list
    if score is None and r_ranks and r_ranks.get("json"):
        data = r_ranks["json"]
        if isinstance(data, dict):
            data = data.get("data") or data.get("ranks") or data.get("students") or []
        if isinstance(data, list):
            for item in data:
                if not isinstance(item, dict):
                    continue
                rn = item.get("roll_no") or item.get("rollNo") or ""
                if str(rn).strip().lower() == roll_no.strip().lower():
                    score = _extract_score(item)
                    break

    # ── extract rank ─────────────────────────────────────────────────────────
    rank = None
    if r_ranks and r_ranks.get("json"):
        rank = _extract_rank(r_ranks["json"], roll_no)

    # ── extract programming languages ────────────────────────────────────────
    prog_langs: Dict[str, int] = {}
    for src in [r_user.get("json"), r_pcd.get("json"), r_pc.get("json")]:
        prog_langs = _extract_programming_languages(src)
        if prog_langs:
            break

    # ── extract streak ───────────────────────────────────────────────────────
    streak = _extract_streak(r_edc.get("json"))

    # ── assemble clean output ────────────────────────────────────────────────
    summary = {
        "ok":        True,
        "roll_no":   roll_no,
        "student_id": student_id,
        "batch_id":  batch_id,
        # ─── main stats ───────────────────────────────
        "problems": {
            "easy":   easy,
            "medium": medium,
            "hard":   hard,
            "total":  total,
        },
        "score": score,
        "rank":  rank,
        "programmingLanguages": prog_langs,
        "streak": {
            "current_streak": streak,
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


# ─────────────────────────────────────────────
if __name__ == "__main__":
    port = int(os.getenv("PORT", "5000"))
    app.run(host="0.0.0.0", port=port)