import os
import requests
import logging
from datetime import datetime, timedelta
from flask import Flask, request, jsonify
from flask_cors import CORS

# -----------------------------
# App Config
# -----------------------------

app = Flask(__name__)
CORS(app)

BASE_URL = os.getenv("MAYA_BASE_URL", "https://maya.technicalhub.io")
LOGIN_URL = f"{BASE_URL}/node/api/secure-login"

VERIFY_SSL = os.getenv("VERIFY_SSL", "false").lower() == "true"
REQUEST_TIMEOUT = int(os.getenv("REQUEST_TIMEOUT", "30"))

# -----------------------------
# Logging Setup
# -----------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

# -----------------------------
# Helper: Safe JSON
# -----------------------------

def safe_json(response):
    try:
        return response.json()
    except Exception:
        return None

# -----------------------------
# Helper: Calculate Current Streak
# -----------------------------

def calculate_current_streak(formatted_counts):
    if not formatted_counts:
        return 0

    dates = []

    for entry in formatted_counts:
        for date_str in entry.keys():
            try:
                dates.append(datetime.strptime(date_str, "%d-%m-%Y"))
            except ValueError:
                continue

    if not dates:
        return 0

    dates = sorted(set(dates))
    today = dates[-1]

    streak = 1
    for i in range(len(dates) - 2, -1, -1):
        if dates[i] == today - timedelta(days=1):
            streak += 1
            today = dates[i]
        else:
            break

    return streak

# -----------------------------
# Login
# -----------------------------

def login(session, roll_no, password):
    payload = {
        "roll_no": roll_no,
        "password": password,
        "forcelogin": False
    }

    try:
        response = session.post(
            LOGIN_URL,
            json=payload,
            timeout=REQUEST_TIMEOUT,
            verify=VERIFY_SSL
        )
    except Exception as e:
        return None, f"Login request failed: {str(e)}"

    if response.status_code != 200:
        return None, f"Login failed (status {response.status_code})"

    data = safe_json(response)
    if not data or "student_id" not in data:
        return None, "Invalid login response"

    return data["student_id"], None

# -----------------------------
# Fetch All Stats
# -----------------------------

def fetch_stats(roll_no, password):
    session = requests.Session()

    # ---- LOGIN ----
    student_id, login_error = login(session, roll_no, password)
    if login_error:
        return {"ok": False, "stage": "login", "error": login_error}

    logging.info(f"Login successful for {roll_no}")

    # ---- USER PROFILE ----
    user_resp = session.get(
        f"{BASE_URL}/node/api/get-user-by-id/{student_id}",
        timeout=REQUEST_TIMEOUT,
        verify=VERIFY_SSL
    )

    user_data = safe_json(user_resp)
    if not user_data or "current_program" not in user_data:
        return {"ok": False, "stage": "profile", "error": "Failed to fetch profile"}

    batch_id = user_data["current_program"][0]["batch"]

    # ---- BATCH RANKS ----
    batch_resp = session.post(
        f"{BASE_URL}/node/api/get-batch-ranks",
        json={"roll_no": roll_no, "batch": batch_id},
        timeout=REQUEST_TIMEOUT,
        verify=VERIFY_SSL
    )

    batch_data = safe_json(batch_resp)
    if not batch_data or "current_user" not in batch_data:
        return {"ok": False, "stage": "batch_ranks", "error": "Batch data missing"}

    current_user = batch_data["current_user"][0]

    easy = current_user["problems_count"]["easy"]
    medium = current_user["problems_count"]["medium"]
    hard = current_user["problems_count"]["hard"]
    score = current_user["score"]
    rank = current_user["rank"]
    total = easy + medium + hard

    # ---- LANGUAGE STATS ----
    lang_resp = session.post(
        f"{BASE_URL}/node/api/get-student-problems-count",
        json={"roll_no": roll_no},
        timeout=REQUEST_TIMEOUT,
        verify=VERIFY_SSL
    )

    lang_data = safe_json(lang_resp)
    programming_languages = lang_data.get("programmingLanguages", {}) if lang_data else {}

    # ---- DAILY STATS ----
    daily_resp = session.post(
        f"{BASE_URL}/node/api/get-student-every-day-problems-count",
        json={"roll_no": roll_no},
        timeout=REQUEST_TIMEOUT,
        verify=VERIFY_SSL
    )

    daily_data = safe_json(daily_resp)
    formatted_counts = daily_data.get("formattedCounts", []) if daily_data else []

    current_streak = calculate_current_streak(formatted_counts)

    return {
        "ok": True,
        "result": {
            "easy": easy,
            "medium": medium,
            "hard": hard,
            "total": total,
            "score": score,
            "rank": rank,
            "programmingLanguages": programming_languages,
            "current_streak": current_streak
        }
    }

# -----------------------------
# Routes
# -----------------------------

@app.route("/")
def root():
    return jsonify({"status": "Maya API running"})

@app.route("/api/health")
def health():
    return jsonify({"status": "healthy"})

@app.route("/api/scrape", methods=["POST"])
def scrape():
    data = request.get_json()

    if not data:
        return jsonify({"ok": False, "error": "Invalid JSON"}), 400

    roll_no = data.get("roll_no")
    password = data.get("password")

    if not roll_no or not password:
        return jsonify({"ok": False, "error": "Missing credentials"}), 400

    result = fetch_stats(roll_no, password)

    if not result["ok"]:
        return jsonify(result), 500

    return jsonify(result)

# -----------------------------
# Run
# -----------------------------

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
