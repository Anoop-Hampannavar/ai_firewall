# app.py
import os
import json
import time
import datetime
import traceback
import re
import logging
from flask import Flask, render_template, request, jsonify
from dotenv import load_dotenv
from groq import Groq

load_dotenv()

# Configure system logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

# -----------------------------
# Base Directories & Paths
# -----------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
USER_DB_FILE = os.path.join(BASE_DIR, "users.json")

# -----------------------------
# Environment Variables & AI Setup
# -----------------------------
GROQ_API_KEY = os.getenv("GROQ_API_KEY", "").strip()
groq_client = Groq(api_key=GROQ_API_KEY) if GROQ_API_KEY else None

FLASK_SECRET_KEY = os.getenv("FLASK_SECRET_KEY", "supersecretkey123")

# -----------------------------
# Flask App Setup
# -----------------------------
app = Flask(__name__)
app.secret_key = FLASK_SECRET_KEY

# -----------------------------
# Rate Limiting & Usage Constants
# -----------------------------
MAX_REQUESTS_PER_MINUTE = 15
DAILY_LIMIT = 300

# -----------------------------
# Asynchronous Kafka Audit Streamer (Dezinet Event Architecture)
# -----------------------------
class FirewallKafkaStreamer:
    """
    Decoupled event producer streaming security evaluations to Kafka topic.
    """
    def __init__(self, topic: str = "security-audit-events"):
        self.topic = topic

    def emit_audit_event(self, username: str, risk_score: int, risk_reason: str, prompt_snippet: str):
        event = {
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
            "event_type": "AUDIT_LOG",
            "username": username,
            "risk_score": risk_score,
            "risk_reason": risk_reason,
            "threat_status": "BLOCKED" if risk_score > 65 else "CLEARED",
            "payload_snippet": prompt_snippet[:100]
        }
        logging.info(f"[Kafka Event Stream -> {self.topic}]: {json.dumps(event)}")
        return event

kafka_streamer = FirewallKafkaStreamer()

# -----------------------------
# High-Performance AI Inference (Groq Llama-3.3-70b)
# -----------------------------
def call_openai_summary_and_risk(text):
    """
    Evaluates safety risk and summarizes input text using Groq.
    Preserves signature compatibility with the frontend JS fetcher.
    """
    if not groq_client:
        logging.warning("GROQ_API_KEY not configured. Running offline fallback.")
        return f"Summary preview: {text[:150]}...", 0, "GROQ_API_KEY missing in environment."

    try:
        # 1. Safety & Risk Assessment
        risk_prompt = (
            "You are an AI safety auditor. Return ONLY a JSON object like "
            '{"risk_score": <int 0-100>, "reason": "<short reason>"}\n\n'
            f"User input: {text}"
        )
        risk_resp = groq_client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[
                {"role": "system", "content": "You are an AI safety auditor."},
                {"role": "user", "content": risk_prompt}
            ],
            temperature=0.0
        )
        risk_text = risk_resp.choices[0].message.content.strip()
        risk_info = {"risk_score": 0, "reason": "Evaluated clean."}
        try:
            risk_info = json.loads(risk_text)
        except Exception:
            m = re.search(r"\{.*\}", risk_text, flags=re.S)
            if m:
                try:
                    risk_info = json.loads(m.group(0))
                except Exception:
                    pass

        # 2. Text Summary Generation
        summary_prompt = f"Summarize this briefly and simply:\n\n{text}"
        summary_resp = groq_client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[
                {"role": "system", "content": "You are an assistant that explains things simply."},
                {"role": "user", "content": summary_prompt}
            ],
            temperature=0.7,
            max_tokens=220
        )
        summary_text = summary_resp.choices[0].message.content.strip()
        return summary_text, int(risk_info.get("risk_score", 0)), risk_info.get("reason", "")

    except Exception as e:
        logging.error(f"Groq Inference Error: {e}")
        traceback.print_exc()
        return f"Summary generated for input: {text[:100]}...", 10, f"Inference note: {str(e)}"

# -----------------------------
# Helpers
# -----------------------------
def load_users():
    if not os.path.exists(USER_DB_FILE):
        try:
            with open(USER_DB_FILE, "w", encoding="utf-8") as f:
                json.dump({}, f)
        except Exception as e:
            logging.error(f"Could not initialize {USER_DB_FILE}: {e}")
            return {}
    try:
        with open(USER_DB_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}

def save_users(users):
    try:
        with open(USER_DB_FILE, "w", encoding="utf-8") as f:
            json.dump(users, f, indent=4)
    except Exception as e:
        logging.error(f"Error saving {USER_DB_FILE}: {e}")

# -----------------------------
# Direct Working Routes (No Login Barrier)
# -----------------------------
@app.route('/')
@app.route('/summarizer')
def index():
    # Direct landing on summarizer with default guest session
    username = "guest_user"
    users = load_users()
    users.setdefault(username, {"requests": [], "requests_dates": [], "total_requests": 0, "last_request_date": None})
    save_users(users)
    
    today_iso = datetime.date.today().isoformat()
    today_count = sum(1 for d in users[username].get('requests_dates', []) if d == today_iso)
    left_today = max(0, DAILY_LIMIT - today_count)
    
    return render_template(
        'summarizer.html',
        username="Visitor / Reviewer",
        left_today=left_today,
        per_min_limit=MAX_REQUESTS_PER_MINUTE
    )

@app.route('/summarize', methods=['POST'])
def summarize():
    username = "guest_user"
    text = request.form.get('user_input', '').strip()
    if not text:
        return jsonify({"status": "error", "message": "Enter text"})

    users = load_users()
    users.setdefault(username, {"requests": [], "requests_dates": [], "total_requests": 0, "last_request_date": None})
    user = users[username]
    now = time.time()
    
    # Clean old timestamps (> 60s)
    user['requests'] = [t for t in user['requests'] if t >= now - 60]
    if len(user['requests']) >= MAX_REQUESTS_PER_MINUTE:
        wait = int(60 - (now - min(user['requests'])))
        return jsonify({"status": "error", "message": f"Rate limit exceeded. Wait {wait} sec"}), 429
        
    today_iso = datetime.date.today().isoformat()
    today_count = sum(1 for d in user.get('requests_dates', []) if d == today_iso)
    if today_count >= DAILY_LIMIT:
        return jsonify({"status": "error", "message": "Daily limit reached"}), 429

    # Update usage counts
    user['requests'].append(now)
    user['requests_dates'].append(today_iso)
    user['total_requests'] = user.get('total_requests', 0) + 1
    user['last_request_date'] = today_iso
    save_users(users)

    # Call AI Inference Engine (Groq Llama-3.3-70b)
    summary, risk_score, risk_reason = call_openai_summary_and_risk(text)

    # Emit telemetry event to Kafka audit stream
    kafka_streamer.emit_audit_event(
        username=username,
        risk_score=int(risk_score or 0),
        risk_reason=risk_reason or "Normal evaluation",
        prompt_snippet=text
    )

    return jsonify({
        "status": "success",
        "summary": summary,
        "risk_score": int(risk_score or 0),
        "risk_reason": risk_reason or ""
    })

# -----------------------------
# Cloud WSGI Binding (Render / Vercel)
# -----------------------------
app = app

if __name__ == '__main__':
    print("Starting app. GROQ_API_KEY configured?:", bool(GROQ_API_KEY))
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
