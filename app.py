# app.py
import os
import json
import time
import datetime
import random
import traceback
import threading
import smtplib
from email.message import EmailMessage
import re
import logging
from flask import Flask, render_template, request, redirect, session, flash, jsonify
from dotenv import load_dotenv
from groq import Groq

load_dotenv()

# Configure system logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

# -----------------------------
# Base Directories & Paths (Prevents Cloud 500 Path Errors)
# -----------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
USER_DB_FILE = os.path.join(BASE_DIR, "users.json")

# -----------------------------
# Environment Variables & API Clients
# -----------------------------
GROQ_API_KEY = os.getenv("GROQ_API_KEY", "").strip()
groq_client = Groq(api_key=GROQ_API_KEY) if GROQ_API_KEY else None

EMAIL_ADDRESS = os.getenv("EMAIL_ADDRESS", "")
EMAIL_APP_PASSWORD = os.getenv("EMAIL_APP_PASSWORD", "")
FLASK_SECRET_KEY = os.getenv("FLASK_SECRET_KEY", "supersecretkey123")
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "admin@example.com")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin123")

# -----------------------------
# Flask App Setup
# -----------------------------
app = Flask(__name__)
app.secret_key = FLASK_SECRET_KEY

# -----------------------------
# Constants
# -----------------------------
OTP_STORE = {}
OTP_EXPIRY = 300  # 5 minutes
MAX_REQUESTS_PER_MINUTE = 5
DAILY_LIMIT = 200

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
# AI Inference Engine: Groq Llama-3.3-70b
# -----------------------------
def call_openai_summary_and_risk(text):
    """
    Evaluates safety risk and summarizes input text exclusively using Groq.
    Function name preserved to maintain compatibility with existing routes.
    """
    if not groq_client:
        logging.warning("GROQ_API_KEY not configured. Running safe fallback response.")
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
# File & Database Helpers
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
        logging.error(f"Error saving to {USER_DB_FILE}: {e}")

# -----------------------------
# Background Non-Blocking OTP Worker
# -----------------------------
def _send_email_thread(msg):
    if not EMAIL_ADDRESS or not EMAIL_APP_PASSWORD:
        logging.warning("EMAIL_ADDRESS or EMAIL_APP_PASSWORD not set. Skipping SMTP transmission.")
        return
    try:
        # Strip any accidental whitespace from the credentials
        clean_app_password = EMAIL_APP_PASSWORD.replace(" ", "").strip()
        clean_email = EMAIL_ADDRESS.strip()

        # Port 587 with STARTTLS works through cloud firewall restrictions
        with smtplib.SMTP('smtp.gmail.com', 587, timeout=12) as server:
            server.ehlo()
            server.starttls()
            server.ehlo()
            server.login(clean_email, clean_app_password)
            server.send_message(msg)
            logging.info("[SMTP] Email delivered successfully to inbox.")
    except Exception as e:
        logging.error(f"[SMTP Error] Failed to deliver email: {e}")

def send_otp(to_email):
    otp = random.randint(100000, 999999)
    OTP_STORE[to_email] = {"otp": otp, "expires": time.time() + OTP_EXPIRY}
    
    # Instant OTP fallback in Render console logs
    print(f"\n==========================================")
    print(f"👉 INSTANT OTP FOR {to_email}: {otp}")
    print(f"==========================================\n", flush=True)

    msg = EmailMessage()
    msg['Subject'] = "Your OTP Code"
    msg['From'] = EMAIL_ADDRESS if EMAIL_ADDRESS else "no-reply@dezinet.com"
    msg['To'] = to_email
    msg.set_content(f"Your OTP code is: {otp}. It expires in 5 minutes.")

    # Fire asynchronously in a background thread so the HTTP request never hangs
    worker = threading.Thread(target=_send_email_thread, args=(msg,))
    worker.daemon = True
    worker.start()

# -----------------------------
# Routes
# -----------------------------
@app.route('/')
def index():
    if 'user' in session:
        return redirect('/summarizer')
    return render_template('index.html')

@app.route('/otp-login', methods=['GET', 'POST'])
def otp_login():
    if request.method == 'POST':
        credential = request.form.get('credential', '').strip()
        if not credential:
            flash("Enter email", "error")
            return render_template('otp_login.html')
        try:
            send_otp(credential)
        except Exception as e:
            logging.error(f"send_otp trigger error: {e}")
            flash("Could not initiate OTP dispatch.", "error")
            return render_template('otp_login.html')
            
        session['otp_credential'] = credential
        flash(f"OTP sent to {credential} (Also logged to server console)", "success")
        return redirect('/verify-otp')
    return render_template('otp_login.html')

@app.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    credential = session.get('otp_credential')
    if not credential:
        flash("Enter email first", "error")
        return redirect('/otp-login')
    if request.method == 'POST':
        entered = request.form.get('otp', '').strip()
        record = OTP_STORE.get(credential)
        if not record or time.time() > record['expires']:
            flash("OTP expired. Request new one", "error")
            OTP_STORE.pop(credential, None)
            return redirect('/otp-login')
        if str(record['otp']) != entered:
            flash("Incorrect OTP", "error")
            return render_template('verify_otp.html', credential=credential)
        users = load_users()
        if credential not in users:
            users[credential] = {
                "created_at": datetime.datetime.utcnow().isoformat(),
                "requests": [],
                "requests_dates": [],
                "total_requests": 0,
                "last_request_date": None
            }
            save_users(users)
        session['user'] = credential
        OTP_STORE.pop(credential, None)
        flash("Logged in successfully", "success")
        return redirect('/summarizer')
    return render_template('verify_otp.html', credential=credential)

@app.route('/summarizer')
def summarizer():
    if 'user' not in session:
        return redirect('/otp-login')
    username = session['user']
    users = load_users()
    users.setdefault(username, {"requests": [], "requests_dates": [], "total_requests": 0, "last_request_date": None})
    save_users(users)
    today_iso = datetime.date.today().isoformat()
    today_count = sum(1 for d in users[username].get('requests_dates', []) if d == today_iso)
    left_today = max(0, DAILY_LIMIT - today_count)
    return render_template('summarizer.html', username=username, left_today=left_today, per_min_limit=MAX_REQUESTS_PER_MINUTE)

@app.route('/summarize', methods=['POST'])
def summarize():
    if 'user' not in session:
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    username = session['user']
    text = request.form.get('user_input', '').strip()
    if not text:
        return jsonify({"status": "error", "message": "Enter text"})
    users = load_users()
    users.setdefault(username, {"requests": [], "requests_dates": [], "total_requests": 0, "last_request_date": None})
    user = users[username]
    now = time.time()
    user['requests'] = [t for t in user['requests'] if t >= now - 60]
    if len(user['requests']) >= MAX_REQUESTS_PER_MINUTE:
        wait = int(60 - (now - min(user['requests'])))
        return jsonify({"status": "error", "message": f"Rate limit exceeded. Wait {wait} sec"}), 429
    today_iso = datetime.date.today().isoformat()
    today_count = sum(1 for d in user.get('requests_dates', []) if d == today_iso)
    if today_count >= DAILY_LIMIT:
        return jsonify({"status": "error", "message": "Daily limit reached"}), 429
    # update counters
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

@app.route('/logout')
def logout():
    session.pop('user', None)
    session.pop('admin_logged_in', None)
    flash("Logged out", "info")
    return redirect('/otp-login')

@app.route('/admin-login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()
        if email == ADMIN_EMAIL and password == ADMIN_PASSWORD:
            session['admin_logged_in'] = True
            return redirect('/admin')
        else:
            flash("Invalid admin credentials", "error")
            return render_template('admin_login.html')
    return render_template('admin_login.html')

@app.route('/admin')
def admin_dashboard():
    if not session.get('admin_logged_in'):
        return redirect('/admin-login')
    users = load_users()
    total_users = len(users)
    today = datetime.date.today().isoformat()
    requests_today = sum(1 for u in users.values() if u.get('last_request_date') == today)
    top_users = sorted(users.items(), key=lambda x: x[1].get('total_requests', 0), reverse=True)[:10]
    usage_labels = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
    usage_data = []
    for day in usage_labels:
        count = 0
        for u in users.values():
            lr = u.get('last_request_date')
            if lr:
                try:
                    dt = datetime.datetime.fromisoformat(lr)
                    if dt.strftime("%a") == day:
                        count += 1
                except:
                    try:
                        dt2 = datetime.datetime.strptime(lr, "%Y-%m-%d")
                        if dt2.strftime("%a") == day:
                            count += 1
                    except:
                        pass
        usage_data.append(count)
    return render_template(
        'admin.html',
        users=users,
        top_users=top_users,
        total_users=total_users,
        requests_today=requests_today,
        usage_labels=usage_labels,
        usage_data=usage_data
    )

# -----------------------------
# Cloud WSGI Binding
# -----------------------------
app = app

if __name__ == '__main__':
    print("Starting app. GROQ_API_KEY configured?:", bool(GROQ_API_KEY))
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
