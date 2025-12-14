import threading
import time
import os
import json
import base64
import datetime
import requests
import socket
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from collections import deque
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash

import firebase_admin
from firebase_admin import credentials, firestore
import ssl

# =========================================================
# ⚙️ CONFIGURATION
# =========================================================
app = Flask(__name__)
# IMPORTANT: In a production environment like Render, SECRET_KEY should be an env variable.
app.secret_key = os.environ.get("SECRET_KEY", "super_secret_key_change_this")
SENSOR_BUFFER = deque(maxlen=50)

# STATE FLAGS
LAST_FALL_TIME = 0
FALL_DETECTED_FLAG = False
FALL_COOLDOWN_SECONDS = 60 # Cooldown period

# FIREBASE INIT
if not firebase_admin._apps:
    # Use the environment variable for security on Render
    try:
        # Load credentials from environment variable for secure deployment
        firebase_json_creds = os.environ.get("FIREBASE_CREDENTIALS")
        if firebase_json_creds:
            cred_dict = json.loads(firebase_json_creds)
            cred = credentials.Certificate(cred_dict)
            firebase_admin.initialize_app(cred)
            print("✅ Firebase initialized securely.")
        elif os.path.exists("fire_base_key.json"):
            # Fallback for local development
            cred = credentials.Certificate("fire_base_key.json")
            firebase_admin.initialize_app(cred)
            print("✅ Firebase initialized from local file.")
        else:
            print("❌ FIREBASE_CREDENTIALS or fire_base_key.json not found.")

    except Exception as e:
        print(f"❌ Firebase initialization failed: {e}")

# Check if initialization was successful before getting client
db = firestore.client() if firebase_admin._apps else None
if not db:
    print("WARNING: Firestore client could not be initialized.")


# FITBIT CONFIG
CLIENT_ID = os.environ.get("FITBIT_CLIENT_ID", "23TLXD")
CLIENT_SECRET = os.environ.get("FITBIT_CLIENT_SECRET", "ed74b777cdd2af88ec45df1624251ae9")
TOKEN_URL = "https://api.fitbit.com/oauth2/token"
TOKEN_FILE = "fitbit_token.json"

# EMAIL CONFIGURATION (Read from environment variables for security)
EMAIL_SENDER = os.environ.get("EMAIL_SENDER", "harikrishnanharidas7@gmail.com")
EMAIL_PASSWORD = os.environ.get("EMAIL_PASSWORD", "rufe akup sfvf vspe ") # PASTE 16-CHAR APP PASSWORD
EMAIL_RECEIVER = os.environ.get("EMAIL_RECEIVER", "harikrishnanharidas7@gmail.com")
DAILY_GOAL = int(os.environ.get("DAILY_GOAL", 5000))

# =========================================================
# 📧 EMAIL & FALL LOGIC (Non-Blocking)
# =========================================================
def send_email_blocking(subject, body_content):
    """
    The actual email sending function (runs in a separate thread).
    Uses port 465 (SSL) for better compatibility on cloud platforms.
    """
    if not EMAIL_SENDER or not EMAIL_PASSWORD or not EMAIL_RECEIVER:
        print("❌ Email credentials missing. Cannot send email.")
        return False
        
    try:
        msg = MIMEMultipart()
        msg['From'] = EMAIL_SENDER
        msg['To'] = EMAIL_RECEIVER
        msg['Subject'] = subject
        msg.attach(MIMEText(f"<html><body>{body_content}</body></html>", 'html'))

        context = ssl.create_default_context()
        
        # CRITICAL CHANGE: Use SMTP_SSL on port 465
        with smtplib.SMTP_SSL('smtp.gmail.com', 465, context=context) as server:
            server.login(EMAIL_SENDER, EMAIL_PASSWORD)
            server.sendmail(EMAIL_SENDER, EMAIL_RECEIVER, msg.as_string())
        
        print(f"📧 Email sent: {subject}")
        return True
    except Exception as e:
        print(f"❌ Email Failed: {e}")
        return False

def non_blocking_email(subject, body_content):
    """Launches the email sending in a separate thread."""
    email_thread = threading.Thread(
        target=send_email_blocking,
        args=(subject, body_content)
    )
    email_thread.start()
    print("📧 Email task launched in background thread.")

def check_fall_logic(x):
    """
    Checks for a fall event. Triggers the non-blocking email if detected.
    """
    global LAST_FALL_TIME, FALL_DETECTED_FLAG
    
    # Simple threshold check for fall: acceleration magnitude > 9.0 (m/s^2)
    if abs(x) > 9.0:
        current_time = time.time()
        
        # Check if the cooldown period has passed
        if current_time - LAST_FALL_TIME > FALL_COOLDOWN_SECONDS:
            print(f"⚠️ FALL DETECTED! X: {x} (Alerting)")
            FALL_DETECTED_FLAG = True
            LAST_FALL_TIME = current_time
            
            # --- CRITICAL CHANGE: Use non-blocking email sender ---
            non_blocking_email(
                "🚨 FALL DETECTED!", 
                f"<h2>⚠️ Emergency Alert</h2><p>A sudden acceleration change was detected.</p><p>Sensor X-Axis: {x}</p><p>Please check on the individual immediately.</p>"
            )
        else:
            print(f"⚠️ Fall detected, but still in cooldown period.")

# =========================================================
# 🔄 FITBIT ENGINE (Background worker uses the blocking email sender)
# =========================================================
# NOTE: The Fitbit functions (save_token, load_token, refresh_access_token, get_session, fitbit_get, get_today_activity, sync_history_data) 
# remain largely the same, but they are safe because they are run inside the dedicated 'background_worker' thread, which is allowed to block.

def save_token(token):
    if "expires_at" not in token and "expires_in" in token:
        token["expires_at"] = int(datetime.datetime.now().timestamp() + int(token.get("expires_in", 0)))
    with open(TOKEN_FILE, "w") as f: json.dump(token, f, indent=4)
    if db: db.collection("fitbit_tokens").document("user1").set(token)

def load_token():
    if os.path.exists(TOKEN_FILE):
        try:
            with open(TOKEN_FILE, "r") as f:
                return json.load(f)
        except: pass
    if db:
        doc = db.collection("fitbit_tokens").document("user1").get()
        if doc.exists: return doc.to_dict()
    return None

def refresh_access_token(refresh_token):
    auth_header = base64.b64encode(f"{CLIENT_ID}:{CLIENT_SECRET}".encode()).decode()
    r = requests.post(TOKEN_URL, headers={
        "Authorization": f"Basic {auth_header}", "Content-Type": "application/x-www-form-urlencoded"
    }, data={"grant_type": "refresh_token", "refresh_token": refresh_token})
    if r.status_code != 200: return None
    token = r.json()
    save_token(token)
    return token

def get_session():
    token = load_token()
    if not token: return None
    if datetime.datetime.now().timestamp() > token.get("expires_at", 0):
        return refresh_access_token(token.get("refresh_token"))
    return token

def fitbit_get(url):
    token = get_session()
    if not token: return None
    headers = {"Authorization": f"Bearer {token['access_token']}"}
    r = requests.get(url, headers=headers)
    if r.status_code == 401:
        token = refresh_access_token(token.get("refresh_token"))
        if token:
            headers = {"Authorization": f"Bearer {token['access_token']}"}
            return requests.get(url, headers=headers)
    return r

def get_today_activity():
    today_str = datetime.date.today().strftime("%Y-%m-%d")
    print(f"\n⚡ [Background] Fetching Data ({today_str})...")
    url = f"https://api.fitbit.com/1/user/-/activities/date/{today_str}.json"
    r = fitbit_get(url)
    if not r or r.status_code != 200: return

    data = r.json().get("summary", {})
    steps = data.get("steps", 0)
    calories = data.get("caloriesOut", 0)
    
    distance = 0
    for d in data.get("distances", []):
        if d["activity"] == "total": distance = d["distance"]

    # Goal Email Logic (This is in the background thread, so it can be blocking)
    doc_ref = db.collection("todays_data").document("latest")
    current_doc = doc_ref.get()
    email_sent = False
    if current_doc.exists and current_doc.to_dict().get("date") == today_str:
        email_sent = current_doc.to_dict().get("email_sent", False)

    if steps >= DAILY_GOAL and not email_sent:
        print(f"🎯 Goal reached!")
        # This send_email_blocking is okay here because it's in the background worker thread.
        if send_email_blocking("🏆 Goal Reached!", f"You hit {steps} steps and burned {calories} calories!"):
            email_sent = True

    payload = {
        "steps": steps, "calories": calories, "distance": distance,
        "date": today_str, "last_updated": datetime.datetime.now().strftime("%H:%M:%S"),
        "email_sent": email_sent, "goal_reached": (steps >= DAILY_GOAL)
    }
    db.collection("todays_data").document("latest").set(payload)
    db.collection("fitbit_daily").document(today_str).set(payload)
    print(f"✅ Updated: {steps} steps | {calories} kcal")

def sync_history_data():
    today = datetime.date.today()
    start = today - datetime.timedelta(days=60)
    str_today, str_start = today.strftime("%Y-%m-%d"), start.strftime("%Y-%m-%d")
    
    print("📥 Syncing History (Steps & Calories)...")

    # 1. Fetch Steps History
    url_steps = f"https://api.fitbit.com/1/user/-/activities/steps/date/{str_start}/{str_today}.json"
    r_steps = fitbit_get(url_steps)
    
    # 2. Fetch Calories History
    url_cals = f"https://api.fitbit.com/1/user/-/activities/calories/date/{str_start}/{str_today}.json"
    r_cals = fitbit_get(url_cals)

    if not r_steps or r_steps.status_code != 200 or not r_cals or r_cals.status_code != 200:
        print("❌ History sync failed")
        return

    steps_list = r_steps.json().get("activities-steps", [])
    cals_list = r_cals.json().get("activities-calories", [])

    history_map = {}
    
    for item in steps_list:
        d = item["dateTime"]
        history_map[d] = {"steps": int(item["value"]), "calories": 0}
        
    for item in cals_list:
        d = item["dateTime"]
        if d in history_map:
            history_map[d]["calories"] = int(item["value"])

    # Batch save to Firestore
    batch = db.batch()
    count = 0
    for date_str, data in history_map.items():
        doc_ref = db.collection("fitbit_daily").document(date_str)
        batch.set(doc_ref, {"date": date_str, "steps": data["steps"], "calories": data["calories"]}, merge=True)
        count += 1
        if count >= 400:
            batch.commit()
            batch = db.batch()
            count = 0
    batch.commit()
    print("✅ History Synced Successfully")

def background_worker():
    if not db:
        print("Background worker cannot run without a valid Firestore connection.")
        return
        
    try: sync_history_data() 
    except Exception as e: print(f"❌ Initial history sync failed: {e}")
    
    while True:
        try: get_today_activity() 
        except Exception as e: print(f"❌ Background activity fetch failed: {e}")
        time.sleep(60)

# =========================================================
# 🌐 FLASK ROUTES
# =========================================================

# --- 1. LOGIN & REGISTER SYSTEM ---
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        
        users_ref = db.collection("users").where("username", "==", username).stream()
        user_found = False
        for user in users_ref:
            if user.to_dict().get("password") == password:
                user_found = True
                break
        
        if user_found:
            session['user'] = username
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid Username or Password!", "error")
            
    return render_template("login.html")

@app.route("/register", methods=["POST"])
def register():
    username = request.form.get("username")
    password = request.form.get("password")
    existing = db.collection("users").where("username", "==", username).get()
    if len(existing) > 0:
        flash("⚠️ Username taken!", "error")
        return redirect(url_for('login'))
    db.collection("users").add({"username": username, "password": password})
    flash("✅ Account created!", "success")
    return redirect(url_for('login'))

@app.route("/logout")
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))

# --- 2. DATA HELPERS & VIEWS ---
def get_dashboard_data():
    today_doc = db.collection("todays_data").document("latest").get()
    today = today_doc.to_dict() if today_doc.exists else {"steps": 0, "calories": 0, "distance": 0, "goal_reached": False}
    
    docs = db.collection("fitbit_daily").order_by("date").limit_to_last(30).get()
    all_data = [d.to_dict() for d in docs]
    
    labels = [d['date'] for d in all_data]
    steps_data = [d['steps'] for d in all_data]
    
    weekly_raw = all_data[-7:]
    weekly_labels = [d['date'] for d in weekly_raw]
    weekly_data = [d['steps'] for d in weekly_raw]

    return today, labels, steps_data, weekly_labels, weekly_data

@app.route("/")
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))
        
    if not db:
        flash("CRITICAL ERROR: Database connection failed.", "error")
        return render_template("dashboard.html", today={"steps": 0}, fall_detected=False)
        
    today, m_labels, m_steps, w_labels, w_steps = get_dashboard_data()
    
    return render_template(
        "dashboard.html",
        today=today,
        fall_detected=FALL_DETECTED_FLAG,
        email_receiver=EMAIL_RECEIVER,
        month_labels=m_labels,
        month_steps=m_steps,
        week_labels=w_labels,
        week_steps=w_steps
    )

@app.route("/reset_fall")
def reset_fall():
    global FALL_DETECTED_FLAG
    FALL_DETECTED_FLAG = False
    return jsonify({"status": "cleared"})

@app.route("/acceleration")
def acceleration_page(): return render_template("acceleration.html")

@app.route("/sender")
def sender_page(): return render_template("sender.html")

@app.route("/api/record_acceleration", methods=["POST"])
def record_acceleration():
    """
    This endpoint is now non-blocking because check_fall_logic triggers a 
    separate thread for the email.
    """
    data = request.json
    x = data.get("x", 0)
    
    # 1. Fall detection (fast, in main thread)
    check_fall_logic(x)
    
    # 2. Buffer update (fast, in main thread)
    SENSOR_BUFFER.append({
        "time": datetime.datetime.now().strftime("%H:%M:%S"), 
        "x": x, 
        "y": data.get("y"), 
        "z": data.get("z")
    })
    
    # 3. Respond immediately (prevents timeout)
    return jsonify({"status": "success"})

@app.route("/api/get_acceleration")
def get_acceleration(): return jsonify({"sensor_data": list(SENSOR_BUFFER), "alert": FALL_DETECTED_FLAG})

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except: return "127.0.0.1"

if __name__ == "__main__":
    if CLIENT_ID == "23TLXD":
        print("❌ ERROR: Please update your Fitbit Client ID.")
    else:
        # Start the dedicated background thread for Fitbit sync
        t = threading.Thread(target=background_worker, daemon=True)
        t.start()
        
        ip = get_local_ip()
        print(f"\n🌍 DASHBOARD: http://{ip}:5000")
        # Ensure use_reloader=False when using threading for background workers
        app.run(host="0.0.0.0", debug=True, use_reloader=False, port=5000)
