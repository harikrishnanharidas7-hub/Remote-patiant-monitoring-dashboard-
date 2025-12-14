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

# =========================================================
#  CONFIGURATION
# =========================================================
app = Flask(__name__)
app.secret_key = "super_secret_key_change_this"  
SENSOR_BUFFER = deque(maxlen=50)

# STATE FLAGS
LAST_FALL_TIME = 0
FALL_DETECTED_FLAG = False

# FIREBASE INIT
if not firebase_admin._apps:
    cred = credentials.Certificate("fire_base_key.json")
    firebase_admin.initialize_app(cred)
db = firestore.client()

# FITBIT CONFIG
CLIENT_ID = "23TQWX"
CLIENT_SECRET = "eb1cd2cf1c005a0a631a971722211f49" 
TOKEN_URL = "https://api.fitbit.com/oauth2/token"
TOKEN_FILE = "fitbit_token.json"

# EMAIL CONFIGURATION
EMAIL_SENDER = "harikrishnanharidas7@gmail.com"  
EMAIL_PASSWORD = "rufe akup sfvf vspe "             #  PASTE 16-CHAR APP PASSWORD
EMAIL_RECEIVER = "harikrishnanharidas7@gmail.com"
DAILY_GOAL = 5000

# =========================================================
# EMAIL & FALL LOGIC
# =========================================================
def send_email(subject, body_content):
    try:
        msg = MIMEMultipart()
        msg['From'] = EMAIL_SENDER
        msg['To'] = EMAIL_RECEIVER
        msg['Subject'] = subject
        msg.attach(MIMEText(f"<html><body>{body_content}</body></html>", 'html'))

        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(EMAIL_SENDER, EMAIL_PASSWORD)
        server.sendmail(EMAIL_SENDER, EMAIL_RECEIVER, msg.as_string())
        server.quit()
        print(f"📧 Email sent: {subject}")
        return True
    except Exception as e:
        print(f"❌ Email Failed: {e}")
        return False

def check_fall_logic(x):
    global LAST_FALL_TIME, FALL_DETECTED_FLAG
    if x > 9 or x < -9:
        current_time = time.time()
        if current_time - LAST_FALL_TIME > 60:
            print(f"⚠️ FALL DETECTED! X: {x}")
            FALL_DETECTED_FLAG = True
            LAST_FALL_TIME = current_time
            send_email("🚨 FALL DETECTED!", f"<h2>⚠️ Emergency Alert</h2><p>Sensor X-Axis: {x}</p>")

# =========================================================
# 🔄 FITBIT ENGINE
# =========================================================
def save_token(token):
    if "expires_at" not in token and "expires_in" in token:
        token["expires_at"] = int(datetime.datetime.now().timestamp() + int(token.get("expires_in", 0)))
    with open(TOKEN_FILE, "w") as f: json.dump(token, f, indent=4)
    db.collection("fitbit_tokens").document("user1").set(token)

def load_token():
    if os.path.exists(TOKEN_FILE):
        try:
            with open(TOKEN_FILE, "r") as f:
                return json.load(f)
        except: pass
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
    
    # --- UPDATED: FETCH CALORIES DIRECTLY ---
    # Fitbit returns "caloriesOut" which includes BMR + Activity
    calories = data.get("caloriesOut", 0) 
    
    distance = 0
    for d in data.get("distances", []):
        if d["activity"] == "total": distance = d["distance"]

    # Goal Email Logic
    doc_ref = db.collection("todays_data").document("latest")
    current_doc = doc_ref.get()
    email_sent = False
    if current_doc.exists and current_doc.to_dict().get("date") == today_str:
        email_sent = current_doc.to_dict().get("email_sent", False)

    if steps >= DAILY_GOAL and not email_sent:
        print(f"🎯 Goal reached!")
        if send_email("🏆 Goal Reached!", f"You hit {steps} steps and burned {calories} calories!"):
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

    # Convert to dictionary for easy merging: { "2023-10-01": {"steps": 5000, "calories": 2000} }
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
    try: sync_history_data() 
    except: pass
    while True:
        try: get_today_activity() 
        except: pass
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

# --- 2. DATA HELPERS ---
def get_dashboard_data():
    today_doc = db.collection("todays_data").document("latest").get()
    today = today_doc.to_dict() if today_doc.exists else {"steps": 0, "calories": 0, "distance": 0, "goal_reached": False}
    
    # Fix: Use .get() instead of .stream() for limited queries
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
    data = request.json
    x = data.get("x", 0)
    check_fall_logic(x)
    SENSOR_BUFFER.append({"time": datetime.datetime.now().strftime("%H:%M:%S"), "x": x, "y": data.get("y"), "z": data.get("z")})
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
    if CLIENT_ID == "YOUR_CLIENT_ID_HERE":
        print("❌ ERROR: Please update your Fitbit Client ID.")
    else:
        t = threading.Thread(target=background_worker, daemon=True)
        t.start()
        ip = get_local_ip()
        print(f"\n🌍 DASHBOARD: http://{ip}:5000")
        app.run(host="0.0.0.0", debug=True, use_reloader=False, port=5000)
