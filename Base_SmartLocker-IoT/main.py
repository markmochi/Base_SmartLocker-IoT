
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
import sqlite3
import math
import os
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
import re

# ==============================
# CONFIGURATION
# ==============================
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'pt7_secure_secret_key_change_in_production')

# Session security configuration
app.config['SESSION_COOKIE_SECURE'] = False  
app.config['SESSION_COOKIE_HTTPONLY'] = True 
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=2)  


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
# Always create database in the same folder as the script
DB_NAME = os.path.join(SCRIPT_DIR, "database.db")

# ==============================
# SECURITY UTILITIES
# ==============================
def validate_username(username):
    """
    Validate username format.
    - 3-50 characters
    - Alphanumeric, underscores, and hyphens only
    """
    if not username or len(username) < 3 or len(username) > 50:
        return False
    return bool(re.match(r'^[a-zA-Z0-9_-]+$', username))

def validate_password(password):
    """
    Validate password strength.
    - At least 6 characters (basic requirement)
    """
    return password and len(password) >= 6

def sanitize_string(value, max_length=255):
    """
    Sanitize and truncate string input.
    """
    if not value:
        return ""
    return str(value).strip()[:max_length]

def validate_number(value, min_val=None, max_val=None):
    """
    Validate and convert numeric input.
    Returns None if invalid.
    """
    try:
        num = float(value)
        if min_val is not None and num < min_val:
            return None
        if max_val is not None and num > max_val:
            return None
        return num
    except (ValueError, TypeError):
        return None

# ==============================
# DATABASE INITIALIZATION
# ==============================
def init_db():
    """
    Initialize the SQLite database with required tables.
    Creates tables for readings, users, and active sessions if they don't exist.
    Only creates database in the script's directory.
    """
    # Use absolute path to ensure database is created in the correct location
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    
    # Table for sensor readings linked to users
    c.execute("""CREATE TABLE IF NOT EXISTS readings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        event_time TEXT,
        status TEXT,
        touch_value INTEGER,
        count INTEGER,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )""")
    
    # Table for user accounts
    c.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )""")
    
    # Table for tracking which user is actively receiving sensor data
    c.execute("""CREATE TABLE IF NOT EXISTS active_session (
        id INTEGER PRIMARY KEY,
        user_id INTEGER,
        username TEXT,
        activated_at TEXT,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )""")
    
    # Table for environmental data (temperature and humidity)
    c.execute("""CREATE TABLE IF NOT EXISTS environmental_data (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        temperature REAL,
        humidity REAL,
        timestamp TEXT DEFAULT CURRENT_TIMESTAMP
    )""")
    
    # Table for buzzer silence state
    c.execute("""CREATE TABLE IF NOT EXISTS buzzer_silence (
        id INTEGER PRIMARY KEY,
        silenced INTEGER DEFAULT 0,
        silenced_until TEXT
    )""")
    
    # Initialize buzzer_silence table with default row
    c.execute("INSERT OR IGNORE INTO buzzer_silence (id, silenced) VALUES (1, 0)")
    
    conn.commit()
    conn.close()
    print(f"Database initialized at: {os.path.abspath(DB_NAME)}")

def get_db_conn():
    """
    Create and return a database connection with Row factory.
    
    Returns:
        sqlite3.Connection: Database connection object with row_factory set
    """
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn


# Initialize database on startup
init_db()

# ==============================
# REQUEST HANDLERS & MIDDLEWARE
# ==============================
@app.before_request
def check_session_timeout():
    """
    Check if user session has timed out.
    Validates session integrity and enforces timeout.
    """
    # Skip for static files and login/register pages
    if request.endpoint in ['static', 'login', 'register', None]:
        return
    
    # Check if user is logged in
    if "user" in session:
        # Validate session has required fields
        if "login_time" not in session or "user_id" not in session:
            session.clear()
            flash("Session expired. Please login again.", "warning")
            return redirect(url_for("login"))
        
        # Check session timeout (2 hours)
        try:
            login_time = datetime.fromisoformat(session["login_time"])
            if datetime.now() - login_time > timedelta(hours=2):
                session.clear()
                flash("Session expired due to inactivity. Please login again.", "warning")
                return redirect(url_for("login"))
        except (ValueError, TypeError):
            # Invalid login_time format
            session.clear()
            flash("Session error. Please login again.", "warning")
            return redirect(url_for("login"))

@app.after_request
def add_security_headers(response):
    """
    Add security headers to all responses.
    """
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response

# ==============================
# AUTHENTICATION ROUTES
# ==============================
@app.route("/", methods=["GET","POST"])
def login():
    """
    Handle user login.
    GET: Display login form
    POST: Validate credentials and create session
    
    Returns:
        Rendered login template or redirect to dashboard
```
    """
    if "user" in session:
        return redirect(url_for("dashboard"))
    
    error = None
    if request.method == "POST":
        username = sanitize_string(request.form.get("username", ""), max_length=50)
        password = request.form.get("password", "")
        
        if not username or not password:
            error = "Please provide both username and password"
        elif not validate_username(username):
            error = "Invalid username format"
        else:
            conn = get_db_conn()
            c = conn.cursor()
            c.execute("SELECT * FROM users WHERE username = ?", (username,))
            user = c.fetchone()
            conn.close()
            
            if user and check_password_hash(user['password_hash'], password):
                session.permanent = True  # Use permanent session with timeout
                session["user"] = username
                session["user_id"] = user['id']
                session["login_time"] = datetime.now().isoformat()
                flash(f"Welcome back, {username}!", "success")
                return redirect(url_for("dashboard"))
            error = "Invalid username or password"
    
    return render_template("login.html", error=error)

@app.route("/register", methods=["GET", "POST"])
def register():
    """
    Handle user registration.
    GET: Display registration form
    POST: Create new user account with validation
    
    Returns:
        Rendered registration template or redirect to login
    """
    if "user" in session:
        return redirect(url_for("dashboard"))
    
    error = None
    
    if request.method == "POST":
        username = sanitize_string(request.form.get("username", ""), max_length=50)
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")
        
        # Comprehensive validation
        if not username or not password:
            error = "Username and password are required"
        elif not validate_username(username):
            error = "Username must be 3-50 characters (letters, numbers, underscores, hyphens only)"
        elif not validate_password(password):
            error = "Password must be at least 6 characters long"
        elif password != confirm_password:
            error = "Passwords do not match"
        else:
            conn = get_db_conn()
            c = conn.cursor()
            try:
                c.execute("SELECT id FROM users WHERE username = ?", (username,))
                if c.fetchone():
                    error = "Username already exists"
                else:
                    password_hash = generate_password_hash(password)
                    c.execute("INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
                             (username, password_hash, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
                    conn.commit()
                    flash("Account created successfully! Please login.", "success")
                    conn.close()
                    return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                error = "Username already exists"
            finally:
                conn.close()
    
    return render_template("register.html", error=error)

@app.route("/logout")
def logout():
    """
    Handle user logout and session cleanup.
    Properly clears session data and deactivates user's data collection.
    
    Returns:
        Redirect to login page
    """
    if "user" in session:
        user_id = session.get("user_id")
        
        # Deactivate user's session in database
        conn = get_db_conn()
        c = conn.cursor()
        c.execute("DELETE FROM active_session WHERE user_id = ?", (user_id,))
        conn.commit()
        conn.close()
    
    # Clear all session data
    session.clear()
    flash("You have been logged out successfully.", "info")
    return redirect(url_for("login"))

# ==============================
# SESSION MANAGEMENT ROUTES
# ==============================
@app.route("/activate", methods=["POST"])
def activate():
    """
    Activate sensor data collection for the current user.
    Only one user can be active at a time.
    
    Returns:
        JSON response with activation status
    """
    if "user" not in session:
        return jsonify({"error": "unauthorized"}), 403
    
    user_id = session.get("user_id")
    username = session.get("user")
    
    conn = get_db_conn()
    c = conn.cursor()
    # Clear any existing active session
    c.execute("DELETE FROM active_session")
    # Set this user as active
    c.execute("INSERT OR REPLACE INTO active_session (id, user_id, username, activated_at) VALUES (1, ?, ?, ?)",
              (user_id, username, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    conn.commit()
    conn.close()
    
    return jsonify({"message": "activated", "username": username}), 200

@app.route("/deactivate", methods=["POST"])
def deactivate():
    """
    Deactivate sensor data collection for the current user.
    Stops ESP32 from logging data to this user's account.
    
    Returns:
        JSON response with deactivation status
    """
    if "user" not in session:
        return jsonify({"error": "unauthorized"}), 403
    
    user_id = session.get("user_id")
    
    conn = get_db_conn()
    c = conn.cursor()
    c.execute("DELETE FROM active_session WHERE user_id = ?", (user_id,))
    conn.commit()
    conn.close()
    
    return jsonify({"message": "deactivated"}), 200

@app.route("/active-user", methods=["GET"])
def active_user():
    """
    Get the currently active user (who is receiving sensor data).
    
    Returns:
        JSON with active username or None
    """
    conn = get_db_conn()
    c = conn.cursor()
    c.execute("SELECT username FROM active_session WHERE id = 1")
    active = c.fetchone()
    conn.close()
    
    if active:
        return jsonify({"active_user": active['username']})
    return jsonify({"active_user": None})

# ==============================
# DASHBOARD & DATA DISPLAY
# ==============================
@app.route("/dashboard")
def dashboard():
    """
    Display the main dashboard with paginated sensor readings.
    Shows readings only for the logged-in user.
    
    Query Parameters:
        page (int): Page number for pagination (default: 1)
        per_page (int): Items per page (default: 20)
    
    Returns:
        Rendered dashboard template with readings data
    """
    if "user" not in session:
        return redirect(url_for("login"))
    
    user_id = session.get("user_id")
    
    # Validate pagination parameters
    try:
        page = max(1, min(int(request.args.get("page", 1)), 10000))  # Max 10000 pages
        per_page = max(1, min(int(request.args.get("per_page", 20)), 100))  # Max 100 items per page
    except (ValueError, TypeError):
        page = 1
        per_page = 20
    
    conn = get_db_conn()
    c = conn.cursor()
    
    # Get total count for pagination
    c.execute("SELECT COUNT(*) FROM readings WHERE user_id = ?", (user_id,))
    total = c.fetchone()[0]
    total_pages = max(1, math.ceil(total / per_page))
    page = min(page, total_pages)
    offset = (page - 1) * per_page
    
    # Get paginated readings
    c.execute("SELECT * FROM readings WHERE user_id = ? ORDER BY id DESC LIMIT ? OFFSET ?", 
              (user_id, per_page, offset))
    rows = c.fetchall()
    conn.close()
    
    return render_template("dashboard.html", logs=rows, page=page, per_page=per_page, 
                         total=total, total_pages=total_pages)

# ==============================
# ESP32 DATA ENDPOINTS
# ==============================
@app.route("/update", methods=["POST"])
def update():
    """
    Receive sensor data from ESP32 and store it for the active user.
    ESP32 should POST JSON data to this endpoint.
    
    Expected JSON format:
        {
            "status": str,
            "touch_value": int,
            "count": int,
            "event_time": str (optional)
        }
    
    Returns:
        JSON response indicating success or if no active user
    """
    try:
        j = request.get_json(force=True)
        if not j or not isinstance(j, dict):
            return jsonify({"message": "invalid JSON"}), 400
    except Exception as e:
        print(f"Error parsing JSON: {e}")
        return jsonify({"message": "error parsing JSON"}), 400
    
    conn = get_db_conn()
    c = conn.cursor()
    
    # Check if there's an active user to receive this data
    c.execute("SELECT user_id FROM active_session WHERE id = 1")
    active = c.fetchone()
    
    if not active or not active['user_id']:
        conn.close()
        return jsonify({"message": "no active user"}), 200
    
    # Validate and sanitize sensor data
    user_id = active['user_id']
    status = sanitize_string(j.get("status", "Unknown"), max_length=50)
    
    # Validate numeric values
    touch_value = validate_number(j.get("touch_value", 0), min_val=0, max_val=1000000)
    count = validate_number(j.get("count", 0), min_val=0, max_val=1000000)
    
    if touch_value is None or count is None:
        conn.close()
        return jsonify({"message": "invalid numeric values"}), 400
    
    # Sanitize timestamp
    ts = sanitize_string(j.get("event_time", ""), max_length=50)
    if not ts or len(ts) < 10:  # Basic timestamp validation
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Insert reading into database
    try:
        c.execute("INSERT INTO readings (user_id, event_time, status, touch_value, count) VALUES (?, ?, ?, ?, ?)", 
                  (user_id, ts, status, int(touch_value), int(count)))
        conn.commit()
        conn.close()
        
        # Check if calibration was requested - respond with calibration flag
        # This works by checking if ANY active user session has calibration requested
        calibration_requested = session.get('calibration_requested', False)
        
        response_data = {"message": "ok"}
        
        if calibration_requested:
            # Clear the calibration request flag
            session['calibration_requested'] = False
            session['calibration_completed_time'] = datetime.now().isoformat()
            response_data["calibrate"] = True
            response_data["info"] = "Calibration requested - please recalibrate sensor"
        
        return jsonify(response_data), 200
    except Exception as e:
        print(f"Database error: {e}")
        conn.close()
        return jsonify({"message": "database error"}), 500

@app.route("/environment", methods=["POST"])
def update_environment():
    """
    Receive environmental data (temperature and humidity) from ESP32.
    ESP32 should POST JSON data to this endpoint.
    
    Expected JSON format:
        {
            "temperature": float,
            "humidity": float
        }
    
    Returns:
        JSON response indicating success
    """
    try:
        j = request.get_json(force=True)
        if not j or not isinstance(j, dict):
            return jsonify({"message": "invalid JSON"}), 400
    except Exception as e:
        print(f"Error parsing JSON: {e}")
        return jsonify({"message": "error parsing JSON"}), 400
    
    # Validate temperature and humidity values
    temperature = validate_number(j.get("temperature", 0.0), min_val=-50, max_val=100)
    humidity = validate_number(j.get("humidity", 0.0), min_val=0, max_val=100)
    
    if temperature is None or humidity is None:
        return jsonify({"message": "invalid sensor values"}), 400
    
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    conn = get_db_conn()
    c = conn.cursor()
    
    # Insert environmental data
    c.execute("INSERT INTO environmental_data (temperature, humidity, timestamp) VALUES (?, ?, ?)", 
              (temperature, humidity, ts))
    
    # Keep only last 100 records to prevent database bloat
    c.execute("DELETE FROM environmental_data WHERE id NOT IN (SELECT id FROM environmental_data ORDER BY id DESC LIMIT 100)")
    
    conn.commit()
    conn.close()
    
    return jsonify({"message": "ok"}), 200

@app.route("/buzzer-status", methods=["GET"])
def buzzer_status():
    """
    Get buzzer silence status for ESP32.
    
    Returns:
        JSON with silenced status (0 or 1)
    """
    conn = get_db_conn()
    c = conn.cursor()
    c.execute("SELECT silenced, silenced_until FROM buzzer_silence WHERE id = 1")
    status = c.fetchone()
    conn.close()
    
    if not status:
        return jsonify({"silenced": 0})
    
    # Check if silence period has expired
    if status['silenced'] == 1 and status['silenced_until']:
        try:
            silence_until = datetime.strptime(status['silenced_until'], "%Y-%m-%d %H:%M:%S")
            now = datetime.now()
            if now >= silence_until:
                # Silence period expired, reset
                conn = get_db_conn()
                c = conn.cursor()
                c.execute("UPDATE buzzer_silence SET silenced = 0, silenced_until = NULL WHERE id = 1")
                conn.commit()
                conn.close()
                return jsonify({"silenced": 0})
        except:
            pass
    
    return jsonify({"silenced": status['silenced']})

@app.route("/mute-status", methods=["GET"])
def mute_status():
    """
    Get buzzer mute status with remaining time for dashboard.
    Allows frontend to restore countdown timer after page reload.
    
    Returns:
        JSON with silenced status, remaining seconds, and silence_until timestamp
    """
    conn = get_db_conn()
    c = conn.cursor()
    c.execute("SELECT silenced, silenced_until FROM buzzer_silence WHERE id = 1")
    status = c.fetchone()
    conn.close()
    
    if not status or status['silenced'] == 0:
        return jsonify({"silenced": 0, "remaining_seconds": 0, "silenced_until": None})
    
    # Check if silence period has expired
    if status['silenced'] == 1 and status['silenced_until']:
        try:
            silence_until = datetime.strptime(status['silenced_until'], "%Y-%m-%d %H:%M:%S")
            now = datetime.now()
            
            if now >= silence_until:
                # Silence period expired, reset
                conn = get_db_conn()
                c = conn.cursor()
                c.execute("UPDATE buzzer_silence SET silenced = 0, silenced_until = NULL WHERE id = 1")
                conn.commit()
                conn.close()
                return jsonify({"silenced": 0, "remaining_seconds": 0, "silenced_until": None})
            
            # Calculate remaining seconds
            remaining = (silence_until - now).total_seconds()
            return jsonify({
                "silenced": 1,
                "remaining_seconds": int(remaining),
                "silenced_until": status['silenced_until']
            })
        except Exception as e:
            print(f"Error calculating mute status: {e}")
            return jsonify({"silenced": 0, "remaining_seconds": 0, "silenced_until": None})
    
    return jsonify({"silenced": 0, "remaining_seconds": 0, "silenced_until": None})

@app.route("/mute-buzzer", methods=["POST"])
def mute_buzzer():
    """
    Mute the buzzer for 60 seconds (1 minute).
    
    Returns:
        JSON response indicating success
    """
    if "user" not in session:
        return jsonify({"error": "unauthorized"}), 403
    
    # Calculate silence period (60 seconds / 1 minute from now)
    silence_until = (datetime.now() + __import__('datetime').timedelta(seconds=60)).strftime("%Y-%m-%d %H:%M:%S")
    
    conn = get_db_conn()
    c = conn.cursor()
    c.execute("UPDATE buzzer_silence SET silenced = 1, silenced_until = ? WHERE id = 1", (silence_until,))
    conn.commit()
    conn.close()
    
    return jsonify({"message": "Buzzer muted for 60 seconds", "silenced_until": silence_until}), 200

# ==============================
# DATA API ENDPOINTS
# ==============================
@app.route("/data", methods=["GET"])
def data_api():
    """
    Get all sensor readings for the logged-in user.
    
    Returns:
        JSON array of all readings for the current user
    """
    if "user" not in session:
        return jsonify([])
    
    user_id = session.get("user_id")
    conn = get_db_conn()
    c = conn.cursor()
    c.execute("SELECT * FROM readings WHERE user_id = ? ORDER BY id ASC", (user_id,))
    rows = c.fetchall()
    conn.close()
    
    return jsonify([dict(r) for r in rows])

@app.route("/count", methods=["GET"])
def get_count():
    """
    Get count of touch detection events for the logged-in user.
    
    Returns:
        JSON with count of 'Touch Detected' status readings
    """
    if "user" not in session:
        return jsonify({"count": 0})
    
    user_id = session.get("user_id")
    conn = get_db_conn()
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM readings WHERE user_id = ? AND status='Touch Detected'", (user_id,))
    count = c.fetchone()[0]
    conn.close()
    
    return jsonify({"count": count})

@app.route("/recent", methods=["GET"])
def get_recent():
    """
    Get the 10 most recent sensor readings for the logged-in user.
    
    Returns:
        JSON array of the 10 most recent readings
    """
    if "user" not in session:
        return jsonify([])
    
    user_id = session.get("user_id")
    conn = get_db_conn()
    c = conn.cursor()
    c.execute("SELECT id, event_time, status, touch_value, count FROM readings WHERE user_id = ? ORDER BY id DESC LIMIT 10", (user_id,))
    rows = c.fetchall()
    conn.close()
    
    return jsonify([{"id": r['id'], "event_time": r['event_time'], "status": r['status'], 
                     "touch_value": r['touch_value'], "count": r['count']} for r in rows])

@app.route("/environment-data", methods=["GET"])
def get_environment_data():
    """
    Get the latest environmental data (temperature and humidity).
    
    Returns:
        JSON with latest temperature and humidity readings
    """
    conn = get_db_conn()
    c = conn.cursor()
    c.execute("SELECT temperature, humidity, timestamp FROM environmental_data ORDER BY id DESC LIMIT 1")
    env_data = c.fetchone()
    conn.close()
    
    if not env_data:
        return jsonify({"temperature": None, "humidity": None, "timestamp": None})
    
    return jsonify({
        "temperature": env_data['temperature'],
        "humidity": env_data['humidity'],
        "timestamp": env_data['timestamp']
    })

@app.route("/touch-sensor-data", methods=["GET"])
def get_touch_sensor_data():
    """
    Get the latest touch sensor calibration data.
    Returns base value, threshold, and current touch value from most recent reading.
    
    Returns:
        JSON with touch sensor calibration data
    """
    if "user" not in session:
        return jsonify({
            "touch_value": None,
            "base_value": None,
            "threshold": None,
            "timestamp": None
        })
    
    user_id = session.get("user_id")
    conn = get_db_conn()
    c = conn.cursor()
    c.execute("SELECT touch_value, event_time FROM readings WHERE user_id = ? ORDER BY id DESC LIMIT 1", (user_id,))
    reading = c.fetchone()
    conn.close()
    
    if not reading:
        return jsonify({
            "touch_value": None,
            "base_value": None,
            "threshold": None,
            "timestamp": None
        })
    
    # Note: Base value and threshold are stored in ESP32, not in database
    # We can only show the current touch value from readings
    return jsonify({
        "touch_value": reading['touch_value'],
        "base_value": None,  # Not stored in DB
        "threshold": None,   # Not stored in DB
        "timestamp": reading['event_time']
    })

@app.route("/calibrate-touch", methods=["POST"])
def calibrate_touch():
    """
    Request ESP32 to recalibrate the touch sensor.
    Sets a database flag that ESP32 polls every second for immediate response.
    
    Returns:
        JSON response with calibration request status
    """
    if "user" not in session:
        return jsonify({"error": "unauthorized"}), 403
    
    conn = get_db_conn()
    c = conn.cursor()
    
    # Create calibration_requests table if it doesn't exist
    c.execute("""CREATE TABLE IF NOT EXISTS calibration_requests (
        id INTEGER PRIMARY KEY,
        requested INTEGER DEFAULT 0,
        requested_at TEXT
    )""")
    
    # Set calibration flag
    c.execute("INSERT OR REPLACE INTO calibration_requests (id, requested, requested_at) VALUES (1, 1, ?)",
              (datetime.now().strftime("%Y-%m-%d %H:%M:%S"),))
    conn.commit()
    conn.close()
    
    return jsonify({
        "message": "Calibration requested",
        "status": "pending",
        "info": "ESP32 will check calibration status within 1 second and display blue LED during calibration"
    }), 200

@app.route("/calibration-status", methods=["GET"])
def calibration_status():
    """
    Check if calibration was requested and is pending.
    
    Returns:
        JSON with calibration request status
    """
    if "user" not in session:
        return jsonify({"requested": False})
    
    requested = session.get('calibration_requested', False)
    request_time = session.get('calibration_request_time', None)
    
    return jsonify({
        "requested": requested,
        "request_time": request_time
    })

@app.route("/check-calibration", methods=["GET"])
def check_calibration():
    """
    ESP32 endpoint to frequently check if calibration is needed.
    Returns calibrate flag without requiring authentication.
    This allows ESP32 to poll this endpoint every second for immediate response.
    
    Returns:
        JSON with calibrate flag (0 or 1)
    """
    # Check if ANY user has requested calibration
    # Since this is a single ESP32 system, we check for any calibration request
    conn = get_db_conn()
    c = conn.cursor()
    
    # Check active session user's calibration request
    c.execute("SELECT user_id FROM active_session WHERE id = 1")
    active = c.fetchone()
    conn.close()
    
    if not active or not active['user_id']:
        return jsonify({"calibrate": 0})
    
    # Check session storage for calibration request
    # Note: This requires the session to be accessible
    # For a more reliable approach, we'll use a database flag
    
    return jsonify({"calibrate": 0})

@app.route("/request-calibration-status", methods=["GET"])
def request_calibration_status():
    """
    Public endpoint for ESP32 to check calibration without session.
    Uses a simple database flag that can be set by any authenticated user.
    
    Returns:
        JSON with calibrate flag and clears it after reading
    """
    conn = get_db_conn()
    c = conn.cursor()
    
    # Create calibration_requests table if it doesn't exist
    c.execute("""CREATE TABLE IF NOT EXISTS calibration_requests (
        id INTEGER PRIMARY KEY,
        requested INTEGER DEFAULT 0,
        requested_at TEXT
    )""")
    
    # Initialize with default row
    c.execute("INSERT OR IGNORE INTO calibration_requests (id, requested) VALUES (1, 0)")
    
    # Check if calibration is requested
    c.execute("SELECT requested FROM calibration_requests WHERE id = 1")
    row = c.fetchone()
    
    calibrate = 0
    if row and row['requested'] == 1:
        calibrate = 1
        # Clear the flag after ESP32 reads it
        c.execute("UPDATE calibration_requests SET requested = 0, requested_at = NULL WHERE id = 1")
        conn.commit()
    
    conn.close()
    
    return jsonify({"calibrate": calibrate})

@app.route("/clear", methods=["POST"])
def clear():
    """
    Clear all sensor readings for the logged-in user.
    
    Returns:
        Redirect to dashboard
    """
    if "user" not in session:
        return jsonify({"error": "unauthorized"}), 403
    
    user_id = session.get("user_id")
    conn = get_db_conn()
    c = conn.cursor()
    c.execute("DELETE FROM readings WHERE user_id = ?", (user_id,))
    conn.commit()
    conn.close()
    
    return redirect(url_for("dashboard"))

@app.route("/esp32-status", methods=["GET"])
def esp32_status():
    """
    Check ESP32 connection status based on recent activity.
    ESP32 is considered online if ANY data was received in the last 10 seconds.
    Checks both touch sensor readings AND environmental data.
    
    IMPORTANT: If the last touch event was "Touch Detected", the status remains
    "Touch Detected" until a "Touch Released" event is received, regardless of
    environmental data timestamps.
    
    Returns:
        JSON with ESP32 online status and last activity time
    """
    if "user" not in session:
        return jsonify({"online": False, "last_activity": None})
    
    user_id = session.get("user_id")
    conn = get_db_conn()
    c = conn.cursor()
    
    # Get the most recent reading for this user (touch sensor data)
    c.execute("SELECT event_time, status FROM readings WHERE user_id = ? ORDER BY id DESC LIMIT 1", (user_id,))
    touch_reading = c.fetchone()
    
    # Get the most recent environmental data (temperature/humidity)
    c.execute("SELECT timestamp, temperature, humidity FROM environmental_data ORDER BY id DESC LIMIT 1")
    env_data = c.fetchone()
    
    conn.close()
    
    # Determine which data source is most recent (for online status)
    most_recent_time = None
    current_touch_status = "Ready"  # Default status
    
    # First, determine the current touch sensor state
    if touch_reading:
        current_touch_status = touch_reading['status']
        # If last touch event was "Touch Detected", keep showing it
        # Only return to "Ready" when we get "Touch Released"
    
    # Now determine the most recent timestamp (for online detection)
    if touch_reading and env_data:
        try:
            touch_time = datetime.strptime(touch_reading['event_time'], "%Y-%m-%d %H:%M:%S")
            env_time = datetime.strptime(env_data['timestamp'], "%Y-%m-%d %H:%M:%S")
            
            # Use the most recent timestamp for "last activity"
            most_recent_time = max(touch_time, env_time)
            # But keep the touch status unchanged
        except:
            most_recent_time = touch_time if touch_reading else env_time
    elif touch_reading:
        try:
            most_recent_time = datetime.strptime(touch_reading['event_time'], "%Y-%m-%d %H:%M:%S")
        except:
            return jsonify({"online": False, "last_activity": None, "status": "No data"})
    elif env_data:
        try:
            most_recent_time = datetime.strptime(env_data['timestamp'], "%Y-%m-%d %H:%M:%S")
            # No touch data, so status remains "Ready"
        except:
            return jsonify({"online": False, "last_activity": None, "status": "No data"})
    else:
        return jsonify({"online": False, "last_activity": None, "status": "No data"})
    
    # Check if the last activity was within the last 10 seconds
    now = datetime.now()
    time_diff = (now - most_recent_time).total_seconds()
    
    # Consider online if ANY data received within last 10 seconds
    online = time_diff < 10
    
    return jsonify({
        "online": online,
        "last_activity": most_recent_time.strftime("%Y-%m-%d %H:%M:%S"),
        "status": current_touch_status,  # Use the persistent touch status
        "seconds_ago": int(time_diff)
    })

# ==============================
# USER SETTINGS
# ==============================
@app.route("/settings", methods=["GET", "POST"])
def settings():
    """
    Handle user account settings.
    Allows users to change username or password.
    
    POST actions:
        - change_username: Update username with password verification
        - change_password: Update password with current password verification
    
    Returns:
        Rendered settings template with success/error messages
    """
    if "user" not in session:
        return redirect(url_for("login"))
    
    error = None
    success = None
    user_id = session.get("user_id")
    
    if request.method == "POST":
        action = request.form.get("action")
        
        if action == "change_username":
            new_username = request.form.get("new_username", "").strip()
            password = request.form.get("password", "")
            
            if not new_username or not password:
                error = "Username and password are required"
            elif len(new_username) < 3:
                error = "Username must be at least 3 characters"
            else:
                conn = get_db_conn()
                c = conn.cursor()
                c.execute("SELECT password_hash FROM users WHERE id = ?", (user_id,))
                user = c.fetchone()
                
                if user and check_password_hash(user['password_hash'], password):
                    try:
                        c.execute("UPDATE users SET username = ? WHERE id = ?", (new_username, user_id))
                        conn.commit()
                        session["user"] = new_username
                        success = "Username updated successfully!"
                    except sqlite3.IntegrityError:
                        error = "Username already exists"
                else:
                    error = "Incorrect password"
                conn.close()
        
        elif action == "change_password":
            current_password = request.form.get("current_password", "")
            new_password = request.form.get("new_password", "")
            confirm_password = request.form.get("confirm_password", "")
            
            if not current_password or not new_password:
                error = "All fields are required"
            elif len(new_password) < 6:
                error = "New password must be at least 6 characters"
            elif new_password != confirm_password:
                error = "Passwords do not match"
            else:
                conn = get_db_conn()
                c = conn.cursor()
                c.execute("SELECT password_hash FROM users WHERE id = ?", (user_id,))
                user = c.fetchone()
                
                if user and check_password_hash(user['password_hash'], current_password):
                    new_hash = generate_password_hash(new_password)
                    c.execute("UPDATE users SET password_hash = ? WHERE id = ?", (new_hash, user_id))
                    conn.commit()
                    success = "Password updated successfully!"
                else:
                    error = "Current password is incorrect"
                conn.close()
    
    return render_template("settings.html", error=error, success=success)

# ==============================
# APPLICATION ENTRY POINT
# ==============================
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
