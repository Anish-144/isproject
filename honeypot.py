# honeypot.py — SecureCorp Cybersecurity Honeypot
from flask import Flask, request, jsonify, render_template, redirect, url_for, session, flash
import json, datetime, os, re, time, hashlib
from collections import defaultdict
from werkzeug.utils import secure_filename
from mitre_mapping import enrich_with_mitre
from response_engine import is_blocked, auto_respond

app = Flask(__name__)
app.secret_key = "securecorp-honeypot-secret-key-do-not-share"

os.makedirs("logs", exist_ok=True)
os.makedirs("uploads", exist_ok=True)

# ── Automated response: block requests from blocklisted IPs ─────────────────
@app.before_request
def check_blocklist():
    if is_blocked(request.remote_addr):
        return jsonify({"error": "Access denied — your IP has been blocked"}), 403

LOGFILE = "honeypot_logs.json"
LOGPATH = os.path.join("logs", LOGFILE)
MAX_LOG_BYTES = 10_000_000  # rotate at ~10MB

# ── Fake user database (honeypot — all logins are trapped) ──────────────────
CUSTOMER_USERS = {
    "customer@securecorp.com": "SecurePass123",
    "demo": "demo123",
}
ADMIN_USERS = {
    "admin@securecorp.com": "AdminSecure!456",
}

# ── Brute force tracking ────────────────────────────────────────────────────
login_attempts = defaultdict(list)  # ip -> [timestamps]
BRUTE_FORCE_THRESHOLD = 5
BRUTE_FORCE_WINDOW = 300  # 5 minutes

# ── Attack detection patterns ───────────────────────────────────────────────
SQL_INJECTION_PATTERNS = [
    re.compile(r"['\"]?\s*or\s+[\d'\"]+\s*=\s*[\d'\"]+", re.IGNORECASE),
    re.compile(r"['\"]?\s*or\s+true", re.IGNORECASE),
    re.compile(r"union\s+(all\s+)?select", re.IGNORECASE),
    re.compile(r"['\"];\s*drop\s+", re.IGNORECASE),
    re.compile(r"['\"];\s*delete\s+", re.IGNORECASE),
    re.compile(r"['\"];\s*insert\s+", re.IGNORECASE),
    re.compile(r"['\"];\s*update\s+", re.IGNORECASE),
    re.compile(r"select\s+.*\s+from\s+", re.IGNORECASE),
    re.compile(r"drop\s+table", re.IGNORECASE),
    re.compile(r"['\"]?\s*--\s*$", re.IGNORECASE),
    re.compile(r"admin['\"]?\s*--", re.IGNORECASE),
    re.compile(r"1\s*=\s*1", re.IGNORECASE),
    re.compile(r"'\s*or\s*'", re.IGNORECASE),
    re.compile(r"sleep\s*\(", re.IGNORECASE),
    re.compile(r"benchmark\s*\(", re.IGNORECASE),
]

XSS_PATTERNS = [
    re.compile(r"<script[^>]*>", re.IGNORECASE),
    re.compile(r"javascript\s*:", re.IGNORECASE),
    re.compile(r"on(error|load|click|mouseover|focus|blur)\s*=", re.IGNORECASE),
    re.compile(r"<img[^>]+onerror", re.IGNORECASE),
    re.compile(r"<svg[^>]*>", re.IGNORECASE),
    re.compile(r"<iframe[^>]*>", re.IGNORECASE),
    re.compile(r"eval\s*\(", re.IGNORECASE),
    re.compile(r"document\.(cookie|write)", re.IGNORECASE),
    re.compile(r"alert\s*\(", re.IGNORECASE),
]

SUSPICIOUS_FILE_EXTENSIONS = {'.exe', '.bat', '.sh', '.php', '.jsp', '.asp', '.cmd', '.ps1', '.py', '.rb', '.pl'}
SUSPICIOUS_FILE_CONTENT_PATTERNS = [
    re.compile(rb"<script", re.IGNORECASE),
    re.compile(rb"<%", re.IGNORECASE),
    re.compile(rb"<\?php", re.IGNORECASE),
    re.compile(rb"#!/", re.IGNORECASE),
    re.compile(rb"import\s+os", re.IGNORECASE),
    re.compile(rb"exec\s*\(", re.IGNORECASE),
    re.compile(rb"eval\s*\(", re.IGNORECASE),
]

# ── Logging ─────────────────────────────────────────────────────────────────
def rotate_if_needed():
    if os.path.exists(LOGPATH) and os.path.getsize(LOGPATH) > MAX_LOG_BYTES:
        i = 1
        while True:
            rot = LOGPATH + f".{i}.old"
            if not os.path.exists(rot):
                os.rename(LOGPATH, rot)
                break
            i += 1

def write_log(entry):
    rotate_if_needed()
    with open(LOGPATH, "a") as f:
        f.write(json.dumps(entry, default=str) + "\n")

def build_log(req, event_type="request", severity="low", details=None, extra=None):
    """Build a standardized log entry."""
    log = {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "ip": req.remote_addr,
        "endpoint": req.path,
        "method": req.method,
        "event_type": event_type,
        "severity": severity,
        "details": details or {},
        "headers": {"User-Agent": req.headers.get("User-Agent", "")},
        "args": req.args.to_dict(),
        "form": req.form.to_dict(),
        "data": req.get_data(as_text=True)[:2000],  # cap at 2KB
    }
    # Run attack detection
    attack_info = detect_attacks(log)
    log["predicted_class"] = attack_info["predicted_class"]
    log["is_anomaly"] = attack_info["is_anomaly"]
    if attack_info["attack_type"] != "none":
        log["event_type"] = "attack_detected"
        log["severity"] = attack_info["severity"]
        log["details"]["attack_type"] = attack_info["attack_type"]
        log["details"]["attack_patterns"] = attack_info.get("patterns", [])
    if extra:
        log["details"].update(extra)
    # Enrich with MITRE ATT&CK mapping
    enrich_with_mitre(log)
    # Automated response (block IP on critical events)
    auto_respond(log)
    return log

# ── Attack detection engine ─────────────────────────────────────────────────
def get_payload_text(log):
    parts = []
    if log.get("data"):
        parts.append(str(log["data"]))
    if log.get("args"):
        parts.extend(str(v) for v in log["args"].values())
    if log.get("form"):
        parts.extend(str(v) for v in log["form"].values())
    return " ".join(parts)

def detect_attacks(log):
    """Detect SQL injection, XSS, and other attacks in the request."""
    result = {"predicted_class": "benign", "is_anomaly": False,
              "attack_type": "none", "severity": "low", "patterns": []}
    payload = get_payload_text(log)
    if not payload.strip():
        return result

    # SQL Injection
    for p in SQL_INJECTION_PATTERNS:
        m = p.search(payload)
        if m:
            result["predicted_class"] = "sqli"
            result["is_anomaly"] = True
            result["attack_type"] = "SQL Injection"
            result["severity"] = "critical"
            result["patterns"].append(m.group(0)[:80])
            return result

    # XSS
    for p in XSS_PATTERNS:
        m = p.search(payload)
        if m:
            result["predicted_class"] = "xss"
            result["is_anomaly"] = True
            result["attack_type"] = "Cross-Site Scripting"
            result["severity"] = "high"
            result["patterns"].append(m.group(0)[:80])
            return result

    return result

def check_brute_force(ip):
    """Returns True if the IP has exceeded the brute force threshold."""
    now = time.time()
    login_attempts[ip] = [t for t in login_attempts[ip] if now - t < BRUTE_FORCE_WINDOW]
    login_attempts[ip].append(now)
    return len(login_attempts[ip]) > BRUTE_FORCE_THRESHOLD

def check_file_suspicious(filename, content_bytes):
    """Check if an uploaded file is suspicious."""
    issues = []
    _, ext = os.path.splitext(filename.lower())
    if ext in SUSPICIOUS_FILE_EXTENSIONS:
        issues.append(f"Suspicious file extension: {ext}")
    for p in SUSPICIOUS_FILE_CONTENT_PATTERNS:
        if p.search(content_bytes[:4096]):
            issues.append(f"Suspicious content pattern detected")
            break
    return issues

# ═══════════════════════════════════════════════════════════════════════════
# PUBLIC LANDING PAGE ROUTES
# ═══════════════════════════════════════════════════════════════════════════

@app.route("/", methods=["GET", "POST"])
def home():
    log = build_log(request, event_type="page_view", severity="low",
                    details={"page": "home"})
    write_log(log)
    return render_template("index.html")

@app.route("/services", methods=["GET"])
def services():
    log = build_log(request, event_type="page_view", severity="low",
                    details={"page": "services"})
    write_log(log)
    return render_template("services.html")

@app.route("/about", methods=["GET"])
def about():
    log = build_log(request, event_type="page_view", severity="low",
                    details={"page": "about"})
    write_log(log)
    return render_template("about.html")

@app.route("/blog", methods=["GET"])
def blog():
    log = build_log(request, event_type="page_view", severity="low",
                    details={"page": "blog"})
    write_log(log)
    return render_template("blog.html")

@app.route("/careers", methods=["GET"])
def careers():
    log = build_log(request, event_type="page_view", severity="low",
                    details={"page": "careers"})
    write_log(log)
    return render_template("careers.html")

@app.route("/contact", methods=["GET", "POST"])
def contact():
    if request.method == "POST":
        log = build_log(request, event_type="form_submit", severity="low",
                        details={"page": "contact", "form_type": "contact"})
        write_log(log)
        flash("Thank you for your message! We will get back to you soon.", "success")
        return redirect(url_for("contact"))
    log = build_log(request, event_type="page_view", severity="low",
                    details={"page": "contact"})
    write_log(log)
    return render_template("contact.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        log = build_log(request, event_type="registration_attempt", severity="low",
                        details={"page": "register"})
        write_log(log)
        flash("Account created successfully! Please check your email for verification.", "success")
        return redirect(url_for("register"))
    log = build_log(request, event_type="page_view", severity="low",
                    details={"page": "register"})
    write_log(log)
    return render_template("register.html")

@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        log = build_log(request, event_type="password_reset", severity="low",
                        details={"page": "forgot_password"})
        write_log(log)
        flash("If an account with that email exists, we have sent a password reset link.", "success")
        return redirect(url_for("forgot_password"))
    log = build_log(request, event_type="page_view", severity="low",
                    details={"page": "forgot_password"})
    write_log(log)
    return render_template("forgot-password.html")

# Legacy login route
@app.route("/login", methods=["GET", "POST"])
def login_redirect():
    return redirect(url_for("customer_login"))

# ═══════════════════════════════════════════════════════════════════════════
# CUSTOMER PORTAL
# ═══════════════════════════════════════════════════════════════════════════

@app.route("/customer/login", methods=["GET", "POST"])
def customer_login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        ip = request.remote_addr
        is_brute = check_brute_force(ip)

        # Check for attacks in credentials
        log = build_log(request, event_type="login_attempt", severity="low",
                        details={"portal": "customer", "username": username, "success": False})

        if is_brute:
            log["event_type"] = "brute_force_detected"
            log["severity"] = "high"
            log["is_anomaly"] = True
            log["details"]["brute_force"] = True

        write_log(log)

        # Honeypot: accept valid fake credentials
        if username in CUSTOMER_USERS and CUSTOMER_USERS[username] == password and not log["is_anomaly"]:
            log2 = build_log(request, event_type="login_success", severity="low",
                             details={"portal": "customer", "username": username, "success": True})
            write_log(log2)
            session["customer_user"] = username
            return redirect(url_for("customer_dashboard"))

        flash("Invalid username or password. Please try again.", "danger")
        return render_template("customer_login.html")

    log = build_log(request, event_type="page_view", severity="low",
                    details={"page": "customer_login"})
    write_log(log)
    return render_template("customer_login.html")

@app.route("/customer/dashboard", methods=["GET"])
def customer_dashboard():
    if "customer_user" not in session:
        return redirect(url_for("customer_login"))
    log = build_log(request, event_type="page_view", severity="low",
                    details={"page": "customer_dashboard", "user": session["customer_user"]})
    write_log(log)

    # Load fake query responses
    queries = session.get("queries", [])
    uploads = session.get("uploads", [])
    return render_template("customer_dashboard.html",
                           user=session["customer_user"], queries=queries, uploads=uploads)

@app.route("/customer/query", methods=["POST"])
def customer_query():
    if "customer_user" not in session:
        return redirect(url_for("customer_login"))
    query_text = request.form.get("query", "")
    log = build_log(request, event_type="query_submit", severity="low",
                    details={"portal": "customer", "user": session["customer_user"],
                             "query": query_text[:500]})
    write_log(log)

    # Store query in session
    queries = session.get("queries", [])
    queries.append({
        "id": len(queries) + 1,
        "text": query_text[:500],
        "time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M"),
        "status": "Received",
        "response": "Our team will review your query shortly."
    })
    session["queries"] = queries
    flash("Query submitted successfully!", "success")
    return redirect(url_for("customer_dashboard"))

@app.route("/customer/upload", methods=["POST"])
def customer_upload():
    if "customer_user" not in session:
        return redirect(url_for("customer_login"))

    if "file" not in request.files:
        flash("No file selected.", "danger")
        return redirect(url_for("customer_dashboard"))

    file = request.files["file"]
    if file.filename == "":
        flash("No file selected.", "danger")
        return redirect(url_for("customer_dashboard"))

    filename = secure_filename(file.filename)
    content_bytes = file.read()
    file_size = len(content_bytes)

    # Check for suspicious files
    suspicions = check_file_suspicious(filename, content_bytes)

    sev = "low"
    etype = "file_upload"
    extra = {
        "portal": "customer",
        "user": session["customer_user"],
        "filename": filename,
        "file_size": file_size,
    }
    if suspicions:
        sev = "critical"
        etype = "suspicious_upload"
        extra["suspicions"] = suspicions

    log = build_log(request, event_type=etype, severity=sev, extra=extra)
    if suspicions:
        log["is_anomaly"] = True
        log["predicted_class"] = "malicious_upload"
    write_log(log)

    # Save file regardless (honeypot collects evidence)
    save_path = os.path.join("uploads", filename)
    with open(save_path, "wb") as f:
        f.write(content_bytes)

    uploads = session.get("uploads", [])
    uploads.append({
        "id": len(uploads) + 1,
        "filename": filename,
        "size": f"{file_size / 1024:.1f} KB",
        "time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M"),
        "status": "Uploaded"
    })
    session["uploads"] = uploads
    flash(f"File '{filename}' uploaded successfully!", "success")
    return redirect(url_for("customer_dashboard"))

@app.route("/customer/logout")
def customer_logout():
    log = build_log(request, event_type="logout", severity="low",
                    details={"portal": "customer", "user": session.get("customer_user", "")})
    write_log(log)
    session.pop("customer_user", None)
    session.pop("queries", None)
    session.pop("uploads", None)
    return redirect(url_for("home"))

# ═══════════════════════════════════════════════════════════════════════════
# ADMIN PORTAL
# ═══════════════════════════════════════════════════════════════════════════

@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        ip = request.remote_addr
        is_brute = check_brute_force(ip)

        log = build_log(request, event_type="admin_login_attempt", severity="medium",
                        details={"portal": "admin", "username": username, "success": False})

        if is_brute:
            log["event_type"] = "brute_force_detected"
            log["severity"] = "high"
            log["is_anomaly"] = True
            log["details"]["brute_force"] = True

        write_log(log)

        if username in ADMIN_USERS and ADMIN_USERS[username] == password and not log["is_anomaly"]:
            log2 = build_log(request, event_type="admin_login_success", severity="medium",
                             details={"portal": "admin", "username": username, "success": True})
            write_log(log2)
            session["admin_user"] = username
            return redirect(url_for("admin_dashboard"))

        flash("Invalid admin credentials.", "danger")
        return render_template("admin_login.html")

    log = build_log(request, event_type="page_view", severity="low",
                    details={"page": "admin_login"})
    write_log(log)
    return render_template("admin_login.html")

@app.route("/admin/dashboard", methods=["GET"])
def admin_dashboard():
    if "admin_user" not in session:
        return redirect(url_for("admin_login"))
    log = build_log(request, event_type="page_view", severity="low",
                    details={"page": "admin_dashboard", "user": session["admin_user"]})
    write_log(log)

    # Load logs for admin view
    queries = []
    uploaded_files = []
    try:
        with open(LOGPATH) as f:
            for line in f:
                try:
                    entry = json.loads(line)
                except:
                    continue
                if entry.get("event_type") == "query_submit":
                    queries.append(entry)
                if entry.get("event_type") in ("file_upload", "suspicious_upload"):
                    uploaded_files.append(entry)
    except FileNotFoundError:
        pass

    return render_template("admin_dashboard.html",
                           user=session["admin_user"],
                           queries=queries[-50:],
                           uploaded_files=uploaded_files[-50:])

@app.route("/admin/logout")
def admin_logout():
    log = build_log(request, event_type="logout", severity="low",
                    details={"portal": "admin", "user": session.get("admin_user", "")})
    write_log(log)
    session.pop("admin_user", None)
    return redirect(url_for("home"))

# ═══════════════════════════════════════════════════════════════════════════
# HONEYPOT TRAP ROUTES
# ═══════════════════════════════════════════════════════════════════════════

@app.route("/admin-panel", methods=["GET", "POST"])
def trap_admin_panel():
    log = build_log(request, event_type="honeypot_trap", severity="high",
                    details={"trap": "/admin-panel", "description": "Attacker probing for admin panel"})
    log["is_anomaly"] = True
    write_log(log)
    return "Access Denied — Unauthorized", 403

@app.route("/debug-console", methods=["GET", "POST"])
def trap_debug_console():
    log = build_log(request, event_type="honeypot_trap", severity="high",
                    details={"trap": "/debug-console", "description": "Attacker probing for debug console"})
    log["is_anomaly"] = True
    write_log(log)
    return "Access Denied — Unauthorized", 403

@app.route("/wp-admin", methods=["GET", "POST"])
def trap_wp_admin():
    log = build_log(request, event_type="honeypot_trap", severity="high",
                    details={"trap": "/wp-admin", "description": "WordPress admin probe"})
    log["is_anomaly"] = True
    write_log(log)
    return "Not Found", 404

@app.route("/phpmyadmin", methods=["GET", "POST"])
def trap_phpmyadmin():
    log = build_log(request, event_type="honeypot_trap", severity="high",
                    details={"trap": "/phpmyadmin", "description": "phpMyAdmin probe"})
    log["is_anomaly"] = True
    write_log(log)
    return "Not Found", 404

@app.route("/.env", methods=["GET"])
def trap_env():
    log = build_log(request, event_type="honeypot_trap", severity="critical",
                    details={"trap": "/.env", "description": "Environment file probe"})
    log["is_anomaly"] = True
    write_log(log)
    return "Not Found", 404

# ═══════════════════════════════════════════════════════════════════════════
# API ROUTES
# ═══════════════════════════════════════════════════════════════════════════

@app.route("/api/log", methods=["POST"])
def api_log():
    entry = build_log(request, event_type="client_log", severity="low")
    entry["details"]["client_data"] = request.get_json(silent=True)
    write_log(entry)
    return jsonify({"status": "logged"})

@app.route("/api/contact", methods=["POST"])
def api_contact():
    log = build_log(request, event_type="form_submit", severity="low",
                    details={"form_type": "contact_api"})
    write_log(log)
    return jsonify({"status": "success", "message": "Message received"})

# ═══════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=True)
