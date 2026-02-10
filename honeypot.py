# honeypot.py
from flask import Flask, request, jsonify, render_template_string
import json, datetime, os, joblib
from flask_cors import CORS
from honey_logger import HoneyLogger

app = Flask(__name__)
CORS(app) # Enable CORS for all routes (important for React frontend on port 3000)

# Initialize HoneyLogger
honey_logger = HoneyLogger()

os.makedirs("logs", exist_ok=True)
LOGFILE = "honeypot_logs.jsonl"
LOGPATH = os.path.join("logs", LOGFILE)
MAX_LOG_BYTES = 5_000_000  # rotate at ~5MB

# Optional: load models if present (if not, handlers will continue to work)
try:
    iso = joblib.load(os.path.join("models","isolation_forest.joblib"))
    rf = joblib.load(os.path.join("models","rf_attack_classifier.joblib"))
except Exception:
    iso = None
    rf = None

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
        f.write(json.dumps(entry) + "\n")

def make_entry(req):
    headers = dict(req.headers)
    entry = {
        "time": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "ip": req.remote_addr,
        "path": req.path,
        "method": req.method,
        "args": req.args.to_dict(),
        "form": req.form.to_dict(),
        "data": req.get_data(as_text=True),
        "headers": headers
    }
    return entry

@app.before_request
def log_request_info():
    # Skip logging for static files or if needed
    if request.path.startswith('/static'):
        return

    # Gather details for HoneyLogger
    details = {
        "args": request.args.to_dict(),
        "form": request.form.to_dict(),
        "headers": dict(request.headers),
        "data": request.get_data(as_text=True)
    }
    
    # Generic request logging (will auto-detect attacks)
    honey_logger.log_event(
        timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        ip=request.remote_addr,
        endpoint=request.path,
        method=request.method,
        event_type="request",
        details=details
    )


@app.route("/", methods=["GET","POST"])
def trap_root():
    entry = make_entry(request)
    # classification if models are available
    entry['predicted_class'] = None
    entry['is_anomaly'] = None
    try:
        if iso is not None and rf is not None:
            from log_parser import extract_features
            Xvec = extract_features(entry)
            # map to vector used by models
            X = [Xvec["path_len"], Xvec["ua_len"], Xvec["data_len"],
                 Xvec["count_sql_tokens"], Xvec["count_xss_tokens"],
                 Xvec["num_params"], 1 if entry.get("method")=="POST" else 0]
            entry['is_anomaly'] = bool(iso.predict([X])[0] == -1)
            labels = {0:"benign",1:"sqli",2:"xss"}
            entry['predicted_class'] = labels.get(int(rf.predict([X])[0]), "unknown")
    except Exception:
        pass
    write_log(entry)
    return render_template_string(open('templates/index.html', encoding='utf-8').read())

@app.route("/login", methods=["GET","POST"])
def trap_login():
    entry = make_entry(request)
    entry['predicted_class'] = None
    entry['is_anomaly'] = None
    try:
        if iso is not None and rf is not None:
            from log_parser import extract_features
            Xvec = extract_features(entry)
            X = [Xvec["path_len"], Xvec["ua_len"], Xvec["data_len"],
                 Xvec["count_sql_tokens"], Xvec["count_xss_tokens"],
                 Xvec["num_params"], 1 if entry.get("method")=="POST" else 0]
            entry['is_anomaly'] = bool(iso.predict([X])[0] == -1)
            labels = {0:"benign",1:"sqli",2:"xss"}
            entry['predicted_class'] = labels.get(int(rf.predict([X])[0]), "unknown")
    except Exception:
        pass
    write_log(entry)
    
    # Show error message for failed login attempts
    if request.method == "POST":
        error_html = open('templates/login.html', encoding='utf-8').read().replace(
            '<h2 style="text-align: center; margin-bottom: 2rem; color: #333;">Secure Login Portal</h2>',
            '<h2 style="text-align: center; margin-bottom: 2rem; color: #333;">Secure Login Portal</h2><div class="alert alert-danger">Invalid username or password. Please try again.</div>'
        )
        return error_html, 401
    else:
        return render_template_string(open('templates/login.html', encoding='utf-8').read())

@app.route("/api/data", methods=["GET"])
def api_data():
    entry = make_entry(request)
    entry['predicted_class'] = None
    entry['is_anomaly'] = None
    write_log(entry)
    # deception: return fake-but-innocuous JSON
    return jsonify({"status":"ok","data":{"user":"john.doe","email":"john.doe@example.com","files":["report.doc","notes.txt"]}})

@app.route("/admin", methods=["GET","POST"])
def trap_admin():
    entry = make_entry(request)
    entry['predicted_class'] = None
    entry['is_anomaly'] = None
    try:
        if iso is not None and rf is not None:
            from log_parser import extract_features
            Xvec = extract_features(entry)
            X = [Xvec["path_len"], Xvec["ua_len"], Xvec["data_len"],
                 Xvec["count_sql_tokens"], Xvec["count_xss_tokens"],
                 Xvec["num_params"], 1 if entry.get("method")=="POST" else 0]
            entry['is_anomaly'] = bool(iso.predict([X])[0] == -1)
            labels = {0:"benign",1:"sqli",2:"xss"}
            entry['predicted_class'] = labels.get(int(rf.predict([X])[0]), "unknown")
    except Exception:
        pass
    write_log(entry)
    return "Access Denied - Admin privileges required", 403

@app.route("/dashboard", methods=["GET","POST"])
def trap_dashboard():
    entry = make_entry(request)
    entry['predicted_class'] = None
    entry['is_anomaly'] = None
    try:
        if iso is not None and rf is not None:
            from log_parser import extract_features
            Xvec = extract_features(entry)
            X = [Xvec["path_len"], Xvec["ua_len"], Xvec["data_len"],
                 Xvec["count_sql_tokens"], Xvec["count_xss_tokens"],
                 Xvec["num_params"], 1 if entry.get("method")=="POST" else 0]
            entry['is_anomaly'] = bool(iso.predict([X])[0] == -1)
            labels = {0:"benign",1:"sqli",2:"xss"}
            entry['predicted_class'] = labels.get(int(rf.predict([X])[0]), "unknown")
    except Exception:
        pass
    write_log(entry)
    return "Please login to access dashboard", 401

@app.route("/wp-admin", methods=["GET","POST"])
def trap_wp_admin():
    entry = make_entry(request)
    entry['predicted_class'] = None
    entry['is_anomaly'] = None
    try:
        if iso is not None and rf is not None:
            from log_parser import extract_features
            Xvec = extract_features(entry)
            X = [Xvec["path_len"], Xvec["ua_len"], Xvec["data_len"],
                 Xvec["count_sql_tokens"], Xvec["count_xss_tokens"],
                 Xvec["num_params"], 1 if entry.get("method")=="POST" else 0]
            entry['is_anomaly'] = bool(iso.predict([X])[0] == -1)
            labels = {0:"benign",1:"sqli",2:"xss"}
            entry['predicted_class'] = labels.get(int(rf.predict([X])[0]), "unknown")
    except Exception:
        pass
    write_log(entry)
    return "WordPress admin access denied", 403

@app.route("/services", methods=["GET","POST"])
def services():
    entry = make_entry(request)
    entry['predicted_class'] = None
    entry['is_anomaly'] = None
    try:
        if iso is not None and rf is not None:
            from log_parser import extract_features
            Xvec = extract_features(entry)
            X = [Xvec["path_len"], Xvec["ua_len"], Xvec["data_len"],
                 Xvec["count_sql_tokens"], Xvec["count_xss_tokens"],
                 Xvec["num_params"], 1 if entry.get("method")=="POST" else 0]
            entry['is_anomaly'] = bool(iso.predict([X])[0] == -1)
            labels = {0:"benign",1:"sqli",2:"xss"}
            entry['predicted_class'] = labels.get(int(rf.predict([X])[0]), "unknown")
    except Exception:
        pass
    write_log(entry)
    return render_template_string(open('templates/services.html', encoding='utf-8').read())

@app.route("/about", methods=["GET","POST"])
def about():
    entry = make_entry(request)
    entry['predicted_class'] = None
    entry['is_anomaly'] = None
    try:
        if iso is not None and rf is not None:
            from log_parser import extract_features
            Xvec = extract_features(entry)
            X = [Xvec["path_len"], Xvec["ua_len"], Xvec["data_len"],
                 Xvec["count_sql_tokens"], Xvec["count_xss_tokens"],
                 Xvec["num_params"], 1 if entry.get("method")=="POST" else 0]
            entry['is_anomaly'] = bool(iso.predict([X])[0] == -1)
            labels = {0:"benign",1:"sqli",2:"xss"}
            entry['predicted_class'] = labels.get(int(rf.predict([X])[0]), "unknown")
    except Exception:
        pass
    write_log(entry)
    return render_template_string(open('templates/about.html', encoding='utf-8').read())

@app.route("/contact", methods=["GET","POST"])
def contact():
    entry = make_entry(request)
    entry['predicted_class'] = None
    entry['is_anomaly'] = None
    try:
        if iso is not None and rf is not None:
            from log_parser import extract_features
            Xvec = extract_features(entry)
            X = [Xvec["path_len"], Xvec["ua_len"], Xvec["data_len"],
                 Xvec["count_sql_tokens"], Xvec["count_xss_tokens"],
                 Xvec["num_params"], 1 if entry.get("method")=="POST" else 0]
            entry['is_anomaly'] = bool(iso.predict([X])[0] == -1)
            labels = {0:"benign",1:"sqli",2:"xss"}
            entry['predicted_class'] = labels.get(int(rf.predict([X])[0]), "unknown")
    except Exception:
        pass
    write_log(entry)
    if request.method == "POST":
        # Log the contact form submission
        contact_entry = make_entry(request)
        contact_entry['form_type'] = 'contact'
        write_log(contact_entry)
        return render_template_string(open('templates/contact.html', encoding='utf-8').read().replace(
            '<h2 style="text-align: center; margin-bottom: 2rem; color: #333;">Contact Us</h2>',
            '<h2 style="text-align: center; margin-bottom: 2rem; color: #333;">Contact Us</h2><div class="alert alert-success">Thank you for your message! We will get back to you soon.</div>'
        ))
    return render_template_string(open('templates/contact.html', encoding='utf-8').read())

@app.route("/register", methods=["GET","POST"])
def register():
    entry = make_entry(request)
    entry['predicted_class'] = None
    entry['is_anomaly'] = None
    try:
        if iso is not None and rf is not None:
            from log_parser import extract_features
            Xvec = extract_features(entry)
            X = [Xvec["path_len"], Xvec["ua_len"], Xvec["data_len"],
                 Xvec["count_sql_tokens"], Xvec["count_xss_tokens"],
                 Xvec["num_params"], 1 if entry.get("method")=="POST" else 0]
            entry['is_anomaly'] = bool(iso.predict([X])[0] == -1)
            labels = {0:"benign",1:"sqli",2:"xss"}
            entry['predicted_class'] = labels.get(int(rf.predict([X])[0]), "unknown")
    except Exception:
        pass
    write_log(entry)
    if request.method == "POST":
        register_entry = make_entry(request)
        register_entry['form_type'] = 'register'
        write_log(register_entry)
        return render_template_string(open('templates/register.html', encoding='utf-8').read().replace(
            '<h2 style="text-align: center; margin-bottom: 2rem; color: #333;">Create Account</h2>',
            '<h2 style="text-align: center; margin-bottom: 2rem; color: #333;">Create Account</h2><div class="alert alert-success">Account created successfully! Please check your email for verification.</div>'
        ))
    return render_template_string(open('templates/register.html', encoding='utf-8').read())

@app.route("/forgot-password", methods=["GET","POST"])
def forgot_password():
    entry = make_entry(request)
    entry['predicted_class'] = None
    entry['is_anomaly'] = None
    try:
        if iso is not None and rf is not None:
            from log_parser import extract_features
            Xvec = extract_features(entry)
            X = [Xvec["path_len"], Xvec["ua_len"], Xvec["data_len"],
                 Xvec["count_sql_tokens"], Xvec["count_xss_tokens"],
                 Xvec["num_params"], 1 if entry.get("method")=="POST" else 0]
            entry['is_anomaly'] = bool(iso.predict([X])[0] == -1)
            labels = {0:"benign",1:"sqli",2:"xss"}
            entry['predicted_class'] = labels.get(int(rf.predict([X])[0]), "unknown")
    except Exception:
        pass
    write_log(entry)
    if request.method == "POST":
        forgot_entry = make_entry(request)
        forgot_entry['form_type'] = 'forgot_password'
        write_log(forgot_entry)
        return render_template_string(open('templates/forgot-password.html', encoding='utf-8').read().replace(
            '<h2 style="text-align: center; margin-bottom: 2rem; color: #333;">Reset Password</h2>',
            '<h2 style="text-align: center; margin-bottom: 2rem; color: #333;">Reset Password</h2><div class="alert alert-success">If an account with that email exists, we have sent you a password reset link.</div>'
        ))
    return render_template_string(open('templates/forgot-password.html', encoding='utf-8').read())

@app.route("/blog", methods=["GET","POST"])
def blog():
    entry = make_entry(request)
    entry['predicted_class'] = None
    entry['is_anomaly'] = None
    try:
        if iso is not None and rf is not None:
            from log_parser import extract_features
            Xvec = extract_features(entry)
            X = [Xvec["path_len"], Xvec["ua_len"], Xvec["data_len"],
                 Xvec["count_sql_tokens"], Xvec["count_xss_tokens"],
                 Xvec["num_params"], 1 if entry.get("method")=="POST" else 0]
            entry['is_anomaly'] = bool(iso.predict([X])[0] == -1)
            labels = {0:"benign",1:"sqli",2:"xss"}
            entry['predicted_class'] = labels.get(int(rf.predict([X])[0]), "unknown")
    except Exception:
        pass
    write_log(entry)
    return render_template_string(open('templates/blog.html', encoding='utf-8').read())

@app.route("/careers", methods=["GET","POST"])
def careers():
    entry = make_entry(request)
    entry['predicted_class'] = None
    entry['is_anomaly'] = None
    try:
        if iso is not None and rf is not None:
            from log_parser import extract_features
            Xvec = extract_features(entry)
            X = [Xvec["path_len"], Xvec["ua_len"], Xvec["data_len"],
                 Xvec["count_sql_tokens"], Xvec["count_xss_tokens"],
                 Xvec["num_params"], 1 if entry.get("method")=="POST" else 0]
            entry['is_anomaly'] = bool(iso.predict([X])[0] == -1)
            labels = {0:"benign",1:"sqli",2:"xss"}
            entry['predicted_class'] = labels.get(int(rf.predict([X])[0]), "unknown")
    except Exception:
        pass
    write_log(entry)
    return render_template_string(open('templates/careers.html', encoding='utf-8').read())

@app.route("/admin-panel", methods=["GET", "POST"])
def trap_admin_panel():
    honey_logger.log_event(
        timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        ip=request.remote_addr,
        endpoint=request.path,
        method=request.method,
        event_type="access_denied_trap",
        details="Attempted access to fake admin panel",
        severity="medium"
    )
    return "Access Denied", 403

@app.route("/config-backup", methods=["GET"])
def trap_config_backup():
    honey_logger.log_event(
        timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        ip=request.remote_addr,
        endpoint=request.path,
        method=request.method,
        event_type="access_denied_trap",
        details="Attempted access to fake config backup",
        severity="medium"
    )
    return "Access Denied", 403

@app.route("/api/contact", methods=["POST"])
def api_contact():
    entry = make_entry(request)
    entry['api_call'] = 'contact'
    write_log(entry)
    return jsonify({"status": "success", "message": "Message received"})

@app.route("/download/<filename>", methods=["GET"])
def download_file(filename):
    entry = make_entry(request)
    entry['download_attempt'] = filename
    write_log(entry)
    honey_logger.log_event(
        timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        ip=request.remote_addr,
        endpoint=request.path,
        method=request.method,
        event_type="file_download_attempt",
        details={"filename": filename},
        severity="low"
    )
    return "File not found", 404

@app.route("/api/log", methods=["POST"])
def api_log():
    try:
        data = request.get_json(silent=True) or {}
        
        # Log via HoneyLogger (it will write to banking_logs.json)
        honey_logger.log_event(
            timestamp=data.get('timestamp') or datetime.datetime.now(datetime.timezone.utc).isoformat(),
            ip=request.remote_addr, # We use the direct IP as we don't trust client-sent IP for security logs
            endpoint=data.get('page_visited') or 'frontend_log',
            method="POST",
            event_type=data.get('event_type') or 'frontend_log',
            details=data.get('input_data') or data,
            severity="high" if data.get('is_suspicious') else "low"
        )
        
        # Also maintain legacy logging for now
        entry = make_entry(request)
        entry['client_log'] = data
        write_log(entry)

        return jsonify({"status": "logged"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route("/apply/<position>", methods=["GET","POST"])
def apply_position(position):
    entry = make_entry(request)
    entry['job_application'] = position
    write_log(entry)
    return "Application submitted successfully", 200

if __name__ == "__main__":
    # run on 0.0.0.0 for lab VMs; ensure you run in isolated network
    app.run(host="0.0.0.0", port=8080, debug=True)
