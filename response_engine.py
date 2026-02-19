# response_engine.py — Automated response module for SecureCorp honeypot
# Handles IP blocking, blocklist management, and alert notifications.

import json
import os
import datetime

BLOCKLIST_FILE = os.path.join("logs", "blocklist.json")

# ── Blocklist management ────────────────────────────────────────────────────

def load_blocklist():
    """Load the blocklist from disk. Returns a dict {ip: {reason, timestamp}}."""
    if not os.path.exists(BLOCKLIST_FILE):
        return {}
    try:
        with open(BLOCKLIST_FILE, "r") as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        return {}


def save_blocklist(blocklist):
    """Save the blocklist dict to disk."""
    os.makedirs(os.path.dirname(BLOCKLIST_FILE), exist_ok=True)
    with open(BLOCKLIST_FILE, "w") as f:
        json.dump(blocklist, f, indent=2, default=str)


def block_ip(ip, reason="auto-blocked"):
    """Add an IP to the blocklist with a reason and timestamp."""
    blocklist = load_blocklist()
    if ip not in blocklist:
        blocklist[ip] = {
            "reason": reason,
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "blocked": True,
        }
        save_blocklist(blocklist)
        print(f"[RESPONSE ENGINE] 🚫 Blocked IP: {ip} — Reason: {reason}")
        return True
    return False  # already blocked


def unblock_ip(ip):
    """Remove an IP from the blocklist."""
    blocklist = load_blocklist()
    if ip in blocklist:
        del blocklist[ip]
        save_blocklist(blocklist)
        print(f"[RESPONSE ENGINE] ✅ Unblocked IP: {ip}")
        return True
    return False


def is_blocked(ip):
    """Check whether an IP is currently blocked."""
    blocklist = load_blocklist()
    return ip in blocklist


def get_blocked_count():
    """Return the number of currently blocked IPs."""
    return len(load_blocklist())


# ── Automated response logic ────────────────────────────────────────────────

def auto_respond(log_entry):
    """
    Evaluate a log entry and take automated action if warranted.

    Current policy:
        - severity == 'critical'  →  block the IP
        - severity == 'critical'  →  send alert (placeholder)

    This function is called inside the honeypot's build_log() pipeline.
    """
    severity = str(log_entry.get("severity", "")).lower()
    ip = log_entry.get("ip", "")

    if severity == "critical" and ip:
        details = log_entry.get("details", {})
        attack_type = details.get("attack_type", log_entry.get("event_type", "unknown"))
        reason = f"Critical event: {attack_type}"
        was_new = block_ip(ip, reason)
        if was_new:
            send_alert(log_entry)


# ── Alert functions (configurable / pluggable) ──────────────────────────────

def send_alert(log_entry):
    """
    Send an alert for a critical security event.

    Currently prints to console. To enable Telegram or email:
      1. Set environment variables (TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID)
         or (ALERT_EMAIL_TO, SMTP_HOST, etc.)
      2. Uncomment the relevant function below.

    This is intentionally modular — swap in your own notification backend.
    """
    ip = log_entry.get("ip", "?")
    severity = log_entry.get("severity", "?")
    event = log_entry.get("event_type", "?")
    details = log_entry.get("details", {})
    attack = details.get("attack_type", "N/A")
    mitre = log_entry.get("mitre_id", "N/A")
    ts = log_entry.get("timestamp", "?")

    msg = (
        f"🚨 CRITICAL ALERT 🚨\n"
        f"  Time:     {ts}\n"
        f"  IP:       {ip}\n"
        f"  Event:    {event}\n"
        f"  Attack:   {attack}\n"
        f"  MITRE:    {mitre}\n"
        f"  Severity: {severity}\n"
        f"  Action:   IP has been auto-blocked"
    )
    print(msg)

    # ── Optional: Telegram alert ────────────────────────────────────────────
    # send_telegram_alert(msg)

    # ── Optional: Email alert ───────────────────────────────────────────────
    # send_email_alert(msg)


def send_telegram_alert(message):
    """
    Send alert via Telegram Bot API.
    Requires env vars: TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID
    """
    import requests as req
    token = os.environ.get("TELEGRAM_BOT_TOKEN", "")
    chat_id = os.environ.get("TELEGRAM_CHAT_ID", "")
    if not token or not chat_id:
        return
    try:
        req.post(
            f"https://api.telegram.org/bot{token}/sendMessage",
            json={"chat_id": chat_id, "text": message, "parse_mode": "HTML"},
            timeout=5,
        )
    except Exception as e:
        print(f"[ALERT] Telegram send failed: {e}")


def send_email_alert(message):
    """
    Send alert via email (SMTP).
    Requires env vars: ALERT_EMAIL_TO, SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS
    """
    import smtplib
    from email.mime.text import MIMEText

    to_addr = os.environ.get("ALERT_EMAIL_TO", "")
    smtp_host = os.environ.get("SMTP_HOST", "")
    smtp_port = int(os.environ.get("SMTP_PORT", "587"))
    smtp_user = os.environ.get("SMTP_USER", "")
    smtp_pass = os.environ.get("SMTP_PASS", "")

    if not all([to_addr, smtp_host, smtp_user, smtp_pass]):
        return
    try:
        msg = MIMEText(message)
        msg["Subject"] = "🚨 SecureCorp Honeypot — Critical Alert"
        msg["From"] = smtp_user
        msg["To"] = to_addr
        with smtplib.SMTP(smtp_host, smtp_port) as server:
            server.starttls()
            server.login(smtp_user, smtp_pass)
            server.send_message(msg)
    except Exception as e:
        print(f"[ALERT] Email send failed: {e}")
