# simulate_traffic.py — Generate diverse traffic for SecureCorp honeypot
import requests, random, time
BASE = "http://127.0.0.1:8080"
UA = "Mozilla/5.0 (compatible; DemoBot/1.0)"
session = requests.Session()
session.headers.update({"User-Agent": UA})

# ── Payloads ────────────────────────────────────────────────────────────────
sqli_payloads = [
    "' OR 1=1--", "' OR '1'='1", "'; DROP TABLE users; --",
    "' UNION SELECT null--", "admin'--", "' OR ''='",
    "1' OR '1'='1'--", "' OR 1=1#", "') OR ('1'='1",
    "1; DROP TABLE users", "' UNION SELECT username,password FROM users--",
    "' AND 1=1--", "' OR 'x'='x", "'; EXEC xp_cmdshell('dir')--",
]

xss_payloads = [
    '<script>alert(1)</script>', '<img src=x onerror=alert(1)>',
    '<svg/onload=alert(1)>', '<body onload=alert(1)>',
    'javascript:alert(1)', '<iframe src="javascript:alert(1)">',
]

benign_logins = [
    {"username": "john", "password": "password123"},
    {"username": "customer@securecorp.com", "password": "SecurePass123"},
    {"username": "demo", "password": "demo123"},
    {"username": "alice.smith", "password": "alicePass!"},
    {"username": "bob_jones", "password": "BobJ2024"},
]

benign_paths = ["/", "/services", "/about", "/blog", "/careers", "/contact"]
trap_paths = ["/admin-panel", "/debug-console", "/wp-admin", "/phpmyadmin", "/.env"]

# ── Traffic generators ──────────────────────────────────────────────────────
def send_benign_browsing(n=30):
    print(f"  Browsing {n} benign pages...")
    for _ in range(n):
        try:
            session.get(BASE + random.choice(benign_paths), timeout=2)
        except:
            pass
        time.sleep(0.05)

def send_benign_logins(n=15):
    print(f"  Sending {n} benign customer logins...")
    for _ in range(n):
        creds = random.choice(benign_logins)
        try:
            session.post(BASE + "/customer/login", data=creds, timeout=2)
        except:
            pass
        time.sleep(0.05)

def send_sqli_attacks():
    print(f"  Sending {len(sqli_payloads)} SQLi attacks...")
    for p in sqli_payloads:
        try:
            session.post(BASE + "/customer/login",
                         data={"username": p, "password": "pass"}, timeout=2)
        except:
            pass
        time.sleep(0.05)

def send_xss_attacks():
    print(f"  Sending {len(xss_payloads)} XSS attacks...")
    for p in xss_payloads:
        try:
            session.get(BASE + "/contact?q=" + requests.utils.quote(p), timeout=2)
        except:
            pass
        time.sleep(0.05)

def send_brute_force(n=8):
    print(f"  Sending {n} brute force login attempts...")
    for _ in range(n):
        try:
            session.post(BASE + "/customer/login",
                         data={"username": "admin", "password": f"guess{random.randint(1,9999)}"}, timeout=2)
        except:
            pass
        time.sleep(0.05)

def send_admin_brute(n=6):
    print(f"  Sending {n} admin brute force attempts...")
    for _ in range(n):
        try:
            session.post(BASE + "/admin/login",
                         data={"username": "admin", "password": f"pass{random.randint(1,9999)}"}, timeout=2)
        except:
            pass
        time.sleep(0.05)

def send_trap_probes():
    print(f"  Probing {len(trap_paths)} honeypot traps...")
    for p in trap_paths:
        try:
            session.get(BASE + p, timeout=2)
        except:
            pass
        time.sleep(0.05)

def send_contact_forms(n=5):
    print(f"  Submitting {n} contact forms...")
    for _ in range(n):
        try:
            session.post(BASE + "/contact", data={
                "name": f"User{random.randint(1,100)}",
                "email": f"user{random.randint(1,100)}@example.com",
                "message": "I'd like to learn more about your security services."
            }, timeout=2)
        except:
            pass
        time.sleep(0.05)

def send_customer_queries(n=5):
    print(f"  Submitting {n} customer queries...")
    # Login first
    try:
        session.post(BASE + "/customer/login",
                     data={"username": "demo", "password": "demo123"}, timeout=2)
    except:
        pass
    for _ in range(n):
        try:
            session.post(BASE + "/customer/query", data={
                "query": f"How do I configure firewall rule #{random.randint(1,100)}?"
            }, timeout=2)
        except:
            pass
        time.sleep(0.05)


if __name__ == "__main__":
    print("SecureCorp Traffic Simulator")
    print("=" * 40)
    send_benign_browsing(30)
    send_benign_logins(15)
    send_contact_forms(5)
    send_customer_queries(5)
    send_sqli_attacks()
    send_xss_attacks()
    send_brute_force(8)
    send_admin_brute(6)
    send_trap_probes()
    print("=" * 40)
    print("Done! Traffic simulation complete.")
