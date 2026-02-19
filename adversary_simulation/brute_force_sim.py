# brute_force_sim.py — Simulate brute force attacks against the honeypot
# Maps to MITRE ATT&CK T1110 (Credential Access — Brute Force)
#
# Usage:  python -m adversary_simulation.brute_force_sim
# Requires the honeypot to be running on http://127.0.0.1:8080

import requests
import random
import time
import string

BASE = "http://127.0.0.1:8080"
UA = "Mozilla/5.0 (compatible; BruteBot/2.1)"

# ── Credential lists ────────────────────────────────────────────────────────
USERNAMES = [
    "admin", "root", "administrator", "test", "user",
    "admin@securecorp.com", "support", "info", "backup",
    "sysadmin", "operator", "service", "guest", "manager",
]

COMMON_PASSWORDS = [
    "password", "123456", "admin", "root", "letmein",
    "password123", "qwerty", "abc123", "monkey", "master",
    "dragon", "login", "welcome", "shadow", "sunshine",
]


def random_password():
    """Generate a random password guess."""
    return "".join(random.choices(string.ascii_letters + string.digits, k=random.randint(6, 12)))


def simulate_customer_brute_force(attempts=12):
    """Rapid login attempts against customer portal — triggers brute_force_detected."""
    print(f"\n[BRUTE FORCE] Sending {attempts} rapid login attempts to /customer/login ...")
    session = requests.Session()
    session.headers.update({"User-Agent": UA})
    success = 0
    for i in range(attempts):
        username = random.choice(USERNAMES)
        password = random.choice(COMMON_PASSWORDS) if random.random() < 0.5 else random_password()
        try:
            r = session.post(f"{BASE}/customer/login",
                             data={"username": username, "password": password}, timeout=3)
            success += 1
            print(f"  [{i+1}/{attempts}] {username}:{password}  →  HTTP {r.status_code}")
        except requests.RequestException as e:
            print(f"  [{i+1}/{attempts}] FAILED — {e}")
        time.sleep(0.1)  # fast but not instant — realistic brute cadence
    print(f"[BRUTE FORCE] Customer portal: {success}/{attempts} requests sent.\n")


def simulate_admin_brute_force(attempts=10):
    """Rapid login attempts against admin portal — triggers brute_force_detected."""
    print(f"[BRUTE FORCE] Sending {attempts} rapid login attempts to /admin/login ...")
    session = requests.Session()
    session.headers.update({"User-Agent": UA})
    success = 0
    for i in range(attempts):
        username = random.choice(["admin", "root", "administrator", "admin@securecorp.com"])
        password = random.choice(COMMON_PASSWORDS) if random.random() < 0.5 else random_password()
        try:
            r = session.post(f"{BASE}/admin/login",
                             data={"username": username, "password": password}, timeout=3)
            success += 1
            print(f"  [{i+1}/{attempts}] {username}:{password}  →  HTTP {r.status_code}")
        except requests.RequestException as e:
            print(f"  [{i+1}/{attempts}] FAILED — {e}")
        time.sleep(0.1)
    print(f"[BRUTE FORCE] Admin portal: {success}/{attempts} requests sent.\n")


if __name__ == "__main__":
    print("=" * 60)
    print("  ADVERSARY SIMULATION — Brute Force (T1110)")
    print("=" * 60)
    simulate_customer_brute_force(12)
    simulate_admin_brute_force(10)
    print("=" * 60)
    print("  Brute force simulation complete.")
    print("  Check logs/honeypot_logs.json for brute_force_detected events.")
    print("=" * 60)
