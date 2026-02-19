# port_scan_sim.py — Simulate port/service scanning against the honeypot
# Maps to MITRE ATT&CK T1046 (Discovery — Network Service Scanning)
#
# Usage:  python -m adversary_simulation.port_scan_sim
# Requires the honeypot to be running on http://127.0.0.1:8080

import requests
import time

BASE = "http://127.0.0.1:8080"

# Scanner-style User-Agents
SCANNER_UAS = [
    "Nmap Scripting Engine; https://nmap.org/book/nse.html",
    "Mozilla/5.0 (compatible; Nikto/2.1.6)",
    "DirBuster-1.0-RC1 (http://www.owasp.org/)",
    "sqlmap/1.6.4#stable (https://sqlmap.org)",
    "Mozilla/5.0 zgrab/0.x",
]

# Paths to probe — includes honeypot traps + common recon paths
PROBE_PATHS = [
    # Existing honeypot traps (will trigger honeypot_trap events)
    "/admin-panel",
    "/debug-console",
    "/wp-admin",
    "/phpmyadmin",
    "/.env",
    # Additional common recon targets
    "/robots.txt",
    "/.git/config",
    "/wp-login.php",
    "/administrator",
    "/cpanel",
    "/server-status",
    "/api/v1/users",
    "/backup.sql",
    "/config.php",
    "/test",
    "/.htaccess",
    "/actuator/health",
    "/swagger.json",
    "/graphql",
    "/api/debug",
]


def simulate_port_scan():
    """Probe known paths with scanner-like User-Agents."""
    print(f"\n[PORT SCAN] Probing {len(PROBE_PATHS)} paths with scanner User-Agents ...")
    session = requests.Session()
    hits = 0
    for i, path in enumerate(PROBE_PATHS):
        ua = SCANNER_UAS[i % len(SCANNER_UAS)]
        session.headers.update({"User-Agent": ua})
        try:
            r = session.get(f"{BASE}{path}", timeout=3, allow_redirects=False)
            status = r.status_code
            hits += 1
            marker = "🪤 TRAP" if status == 403 or (status == 404 and path in ["/wp-admin", "/phpmyadmin", "/.env"]) else ""
            print(f"  [{i+1}/{len(PROBE_PATHS)}] {path:30s}  →  HTTP {status}  {marker}")
        except requests.RequestException as e:
            print(f"  [{i+1}/{len(PROBE_PATHS)}] {path:30s}  →  FAILED ({e})")
        time.sleep(0.15)  # realistic scan cadence

    print(f"\n[PORT SCAN] {hits}/{len(PROBE_PATHS)} paths probed.")


def simulate_head_scan():
    """Send HEAD requests — common in service fingerprinting."""
    head_paths = ["/", "/services", "/about", "/customer/login", "/admin/login"]
    print(f"\n[HEAD SCAN] Sending HEAD requests to {len(head_paths)} endpoints ...")
    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0 (compatible; ServiceScanner/1.0)"})
    for path in head_paths:
        try:
            r = session.head(f"{BASE}{path}", timeout=3)
            print(f"  HEAD {path:30s}  →  HTTP {r.status_code}")
        except requests.RequestException as e:
            print(f"  HEAD {path:30s}  →  FAILED ({e})")
        time.sleep(0.1)


if __name__ == "__main__":
    print("=" * 60)
    print("  ADVERSARY SIMULATION — Port / Service Scan (T1046)")
    print("=" * 60)
    simulate_port_scan()
    simulate_head_scan()
    print("\n" + "=" * 60)
    print("  Port scan simulation complete.")
    print("  Check logs/honeypot_logs.json for honeypot_trap events.")
    print("=" * 60)
