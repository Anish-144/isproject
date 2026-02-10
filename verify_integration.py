import requests
import time
import json

BASE_URL = "http://localhost:8080"

def test_backend_health():
    try:
        r = requests.get(BASE_URL + "/")
        print(f"Backend Health: {r.status_code}")
    except Exception as e:
        print(f"Backend Health: Failed ({e})")

def test_log_endpoint():
    try:
        payload = {
            "event_type": "test_event",
            "input_data": {"test": "data"},
            "timestamp": "2024-01-01T00:00:00Z"
        }
        r = requests.post(BASE_URL + "/api/log", json=payload)
        print(f"Log Endpoint: {r.status_code} - {r.json()}")
    except Exception as e:
        print(f"Log Endpoint: Failed ({e})")

def test_trap_route():
    try:
        r = requests.get(BASE_URL + "/admin-panel")
        print(f"Trap Route (/admin-panel): {r.status_code}")
    except Exception as e:
        print(f"Trap Route: Failed ({e})")

def test_suspicious_log():
    try:
        payload = {
            "event_type": "form_submission",
            "input_data": {"username": "admin' OR 1=1 --"}, # SQLi pattern
            "timestamp": "2024-01-01T00:00:00Z"
        }
        r = requests.post(BASE_URL + "/api/log", json=payload)
        print(f"Suspicious Log Test: {r.status_code} - {r.json()}")
    except Exception as e:
        print(f"Suspicious Log Test: Failed ({e})")

if __name__ == "__main__":
    print("Verifying Honeypot Backend...")
    # We assume the user needs to start the server, but we can try to connect if it's already running? 
    # Or just print instructions. 
    # For this script to work, the server must be running.
    # Since we can't easily start the server in background and keep it running for this script in the same turn without issues,
    # We will just print what this script DOES, or try to run it if we start the server.
    
    # Actually, I can try to start the server in a background process, wait a bit, run tests, then kill it.
    pass
