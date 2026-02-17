# 🛡️ SecureCorp — AI-Powered Cybersecurity Honeypot

A realistic cybersecurity company website that functions as a **honeypot**, silently logging all visitor activity, detecting attacks, and feeding data to an AI-powered SOC dashboard.

---

## 📋 Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Getting Started](#getting-started)
- [Test Credentials](#test-credentials)
- [Website Pages](#website-pages)
- [Honeypot Features](#honeypot-features)
- [Attack Detection](#attack-detection)
- [Log Format](#log-format)
- [SOC Dashboard](#soc-dashboard)
- [File Structure](#file-structure)
- [Workflow](#workflow)

---

## Overview

SecureCorp presents itself as a legitimate cybersecurity company with a public website, customer portal, and admin portal. Behind the scenes, **every request is logged and analyzed** for malicious activity using both rule-based pattern matching and ML models (Isolation Forest + Random Forest).

## Architecture

```
┌──────────────────────────────────────────────────────┐
│                    Browser / Attacker                  │
└──────────────┬───────────────────────────┬────────────┘
               │                           │
    ┌──────────▼──────────┐    ┌───────────▼───────────┐
    │  Flask Honeypot     │    │  Streamlit Dashboard   │
    │  (port 8080)        │    │  (port 8501)           │
    │                     │    │                        │
    │  • Public Pages     │    │  • KPI Metrics         │
    │  • Customer Portal  │    │  • Event Charts        │
    │  • Admin Portal     │    │  • Attack Log Viewer   │
    │  • Trap Routes      │    │  • Trap Hit Monitor    │
    │  • Attack Detection │    │  • Upload Tracker      │
    └──────────┬──────────┘    └───────────┬───────────┘
               │                           │
               ▼                           ▼
    ┌──────────────────────────────────────────────────┐
    │           logs/honeypot_logs.json                  │
    │  (JSONL — one JSON object per line)               │
    └──────────────────────┬───────────────────────────┘
                           │
                ┌──────────▼──────────┐
                │   ML Models          │
                │  • IsolationForest   │
                │  • RandomForest      │
                │  (models/ directory) │
                └─────────────────────┘
```

## Getting Started

### Prerequisites

```bash
pip install flask pandas scikit-learn joblib streamlit requests
```

### Step 1: Start the Honeypot

```bash
python honeypot.py
```

Runs on **http://localhost:8080**

### Step 2: Generate Training Data

```bash
python simulate_traffic.py
```

Sends benign browsing, customer logins, SQLi attacks, XSS payloads, brute force attempts, and trap probes.

### Step 3: Parse Logs & Train Models

```bash
python log_parser.py
python train_models.py
```

### Step 4: Start the SOC Dashboard

```bash
python -m streamlit run dashboard.py
```

Runs on **http://localhost:8501**

### Step 5: Monitor in Real-Time (Optional)

```bash
python predict_service.py
```

Prints live ML predictions for incoming log entries.

---

## Test Credentials

### Customer Portal (`/customer/login`)

| Username | Password |
|---|---|
| `demo` | `demo123` |
| `customer@securecorp.com` | `SecurePass123` |

### Admin Portal (`/admin/login`)

| Username | Password |
|---|---|
| `admin@securecorp.com` | `AdminSecure!456` |

> ⚠️ These are **honeypot credentials** — all logins are trapped and logged.

---

## Website Pages

### Public Landing Page
| Route | Description |
|---|---|
| `/` | Home — company description, features, stats |
| `/services` | Services offered |
| `/about` | About the company |
| `/blog` | Company blog |
| `/careers` | Career listings |
| `/contact` | Contact form (submissions logged) |
| `/register` | Registration form (logged) |
| `/forgot-password` | Password reset (logged) |

### Customer Portal
| Route | Description |
|---|---|
| `/customer/login` | Customer login |
| `/customer/dashboard` | Dashboard — submit queries, upload files, view responses |
| `/customer/query` | POST — submit a query |
| `/customer/upload` | POST — upload PDF/documents |
| `/customer/logout` | Logout |

### Admin Portal
| Route | Description |
|---|---|
| `/admin/login` | Admin login |
| `/admin/dashboard` | View customer queries & uploaded files |
| `/admin/logout` | Logout |

---

## Honeypot Features

### Trap Routes

These routes exist solely to catch attackers probing for vulnerabilities. They **log access and deny entry**.

| Route | Response | Severity |
|---|---|---|
| `/admin-panel` | 403 Forbidden | High |
| `/debug-console` | 403 Forbidden | High |
| `/wp-admin` | 404 Not Found | High |
| `/phpmyadmin` | 404 Not Found | High |
| `/.env` | 404 Not Found | Critical |

### What Gets Logged

- ✅ All page views and navigation
- ✅ Login attempts (success and failure)
- ✅ Form submissions (contact, registration, queries)
- ✅ File uploads (with content scanning)
- ✅ Client-side interactions (clicks, key sequences, mouse patterns via JS)
- ✅ API requests
- ✅ Brute force detection (>5 failed logins / 5 min from same IP)

---

## Attack Detection

### SQL Injection (15 patterns)
Detects: `' OR 1=1--`, `UNION SELECT`, `DROP TABLE`, `'; DELETE`, `admin'--`, `1=1`, `sleep()`, `benchmark()`, and more.

### Cross-Site Scripting (9 patterns)
Detects: `<script>`, `javascript:`, `onerror=`, `onload=`, `<svg>`, `<iframe>`, `eval()`, `document.cookie`, `alert()`.

### Brute Force Login
Tracks failed login attempts per IP. Flags when >5 attempts occur within a 5-minute window.

### Malicious File Uploads
- **Extension check**: `.exe`, `.bat`, `.sh`, `.php`, `.jsp`, `.asp`, `.cmd`, `.ps1`, `.py`
- **Content scan**: Detects `<script>`, `<?php`, `#!/`, `import os`, `exec()`, `eval()` in first 4KB

---

## Log Format

All logs are appended to `logs/honeypot_logs.json` (one JSON object per line):

```json
{
  "timestamp": "2026-02-17T05:01:23.456789+00:00",
  "ip": "127.0.0.1",
  "endpoint": "/customer/login",
  "method": "POST",
  "event_type": "attack_detected",
  "severity": "critical",
  "details": {
    "portal": "customer",
    "username": "' OR 1=1--",
    "attack_type": "SQL Injection",
    "attack_patterns": ["' OR 1=1"]
  },
  "headers": {"User-Agent": "Mozilla/5.0 ..."},
  "args": {},
  "form": {"username": "' OR 1=1--", "password": "pass"},
  "data": "",
  "predicted_class": "sqli",
  "is_anomaly": true
}
```

### Event Types

| Event Type | Description |
|---|---|
| `page_view` | Normal page navigation |
| `login_attempt` | Login attempt (any portal) |
| `login_success` | Successful login |
| `admin_login_attempt` | Admin login attempt |
| `brute_force_detected` | IP exceeded login threshold |
| `attack_detected` | SQLi / XSS detected |
| `form_submit` | Contact or other form submission |
| `query_submit` | Customer query submission |
| `file_upload` | Clean file upload |
| `suspicious_upload` | File with suspicious content/extension |
| `honeypot_trap` | Trap route accessed |
| `registration_attempt` | New user registration |
| `password_reset` | Password reset request |
| `logout` | User logout |
| `client_log` | Client-side JS interaction log |

### Severity Levels

| Level | Color | Meaning |
|---|---|---|
| `low` | 🟢 Green | Normal activity |
| `medium` | 🟡 Yellow | Suspicious but not confirmed |
| `high` | 🟠 Orange | Likely attack / trap hit |
| `critical` | 🔴 Red | Confirmed attack / malicious upload |

---

## SOC Dashboard

The Streamlit dashboard (`dashboard.py`) provides:

- **KPI metrics**: Total events, attacks, anomalies, trap hits, brute force, uploads
- **Charts**: Event type distribution, severity breakdown, ML classification
- **Tabbed views**: All Events, Attacks, Traps, Uploads
- **Filters**: By severity, event type, anomalies only
- **Export**: Download features CSV or raw logs JSON

---

## File Structure

```
isproject-main/
├── honeypot.py              # Flask honeypot server (port 8080)
├── dashboard.py             # Streamlit SOC dashboard (port 8501)
├── log_parser.py            # Feature extraction from logs
├── train_models.py          # ML model training (IsolationForest + RF)
├── predict_service.py       # Real-time prediction monitor
├── simulate_traffic.py      # Traffic generator for testing
├── templates/
│   ├── base.html            # Base template (nav, CSS, JS logging)
│   ├── index.html           # Landing page
│   ├── services.html        # Services page
│   ├── about.html           # About page
│   ├── blog.html            # Blog page
│   ├── careers.html         # Careers page
│   ├── contact.html         # Contact form
│   ├── login.html           # Legacy login (redirects to customer)
│   ├── register.html        # Registration form
│   ├── forgot-password.html # Password reset
│   ├── customer_login.html  # Customer portal login
│   ├── customer_dashboard.html # Customer dashboard
│   ├── admin_login.html     # Admin portal login
│   └── admin_dashboard.html # Admin dashboard
├── logs/
│   ├── honeypot_logs.json   # All honeypot logs (JSONL)
│   └── features.csv         # Extracted features for ML
├── models/
│   ├── isolation_forest.joblib  # Anomaly detection model
│   └── rf_attack_classifier.joblib  # Attack classification model
└── uploads/                 # Uploaded files (evidence collection)
```

---

## Workflow

```
1. Start honeypot        →  python honeypot.py
2. Generate traffic      →  python simulate_traffic.py
3. Parse logs            →  python log_parser.py
4. Train models          →  python train_models.py
5. Start dashboard       →  streamlit run dashboard.py
6. (Optional) Monitor    →  python predict_service.py
```

---

© 2026 SecureCorp — AI-Powered Honeypot System
