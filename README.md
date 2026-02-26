# 🛡️ SecureCorp AI-SIEM — Honeypot-Based Threat Detection & SOC Dashboard

![Python](https://img.shields.io/badge/Python-3.8+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-2.x-000000?style=for-the-badge&logo=flask&logoColor=white)
![Streamlit](https://img.shields.io/badge/Streamlit-1.x-FF4B4B?style=for-the-badge&logo=streamlit&logoColor=white)
![scikit-learn](https://img.shields.io/badge/scikit--learn-ML-F7931E?style=for-the-badge&logo=scikitlearn&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-22c55e?style=for-the-badge)

An enterprise-grade, AI-powered Security Information and Event Management (SIEM) platform built with Python. It combines a fully functional **Flask honeypot** with a **Streamlit SOC dashboard** featuring real-time threat detection, ML-based classification, MITRE ATT&CK mapping, automated response, and PDF executive reporting.

---

## 📸 Features at a Glance

| Feature | Description |
|---|---|
| 🐝 **Honeypot Server** | Flask-based trap with fake login portals, file upload, admin panels, and hidden endpoints |
| 🧠 **AI Threat Analysis** | Deterministic threat intelligence engine with reasoning, impact, and mitigation steps |
| 📊 **SOC Dashboard** | Enterprise SIEM interface with sidebar navigation, KPI cards, and Plotly charts |
| 🗺️ **Attack Map** | Interactive Folium world map with geo-located attacker pins |
| 🎯 **MITRE ATT&CK** | Auto-enrichment of detected attacks with MITRE technique IDs and tactics |
| 🤖 **ML Models** | Isolation Forest (anomaly) + Random Forest (classification) trained on log features |
| 🚫 **Auto-Response** | IP auto-blocking on critical events with persistent blocklist |
| 📂 **Case Management** | Create, track, and resolve security cases with JSON persistence |
| 📄 **PDF Reports** | Enterprise executive reports with cover page, metrics table, threat analysis, and mitigations |
| 🔄 **Refresh Data** | One-click dashboard refresh button for live data updates |

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────┐
│                   SecureCorp AI-SIEM                     │
├──────────────────────┬──────────────────────────────────┤
│   Flask Honeypot     │      Streamlit SOC Dashboard     │
│   (Port 8080)        │      (Port 8501)                 │
├──────────────────────┼──────────────────────────────────┤
│ • Fake login portals │ • 📊 Dashboard (KPIs, charts)   │
│ • File upload traps  │ • 🐝 Live Honeypot Logs         │
│ • Admin panel traps  │ • 🧠 AI Threat Analysis         │
│ • Hidden endpoints   │ • 🛡 Mitigation Center          │
│ • Attack detection   │ • 📂 Case Management            │
│ • Brute force detect │ • 📊 Reports & PDF Export       │
├──────────────────────┴──────────────────────────────────┤
│  Shared: honeypot_logs.json  │  ML Models  │  Blocklist │
└─────────────────────────────────────────────────────────┘
```

---

## 📁 Project Structure

```
isproject-main/
├── honeypot.py              # Flask honeypot server (port 8080)
├── dashboard.py             # Streamlit SOC dashboard (port 8501)
├── threat_intel.py          # AI threat analysis engine (reasoning, mitigations)
├── case_manager.py          # Case management CRUD + enterprise PDF generation
├── log_parser.py            # Feature extraction from raw logs
├── mitre_mapping.py         # MITRE ATT&CK enrichment for detected attacks
├── response_engine.py       # Automated IP blocking & response actions
├── geo_lookup.py            # IP geolocation for attack map
├── train_models.py          # ML model training (Isolation Forest + Random Forest)
├── predict_service.py       # Prediction service for ML models
├── simulate_traffic.py      # Traffic simulation for testing
├── requirements.txt         # Python dependencies
├── .gitignore               # Git ignore rules
├── README.md                # This file
│
├── templates/               # Flask HTML templates (honeypot website)
│   ├── index.html           # Landing page
│   ├── services.html        # Services page
│   ├── about.html           # About page
│   ├── blog.html            # Blog page
│   ├── careers.html         # Careers page
│   ├── contact.html         # Contact form
│   ├── register.html        # Registration form
│   ├── forgot-password.html # Password reset
│   ├── login.html           # Legacy login
│   ├── customer_login.html  # Customer portal login
│   ├── customer_dashboard.html # Customer portal dashboard
│   ├── admin_login.html     # Admin portal login
│   └── admin_dashboard.html # Admin portal dashboard
│
├── adversary_simulation/    # Attack simulation scripts
│   ├── run_all_attacks.py   # Orchestrator for all attack types
│   ├── sqli_attack.py       # SQL injection simulation
│   ├── xss_attack.py        # XSS simulation
│   ├── brute_force.py       # Brute force simulation
│   └── file_upload.py       # Malicious upload simulation
│
├── logs/                    # Runtime data (gitignored)
│   ├── honeypot_logs.json   # Raw event logs
│   ├── features.csv         # Extracted ML features
│   ├── blocklist.json       # Auto-blocked IPs
│   └── cases.json           # Case management data
│
├── models/                  # Trained ML models (gitignored)
│   ├── isolation_forest.joblib
│   └── rf_attack_classifier.joblib
│
└── uploads/                 # Honeypot-collected files (gitignored)
```

---

## 🚀 Setup & Installation

### Prerequisites

- Python 3.8+
- pip

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/isproject-main.git
cd isproject-main
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Train ML Models

```bash
python train_models.py
```

> **Note:** If no log data exists yet, start the honeypot first, generate traffic, then train.

### 4. Start the Honeypot

```bash
python honeypot.py
```

The honeypot runs at **http://localhost:8080**

### 5. Launch the SOC Dashboard

```bash
python -m streamlit run dashboard.py
```

The dashboard runs at **http://localhost:8501**

### 6. (Optional) Simulate Attacks

```bash
python simulate_traffic.py
# or run specific attacks:
cd adversary_simulation
python run_all_attacks.py
```

---

## 🧠 AI Threat Analysis Engine

The `threat_intel.py` module provides structured threat intelligence for detected events:

| Field | Description |
|---|---|
| **Threat Type** | Classification (SQLi, XSS, Brute Force, Malicious Upload, Recon) |
| **AI Reasoning** | Detailed explanation of why the event is malicious |
| **Risk Score** | 0-100 score based on severity |
| **MITRE ATT&CK** | Mapped technique ID, name, and tactic |
| **Impact** | Potential damage description |
| **Mitigation Steps** | Immediate response actions |
| **Prevention Recommendations** | Long-term hardening measures |

---

## 📄 Executive PDF Reports

The system generates enterprise-grade PDF reports with:

1. **Cover Page** — Branding, date, event count, confidentiality notice
2. **Executive Summary** — Dynamic risk posture assessment
3. **Key Metrics Table** — Formatted statistics with alternating rows
4. **Threat Landscape** — Attack distribution, trends, top attacker IPs
5. **AI Threat Analysis** — Detailed per-threat breakdown with MITRE mapping
6. **Mitigations** — Aggregated response steps and prevention recommendations
7. **Blocklist & Actions** — Auto-blocked IPs and suggested follow-ups

---

## 🎯 Attack Detection

| Attack Type | Detection Method | Severity |
|---|---|---|
| SQL Injection | Regex pattern matching (15+ patterns) | 🔴 Critical |
| Cross-Site Scripting | Regex pattern matching (9+ patterns) | 🟠 High |
| Brute Force | Rate limiting (5 attempts / 5 min window) | 🟠 High |
| Malicious File Upload | Extension + content analysis | 🔴 Critical |
| Reconnaissance | Honeypot trap endpoint access | 🟠 High |

---

## 🗺️ MITRE ATT&CK Mapping

Detected attacks are auto-enriched with MITRE ATT&CK mappings:

| Technique ID | Name | Tactic |
|---|---|---|
| T1190 | Exploit Public-Facing Application | Initial Access |
| T1110 | Brute Force | Credential Access |
| T1059.007 | JavaScript Execution | Execution |
| T1595.002 | Vulnerability Scanning | Reconnaissance |

---

## ⚙️ Configuration

| Setting | Location | Default |
|---|---|---|
| Honeypot Port | `honeypot.py` | 8080 |
| Brute Force Threshold | `honeypot.py` | 5 attempts / 5 min |
| Log Rotation Size | `honeypot.py` | 10 MB |
| Block Duration | `response_engine.py` | Permanent |
| ML Feature Columns | `log_parser.py` | 8 features |

---

## 📦 Dependencies

```
flask
scikit-learn
joblib
pandas
streamlit
plotly
folium
streamlit-folium
fpdf2
```

---

## 👥 Team

Built as a cybersecurity project demonstrating honeypot deployment, ML-based threat detection, and enterprise SOC dashboard design.

---

## 📜 License

This project is for educational and demonstration purposes.
