
# 🛡️ **AI-Powered Honeypot for Intelligent Threat Detection**

A **Flask-based cybersecurity honeypot** designed to simulate vulnerable services, capture real-time HTTP traffic, and apply **machine learning models** for automated threat analysis.
The system enables **anomaly detection, attack classification, real-time monitoring**, and **SOC-style visualization**, making it ideal for **blue-team research, SOC training, and academic demonstration**.

> ⚠️ **Lab / Educational Use Only**
> This project must be deployed only inside an **isolated virtual lab or sandbox network**.
> Never expose this honeypot to the public internet.

---

## 🚀 Features

* **Live Traffic Capture** — logs HTTP requests with structured JSON records
* **Feature Engineering Pipeline** — extracts security-relevant attributes from raw logs
* **Anomaly Detection** — identifies unknown and suspicious behavior using *Isolation Forest*
* **Attack Classification** — labels traffic as *Benign, SQLi, XSS* using *Random Forest*
* **Real-Time Prediction Engine** — continuously monitors new logs and performs live analysis
* **SOC-Style Dashboard** — interactive Streamlit UI for attack visualization & incident analysis

---

## 🧱 System Architecture

```
Client Traffic
      ↓
Flask Honeypot  →  Structured JSON Logs
      ↓
Feature Extraction (log_parser.py)
      ↓
Model Training (train_models.py)
      ↓
Live Prediction Engine (predict_service.py)
      ↓
SOC Dashboard (Streamlit)
```

---

## 🧠 Machine Learning Pipeline

### Feature Extraction

Security-focused features include:

* HTTP method, endpoint, response codes
* Payload length & character distribution
* Header patterns and frequency analysis
* Request rate & behavioral statistics

### Models Used

| Model            | Purpose                                 |
| ---------------- | --------------------------------------- |
| Isolation Forest | Detect anomalous & unknown behavior     |
| Random Forest    | Classify traffic as Benign / SQLi / XSS |

---

## 📊 Dashboard Capabilities

* Real-time attack visualization
* Anomaly timeline & severity scoring
* Top attacker IPs & endpoints
* Attack category distribution
* Model confidence & detection trends

---

## 🧪 Applications

* SOC workflow simulation
* Blue-team training & research
* AI-driven intrusion detection experiments
* Cybersecurity portfolio & academic projects

---

## 🔐 Security & Ethics

* Run only inside **isolated lab networks / VMs**
* Never use real credentials or sensitive data
* All attack payloads are **safe and non-destructive**
* Designed strictly for defensive security research

---

## 🧑‍💻 Author

**Anish Patel**
Cybersecurity | Blue Team | AI for Security


