import streamlit as st
import pandas as pd, json, joblib, os, io
from log_parser import extract_features, LOGPATH
from datetime import datetime

st.set_page_config(page_title="SecureCorp SOC Dashboard", layout="wide")
st.title("🛡️ SecureCorp — SOC Monitoring Dashboard")
st.markdown("---")

# Sidebar
with st.sidebar:
    st.header("🔧 Controls")
    show_raw = st.checkbox("Show raw log details", value=True)
    filter_anomalies = st.checkbox("Only anomalies", value=False)
    filter_severity = st.selectbox("Filter by severity", ["all", "low", "medium", "high", "critical"])
    filter_event = st.selectbox("Filter by event type", ["all", "attack_detected", "login_attempt",
                                "honeypot_trap", "brute_force_detected", "suspicious_upload",
                                "page_view", "form_submit", "query_submit", "file_upload"])
    refresh = st.button("🔄 Refresh")

# ── Load models ─────────────────────────────────────────────────────────────
model_iso = None
model_rf = None
try:
    model_iso = joblib.load(os.path.join("models", "isolation_forest.joblib"))
    model_rf = joblib.load(os.path.join("models", "rf_attack_classifier.joblib"))
except Exception:
    st.sidebar.warning("⚠️ Models not loaded — run `train_models.py`")


def load_logs():
    rows = []
    try:
        with open(LOGPATH) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    except FileNotFoundError:
        return []
    return rows


def get_severity_icon(severity):
    icons = {"low": "🟢", "medium": "🟡", "high": "🟠", "critical": "🔴"}
    return icons.get(str(severity).lower(), "⚪")


def format_ts(ts):
    try:
        dt = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return str(ts)


# ── Load and process ────────────────────────────────────────────────────────
logs = load_logs()
if not logs:
    st.info("No logs found. Start the honeypot (`python honeypot.py`) and generate traffic.")
    st.stop()

# Extract features — produces a flat dict per entry
feats = [extract_features(r) for r in logs]
fdf = pd.DataFrame(feats).fillna(0)

# Carry stored predictions
fdf["stored_class"] = [r.get("predicted_class", "benign") for r in logs]
fdf["stored_anomaly"] = [r.get("is_anomaly", False) for r in logs]
fdf["event_type"] = [r.get("event_type", "request") for r in logs]
fdf["severity"] = [r.get("severity", "low") for r in logs]

# Parse timestamps
if "time" in fdf.columns:
    fdf["time"] = pd.to_datetime(fdf["time"], errors="coerce")

# Method encoding
fdf["method_code"] = fdf["method"].map({"GET": 0, "POST": 1}).fillna(2).astype(int)

# Feature vector for ML models — MUST match training
feature_cols = ["path_len", "ua_len", "data_len", "count_sql_tokens",
                "count_xss_tokens", "num_params", "method_code", "has_sql_special_chars"]
for col in feature_cols:
    if col not in fdf.columns:
        fdf[col] = 0
X = fdf[feature_cols]

# ML predictions (only if models loaded)
if model_rf is not None:
    try:
        fdf["pred"] = model_rf.predict(X)
    except Exception as e:
        st.sidebar.error(f"RF prediction error: {e}")
        fdf["pred"] = 0
else:
    fdf["pred"] = 0

if model_iso is not None:
    try:
        fdf["anomaly"] = model_iso.predict(X)
    except Exception as e:
        st.sidebar.error(f"ISO prediction error: {e}")
        fdf["anomaly"] = 1
else:
    fdf["anomaly"] = 1

# ── Apply filters ───────────────────────────────────────────────────────────
view = fdf.copy()
if filter_anomalies:
    view = view[view["anomaly"] == -1]
if filter_severity != "all":
    view = view[view["severity"] == filter_severity]
if filter_event != "all":
    view = view[view["event_type"] == filter_event]

# ═══════════════════════════════════════════════════════════════════════════
# KPI ROW
# ═══════════════════════════════════════════════════════════════════════════
total = len(fdf)
attacks = fdf["stored_class"].isin(["sqli", "xss", "malicious_upload"]).sum()
anomalies = int((fdf["anomaly"] == -1).sum())
traps = int((fdf["event_type"] == "honeypot_trap").sum())
brute = int((fdf["event_type"] == "brute_force_detected").sum())
uploads = int(fdf["event_type"].isin(["file_upload", "suspicious_upload"]).sum())

k1, k2, k3, k4, k5, k6 = st.columns(6)
k1.metric("Total Events", total)
k2.metric("🔴 Attacks", int(attacks))
k3.metric("⚠️ Anomalies", anomalies)
k4.metric("🪤 Trap Hits", traps)
k5.metric("🔓 Brute Force", brute)
k6.metric("📁 Uploads", uploads)

# ═══════════════════════════════════════════════════════════════════════════
# CHARTS
# ═══════════════════════════════════════════════════════════════════════════
st.subheader("📊 Distribution")
c1, c2, c3 = st.columns(3)

with c1:
    st.write("**Event Types**")
    et_counts = fdf["event_type"].value_counts()
    st.bar_chart(et_counts)

with c2:
    st.write("**Severity Levels**")
    sev_counts = fdf["severity"].value_counts()
    st.bar_chart(sev_counts)

with c3:
    st.write("**ML Classification**")
    labels = {0: "benign", 1: "sqli", 2: "xss"}
    pred_counts = fdf["pred"].map(labels).value_counts()
    st.bar_chart(pred_counts)

# ═══════════════════════════════════════════════════════════════════════════
# DETAILED EVENT LOG
# ═══════════════════════════════════════════════════════════════════════════
st.subheader("🔍 Security Events")
tab1, tab2, tab3, tab4 = st.tabs(["📋 All Events", "🚨 Attacks", "🪤 Traps", "📁 Uploads"])

with tab1:
    recent = view.sort_values("time", ascending=False).head(80) if "time" in view else view.tail(80)
    for idx, row in recent.iterrows():
        sev = str(row.get("severity", "low"))
        icon = get_severity_icon(sev)
        ts = format_ts(row.get("time", ""))
        ip = row.get("ip", "?")
        method = row.get("method", "?")
        path = row.get("path", "?")
        etype = row.get("event_type", "")
        label = f"{icon} {ts}  |  {ip}  |  {method} {path}  |  {etype}  |  {sev}"

        with st.expander(label, expanded=False):
            c1, c2 = st.columns(2)
            with c1:
                st.write(f"**IP:** {ip}")
                st.write(f"**Method:** {method}")
                st.write(f"**Path:** {path}")
                st.write(f"**Event:** {etype}")
                st.write(f"**Severity:** {icon} {sev}")
                pred_label = labels.get(int(row.get("pred", 0)), "unknown")
                st.write(f"**ML Class:** {pred_label}")
                st.write(f"**Anomaly:** {row.get('anomaly', 1) == -1}")
            with c2:
                if idx < len(logs):
                    entry = logs[idx]
                    details = entry.get("details", {})
                    if details:
                        st.write("**Details:**")
                        st.json(details)
                    if entry.get("form"):
                        st.write("**Form Data:**")
                        for k, v in entry["form"].items():
                            st.code(f"{k}: {v}")

with tab2:
    attack_view = fdf[fdf["stored_class"].isin(["sqli", "xss", "malicious_upload"])]
    if attack_view.empty:
        st.info("No attacks detected.")
    else:
        for idx, row in attack_view.sort_values("time", ascending=False).head(50).iterrows():
            sev = str(row.get("severity", "low"))
            icon = get_severity_icon(sev)
            entry = logs[idx] if idx < len(logs) else {}
            details = entry.get("details", {})
            st.error(f"{icon} **{row.get('stored_class', '').upper()}** — {row.get('ip', '?')} — {row.get('method', '?')} {row.get('path', '?')} — {format_ts(row.get('time', ''))}")
            if details.get("attack_patterns"):
                st.code(f"Patterns: {details['attack_patterns']}")
            if entry.get("form"):
                for k, v in entry["form"].items():
                    st.code(f"  {k}: {v}")

with tab3:
    trap_view = fdf[fdf["event_type"] == "honeypot_trap"]
    if trap_view.empty:
        st.info("No honeypot trap hits.")
    else:
        for idx, row in trap_view.sort_values("time", ascending=False).head(50).iterrows():
            entry = logs[idx] if idx < len(logs) else {}
            st.warning(f"🪤 {row.get('ip', '?')} hit **{row.get('path', '?')}** at {format_ts(row.get('time', ''))}")
            if entry.get("details", {}).get("description"):
                st.caption(entry["details"]["description"])

with tab4:
    upload_view = fdf[fdf["event_type"].isin(["file_upload", "suspicious_upload"])]
    if upload_view.empty:
        st.info("No file uploads recorded.")
    else:
        for idx, row in upload_view.sort_values("time", ascending=False).head(50).iterrows():
            entry = logs[idx] if idx < len(logs) else {}
            details = entry.get("details", {})
            icon = "⚠️" if row.get("event_type") == "suspicious_upload" else "📄"
            st.write(f"{icon} **{details.get('filename', '?')}** ({details.get('file_size', 0)} bytes) — {details.get('user', '?')} — {format_ts(row.get('time', ''))}")
            if details.get("suspicions"):
                for s in details["suspicions"]:
                    st.error(f"  🚨 {s}")

# ── Export ──────────────────────────────────────────────────────────────────
st.subheader("📥 Export")
c1, c2 = st.columns(2)
with c1:
    csv_buf = io.StringIO()
    fdf.to_csv(csv_buf, index=False)
    st.download_button("Download Features CSV", csv_buf.getvalue(),
                       file_name="securecorp_features.csv", mime="text/csv")
with c2:
    log_str = json.dumps(logs, indent=2, default=str)
    st.download_button("Download Raw Logs JSON", log_str,
                       file_name="securecorp_logs.json", mime="application/json")

st.caption("SecureCorp SOC Dashboard | Models: IsolationForest (anomaly=-1) · RF (0=benign, 1=sqli, 2=xss)")
