import streamlit as st
import pandas as pd, json, joblib, os, io
import plotly.express as px
import plotly.graph_objects as go
import folium
from streamlit_folium import st_folium
from log_parser import extract_features, LOGPATH
from datetime import datetime, date, timedelta
from geo_lookup import geolocate
from threat_intel import analyze_threat, get_all_mitigations
from response_engine import block_ip as do_block_ip, is_blocked
from case_manager import (get_cases, create_case, update_case_status,
                          generate_case_pdf, generate_executive_pdf, generate_mitigation_pdf)

# ═══════════════════════════════════════════════════════════════════════════════
# PAGE CONFIG
# ═══════════════════════════════════════════════════════════════════════════════
st.set_page_config(page_title="SecureCorp AI-SIEM", page_icon="🛡️",
                   layout="wide", initial_sidebar_state="expanded")

# ═══════════════════════════════════════════════════════════════════════════════
# ENTERPRISE DESIGN SYSTEM — CSS
# ═══════════════════════════════════════════════════════════════════════════════
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap');
html, body, [class*="css"] { font-family: 'Inter', sans-serif; }

/* ── Application Shell ────────────────────────────────────────────────── */
.stApp { background: #0B1220; color: #e2e8f0; }

/* ── Top Command Bar ──────────────────────────────────────────────────── */
.cmd-bar {
    background: linear-gradient(180deg, #111827 0%, #0F172A 100%);
    border-bottom: 1px solid #1e293b;
    padding: 12px 28px; display: flex; align-items: center; justify-content: space-between;
    margin: -1rem -1rem 0 -1rem; position: sticky; top: 0; z-index: 999;
}
.cmd-bar .brand { display: flex; align-items: center; gap: 12px; }
.cmd-bar .brand-icon { font-size: 1.5rem; }
.cmd-bar .brand-name { font-size: 1.05rem; font-weight: 700; color: #f1f5f9; letter-spacing: -0.3px; }
.cmd-bar .brand-tag {
    font-size: 0.6rem; background: #3b82f620; color: #60a5fa; padding: 2px 8px;
    border-radius: 4px; border: 1px solid #3b82f640; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px;
}
.cmd-bar .cmd-right { display: flex; align-items: center; gap: 16px; }
.cmd-bar .status-pill {
    display: flex; align-items: center; gap: 6px; font-size: 0.72rem;
    color: #94a3b8; background: #1e293b; padding: 5px 12px; border-radius: 6px; border: 1px solid #334155;
}
.cmd-bar .status-dot {
    width: 7px; height: 7px; border-radius: 50%; background: #22c55e;
    box-shadow: 0 0 6px #22c55e; animation: pulse 2s infinite;
}
@keyframes pulse { 0%,100%{opacity:1;} 50%{opacity:0.4;} }
.cmd-bar .alert-badge {
    position: relative; font-size: 1.1rem; cursor: pointer; color: #94a3b8;
}
.cmd-bar .alert-badge .count {
    position: absolute; top: -4px; right: -6px; background: #ef4444; color: white;
    font-size: 0.55rem; font-weight: 700; padding: 1px 4px; border-radius: 8px; min-width: 14px; text-align: center;
}

/* ── Page Header ──────────────────────────────────────────────────────── */
.page-header { margin: 20px 0 16px; }
.page-header h2 { font-size: 1.45rem; font-weight: 700; color: #f1f5f9; margin: 0 0 4px; }
.page-header .subtitle { font-size: 0.82rem; color: #64748b; font-weight: 400; }

/* ── Horizontal Filter Bar ────────────────────────────────────────────── */
.filter-bar {
    background: #111827; border: 1px solid #1e293b; border-radius: 10px;
    padding: 12px 20px; margin-bottom: 20px; display: flex; align-items: center; gap: 12px;
}

/* ── KPI Cards ────────────────────────────────────────────────────────── */
.kpi-card {
    background: linear-gradient(135deg, #111827 0%, #0F172A 100%);
    border: 1px solid #1e293b; border-radius: 12px; padding: 20px 18px;
    transition: all 0.25s ease; position: relative; overflow: hidden;
}
.kpi-card:hover { border-color: #334155; transform: translateY(-3px); box-shadow: 0 8px 25px rgba(0,0,0,0.3); }
.kpi-card .kpi-icon { font-size: 1.3rem; margin-bottom: 8px; opacity: 0.8; }
.kpi-card .kpi-value { font-size: 2.1rem; font-weight: 800; line-height: 1; margin-bottom: 6px; }
.kpi-card .kpi-label { font-size: 0.68rem; text-transform: uppercase; letter-spacing: 1.2px; color: #64748b; font-weight: 600; }
.kpi-card .kpi-trend { font-size: 0.7rem; color: #64748b; margin-top: 4px; }
.kpi-accent-red    { border-left: 3px solid #ef4444; } .kpi-accent-red .kpi-value { color: #ef4444; }
.kpi-accent-amber  { border-left: 3px solid #f59e0b; } .kpi-accent-amber .kpi-value { color: #f59e0b; }
.kpi-accent-blue   { border-left: 3px solid #3b82f6; } .kpi-accent-blue .kpi-value { color: #3b82f6; }
.kpi-accent-green  { border-left: 3px solid #22c55e; } .kpi-accent-green .kpi-value { color: #22c55e; }
.kpi-accent-purple { border-left: 3px solid #a855f7; } .kpi-accent-purple .kpi-value { color: #a855f7; }

/* ── Section Headers ──────────────────────────────────────────────────── */
.section-hdr {
    font-size: 0.95rem; font-weight: 600; color: #e2e8f0; margin: 24px 0 12px;
    padding-bottom: 8px; border-bottom: 1px solid #1e293b;
    display: flex; align-items: center; gap: 8px;
}

/* ── Cards / Panels ───────────────────────────────────────────────────── */
.panel {
    background: #111827; border: 1px solid #1e293b; border-radius: 12px;
    padding: 18px; margin-bottom: 16px; transition: border-color 0.2s;
}
.panel:hover { border-color: #334155; }
.panel-header { font-weight: 600; color: #f1f5f9; font-size: 0.88rem; margin-bottom: 10px; display: flex; align-items: center; gap: 8px; }

/* ── Alert Item ───────────────────────────────────────────────────────── */
.alert-item {
    background: #0F172A; border: 1px solid #1e293b; border-radius: 8px;
    padding: 10px 14px; margin-bottom: 6px; transition: all 0.2s;
    display: flex; align-items: center; gap: 10px;
}
.alert-item:hover { border-color: #334155; background: #111827; }
.alert-dot { width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0; }
.alert-dot-critical { background: #ef4444; box-shadow: 0 0 6px #ef444480; }
.alert-dot-high { background: #f59e0b; box-shadow: 0 0 6px #f59e0b80; }
.alert-dot-medium { background: #3b82f6; }
.alert-dot-low { background: #22c55e; }
.alert-info { flex: 1; }
.alert-info .alert-type { font-weight: 600; font-size: 0.8rem; color: #e2e8f0; }
.alert-info .alert-meta { font-size: 0.7rem; color: #64748b; margin-top: 2px; }

/* ── Severity badges ──────────────────────────────────────────────────── */
.sev-badge {
    display: inline-block; padding: 2px 10px; border-radius: 6px;
    font-size: 0.65rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px;
}
.sev-critical { background: #ef444420; color: #ef4444; border: 1px solid #ef444440; }
.sev-high { background: #f59e0b20; color: #f59e0b; border: 1px solid #f59e0b40; }
.sev-medium { background: #3b82f620; color: #3b82f6; border: 1px solid #3b82f640; }
.sev-low { background: #22c55e20; color: #22c55e; border: 1px solid #22c55e40; }

/* ── Risk badges ──────────────────────────────────────────────────────── */
.risk-badge { display: inline-block; padding: 4px 14px; border-radius: 8px; font-weight: 700; font-size: 0.82rem; }
.risk-red { background: #ef444420; color: #ef4444; border: 1px solid #ef444440; }
.risk-yellow { background: #f59e0b20; color: #f59e0b; border: 1px solid #f59e0b40; }
.risk-green { background: #22c55e20; color: #22c55e; border: 1px solid #22c55e40; }

/* ── Map container ────────────────────────────────────────────────────── */
.map-wrap { background: #111827; border: 1px solid #1e293b; border-radius: 12px; padding: 8px; overflow: hidden; }

/* ── Response card ────────────────────────────────────────────────────── */
.resp-card {
    background: #0F172A; border: 1px solid #1e293b; border-radius: 10px;
    padding: 14px 18px; margin-bottom: 8px; transition: border-color 0.2s;
}
.resp-card:hover { border-color: #334155; }
.resp-card .rc-title { font-weight: 600; color: #f1f5f9; font-size: 0.85rem; margin-bottom: 4px; }
.resp-card .rc-meta { color: #64748b; font-size: 0.73rem; }

/* ── AI Insight Widget ────────────────────────────────────────────────── */
.ai-widget {
    background: linear-gradient(135deg, #0F172A 0%, #111827 50%, #0F172A 100%);
    border: 1px solid #3b82f630; border-radius: 12px; padding: 20px;
    position: relative; overflow: hidden;
}
.ai-widget::before {
    content: ''; position: absolute; top: 0; left: 0; right: 0; height: 2px;
    background: linear-gradient(90deg, #3b82f6, #a855f7, #3b82f6); opacity: 0.6;
}
.ai-widget .ai-title { font-weight: 700; font-size: 0.9rem; color: #f1f5f9; margin-bottom: 10px; display: flex; align-items: center; gap: 8px; }
.ai-widget .ai-summary { font-size: 0.82rem; color: #94a3b8; line-height: 1.5; margin-bottom: 12px; }

/* ── Sidebar ──────────────────────────────────────────────────────────── */
section[data-testid="stSidebar"] { background: #0F172A; border-right: 1px solid #1e293b; }
section[data-testid="stSidebar"] .stMarkdown h1,
section[data-testid="stSidebar"] .stMarkdown h2,
section[data-testid="stSidebar"] .stMarkdown h3 { color: #f1f5f9; }
section[data-testid="stSidebar"] .stMarkdown h3 { font-size: 0.7rem; text-transform: uppercase; letter-spacing: 1.5px; color: #475569; font-weight: 600; margin: 16px 0 6px; }

/* ── Streamlit overrides ──────────────────────────────────────────────── */
[data-testid="stMetric"] { background: #111827; border: 1px solid #1e293b; border-radius: 10px; padding: 14px; }
[data-testid="stMetricValue"] { font-size: 1.6rem; font-weight: 700; }
.stTabs [data-baseweb="tab-list"] { gap:4px; background:#111827; border-radius:8px; padding:4px; border:1px solid #1e293b; }
.stTabs [data-baseweb="tab"] { background:transparent; border-radius:6px; color:#64748b; font-weight:500; font-size:0.8rem; padding:7px 14px; }
.stTabs [data-baseweb="tab"]:hover { color:#e2e8f0; background:#1e293b50; }
.stTabs [aria-selected="true"] { background:#1e293b; color:#f1f5f9; }
::-webkit-scrollbar { width: 5px; }
::-webkit-scrollbar-track { background: #0B1220; }
::-webkit-scrollbar-thumb { background: #1e293b; border-radius: 3px; }
.streamlit-expanderHeader { background: #111827; border-radius: 8px; }
div[data-testid="stExpander"] { border: 1px solid #1e293b; border-radius: 10px; }
</style>
""", unsafe_allow_html=True)

# ═══════════════════════════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════════════════════════
SEVERITY_BADGE = {"low": "🟢", "medium": "🟡", "high": "🟠", "critical": "🔴"}
SEVERITY_COLORS = {"critical": "#ef4444", "high": "#f59e0b", "medium": "#3b82f6", "low": "#22c55e"}
def get_severity_icon(s): return SEVERITY_BADGE.get(str(s).lower(), "⚪")
def risk_class(score):
    if score >= 70: return "risk-red"
    if score >= 40: return "risk-yellow"
    return "risk-green"
def format_ts(ts):
    try: return datetime.fromisoformat(str(ts).replace("Z", "+00:00")).strftime("%Y-%m-%d %H:%M:%S")
    except Exception: return str(ts)
def load_logs():
    rows = []
    try:
        with open(LOGPATH) as f:
            for line in f:
                line = line.strip()
                if not line: continue
                try: rows.append(json.loads(line))
                except json.JSONDecodeError: continue
    except FileNotFoundError: pass
    return rows
def load_blocklist():
    p = os.path.join("logs", "blocklist.json")
    if not os.path.exists(p): return {}
    try:
        with open(p) as f: return json.load(f)
    except: return {}

# ═══════════════════════════════════════════════════════════════════════════════
# LOAD DATA + MODELS
# ═══════════════════════════════════════════════════════════════════════════════
model_iso = model_rf = None
try:
    model_iso = joblib.load(os.path.join("models", "isolation_forest.joblib"))
    model_rf = joblib.load(os.path.join("models", "rf_attack_classifier.joblib"))
except Exception:
    pass

logs = load_logs()
blocklist = load_blocklist()

if not logs:
    st.info("No logs found. Start the honeypot (`python honeypot.py`) and generate traffic.")
    st.stop()

feats = [extract_features(r) for r in logs]
fdf = pd.DataFrame(feats).fillna(0)
fdf["stored_class"] = [r.get("predicted_class", "benign") for r in logs]
fdf["stored_anomaly"] = [r.get("is_anomaly", False) for r in logs]
fdf["event_type"] = [r.get("event_type", "request") for r in logs]
fdf["severity"] = [r.get("severity", "low") for r in logs]
fdf["mitre_id"] = [r.get("mitre_id", "") for r in logs]
fdf["mitre_name"] = [r.get("mitre_name", "") for r in logs]
fdf["mitre_tactic"] = [r.get("mitre_tactic", "") for r in logs]
fdf["attack_type"] = [r.get("details", {}).get("attack_type", "") for r in logs]
if "time" in fdf.columns: fdf["time"] = pd.to_datetime(fdf["time"], errors="coerce")
fdf["method_code"] = fdf["method"].map({"GET": 0, "POST": 1}).fillna(2).astype(int)
feature_cols = ["path_len", "ua_len", "data_len", "count_sql_tokens", "count_xss_tokens", "num_params", "method_code", "has_sql_special_chars"]
for col in feature_cols:
    if col not in fdf.columns: fdf[col] = 0
X = fdf[feature_cols]
if model_rf:
    try: fdf["pred"] = model_rf.predict(X)
    except: fdf["pred"] = 0
else: fdf["pred"] = 0
if model_iso:
    try: fdf["anomaly"] = model_iso.predict(X)
    except: fdf["anomaly"] = 1
else: fdf["anomaly"] = 1

attack_mask = fdf["stored_class"].isin(["sqli","xss","malicious_upload"]) | fdf["event_type"].isin(["attack_detected","brute_force_detected"])
attacks_total = int(attack_mask.sum())
if "time" in fdf.columns and pd.api.types.is_datetime64_any_dtype(fdf.get("time")):
    today_mask = fdf["time"].dt.date == date.today()
    attacks_today = int((attack_mask & today_mask).sum()) if today_mask.any() else attacks_total
else: attacks_today = attacks_total
critical_alerts = int((fdf["severity"] == "critical").sum())
unique_ips = int(fdf.loc[attack_mask, "ip"].nunique()) if "ip" in fdf.columns and attack_mask.any() else 0
blocked_count = len(blocklist)
freq_attack = "—"
if not fdf.loc[fdf["attack_type"]!="","attack_type"].empty:
    freq_attack = fdf.loc[fdf["attack_type"]!="","attack_type"].value_counts().index[0]

# Geo data
geo_rows = []
ae = fdf[attack_mask].copy()
if not ae.empty:
    for idx, row in ae.iterrows():
        ip = str(row.get("ip","127.0.0.1"))
        loc = geolocate(ip, f"{idx}-{row.get('event_type','')}")
        geo_rows.append({"ip":ip,"lat":loc["lat"],"lon":loc["lon"],"country":loc["country"],"city":loc["city"],
                         "severity":str(row.get("severity","low")),"attack_type":str(row.get("attack_type","Unknown")),
                         "event_type":str(row.get("event_type","")),"mitre_id":str(row.get("mitre_id","")),"mitre_name":str(row.get("mitre_name",""))})

PLOTLY_LAYOUT = dict(paper_bgcolor="#111827", plot_bgcolor="#111827",
    font=dict(family="Inter, sans-serif", color="#e2e8f0", size=12),
    margin=dict(l=20, r=20, t=40, b=20), legend=dict(bgcolor="rgba(0,0,0,0)", font=dict(size=11)))
COLOR_SEQ = ["#ef4444","#f59e0b","#3b82f6","#22c55e","#a855f7","#ec4899","#06b6d4","#f97316","#10b981","#8b5cf6"]
labels = {0: "benign", 1: "sqli", 2: "xss"}

# ═══════════════════════════════════════════════════════════════════════════════
# TOP COMMAND BAR
# ═══════════════════════════════════════════════════════════════════════════════
alert_count = critical_alerts
ml_status = "Online" if model_rf else "Offline"
st.markdown(f"""
<div class="cmd-bar">
    <div class="brand">
        <span class="brand-icon">🛡️</span>
        <span class="brand-name">SecureCorp AI-SIEM</span>
        <span class="brand-tag">Lab Mode</span>
    </div>
    <div class="cmd-right">
        <div class="status-pill"><span class="status-dot"></span> ML Models: {ml_status}</div>
        <div class="status-pill">🎯 MITRE ATT&CK Active</div>
        <div class="alert-badge">🔔<span class="count">{alert_count}</span></div>
    </div>
</div>
""", unsafe_allow_html=True)

# ═══════════════════════════════════════════════════════════════════════════════
# SIDEBAR — Sectioned Navigation (single radio for proper routing)
# ═══════════════════════════════════════════════════════════════════════════════
NAV_ITEMS = [
    "📊 Dashboard", "🐝 Live Honeypot Logs",
    "🧠 AI Threat Analysis", "🛡 Mitigation Center", "📂 Case Management",
    "📊 Reports",
]
with st.sidebar:
    st.markdown("### 🛡️ SecureCorp")
    st.caption("AI-Powered SIEM Platform")
    st.markdown("---")
    page = st.radio("Navigation", NAV_ITEMS, label_visibility="collapsed", key="nav_main")

# ═══════════════════════════════════════════════════════════════════════════════
# HORIZONTAL FILTER BAR (on applicable pages)
# ═══════════════════════════════════════════════════════════════════════════════
def render_filters():
    fc1, fc2, fc3, fc4, fc5, fc6 = st.columns([1.5,1.5,1,1,1,1])
    with fc1: f_sev = st.selectbox("Severity", ["all","low","medium","high","critical"], key="f_sev")
    with fc2: f_evt = st.selectbox("Event Type", ["all","attack_detected","login_attempt","honeypot_trap","brute_force_detected","suspicious_upload","page_view","form_submit","query_submit","file_upload","client_log"], key="f_evt")
    with fc3: f_from = st.date_input("From", value=date.today()-timedelta(days=30), key="f_from")
    with fc4: f_to = st.date_input("To", value=date.today(), key="f_to")
    with fc5: f_anom = st.checkbox("Only anomalies", key="f_anom")
    with fc6: f_raw = st.checkbox("Show details", value=True, key="f_raw")
    return f_sev, f_evt, f_from, f_to, f_anom, f_raw

def apply_filters(df, f_sev, f_evt, f_from, f_to, f_anom):
    v = df.copy()
    if f_anom: v = v[v["anomaly"] == -1]
    if f_sev != "all": v = v[v["severity"] == f_sev]
    if f_evt != "all": v = v[v["event_type"] == f_evt]
    if "time" in v.columns and pd.api.types.is_datetime64_any_dtype(v.get("time")):
        tm = v["time"].notna()
        if tm.any():
            v = v[~tm | ((v["time"] >= pd.Timestamp(f_from, tz="UTC")) & (v["time"] < pd.Timestamp(f_to, tz="UTC") + pd.Timedelta(days=1)))]
    return v

# ═══════════════════════════════════════════════════════════════════════════════
# PAGE ROUTING
# ═══════════════════════════════════════════════════════════════════════════════

# ──────────────── 📊 DASHBOARD ──────────────────────────────────────────────
if page == "📊 Dashboard":
    # Page header with refresh button
    ph_left, ph_right = st.columns([4, 1])
    with ph_left:
        st.markdown('<div class="page-header"><h2>Dashboard Overview</h2><div class="subtitle">Real-time attack monitoring and threat intelligence</div></div>', unsafe_allow_html=True)
    with ph_right:
        st.markdown('<div style="height:18px"></div>', unsafe_allow_html=True)
        if st.button("🔄 Refresh Data", key="refresh_btn", use_container_width=True):
            st.cache_data.clear()
            st.rerun()

    # Filters
    f_sev, f_evt, f_from, f_to, f_anom, f_raw = render_filters()
    view = apply_filters(fdf, f_sev, f_evt, f_from, f_to, f_anom)

    # KPI ROW
    k1, k2, k3, k4, k5 = st.columns(5)
    kpis = [(k1,"red","⚔️","Attacks Today",attacks_today,"events detected"),
            (k2,"amber","🚨","Critical Alerts",critical_alerts,"require response"),
            (k3,"blue","🌐","Unique Attackers",unique_ips,"distinct IPs"),
            (k4,"green","🚫","Blocked IPs",blocked_count,"auto-blocked"),
            (k5,"purple","🎯","Top Attack",freq_attack,"most frequent")]
    for col, accent, icon, label, val, trend in kpis:
        with col:
            fs = 'style="font-size:1rem"' if isinstance(val,str) and len(str(val))>4 else ""
            st.markdown(f'<div class="kpi-card kpi-accent-{accent}"><div class="kpi-icon">{icon}</div><div class="kpi-label">{label}</div><div class="kpi-value" {fs}>{val}</div><div class="kpi-trend">{trend}</div></div>', unsafe_allow_html=True)

    # ROW 2: Attack Timeline (8) + Active Alerts (4)
    st.markdown('<div class="section-hdr">📈 Threat Analytics</div>', unsafe_allow_html=True)
    r2_left, r2_right = st.columns([2, 1])

    with r2_left:
        st.markdown('<div class="panel"><div class="panel-header">📈 Attack Timeline</div></div>', unsafe_allow_html=True)
        if "time" in fdf.columns and pd.api.types.is_datetime64_any_dtype(fdf.get("time")):
            atk = fdf[attack_mask & fdf["time"].notna()].copy()
            if not atk.empty:
                atk["hour"] = atk["time"].dt.floor("h")
                hourly = atk.groupby("hour").size().reset_index(); hourly.columns = ["Time","Attacks"]
                fig = px.area(hourly, x="Time", y="Attacks", color_discrete_sequence=["#ef4444"])
                fig.update_layout(**PLOTLY_LAYOUT, title=None, height=280)
                fig.update_traces(line=dict(width=2), fillcolor="rgba(239,68,68,0.1)")
                st.plotly_chart(fig, use_container_width=True, key="d_timeline")
            else: st.info("No timestamped attack events.")
        else: st.info("No timestamp data.")

    with r2_right:
        st.markdown('<div class="panel"><div class="panel-header">🚨 Active Alerts</div></div>', unsafe_allow_html=True)
        hi_events = fdf[fdf["severity"].isin(["critical","high"])].copy()
        if not hi_events.empty:
            for alert_i, (_, row) in enumerate(hi_events.sort_values("time", ascending=False).head(8).iterrows()):
                sev = str(row.get("severity","low"))
                atk = row.get("attack_type","") or row.get("event_type","")
                aip = str(row.get("ip","?"))
                blocked_tag = ' <span class="sev-badge sev-low">BLOCKED</span>' if is_blocked(aip) else ''
                st.markdown(f"""<div class="alert-item">
                    <div class="alert-dot alert-dot-{sev}"></div>
                    <div class="alert-info">
                        <div class="alert-type">{atk}{blocked_tag}</div>
                        <div class="alert-meta">{aip} - {format_ts(row.get('time',''))}</div>
                    </div>
                    <span class="sev-badge sev-{sev}">{sev}</span>
                </div>""", unsafe_allow_html=True)
                if not is_blocked(aip) and aip != "?":
                    if st.button(f"🚫 Block {aip}", key=f"blk_alert_{alert_i}", type="primary"):
                        do_block_ip(aip, f"Manual block from Alerts: {atk}")
                        st.success(f"🚫 {aip} blocked!"); st.rerun()
        else: st.info("No active alerts.")

    # ROW 3: Severity Dist (6) + AI Insight Widget (6)
    r3_left, r3_right = st.columns(2)
    with r3_left:
        sev_c = fdf["severity"].value_counts().reset_index(); sev_c.columns = ["Severity","Count"]
        fig = px.pie(sev_c, names="Severity", values="Count", hole=0.5, color="Severity",
                     color_discrete_map={"critical":"#ef4444","high":"#f59e0b","medium":"#3b82f6","low":"#22c55e"}, title="🚦 Severity Distribution")
        fig.update_layout(**PLOTLY_LAYOUT, height=320); fig.update_traces(textposition="inside", textinfo="percent+label", textfont_size=11)
        st.plotly_chart(fig, use_container_width=True, key="d_sev")

    with r3_right:
        # AI Insight Widget
        top_threat = freq_attack
        ai_summary = f"Detected {attacks_total} attack events across {unique_ips} unique source IPs. "
        if critical_alerts > 0: ai_summary += f"{critical_alerts} critical alerts require immediate attention. "
        ai_summary += f"Primary threat vector: {top_threat}. {blocked_count} IPs auto-blocked."
        overall_risk = min(95, critical_alerts * 15 + int((fdf["severity"]=="high").sum()) * 5)
        rc = risk_class(overall_risk)
        st.markdown(f"""<div class="ai-widget">
            <div class="ai-title">🧠 AI Insight Engine</div>
            <div class="ai-summary">{ai_summary}</div>
            <span class="risk-badge {rc}">Risk Score: {overall_risk}/100</span>
            &nbsp;&nbsp;<span class="sev-badge sev-{'critical' if overall_risk >= 70 else 'medium'}">
            {'HIGH RISK' if overall_risk >= 70 else 'MODERATE'}</span>
        </div>""", unsafe_allow_html=True)

    # ROW 4: Attack Map + Charts
    st.markdown('<div class="section-hdr">🌐 Global Threat Map</div>', unsafe_allow_html=True)
    m = folium.Map(location=[20,0], zoom_start=2, tiles="CartoDB dark_matter", control_scale=True)
    ip_counts = {}
    for r in geo_rows: ip_counts[r["ip"]] = ip_counts.get(r["ip"],0)+1
    for r in geo_rows:
        sev=r["severity"]; color=SEVERITY_COLORS.get(sev,"gray"); ac=ip_counts.get(r["ip"],1)
        popup=f'<div style="font-family:Inter;font-size:12px;min-width:180px;background:#111827;color:#e2e8f0;padding:10px;border-radius:8px;border:1px solid #1e293b;"><b>{r["ip"]}</b><br>{r["country"]}<br><span style="color:#ef4444">{r["attack_type"] or r["event_type"]}</span><br>MITRE: {r["mitre_id"]}<br><b style="color:{color}">{sev.upper()}</b> • {ac} attempts</div>'
        folium.CircleMarker(location=[r["lat"],r["lon"]], radius=6+min(ac,10), color=color, fill=True,
                           fill_color=color, fill_opacity=0.7, popup=folium.Popup(popup, max_width=260),
                           tooltip=f"{r['ip']} — {r['country']}").add_to(m)
    st.markdown('<div class="map-wrap">', unsafe_allow_html=True)
    st_folium(m, width=None, height=380, returned_objects=[])
    st.markdown('</div>', unsafe_allow_html=True)

    # Bottom charts
    bc1, bc2 = st.columns(2)
    with bc1:
        at_s = fdf.loc[fdf["attack_type"]!="","attack_type"]
        if not at_s.empty:
            at_c = at_s.value_counts().reset_index(); at_c.columns = ["Attack Type","Count"]
            fig = px.pie(at_c, names="Attack Type", values="Count", hole=0.45, color_discrete_sequence=COLOR_SEQ, title="🎯 Attack Distribution")
            fig.update_layout(**PLOTLY_LAYOUT, height=300); fig.update_traces(textposition="inside", textinfo="percent+label", textfont_size=11)
            st.plotly_chart(fig, use_container_width=True, key="d_atktype")
    with bc2:
        et_c = fdf["event_type"].value_counts().head(8).reset_index(); et_c.columns = ["Event","Count"]
        fig = px.bar(et_c, x="Count", y="Event", orientation="h", color_discrete_sequence=["#3b82f6"], title="📋 Event Breakdown")
        fig.update_layout(**PLOTLY_LAYOUT, yaxis=dict(autorange="reversed"), height=300)
        st.plotly_chart(fig, use_container_width=True, key="d_events")

    # Blocked IPs
    st.markdown('<div class="section-hdr">🚫 Blocked IPs & Auto-Response</div>', unsafe_allow_html=True)
    bl1, bl2 = st.columns(2)
    with bl1:
        if blocklist:
            bl_data = [{"IP":ip,"Reason":info.get("reason",""),"Blocked At":format_ts(info.get("timestamp","")),"Status":"🔴 Active"} for ip,info in blocklist.items()]
            st.dataframe(pd.DataFrame(bl_data), use_container_width=True, hide_index=True)
        else: st.info("No IPs blocked.")
    with bl2:
        crit = fdf[fdf["severity"]=="critical"].copy()
        if not crit.empty:
            resp = [{"Time":format_ts(row.get("time","")),"IP":row.get("ip","?"),"Attack":row.get("attack_type","") or "—",
                     "MITRE":row.get("mitre_id","") or "—","Action":"🚫 Blocked" if row.get("ip","") in blocklist else "⚠️ Alert"}
                    for _,row in crit.sort_values("time",ascending=False).head(12).iterrows()]
            st.dataframe(pd.DataFrame(resp), use_container_width=True, hide_index=True, height=220)
        else: st.info("No auto-response events.")

# ──────────────── 🐝 LIVE HONEYPOT LOGS ─────────────────────────────────────
elif page == "🐝 Live Honeypot Logs":
    st.markdown('<div class="page-header"><h2>Live Honeypot Logs</h2><div class="subtitle">Real-time event stream from honeypot sensors</div></div>', unsafe_allow_html=True)
    f_sev, f_evt, f_from, f_to, f_anom, f_raw = render_filters()
    view = apply_filters(fdf, f_sev, f_evt, f_from, f_to, f_anom)

    inc_all, inc_attacks, inc_traps, inc_uploads = st.tabs(["📋 All Events","🚨 Attacks","🪤 Traps","📁 Uploads"])
    with inc_all:
        recent = view.sort_values("time",ascending=False).head(100) if "time" in view.columns else view.tail(100)
        if not recent.empty:
            tbl = [{"Time":format_ts(row.get("time","")),"IP":row.get("ip","?"),"Method":row.get("method","?"),
                   "Path":row.get("path","?"),"Event":row.get("event_type",""),"Severity":str(row.get("severity","low")).upper(),
                   "MITRE":row.get("mitre_id","") or "—","ML":labels.get(int(row.get("pred",0)),"?")} for _,row in recent.iterrows()]
            st.dataframe(pd.DataFrame(tbl), use_container_width=True, height=400, hide_index=True)
        st.markdown("---")
        st.markdown("**🧠 Select event for AI analysis:**")
        atk_idx = [i for i,l in enumerate(logs) if l.get("event_type") in ("attack_detected","brute_force_detected","suspicious_upload","honeypot_trap")]
        if atk_idx:
            opts = [f"#{i} — {logs[i].get('event_type','')} — {logs[i].get('ip','?')} — {format_ts(logs[i].get('timestamp',''))}" for i in atk_idx[-30:]]
            sel = st.selectbox("Select event", opts, key="log_sel")
            if sel:
                st.session_state["selected_log_idx"] = atk_idx[-30:][opts.index(sel)]
                st.info("✅ Selected. Go to **🧠 AI Threat Analysis** in sidebar.")
        if f_raw and not recent.empty:
            for idx, row in recent.head(30).iterrows():
                sev = str(row.get("severity","low")); icon = get_severity_icon(sev)
                with st.expander(f"{icon} {format_ts(row.get('time',''))} | {row.get('ip','?')} | {row.get('method','?')} {row.get('path','?')} | {row.get('event_type','')}", expanded=False):
                    c1,c2 = st.columns(2)
                    with c1: st.write(f"**IP:** {row.get('ip','?')}"); st.write(f"**Severity:** {icon} {sev}"); st.write(f"**ML:** {labels.get(int(row.get('pred',0)),'?')}")
                    with c2:
                        if row.get("mitre_id"): st.code(f"MITRE: {row.get('mitre_id','')} — {row.get('mitre_name','')}\nTactic: {row.get('mitre_tactic','')}")
                        if idx < len(logs) and logs[idx].get("details"): st.json(logs[idx]["details"])
    with inc_attacks:
        av = fdf[fdf["stored_class"].isin(["sqli","xss","malicious_upload"])]
        if av.empty: st.info("No attacks detected.")
        else:
            for idx,row in av.sort_values("time",ascending=False).head(50).iterrows():
                entry = logs[idx] if idx < len(logs) else {}; det = entry.get("details",{})
                mt = f" [{row.get('mitre_id','')}]" if row.get("mitre_id") else ""
                st.error(f"{get_severity_icon(row.get('severity',''))} **{row.get('stored_class','').upper()}**{mt} — {row.get('ip','?')} — {format_ts(row.get('time',''))}")
                if det.get("attack_patterns"): st.code(f"Patterns: {det['attack_patterns']}")
    with inc_traps:
        tv = fdf[fdf["event_type"]=="honeypot_trap"]
        if tv.empty: st.info("No trap hits.")
        else:
            for idx,row in tv.sort_values("time",ascending=False).head(50).iterrows():
                entry = logs[idx] if idx < len(logs) else {}
                st.warning(f"🪤 {row.get('ip','?')} → **{row.get('path','?')}** at {format_ts(row.get('time',''))}")
    with inc_uploads:
        uv = fdf[fdf["event_type"].isin(["file_upload","suspicious_upload"])]
        if uv.empty: st.info("No uploads.")
        else:
            for idx,row in uv.sort_values("time",ascending=False).head(50).iterrows():
                det = (logs[idx] if idx<len(logs) else {}).get("details",{})
                ic = "⚠️" if row.get("event_type")=="suspicious_upload" else "📄"
                st.write(f"{ic} **{det.get('filename','?')}** ({det.get('file_size',0)}B) — {format_ts(row.get('time',''))}")

# ──────────────── 🧠 AI THREAT ANALYSIS ─────────────────────────────────────
elif page == "🧠 AI Threat Analysis":
    st.markdown('<div class="page-header"><h2>AI Threat Analysis</h2><div class="subtitle">Deep investigation powered by threat intelligence engine</div></div>', unsafe_allow_html=True)
    atk_idx = [i for i,l in enumerate(logs) if l.get("event_type") in ("attack_detected","brute_force_detected","suspicious_upload","honeypot_trap")]
    sel_idx = st.session_state.get("selected_log_idx", None)
    if not atk_idx: st.info("No attack events to analyze.")
    else:
        opts = [f"#{i} — {logs[i].get('event_type','')} — {logs[i].get('ip','?')} — {format_ts(logs[i].get('timestamp',''))}" for i in atk_idx[-50:]]
        default = 0
        if sel_idx is not None and sel_idx in atk_idx[-50:]: default = atk_idx[-50:].index(sel_idx)
        sel = st.selectbox("Select event", opts, index=default, key="ai_sel")
        chosen = atk_idx[-50:][opts.index(sel)]
        analysis = analyze_threat(logs[chosen])
        rc = risk_class(analysis["risk_score"])

        # Risk header
        st.markdown(f'<span class="risk-badge {rc}">Risk: {analysis["risk_score"]}/100</span>&nbsp;&nbsp;'
                    f'<span class="risk-badge {rc}">Confidence: {analysis["confidence_score"]}%</span>', unsafe_allow_html=True)
        st.markdown("")

        with st.expander("🔍 Threat Overview", expanded=True):
            c1,c2 = st.columns(2)
            with c1: st.write(f"**Threat Type:** {analysis['threat_type']}"); st.write(f"**Risk Score:** {analysis['risk_score']}/100"); st.write(f"**Severity:** {get_severity_icon(analysis['severity'])} {analysis['severity'].upper()}")
            with c2: st.write(f"**Source IP:** {analysis['ip']}"); st.write(f"**Endpoint:** {analysis['endpoint']}"); st.write(f"**Time:** {format_ts(analysis['timestamp'])}")
        if analysis.get("reasoning"):
            with st.expander("🧠 AI Reasoning", expanded=True): st.markdown(f"> {analysis['reasoning']}")
        if analysis.get("mitre_technique"):
            with st.expander("🗺️ MITRE ATT&CK Mapping", expanded=True): st.code(f"ID:     {analysis['mitre_technique']}\nName:   {analysis.get('mitre_name','')}\nTactic: {analysis.get('mitre_tactic','')}")
        if analysis.get("impact"):
            with st.expander("💥 Impact Assessment", expanded=False): st.warning(analysis["impact"])
        if analysis.get("mitigation_steps"):
            with st.expander("🛡 Mitigation Steps", expanded=False):
                for i,s in enumerate(analysis["mitigation_steps"],1): st.write(f"**{i}.** {s}")
        if analysis.get("prevention_recommendations"):
            with st.expander("🔒 Prevention Recommendations", expanded=False):
                for i,r in enumerate(analysis["prevention_recommendations"],1): st.write(f"**{i}.** {r}")
        # Raw log
        with st.expander("📋 Raw Log Data", expanded=False): st.json(logs[chosen])
        st.markdown("---")
        ab1, ab2 = st.columns(2)
        with ab1:
            if st.button("📂 Create Case from Analysis", key="create_case", use_container_width=True):
                case = create_case(title=f"{analysis['threat_type']} - {analysis['ip']}", severity=analysis["severity"],
                                  description=f"Attack: {analysis['attack_pattern']}\nImpact: {analysis['impact']}",
                                  log_index=chosen, extra={"threat_type":analysis["threat_type"],"risk_score":analysis["risk_score"],
                                  "mitre_technique":analysis.get("mitre_technique",""),"mitigation_steps":analysis.get("mitigation_steps",[])})
                st.success(f"Case #{case['id']} created!")
        with ab2:
            tip = analysis.get("ip", "")
            if tip and not is_blocked(tip):
                if st.button(f"🚫 Block IP {tip}", key="blk_ai", type="primary", use_container_width=True):
                    do_block_ip(tip, f"Manual block from AI Analysis: {analysis['threat_type']}")
                    st.success(f"🚫 {tip} blocked!"); st.rerun()
            elif tip:
                st.info(f"✅ {tip} is already blocked")

# ──────────────── 🛡 MITIGATION CENTER ──────────────────────────────────────
elif page == "🛡 Mitigation Center":
    st.markdown('<div class="page-header"><h2>Mitigation Center</h2><div class="subtitle">Aggregated defensive recommendations and response actions</div></div>', unsafe_allow_html=True)
    all_steps, all_recs = get_all_mitigations(logs)
    sev_d = fdf["severity"].value_counts().to_dict()
    hi = sev_d.get("critical",0)+sev_d.get("high",0)
    overall = min(95, hi*10+sev_d.get("medium",0)*3) if hi else 10
    rc = risk_class(overall)
    st.markdown(f'<span class="risk-badge {rc}">Overall Risk: {overall}/100</span>', unsafe_allow_html=True)
    st.markdown("")
    mc1, mc2 = st.columns(2)
    with mc1:
        st.markdown("#### 🛡 Mitigation Steps")
        if all_steps:
            for i,s in enumerate(all_steps,1): st.write(f"**{i}.** {s}")
        else: st.info("No mitigations needed.")
    with mc2:
        st.markdown("#### 🔒 Prevention Recommendations")
        if all_recs:
            for i,r in enumerate(all_recs,1): st.write(f"**{i}.** {r}")
        else: st.info("System clean.")
    # Block attacker IPs section
    st.markdown("---")
    st.markdown("#### 🚫 Block Attacker IPs")
    if "ip" in fdf.columns and attack_mask.any():
        top_attacker_ips = fdf.loc[attack_mask, "ip"].value_counts().head(5)
        for bip_i, (bip, cnt) in enumerate(top_attacker_ips.items()):
            bc1, bc2 = st.columns([3, 1])
            with bc1:
                status_tag = "🟢 BLOCKED" if is_blocked(bip) else "🔴 Not Blocked"
                st.write(f"**{bip}** - {cnt} attacks - {status_tag}")
            with bc2:
                if not is_blocked(bip):
                    if st.button(f"🚫 Block", key=f"blk_mit_{bip_i}", type="primary"):
                        do_block_ip(bip, f"Manual block from Mitigation Center")
                        st.success(f"🚫 {bip} blocked!"); st.rerun()
    else:
        st.info("No attacker IPs detected.")
    st.markdown("---")
    if all_steps or all_recs:
        pdf = generate_mitigation_pdf({"risk_score":overall,"severity":"high" if overall>=70 else "medium","threat_type":"Aggregated"}, all_steps, all_recs)
        st.download_button("📄 Download Mitigation Report (PDF)", pdf, file_name="mitigation_report.pdf", mime="application/pdf")

# ──────────────── 📂 CASE MANAGEMENT ────────────────────────────────────────
elif page == "📂 Case Management":
    st.markdown('<div class="page-header"><h2>Case Management</h2><div class="subtitle">Track, manage, and resolve security incidents</div></div>', unsafe_allow_html=True)
    cases = get_cases()
    if not cases: st.info("No cases. Create from AI Threat Analysis tab.")
    else:
        for case in reversed(cases):
            sev = str(case.get("severity","low")).lower(); status = case.get("status","Open")
            si = {"Open":"🔴","In Progress":"🟡","Closed":"🟢"}.get(status,"⚪")
            sc = {"critical":"#ef4444","high":"#f59e0b","medium":"#3b82f6","low":"#22c55e"}.get(sev,"#64748b")
            st.markdown(f"""<div class="resp-card" style="border-left:3px solid {sc};">
                <div class="rc-title">{si} Case #{case['id']}: {case.get('title','Untitled')}</div>
                <div class="rc-meta"><span class="sev-badge sev-{sev}">{sev.upper()}</span> &nbsp;•&nbsp; {status} &nbsp;•&nbsp; {format_ts(case.get('created_at',''))}</div>
            </div>""", unsafe_allow_html=True)
            cc1,cc2,cc3,cc4 = st.columns([2,1,0.7,0.7])
            with cc1:
                with st.expander(f"Details - Case #{case['id']}", expanded=False):
                    st.write(case.get("description","No description"))
                    if case.get("threat_type"): st.write(f"**Threat:** {case['threat_type']}")
                    if case.get("mitre_technique"): st.write(f"**MITRE:** {case['mitre_technique']}")
                    if case.get("mitigation_steps"):
                        for s in case["mitigation_steps"]: st.write(f"- {s}")
            with cc2:
                ns = st.selectbox("Status",["Open","In Progress","Closed"],index=["Open","In Progress","Closed"].index(status),key=f"st_{case['id']}")
                if ns != status: update_case_status(case["id"],ns); st.rerun()
            with cc3:
                pb = generate_case_pdf(case)
                st.download_button("📄 PDF",pb,file_name=f"case_{case['id']}.pdf",mime="application/pdf",key=f"pd_{case['id']}")
            with cc4:
                # Extract IP from case title (format: "Threat Type - IP")
                case_ip = case.get("title","").split(" - ")[-1].strip() if " - " in case.get("title","") else ""
                if case_ip and not is_blocked(case_ip):
                    if st.button("🚫 Block", key=f"blk_case_{case['id']}", type="primary"):
                        do_block_ip(case_ip, f"Manual block from Case #{case['id']}")
                        st.success(f"Blocked!"); st.rerun()
                elif case_ip:
                    st.markdown('<span class="sev-badge sev-low">BLOCKED</span>', unsafe_allow_html=True)

# ──────────────── 📊 REPORTS ────────────────────────────────────────────────
elif page == "📊 Reports":
    st.markdown('<div class="page-header"><h2>Executive Reports</h2><div class="subtitle">Generate and export threat intelligence summaries</div></div>', unsafe_allow_html=True)
    r1,r2,r3,r4 = st.columns(4)
    with r1: st.metric("Total Events", len(logs))
    with r2: st.metric("Attacks", attacks_total)
    with r3: st.metric("Critical", critical_alerts)
    with r4: st.metric("Blocked", blocked_count)
    rc1,rc2 = st.columns(2)
    with rc1:
        sev_c = fdf["severity"].value_counts().reset_index(); sev_c.columns=["Severity","Count"]
        fig = px.pie(sev_c,names="Severity",values="Count",hole=0.45,color="Severity",
                     color_discrete_map={"critical":"#ef4444","high":"#f59e0b","medium":"#3b82f6","low":"#22c55e"},title="Severity Distribution")
        fig.update_layout(**PLOTLY_LAYOUT,height=300); st.plotly_chart(fig,use_container_width=True,key="r_sev")
    with rc2:
        md = fdf.loc[fdf["mitre_id"]!=""]
        if not md.empty:
            ml = md.apply(lambda r: f"{r['mitre_id']} ({r['mitre_name']})" if r.get("mitre_name") else r["mitre_id"], axis=1)
            mc = ml.value_counts().reset_index(); mc.columns=["Technique","Count"]
            fig = px.bar(mc,x="Count",y="Technique",orientation="h",color_discrete_sequence=["#3b82f6"],title="MITRE Techniques")
            fig.update_layout(**PLOTLY_LAYOUT,yaxis=dict(autorange="reversed"),height=300)
            st.plotly_chart(fig,use_container_width=True,key="r_mitre")
        else: st.info("No MITRE data.")
    st.markdown("---")
    stats = {"Total Events":len(logs),"Attacks":attacks_total,"Critical":critical_alerts,"Blocked IPs":blocked_count,"Unique Attackers":unique_ips,"Top Attack":freq_attack}
    atk_sum = fdf.loc[fdf["attack_type"]!="","attack_type"].value_counts().to_dict()
    all_s,all_r = get_all_mitigations(logs)
    # Build threat analysis data for PDF
    _atk_idx = [i for i,l in enumerate(logs) if l.get("event_type") in ("attack_detected","brute_force_detected","suspicious_upload","honeypot_trap")]
    _threats = [analyze_threat(logs[i]) for i in _atk_idx[-5:]] if _atk_idx else None
    # Top attacker IPs
    _top_ips = None
    if "ip" in fdf.columns and attack_mask.any():
        _ip_counts = fdf.loc[attack_mask,"ip"].value_counts().head(5)
        _top_ips = [{"ip":ip,"count":int(c)} for ip,c in _ip_counts.items()]
    pdf = generate_executive_pdf(stats, atk_sum, blocklist, (all_s,all_r), threats=_threats, top_ips=_top_ips)
    st.download_button("📄 Download Executive Report (PDF)", pdf, file_name="executive_report.pdf", mime="application/pdf")

# ── Footer ──────────────────────────────────────────────────────────────────
st.markdown("""
<div style="text-align:center;padding:20px 0 8px;color:#334155;font-size:0.68rem;border-top:1px solid #1e293b;margin-top:28px;">
    SecureCorp AI-SIEM &nbsp;•&nbsp; MITRE ATT&CK &nbsp;•&nbsp; ML: IsolationForest · RandomForest &nbsp;•&nbsp; v2.0
</div>
""", unsafe_allow_html=True)
