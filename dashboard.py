import streamlit as st
import pandas as pd, json, joblib, os, io
import plotly.express as px
import plotly.graph_objects as go
import folium
from streamlit_folium import st_folium
from log_parser import extract_features, LOGPATH
from datetime import datetime, date, timedelta
from geo_lookup import geolocate

# ───────────────────────────────────────────────────────────────────────────────
# PAGE CONFIG
# ───────────────────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="SecureCorp SOC Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ───────────────────────────────────────────────────────────────────────────────
# DARK SOC THEME — CSS INJECTION
# ───────────────────────────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');

/* ── Global reset ──────────────────────────────────────────────────────── */
html, body, [class*="css"] {
    font-family: 'Inter', sans-serif;
}
.stApp {
    background: #0a0a0f;
    color: #c9d1d9;
}

/* ── Header area ───────────────────────────────────────────────────────── */
.soc-header {
    background: linear-gradient(135deg, #0d1117 0%, #161b22 100%);
    border: 1px solid #21262d;
    border-radius: 12px;
    padding: 24px 32px;
    margin-bottom: 24px;
    display: flex;
    align-items: center;
    gap: 16px;
}
.soc-header h1 {
    margin: 0;
    font-size: 1.6rem;
    font-weight: 700;
    color: #e6edf3;
    letter-spacing: -0.5px;
}
.soc-header .subtitle {
    color: #7d8590;
    font-size: 0.85rem;
    margin-top: 4px;
}
.soc-header .live-dot {
    width: 10px; height: 10px;
    border-radius: 50%;
    background: #3fb950;
    box-shadow: 0 0 8px #3fb950;
    animation: pulse-dot 2s infinite;
    display: inline-block;
    margin-right: 6px;
}
@keyframes pulse-dot {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.4; }
}

/* ── KPI Cards ─────────────────────────────────────────────────────────── */
.kpi-card {
    background: #161b22;
    border: 1px solid #21262d;
    border-radius: 10px;
    padding: 20px 16px;
    text-align: center;
    transition: border-color 0.2s, transform 0.15s;
}
.kpi-card:hover {
    border-color: #58a6ff;
    transform: translateY(-2px);
}
.kpi-value {
    font-size: 2.2rem;
    font-weight: 700;
    margin: 8px 0 4px;
    line-height: 1;
}
.kpi-label {
    font-size: 0.75rem;
    text-transform: uppercase;
    letter-spacing: 1px;
    color: #7d8590;
    font-weight: 600;
}
.kpi-accent-red    .kpi-value { color: #f85149; }
.kpi-accent-orange .kpi-value { color: #d29922; }
.kpi-accent-blue   .kpi-value { color: #58a6ff; }
.kpi-accent-green  .kpi-value { color: #3fb950; }
.kpi-accent-purple .kpi-value { color: #bc8cff; }

.kpi-accent-red    { border-left: 3px solid #f85149; }
.kpi-accent-orange { border-left: 3px solid #d29922; }
.kpi-accent-blue   { border-left: 3px solid #58a6ff; }
.kpi-accent-green  { border-left: 3px solid #3fb950; }
.kpi-accent-purple { border-left: 3px solid #bc8cff; }

/* ── Section Headers ───────────────────────────────────────────────────── */
.section-header {
    font-size: 1.1rem;
    font-weight: 600;
    color: #e6edf3;
    margin: 28px 0 14px;
    padding-bottom: 8px;
    border-bottom: 1px solid #21262d;
    display: flex;
    align-items: center;
    gap: 8px;
}

/* ── Chart container ───────────────────────────────────────────────────── */
.chart-box {
    background: #161b22;
    border: 1px solid #21262d;
    border-radius: 10px;
    padding: 16px;
    margin-bottom: 16px;
}

/* ── Severity badges ───────────────────────────────────────────────────── */
.sev-badge {
    display: inline-block;
    padding: 2px 10px;
    border-radius: 12px;
    font-size: 0.7rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}
.sev-critical { background: #f8514922; color: #f85149; border: 1px solid #f8514944; }
.sev-high     { background: #d2992222; color: #d29922; border: 1px solid #d2992244; }
.sev-medium   { background: #58a6ff22; color: #58a6ff; border: 1px solid #58a6ff44; }
.sev-low      { background: #3fb95022; color: #3fb950; border: 1px solid #3fb95044; }

/* ── Map container ─────────────────────────────────────────────────────── */
.map-container {
    background: #161b22;
    border: 1px solid #21262d;
    border-radius: 10px;
    padding: 8px;
    overflow: hidden;
}

/* ── Event rows ────────────────────────────────────────────────────────── */
.event-row {
    background: #161b22;
    border: 1px solid #21262d;
    border-radius: 8px;
    padding: 12px 16px;
    margin-bottom: 6px;
    display: flex;
    align-items: center;
    gap: 12px;
    font-size: 0.82rem;
    transition: border-color 0.2s;
}
.event-row:hover {
    border-color: #30363d;
}

/* ── Sidebar ───────────────────────────────────────────────────────────── */
section[data-testid="stSidebar"] {
    background: #0d1117;
    border-right: 1px solid #21262d;
}
section[data-testid="stSidebar"] .stMarkdown h1,
section[data-testid="stSidebar"] .stMarkdown h2,
section[data-testid="stSidebar"] .stMarkdown h3 {
    color: #e6edf3;
}

/* ── Streamlit metric overrides ────────────────────────────────────────── */
[data-testid="stMetric"] {
    background: #161b22;
    border: 1px solid #21262d;
    border-radius: 10px;
    padding: 16px;
}
[data-testid="stMetricValue"] {
    font-size: 1.8rem;
    font-weight: 700;
}

/* ── Tab styling ───────────────────────────────────────────────────────── */
.stTabs [data-baseweb="tab-list"] {
    gap: 4px;
    background: #161b22;
    border-radius: 8px;
    padding: 4px;
    border: 1px solid #21262d;
}
.stTabs [data-baseweb="tab"] {
    background: transparent;
    border-radius: 6px;
    color: #7d8590;
    font-weight: 500;
    font-size: 0.85rem;
    padding: 8px 16px;
    transition: all 0.2s ease;
}
.stTabs [data-baseweb="tab"]:hover {
    color: #c9d1d9;
    background: #21262d50;
}
.stTabs [aria-selected="true"] {
    background: #21262d;
    color: #e6edf3;
}

/* ── Scrollbar ─────────────────────────────────────────────────────────── */
::-webkit-scrollbar { width: 6px; }
::-webkit-scrollbar-track { background: #0d1117; }
::-webkit-scrollbar-thumb { background: #30363d; border-radius: 3px; }

/* ── Expander ──────────────────────────────────────────────────────────── */
.streamlit-expanderHeader {
    background: #161b22;
    border-radius: 8px;
}

/* ── Info card for response tab ────────────────────────────────────────── */
.response-card {
    background: #161b22;
    border: 1px solid #21262d;
    border-radius: 10px;
    padding: 16px 20px;
    margin-bottom: 10px;
    transition: border-color 0.2s;
}
.response-card:hover {
    border-color: #30363d;
}
.response-card .rc-title {
    font-weight: 600;
    color: #e6edf3;
    font-size: 0.9rem;
    margin-bottom: 4px;
}
.response-card .rc-meta {
    color: #7d8590;
    font-size: 0.78rem;
}
</style>
""", unsafe_allow_html=True)

# ───────────────────────────────────────────────────────────────────────────────
# HEADER
# ───────────────────────────────────────────────────────────────────────────────
st.markdown("""
<div class="soc-header">
    <div>
        <h1>🛡️ SecureCorp — SOC Monitoring Console</h1>
        <div class="subtitle"><span class="live-dot"></span>Live   •   MITRE ATT&CK Enriched   •   Automated Response Active</div>
    </div>
</div>
""", unsafe_allow_html=True)

# ───────────────────────────────────────────────────────────────────────────────
# HELPER FUNCTIONS
# ───────────────────────────────────────────────────────────────────────────────
SEVERITY_BADGE = {"low": "🟢", "medium": "🟡", "high": "🟠", "critical": "🔴"}
SEVERITY_COLORS = {"critical": "red", "high": "orange", "medium": "blue", "low": "green"}


def get_severity_icon(severity):
    return SEVERITY_BADGE.get(str(severity).lower(), "⚪")


def format_ts(ts):
    try:
        dt = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return str(ts)


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


def load_blocklist():
    bl_path = os.path.join("logs", "blocklist.json")
    if not os.path.exists(bl_path):
        return {}
    try:
        with open(bl_path) as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        return {}


# ───────────────────────────────────────────────────────────────────────────────
# SIDEBAR — Filters & Controls
# ───────────────────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("### 🔧 Controls")
    show_raw = st.checkbox("Show raw log details", value=True)
    filter_anomalies = st.checkbox("Only anomalies", value=False)
    filter_severity = st.selectbox("Filter by severity", ["all", "low", "medium", "high", "critical"])
    filter_event = st.selectbox("Filter by event type", [
        "all", "attack_detected", "login_attempt", "honeypot_trap",
        "brute_force_detected", "suspicious_upload", "page_view",
        "form_submit", "query_submit", "file_upload", "client_log",
    ])

    st.markdown("---")
    st.markdown("### 📅 Date Range")
    date_from = st.date_input("From", value=date.today() - timedelta(days=30))
    date_to = st.date_input("To", value=date.today())

    st.markdown("---")
    st.markdown("### 🗺️ MITRE Filter")

    refresh = st.button("🔄 Refresh Data")

    st.markdown("---")
    st.markdown("### 📥 Export")

# ───────────────────────────────────────────────────────────────────────────────
# LOAD MODELS
# ───────────────────────────────────────────────────────────────────────────────
model_iso = None
model_rf = None
try:
    model_iso = joblib.load(os.path.join("models", "isolation_forest.joblib"))
    model_rf = joblib.load(os.path.join("models", "rf_attack_classifier.joblib"))
except Exception:
    st.sidebar.warning("⚠️ ML models not loaded — run `train_models.py`")

# ───────────────────────────────────────────────────────────────────────────────
# DATA LOADING & PROCESSING
# ───────────────────────────────────────────────────────────────────────────────
logs = load_logs()
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

if "time" in fdf.columns:
    fdf["time"] = pd.to_datetime(fdf["time"], errors="coerce")

fdf["method_code"] = fdf["method"].map({"GET": 0, "POST": 1}).fillna(2).astype(int)

feature_cols = ["path_len", "ua_len", "data_len", "count_sql_tokens",
                "count_xss_tokens", "num_params", "method_code", "has_sql_special_chars"]
for col in feature_cols:
    if col not in fdf.columns:
        fdf[col] = 0
X = fdf[feature_cols]

# ML predictions
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

# ── MITRE filter in sidebar (needs data loaded first) ───────────────────────
mitre_options = sorted(fdf.loc[fdf["mitre_id"] != "", "mitre_id"].unique().tolist())
with st.sidebar:
    filter_mitre = st.selectbox("MITRE Technique", ["all"] + mitre_options)

# ── Apply filters ───────────────────────────────────────────────────────────
view = fdf.copy()
if filter_anomalies:
    view = view[view["anomaly"] == -1]
if filter_severity != "all":
    view = view[view["severity"] == filter_severity]
if filter_event != "all":
    view = view[view["event_type"] == filter_event]
if filter_mitre != "all":
    view = view[view["mitre_id"] == filter_mitre]
# Date filter
if "time" in view.columns and pd.api.types.is_datetime64_any_dtype(view.get("time")):
    time_mask = view["time"].notna()
    if time_mask.any():
        date_from_dt = pd.Timestamp(date_from, tz="UTC")
        date_to_dt = pd.Timestamp(date_to, tz="UTC") + pd.Timedelta(days=1)
        view = view[~time_mask | ((view["time"] >= date_from_dt) & (view["time"] < date_to_dt))]

# ── Precompute KPIs ─────────────────────────────────────────────────────────
attack_mask = fdf["stored_class"].isin(["sqli", "xss", "malicious_upload"]) | fdf["event_type"].isin(["attack_detected", "brute_force_detected"])
attacks_total = int(attack_mask.sum())

today_str = date.today().isoformat()
if "time" in fdf.columns and pd.api.types.is_datetime64_any_dtype(fdf.get("time")):
    today_mask = fdf["time"].dt.date == date.today()
    attacks_today = int((attack_mask & today_mask).sum()) if today_mask.any() else attacks_total
else:
    attacks_today = attacks_total

critical_alerts = int((fdf["severity"] == "critical").sum())

if "ip" in fdf.columns:
    unique_attacker_ips = int(fdf.loc[attack_mask, "ip"].nunique()) if attack_mask.any() else 0
else:
    unique_attacker_ips = 0

blocklist = load_blocklist()
blocked_count = len(blocklist)

freq_attack = "—"
if not fdf.loc[fdf["attack_type"] != "", "attack_type"].empty:
    freq_attack = fdf.loc[fdf["attack_type"] != "", "attack_type"].value_counts().index[0]

# ── Build geo data (shared by Attack Map tab) ───────────────────────────────
attack_events = fdf[attack_mask].copy()
geo_rows = []
if not attack_events.empty:
    for idx, row in attack_events.iterrows():
        ip = str(row.get("ip", "127.0.0.1"))
        event_hash = f"{idx}-{row.get('event_type', '')}-{row.get('attack_type', '')}"
        loc = geolocate(ip, event_hash)
        geo_rows.append({
            "ip": ip,
            "lat": loc["lat"],
            "lon": loc["lon"],
            "country": loc["country"],
            "city": loc["city"],
            "severity": str(row.get("severity", "low")),
            "attack_type": str(row.get("attack_type", "Unknown")),
            "event_type": str(row.get("event_type", "")),
            "mitre_id": str(row.get("mitre_id", "")),
            "mitre_name": str(row.get("mitre_name", "")),
        })

# ── Sidebar export buttons ──────────────────────────────────────────────────
with st.sidebar:
    csv_buf = io.StringIO()
    fdf.to_csv(csv_buf, index=False)
    st.download_button("📄 Download Features CSV", csv_buf.getvalue(),
                       file_name="securecorp_features.csv", mime="text/csv")
    log_str = json.dumps(logs, indent=2, default=str)
    st.download_button("📋 Download Raw Logs JSON", log_str,
                       file_name="securecorp_logs.json", mime="application/json")

# ── Shared Plotly theme ─────────────────────────────────────────────────────
PLOTLY_LAYOUT = dict(
    paper_bgcolor="#161b22",
    plot_bgcolor="#161b22",
    font=dict(family="Inter, sans-serif", color="#c9d1d9", size=12),
    margin=dict(l=20, r=20, t=40, b=20),
    legend=dict(bgcolor="rgba(0,0,0,0)", font=dict(size=11)),
)
COLOR_SEQ = ["#f85149", "#d29922", "#58a6ff", "#3fb950", "#bc8cff",
             "#f778ba", "#79c0ff", "#ffa657", "#56d364", "#db61a2"]
labels = {0: "benign", 1: "sqli", 2: "xss"}

# ═══════════════════════════════════════════════════════════════════════════════
# MAIN TABS
# ═══════════════════════════════════════════════════════════════════════════════
tab_overview, tab_map, tab_mitre, tab_incidents, tab_response = st.tabs([
    "📊 Overview",
    "🌐 Attack Map",
    "🗺️ MITRE & Threats",
    "🔍 Incidents",
    "🚫 Response",
])

# ═══════════════════════════════════════════════════════════════════════════════
# TAB 1 — OVERVIEW
# ═══════════════════════════════════════════════════════════════════════════════
with tab_overview:
    st.markdown('<div class="section-header">📈 Key Performance Indicators</div>',
                unsafe_allow_html=True)

    k1, k2, k3, k4, k5 = st.columns(5)
    with k1:
        st.markdown(f"""
        <div class="kpi-card kpi-accent-red">
            <div class="kpi-label">Attacks Today</div>
            <div class="kpi-value">{attacks_today}</div>
        </div>""", unsafe_allow_html=True)
    with k2:
        st.markdown(f"""
        <div class="kpi-card kpi-accent-orange">
            <div class="kpi-label">Critical Alerts</div>
            <div class="kpi-value">{critical_alerts}</div>
        </div>""", unsafe_allow_html=True)
    with k3:
        st.markdown(f"""
        <div class="kpi-card kpi-accent-blue">
            <div class="kpi-label">Unique Attacker IPs</div>
            <div class="kpi-value">{unique_attacker_ips}</div>
        </div>""", unsafe_allow_html=True)
    with k4:
        st.markdown(f"""
        <div class="kpi-card kpi-accent-green">
            <div class="kpi-label">Blocked IPs</div>
            <div class="kpi-value">{blocked_count}</div>
        </div>""", unsafe_allow_html=True)
    with k5:
        st.markdown(f"""
        <div class="kpi-card kpi-accent-purple">
            <div class="kpi-label">Top Attack Type</div>
            <div class="kpi-value" style="font-size:1.1rem">{freq_attack}</div>
        </div>""", unsafe_allow_html=True)

    # ── Charts Row ──────────────────────────────────────────────────────────
    st.markdown('<div class="section-header">📊 Security Analytics</div>',
                unsafe_allow_html=True)
    ov_c1, ov_c2 = st.columns(2)

    with ov_c1:
        # Attacks Over Time
        if "time" in fdf.columns and pd.api.types.is_datetime64_any_dtype(fdf.get("time")):
            atk = fdf[attack_mask & fdf["time"].notna()].copy()
            if not atk.empty:
                atk["hour"] = atk["time"].dt.floor("h")
                hourly = atk.groupby("hour").size().reset_index()
                hourly.columns = ["Time", "Attacks"]
                fig = px.line(hourly, x="Time", y="Attacks",
                              color_discrete_sequence=["#f85149"],
                              title="📈 Attacks Over Time")
                fig.update_layout(**PLOTLY_LAYOUT)
                fig.update_traces(line=dict(width=2), fill="tozeroy",
                                  fillcolor="rgba(248,81,73,0.15)")
                st.plotly_chart(fig, use_container_width=True, key="ov_attacks_time")
            else:
                st.info("No timestamped attack events.")
        else:
            st.info("No timestamp data available.")

    with ov_c2:
        # Severity Distribution
        sev_counts = fdf["severity"].value_counts().reset_index()
        sev_counts.columns = ["Severity", "Count"]
        sev_color_map = {"critical": "#f85149", "high": "#d29922",
                         "medium": "#58a6ff", "low": "#3fb950"}
        fig = px.pie(sev_counts, names="Severity", values="Count",
                     hole=0.45, color="Severity",
                     color_discrete_map=sev_color_map,
                     title="🚦 Severity Distribution")
        fig.update_layout(**PLOTLY_LAYOUT)
        fig.update_traces(textposition="inside", textinfo="percent+label",
                          textfont_size=11)
        st.plotly_chart(fig, use_container_width=True, key="ov_severity")

    # ── Quick summary row ───────────────────────────────────────────────────
    ov_c3, ov_c4 = st.columns(2)
    with ov_c3:
        # Attack Type Donut
        attack_types_s = fdf.loc[fdf["attack_type"] != "", "attack_type"]
        if not attack_types_s.empty:
            at_counts = attack_types_s.value_counts().reset_index()
            at_counts.columns = ["Attack Type", "Count"]
            fig = px.pie(at_counts, names="Attack Type", values="Count",
                         hole=0.45, color_discrete_sequence=COLOR_SEQ,
                         title="🎯 Attack Type Distribution")
            fig.update_layout(**PLOTLY_LAYOUT)
            fig.update_traces(textposition="inside", textinfo="percent+label",
                              textfont_size=11)
            st.plotly_chart(fig, use_container_width=True, key="ov_attack_type")
        else:
            st.info("No attack types detected yet.")

    with ov_c4:
        # Event Type Breakdown
        et_counts = fdf["event_type"].value_counts().head(8).reset_index()
        et_counts.columns = ["Event Type", "Count"]
        fig = px.bar(et_counts, x="Count", y="Event Type", orientation="h",
                     color_discrete_sequence=["#58a6ff"],
                     title="📋 Event Type Breakdown")
        fig.update_layout(**PLOTLY_LAYOUT, yaxis=dict(autorange="reversed"))
        st.plotly_chart(fig, use_container_width=True, key="ov_event_type")


# ═══════════════════════════════════════════════════════════════════════════════
# TAB 2 — ATTACK MAP
# ═══════════════════════════════════════════════════════════════════════════════
with tab_map:
    st.markdown('<div class="section-header">🌐 Attacker Geolocation Map</div>',
                unsafe_allow_html=True)

    # Build folium map
    m = folium.Map(
        location=[20, 0],
        zoom_start=2,
        tiles="CartoDB dark_matter",
        control_scale=True,
    )

    ip_counts = {}
    for r in geo_rows:
        key = r["ip"]
        ip_counts[key] = ip_counts.get(key, 0) + 1

    for r in geo_rows:
        sev = r["severity"]
        color = SEVERITY_COLORS.get(sev, "gray")
        attempt_count = ip_counts.get(r["ip"], 1)

        popup_html = f"""
        <div style="font-family:Inter,sans-serif;font-size:12px;min-width:200px;background:#161b22;color:#c9d1d9;padding:10px;border-radius:8px;border:1px solid #30363d;">
            <div style="font-weight:700;font-size:13px;margin-bottom:6px;color:#e6edf3;">🎯 Attack Event</div>
            <table style="width:100%;border-collapse:collapse;">
                <tr><td style="color:#7d8590;padding:2px 8px 2px 0;">IP</td><td style="font-weight:600;">{r['ip']}</td></tr>
                <tr><td style="color:#7d8590;padding:2px 8px 2px 0;">Country</td><td>{r['country']}</td></tr>
                <tr><td style="color:#7d8590;padding:2px 8px 2px 0;">City</td><td>{r['city']}</td></tr>
                <tr><td style="color:#7d8590;padding:2px 8px 2px 0;">Attack</td><td style="color:#f85149;">{r['attack_type'] or r['event_type']}</td></tr>
                <tr><td style="color:#7d8590;padding:2px 8px 2px 0;">MITRE</td><td>{r['mitre_id']} {r['mitre_name']}</td></tr>
                <tr><td style="color:#7d8590;padding:2px 8px 2px 0;">Severity</td><td><span style="color:{color};font-weight:700;">●</span> {sev.upper()}</td></tr>
                <tr><td style="color:#7d8590;padding:2px 8px 2px 0;">Attempts</td><td style="font-weight:700;">{attempt_count}</td></tr>
            </table>
        </div>
        """
        folium.CircleMarker(
            location=[r["lat"], r["lon"]],
            radius=6 + min(attempt_count, 10),
            color=color, fill=True, fill_color=color, fill_opacity=0.7,
            popup=folium.Popup(popup_html, max_width=280),
            tooltip=f"{r['ip']} — {r['country']} — {sev}",
        ).add_to(m)

    st.markdown('<div class="map-container">', unsafe_allow_html=True)
    st_folium(m, width=None, height=480, returned_objects=[])
    st.markdown('</div>', unsafe_allow_html=True)

    # ── Charts below the map ────────────────────────────────────────────────
    map_c1, map_c2 = st.columns(2)

    with map_c1:
        if "ip" in fdf.columns:
            ip_top = fdf.loc[attack_mask, "ip"].value_counts().head(10).reset_index()
            ip_top.columns = ["IP Address", "Attacks"]
            if not ip_top.empty:
                fig = px.bar(ip_top, x="Attacks", y="IP Address", orientation="h",
                             color_discrete_sequence=["#d29922"],
                             title="🔥 Top Attacker IPs")
                fig.update_layout(**PLOTLY_LAYOUT, yaxis=dict(autorange="reversed"))
                st.plotly_chart(fig, use_container_width=True, key="map_top_ips")
            else:
                st.info("No attacker IPs yet.")
        else:
            st.info("No IP data.")

    with map_c2:
        if geo_rows:
            country_counts = pd.Series([r["country"] for r in geo_rows]).value_counts().head(10).reset_index()
            country_counts.columns = ["Country", "Attacks"]
            fig = px.bar(country_counts, x="Attacks", y="Country", orientation="h",
                         color_discrete_sequence=["#bc8cff"],
                         title="🌍 Top Attacking Countries")
            fig.update_layout(**PLOTLY_LAYOUT, yaxis=dict(autorange="reversed"))
            st.plotly_chart(fig, use_container_width=True, key="map_top_countries")
        else:
            st.info("No geo data available yet.")


# ═══════════════════════════════════════════════════════════════════════════════
# TAB 3 — MITRE & THREAT ANALYSIS
# ═══════════════════════════════════════════════════════════════════════════════
with tab_mitre:
    st.markdown('<div class="section-header">🗺️ MITRE ATT&CK Analysis</div>',
                unsafe_allow_html=True)

    mi_c1, mi_c2 = st.columns(2)

    with mi_c1:
        # MITRE Technique Distribution
        mitre_data = fdf.loc[fdf["mitre_id"] != ""]
        if not mitre_data.empty:
            mitre_labels = mitre_data.apply(
                lambda r: f"{r['mitre_id']} ({r['mitre_name']})" if r.get("mitre_name") else r["mitre_id"],
                axis=1
            )
            mc = mitre_labels.value_counts().reset_index()
            mc.columns = ["MITRE Technique", "Count"]
            fig = px.bar(mc, x="Count", y="MITRE Technique", orientation="h",
                         color_discrete_sequence=["#58a6ff"],
                         title="🗺️ MITRE Technique Distribution")
            fig.update_layout(**PLOTLY_LAYOUT, yaxis=dict(autorange="reversed"))
            st.plotly_chart(fig, use_container_width=True, key="mi_technique")
        else:
            st.info("No MITRE mappings yet — run adversary simulations.")

    with mi_c2:
        # Attack Type Distribution
        attack_types_s = fdf.loc[fdf["attack_type"] != "", "attack_type"]
        if not attack_types_s.empty:
            at_counts = attack_types_s.value_counts().reset_index()
            at_counts.columns = ["Attack Type", "Count"]
            fig = px.pie(at_counts, names="Attack Type", values="Count",
                         hole=0.45, color_discrete_sequence=COLOR_SEQ,
                         title="🎯 Attack Type Distribution")
            fig.update_layout(**PLOTLY_LAYOUT)
            fig.update_traces(textposition="inside", textinfo="percent+label",
                              textfont_size=11)
            st.plotly_chart(fig, use_container_width=True, key="mi_attack_type")
        else:
            st.info("No attack types detected yet.")

    # ── Second row ──────────────────────────────────────────────────────────
    mi_c3, mi_c4 = st.columns(2)

    with mi_c3:
        # MITRE Tactic Breakdown
        tactic_data = fdf.loc[fdf["mitre_tactic"] != "", "mitre_tactic"]
        if not tactic_data.empty:
            tc = tactic_data.value_counts().reset_index()
            tc.columns = ["Tactic", "Count"]
            fig = px.bar(tc, x="Count", y="Tactic", orientation="h",
                         color_discrete_sequence=["#3fb950"],
                         title="🎖️ MITRE Tactic Breakdown")
            fig.update_layout(**PLOTLY_LAYOUT, yaxis=dict(autorange="reversed"))
            st.plotly_chart(fig, use_container_width=True, key="mi_tactic")
        else:
            st.info("No tactic data yet.")

    with mi_c4:
        # Most Targeted Services (endpoints)
        targeted = fdf.loc[attack_mask, "path"]
        if not targeted.empty:
            path_counts = targeted.value_counts().head(10).reset_index()
            path_counts.columns = ["Endpoint", "Attacks"]
            fig = px.bar(path_counts, x="Attacks", y="Endpoint", orientation="h",
                         color_discrete_sequence=["#ffa657"],
                         title="🎯 Most Targeted Services")
            fig.update_layout(**PLOTLY_LAYOUT, yaxis=dict(autorange="reversed"))
            st.plotly_chart(fig, use_container_width=True, key="mi_targeted")
        else:
            st.info("No targeted endpoint data yet.")

    # ── MITRE detail table ──────────────────────────────────────────────────
    if not mitre_data.empty:
        st.markdown('<div class="section-header">📋 MITRE Technique Details</div>',
                    unsafe_allow_html=True)
        mitre_table = mitre_data[["mitre_id", "mitre_name", "mitre_tactic",
                                   "attack_type", "severity", "ip"]].copy()
        mitre_table.columns = ["Technique ID", "Technique Name", "Tactic",
                               "Attack Type", "Severity", "Source IP"]
        st.dataframe(mitre_table.drop_duplicates().reset_index(drop=True),
                     use_container_width=True, hide_index=True, height=300)


# ═══════════════════════════════════════════════════════════════════════════════
# TAB 4 — INCIDENTS
# ═══════════════════════════════════════════════════════════════════════════════
with tab_incidents:
    st.markdown('<div class="section-header">🔍 Security Incidents</div>',
                unsafe_allow_html=True)

    # Sub-tabs for filtering incident categories
    inc_all, inc_attacks, inc_traps, inc_uploads = st.tabs([
        "📋 All Events", "🚨 Attacks", "🪤 Traps", "📁 Uploads"
    ])

    with inc_all:
        recent = view.sort_values("time", ascending=False).head(100) if "time" in view.columns else view.tail(100)

        if not recent.empty:
            table_rows = []
            for idx, row in recent.iterrows():
                sev = str(row.get("severity", "low"))
                table_rows.append({
                    "Time": format_ts(row.get("time", "")),
                    "IP": row.get("ip", "?"),
                    "Method": row.get("method", "?"),
                    "Path": row.get("path", "?"),
                    "Event": row.get("event_type", ""),
                    "Severity": sev.upper(),
                    "MITRE": row.get("mitre_id", "") or "—",
                    "ML Class": labels.get(int(row.get("pred", 0)), "unknown"),
                })

            st.dataframe(
                pd.DataFrame(table_rows),
                use_container_width=True,
                height=400,
                hide_index=True,
            )

        # Expandable details
        if show_raw:
            st.markdown("##### Event Details")
            detail_recent = recent.head(50)
            for idx, row in detail_recent.iterrows():
                sev = str(row.get("severity", "low"))
                icon = get_severity_icon(sev)
                ts = format_ts(row.get("time", ""))
                ip = row.get("ip", "?")
                method = row.get("method", "?")
                path = row.get("path", "?")
                etype = row.get("event_type", "")
                mitre = row.get("mitre_id", "")
                mitre_label = f" | 🗺️ {mitre}" if mitre else ""
                label = f"{icon} {ts}  |  {ip}  |  {method} {path}  |  {etype}  |  {sev}{mitre_label}"

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
                        if mitre:
                            st.write("**🗺️ MITRE ATT&CK:**")
                            st.code(f"ID:     {row.get('mitre_id', '')}\n"
                                    f"Name:   {row.get('mitre_name', '')}\n"
                                    f"Tactic: {row.get('mitre_tactic', '')}")
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

    with inc_attacks:
        attack_view = fdf[fdf["stored_class"].isin(["sqli", "xss", "malicious_upload"])]
        if attack_view.empty:
            st.info("No attacks detected.")
        else:
            for idx, row in attack_view.sort_values("time", ascending=False).head(50).iterrows():
                sev = str(row.get("severity", "low"))
                icon = get_severity_icon(sev)
                entry = logs[idx] if idx < len(logs) else {}
                details = entry.get("details", {})
                mitre = row.get("mitre_id", "")
                mitre_tag = f" [{mitre}]" if mitre else ""
                st.error(f"{icon} **{row.get('stored_class', '').upper()}**{mitre_tag} — "
                         f"{row.get('ip', '?')} — {row.get('method', '?')} {row.get('path', '?')} — "
                         f"{format_ts(row.get('time', ''))}")
                if details.get("attack_patterns"):
                    st.code(f"Patterns: {details['attack_patterns']}")
                if entry.get("form"):
                    for k, v in entry["form"].items():
                        st.code(f"  {k}: {v}")

    with inc_traps:
        trap_view = fdf[fdf["event_type"] == "honeypot_trap"]
        if trap_view.empty:
            st.info("No honeypot trap hits.")
        else:
            for idx, row in trap_view.sort_values("time", ascending=False).head(50).iterrows():
                entry = logs[idx] if idx < len(logs) else {}
                st.warning(f"🪤 {row.get('ip', '?')} hit **{row.get('path', '?')}** "
                           f"at {format_ts(row.get('time', ''))}")
                if entry.get("details", {}).get("description"):
                    st.caption(entry["details"]["description"])

    with inc_uploads:
        upload_view = fdf[fdf["event_type"].isin(["file_upload", "suspicious_upload"])]
        if upload_view.empty:
            st.info("No file uploads recorded.")
        else:
            for idx, row in upload_view.sort_values("time", ascending=False).head(50).iterrows():
                entry = logs[idx] if idx < len(logs) else {}
                details = entry.get("details", {})
                uicon = "⚠️" if row.get("event_type") == "suspicious_upload" else "📄"
                st.write(f"{uicon} **{details.get('filename', '?')}** "
                         f"({details.get('file_size', 0)} bytes) — "
                         f"{details.get('user', '?')} — "
                         f"{format_ts(row.get('time', ''))}")
                if details.get("suspicions"):
                    for s in details["suspicions"]:
                        st.error(f"  🚨 {s}")


# ═══════════════════════════════════════════════════════════════════════════════
# TAB 5 — RESPONSE / BLOCKED IPs
# ═══════════════════════════════════════════════════════════════════════════════
with tab_response:
    st.markdown('<div class="section-header">🚫 Blocked IPs</div>',
                unsafe_allow_html=True)

    if blocklist:
        bl_data = []
        for ip, info in blocklist.items():
            bl_data.append({
                "IP Address": ip,
                "Reason": info.get("reason", ""),
                "Blocked At": format_ts(info.get("timestamp", "")),
                "Status": "🔴 Active" if info.get("blocked", True) else "⚪ Inactive",
            })
        st.dataframe(pd.DataFrame(bl_data), use_container_width=True, hide_index=True)
    else:
        st.info("No IPs are currently blocked.")

    # ── Auto-Response Log ───────────────────────────────────────────────────
    st.markdown('<div class="section-header">⚡ Auto-Response Log</div>',
                unsafe_allow_html=True)

    # Filter for events that triggered auto-response (critical severity events)
    critical_events = fdf[fdf["severity"] == "critical"].copy()
    if not critical_events.empty:
        resp_rows = []
        for idx, row in critical_events.sort_values("time", ascending=False).head(30).iterrows():
            entry = logs[idx] if idx < len(logs) else {}
            details = entry.get("details", {})
            resp_rows.append({
                "Time": format_ts(row.get("time", "")),
                "IP": row.get("ip", "?"),
                "Event": row.get("event_type", ""),
                "Attack Type": row.get("attack_type", "") or details.get("attack_type", "—"),
                "MITRE": row.get("mitre_id", "") or "—",
                "Action": "🚫 IP Blocked" if row.get("ip", "") in blocklist else "⚠️ Alert Sent",
                "Severity": "CRITICAL",
            })
        st.dataframe(pd.DataFrame(resp_rows), use_container_width=True,
                     hide_index=True, height=300)
    else:
        st.info("No auto-response events recorded yet.")

    # ── Alert History ───────────────────────────────────────────────────────
    st.markdown('<div class="section-header">🔔 Alert History</div>',
                unsafe_allow_html=True)

    # Show all high + critical severity events as alert history
    alert_events = fdf[fdf["severity"].isin(["critical", "high"])].copy()
    if not alert_events.empty:
        for idx, row in alert_events.sort_values("time", ascending=False).head(20).iterrows():
            sev = str(row.get("severity", ""))
            icon = get_severity_icon(sev)
            ts = format_ts(row.get("time", ""))
            ip = row.get("ip", "?")
            etype = row.get("event_type", "")
            mitre = row.get("mitre_id", "")
            attack = row.get("attack_type", "") or etype

            mitre_badge = f"&nbsp;&nbsp;<code>{mitre}</code>" if mitre else ""

            st.markdown(f"""
            <div class="response-card" style="border-left: 3px solid {'#f85149' if sev == 'critical' else '#d29922'};">
                <div class="rc-title">{icon} {attack}{mitre_badge}</div>
                <div class="rc-meta">
                    {ts} &nbsp;•&nbsp; IP: <strong>{ip}</strong> &nbsp;•&nbsp;
                    Event: {etype} &nbsp;•&nbsp; Severity: {sev.upper()}
                </div>
            </div>
            """, unsafe_allow_html=True)
    else:
        st.info("No alerts recorded yet.")


# ── Footer ──────────────────────────────────────────────────────────────────
st.markdown("""
<div style="text-align:center;padding:24px 0 8px;color:#30363d;font-size:0.75rem;border-top:1px solid #21262d;margin-top:32px;">
    SecureCorp SOC Console  •  MITRE ATT&CK Enriched  •  Automated Response  •  Models: IsolationForest · RandomForest
</div>
""", unsafe_allow_html=True)
