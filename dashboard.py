import streamlit as st
import pandas as pd, json, joblib, os, io
from log_parser import extract_features, LOGPATH
from datetime import datetime
import re

st.set_page_config(page_title="AI Honeypot Dashboard", layout="wide")
st.title("🛡️ AI-Powered Honeypot Dashboard")
st.markdown("---")

# Sidebar controls
with st.sidebar:
    st.header("Controls")
    show_raw = st.checkbox("Show raw logs", value=True)
    filter_anomalies = st.checkbox("Only anomalies (-1)", value=False)
    filter_path = st.text_input("Filter by path contains", value="")
    filter_ip = st.text_input("Filter by IP contains", value="")
    refresh = st.button("Refresh data")

model_iso = None
model_rf = None
try:
    model_iso = joblib.load(os.path.join("models","isolation_forest.joblib"))
    model_rf = joblib.load(os.path.join("models","rf_attack_classifier.joblib"))
except Exception:
    st.warning("Models not found in models/ — run train_models.py after generating logs.")

def load_logs():
    rows = []
    try:
        with open(LOGPATH) as f:
            for line in f:
                rows.append(json.loads(line))
    except FileNotFoundError:
        return []
    return rows

def analyze_attack_patterns(log_entry):
    """Analyze attack patterns and extract threat intelligence"""
    analysis = {
        'attack_type': 'Unknown',
        'severity': 'Low',
        'payload_analysis': {},
        'threat_indicators': [],
        'recommendations': []
    }
    
    # SQL Injection Detection
    sql_patterns = [
        r"union\s+select", r"drop\s+table", r"delete\s+from", r"insert\s+into",
        r"update\s+set", r"or\s+1\s*=\s*1", r"and\s+1\s*=\s*1", r"'\s*or\s*'",
        r"'\s*;\s*--", r"'\s*;\s*#", r"'\s*;\s*\/\*", r"'\s*;\s*\/\/"
    ]
    
    # XSS Detection
    xss_patterns = [
        r"<script[^>]*>", r"javascript:", r"onerror\s*=", r"onload\s*=",
        r"onclick\s*=", r"onmouseover\s*=", r"<img[^>]*>", r"<iframe[^>]*>",
        r"<object[^>]*>", r"<embed[^>]*>", r"<link[^>]*>", r"<meta[^>]*>"
    ]
    
    # Path Traversal
    path_patterns = [
        r"\.\.\/", r"\.\.\\", r"\.\.%2f", r"\.\.%5c", r"\.\.%252f", r"\.\.%255c"
    ]
    
    # Command Injection
    cmd_patterns = [
        r";\s*cat\s+", r";\s*ls\s+", r";\s*dir\s+", r";\s*whoami", r";\s*id\s*",
        r"|\s*cat\s+", r"|\s*ls\s+", r"|\s*dir\s+", r"|\s*whoami", r"|\s*id\s*",
        r"`.*`", r"\$\(.*\)", r"&&.*", r"\|\|.*"
    ]
    
    # Combine all text fields for analysis
    text_to_analyze = ""
    if 'form' in log_entry and log_entry['form']:
        text_to_analyze += " ".join([str(v) for v in log_entry['form'].values()])
    if 'args' in log_entry and log_entry['args']:
        text_to_analyze += " ".join([str(v) for v in log_entry['args'].values()])
    if 'data' in log_entry and log_entry['data']:
        text_to_analyze += str(log_entry['data'])
    if 'path' in log_entry:
        text_to_analyze += str(log_entry['path'])
    
    text_to_analyze = text_to_analyze.lower()
    
    # Check for SQL Injection
    sql_matches = [pattern for pattern in sql_patterns if re.search(pattern, text_to_analyze, re.IGNORECASE)]
    if sql_matches:
        analysis['attack_type'] = 'SQL Injection'
        analysis['severity'] = 'High'
        analysis['threat_indicators'].append('SQL injection payload detected')
        analysis['payload_analysis']['sql_patterns'] = sql_matches
        analysis['recommendations'].append('Implement parameterized queries')
        analysis['recommendations'].append('Use input validation and sanitization')
    
    # Check for XSS
    xss_matches = [pattern for pattern in xss_patterns if re.search(pattern, text_to_analyze, re.IGNORECASE)]
    if xss_matches:
        analysis['attack_type'] = 'Cross-Site Scripting (XSS)'
        analysis['severity'] = 'High'
        analysis['threat_indicators'].append('XSS payload detected')
        analysis['payload_analysis']['xss_patterns'] = xss_matches
        analysis['recommendations'].append('Implement output encoding')
        analysis['recommendations'].append('Use Content Security Policy (CSP)')
    
    # Check for Path Traversal
    path_matches = [pattern for pattern in path_patterns if re.search(pattern, text_to_analyze, re.IGNORECASE)]
    if path_matches:
        analysis['attack_type'] = 'Path Traversal'
        analysis['severity'] = 'Medium'
        analysis['threat_indicators'].append('Directory traversal attempt detected')
        analysis['payload_analysis']['path_patterns'] = path_matches
        analysis['recommendations'].append('Validate and sanitize file paths')
        analysis['recommendations'].append('Use whitelist-based file access')
    
    # Check for Command Injection
    cmd_matches = [pattern for pattern in cmd_patterns if re.search(pattern, text_to_analyze, re.IGNORECASE)]
    if cmd_matches:
        analysis['attack_type'] = 'Command Injection'
        analysis['severity'] = 'Critical'
        analysis['threat_indicators'].append('Command injection attempt detected')
        analysis['payload_analysis']['cmd_patterns'] = cmd_matches
        analysis['recommendations'].append('Avoid system command execution')
        analysis['recommendations'].append('Use safe APIs and libraries')
    
    # Check for suspicious user agents
    if 'headers' in log_entry and 'User-Agent' in log_entry['headers']:
        ua = log_entry['headers']['User-Agent'].lower()
        if any(suspicious in ua for suspicious in ['sqlmap', 'nikto', 'nmap', 'scanner', 'bot', 'crawler']):
            analysis['threat_indicators'].append('Suspicious User-Agent detected')
            analysis['severity'] = 'Medium' if analysis['severity'] == 'Low' else analysis['severity']
    
    # Check for multiple requests from same IP (potential scanning)
    if 'ip' in log_entry:
        analysis['payload_analysis']['source_ip'] = log_entry['ip']
    
    return analysis

def format_timestamp(timestamp_str):
    """Format timestamp for display"""
    try:
        dt = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
        return dt.strftime('%Y-%m-%d %H:%M:%S')
    except:
        return timestamp_str

def get_severity_color(severity):
    """Get color for severity level"""
    colors = {
        'Low': '🟢',
        'Medium': '🟡', 
        'High': '🟠',
        'Critical': '🔴'
    }
    return colors.get(severity, '⚪')

logs = load_logs()
if not logs:
    st.info("No logs found. Start the honeypot and generate traffic (simulate_traffic.py).")
else:
    df = pd.DataFrame(logs)
    # Compute features to align with model training
    feats = [extract_features(r) for r in logs]
    fdf = pd.DataFrame(feats).fillna(0)
    # Ensure time is datetime for charts
    if "time" in fdf.columns:
        fdf["time"] = pd.to_datetime(fdf["time"], errors="coerce")
    fdf['method_code'] = fdf['method'].map({'GET':0,'POST':1}).fillna(2)
    X = fdf[["path_len","ua_len","data_len","count_sql_tokens","count_xss_tokens","num_params","method_code"]]

    # Predictions
    if model_rf is not None:
        fdf['pred'] = model_rf.predict(X)
    if model_iso is not None:
        fdf['anomaly'] = model_iso.predict(X)

    # Apply sidebar filters
    view_df = fdf.copy()
    if filter_anomalies and 'anomaly' in view_df:
        view_df = view_df[view_df['anomaly'] == -1]
    if filter_path:
        view_df = view_df[view_df['path'].astype(str).str.contains(filter_path, case=False, na=False)]
    if filter_ip:
        view_df = view_df[view_df['ip'].astype(str).str.contains(filter_ip, case=False, na=False)]

    # KPIs
    total_requests = len(fdf)
    anomaly_count = int((fdf['anomaly'] == -1).sum()) if 'anomaly' in fdf else 0
    pred_counts = fdf['pred'].value_counts() if 'pred' in fdf else pd.Series(dtype=int)
    benign_count = int(pred_counts.get(0, 0))
    sqli_count = int(pred_counts.get(1, 0))
    xss_count = int(pred_counts.get(2, 0))

    k1, k2, k3, k4 = st.columns(4)
    k1.metric("Total Requests", f"{total_requests}")
    k2.metric("Anomalies (-1)", f"{anomaly_count}")
    k3.metric("SQLi (pred=1)", f"{sqli_count}")
    k4.metric("XSS (pred=2)", f"{xss_count}")

    # Charts
    st.subheader("Distribution")
    cc1, cc2 = st.columns(2)
    with cc1:
        if 'pred' in fdf:
            chart_data = fdf['pred'].map({0:'benign',1:'sqli',2:'xss'}).value_counts().rename_axis('class').reset_index(name='count')
            st.bar_chart(chart_data.set_index('class'))
        else:
            st.info("Train RandomForest to see class distribution.")
    with cc2:
        if 'anomaly' in fdf:
            st.bar_chart(pd.Series({'normal': (fdf['anomaly'] == 1).sum(), 'anomaly': (fdf['anomaly'] == -1).sum()}))
        else:
            st.info("Train IsolationForest to see anomaly distribution.")

    # Attack Analysis Section
    st.subheader("🔍 Attack Analysis")
    
    # Create tabs for different views
    tab1, tab2, tab3, tab4 = st.tabs(["📊 Overview", "🎯 Attack Details", "📈 Real-time Monitor", "📋 Reports"])
    
    with tab1:
        # Recent events with enhanced display
        st.subheader("Recent Security Events")
        recent = view_df.sort_values("time", ascending=False).head(50) if 'time' in view_df else view_df.tail(50)
        
        if show_raw:
            # Enhanced dataframe with clickable rows
            display_cols = ['time','ip','method','path','pred','anomaly']
            present_cols = [c for c in display_cols if c in recent.columns]
            
            # Add severity analysis
            recent_with_analysis = recent.copy()
            for idx, row in recent_with_analysis.iterrows():
                log_entry = logs[idx] if idx < len(logs) else {}
                analysis = analyze_attack_patterns(log_entry)
                recent_with_analysis.loc[idx, 'severity'] = analysis['severity']
                recent_with_analysis.loc[idx, 'attack_type'] = analysis['attack_type']
            
            # Display with enhanced formatting
            for idx, row in recent_with_analysis.iterrows():
                with st.expander(f"{get_severity_color(row.get('severity', 'Low'))} {format_timestamp(row.get('time', ''))} - {row.get('ip', 'Unknown')} - {row.get('method', 'Unknown')} {row.get('path', 'Unknown')}", expanded=False):
                    col1, col2, col3 = st.columns(3)
                    
                    with col1:
                        st.write("**Basic Info:**")
                        st.write(f"IP: {row.get('ip', 'Unknown')}")
                        st.write(f"Method: {row.get('method', 'Unknown')}")
                        st.write(f"Path: {row.get('path', 'Unknown')}")
                        st.write(f"Time: {format_timestamp(row.get('time', ''))}")
                    
                    with col2:
                        st.write("**AI Analysis:**")
                        st.write(f"Predicted Class: {row.get('pred', 'Unknown')}")
                        st.write(f"Anomaly: {'Yes' if row.get('anomaly', 0) == -1 else 'No'}")
                        st.write(f"Attack Type: {row.get('attack_type', 'Unknown')}")
                        st.write(f"Severity: {get_severity_color(row.get('severity', 'Low'))} {row.get('severity', 'Low')}")
                    
                    with col3:
                        st.write("**Request Details:**")
                        if idx < len(logs):
                            log_entry = logs[idx]
                            if log_entry.get('form'):
                                st.write("**Form Data:**")
                                for k, v in log_entry['form'].items():
                                    st.code(f"{k}: {v}")
                            if log_entry.get('args'):
                                st.write("**Query Parameters:**")
                                for k, v in log_entry['args'].items():
                                    st.code(f"{k}: {v}")
                            if log_entry.get('headers', {}).get('User-Agent'):
                                st.write("**User Agent:**")
                                st.code(log_entry['headers']['User-Agent'])
    
    with tab2:
        st.subheader("🎯 Detailed Attack Analysis")
        
        # Filter for attacks only
        attacks = view_df[view_df.get('pred', 'benign') != 'benign'] if 'pred' in view_df else pd.DataFrame()
        
        if not attacks.empty:
            for idx, row in attacks.iterrows():
                if idx < len(logs):
                    log_entry = logs[idx]
                    analysis = analyze_attack_patterns(log_entry)
                    
                    with st.expander(f"🚨 {analysis['attack_type']} - {get_severity_color(analysis['severity'])} {analysis['severity']} - {row.get('ip', 'Unknown')}", expanded=True):
                        col1, col2 = st.columns(2)
                        
                        with col1:
                            st.write("**Attack Details:**")
                            st.write(f"**Type:** {analysis['attack_type']}")
                            st.write(f"**Severity:** {get_severity_color(analysis['severity'])} {analysis['severity']}")
                            st.write(f"**Source IP:** {row.get('ip', 'Unknown')}")
                            st.write(f"**Target:** {row.get('path', 'Unknown')}")
                            st.write(f"**Method:** {row.get('method', 'Unknown')}")
                            st.write(f"**Timestamp:** {format_timestamp(row.get('time', ''))}")
                            
                            if analysis['threat_indicators']:
                                st.write("**Threat Indicators:**")
                                for indicator in analysis['threat_indicators']:
                                    st.write(f"• {indicator}")
                        
                        with col2:
                            st.write("**Payload Analysis:**")
                            if log_entry.get('form'):
                                st.write("**Form Data:**")
                                for k, v in log_entry['form'].items():
                                    if any(pattern in str(v).lower() for pattern in ['union', 'select', 'script', 'alert', 'drop', 'delete']):
                                        st.error(f"🚨 {k}: {v}")
                                    else:
                                        st.code(f"{k}: {v}")
                            
                            if log_entry.get('args'):
                                st.write("**Query Parameters:**")
                                for k, v in log_entry['args'].items():
                                    if any(pattern in str(v).lower() for pattern in ['union', 'select', 'script', 'alert', 'drop', 'delete']):
                                        st.error(f"🚨 {k}: {v}")
                                    else:
                                        st.code(f"{k}: {v}")
                            
                            if analysis['recommendations']:
                                st.write("**Security Recommendations:**")
                                for rec in analysis['recommendations']:
                                    st.info(f"💡 {rec}")
        else:
            st.info("No attacks detected in the current view.")
    
    with tab3:
        st.subheader("📈 Real-time Security Monitor")
        
        # Auto-refresh every 5 seconds
        if st.button("🔄 Refresh Data"):
            st.rerun()
        
        # Show live statistics
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Total Requests", len(fdf))
        
        with col2:
            attack_count = len(fdf[fdf.get('pred', 'benign') != 'benign']) if 'pred' in fdf else 0
            st.metric("Attacks Detected", attack_count)
        
        with col3:
            anomaly_count = int((fdf['anomaly'] == -1).sum()) if 'anomaly' in fdf else 0
            st.metric("Anomalies", anomaly_count)
        
        with col4:
            unique_ips = fdf['ip'].nunique() if 'ip' in fdf else 0
            st.metric("Unique IPs", unique_ips)
        
        # Live log stream
        st.write("**Live Log Stream:**")
        recent_logs = logs[-10:] if logs else []
        for log in reversed(recent_logs):
            analysis = analyze_attack_patterns(log)
            severity_icon = get_severity_color(analysis['severity'])
            st.write(f"{severity_icon} {format_timestamp(log.get('time', ''))} - {log.get('ip', 'Unknown')} - {log.get('method', 'Unknown')} {log.get('path', 'Unknown')} - {analysis['attack_type']}")
    
    with tab4:
        st.subheader("📋 Security Reports")
        
        # Generate comprehensive report
        if st.button("📊 Generate Security Report"):
            report_data = {
                'total_requests': len(fdf),
                'unique_ips': fdf['ip'].nunique() if 'ip' in fdf else 0,
                'attack_types': fdf['pred'].value_counts().to_dict() if 'pred' in fdf else {},
                'anomalies': int((fdf['anomaly'] == -1).sum()) if 'anomaly' in fdf else 0,
                'time_range': {
                    'start': fdf['time'].min() if 'time' in fdf else 'Unknown',
                    'end': fdf['time'].max() if 'time' in fdf else 'Unknown'
                }
            }
            
            st.write("**Security Report Summary:**")
            st.json(report_data)
            
            # Export options
            st.write("**Export Options:**")
            if st.button("📥 Download CSV Report"):
                csv = fdf.to_csv(index=False)
                st.download_button(
                    label="Download CSV",
                    data=csv,
                    file_name=f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                    mime="text/csv"
                )

    # Downloads
    st.subheader("Export")
    log_bytes = io.StringIO()
    df.to_csv(log_bytes, index=False)
    st.download_button("Download raw logs (CSV)", log_bytes.getvalue(), file_name="raw_logs.csv", mime="text/csv")

    feat_bytes = io.StringIO()
    fdf.to_csv(feat_bytes, index=False)
    st.download_button("Download features (CSV)", feat_bytes.getvalue(), file_name="features.csv", mime="text/csv")

    # Footer
    st.caption("Models: IsolationForest flags anomalies as -1; RF classes: 0=benign,1=sqli,2=xss")
