# log_parser.py — Feature extraction for SecureCorp honeypot logs
import json, csv, os
from datetime import datetime

LOGFILE = "honeypot_logs.json"
LOGPATH = os.path.join("logs", LOGFILE)

# ── SQL injection tokens ────────────────────────────────────────────────────
SQL_TOKENS = [
    "select", "union", "insert", "update", "drop", "delete",
    "--", ";", "/*", "*/", "' or", "' and", "'or", "'and",
    "1=1", "'='", "or 1", "or '1", "or true", "and 1=1",
    "char(", "exec", "execute", "having", "group by",
    "sleep(", "benchmark(", "concat(", "load_file", "outfile",
    "information_schema", "table_name", "column_name",
]

# ── XSS tokens ──────────────────────────────────────────────────────────────
XSS_TOKENS = [
    "<script", "</script", "javascript:", "onerror", "onload",
    "onclick", "onmouseover", "onfocus", "onblur",
    "<img", "<svg", "<iframe", "<object", "<embed", "<body",
    "eval(", "document.cookie", "document.write", "innerhtml",
    "alert(", "prompt(", "confirm(",
]


def extract_features(entry):
    """Extract features from a single log entry for ML models."""
    data = {}

    # Basic fields
    data["time"] = entry.get("timestamp", entry.get("time", ""))
    data["ip"] = entry.get("ip", "")
    data["method"] = entry.get("method", "GET")
    data["path"] = entry.get("endpoint", entry.get("path", "/"))

    # Length features
    data["path_len"] = len(data["path"])
    ua = ""
    headers = entry.get("headers", {})
    if isinstance(headers, dict):
        ua = headers.get("User-Agent", "")
    data["ua_len"] = len(ua)

    raw_data = entry.get("data", "") or ""
    data["data_len"] = len(raw_data)

    # Build payload string from all input sources
    parts = [raw_data]
    args = entry.get("args", {})
    form = entry.get("form", {})
    if isinstance(args, dict):
        parts.extend(str(v) for v in args.values())
    if isinstance(form, dict):
        parts.extend(str(v) for v in form.values())
    payload = " ".join(parts)
    payload_lower = payload.lower()

    # SQL token count
    data["count_sql_tokens"] = sum(payload_lower.count(t) for t in SQL_TOKENS)

    # XSS token count
    data["count_xss_tokens"] = sum(payload_lower.count(t) for t in XSS_TOKENS)

    # Parameter count
    num_args = len(args) if isinstance(args, dict) else 0
    num_form = len(form) if isinstance(form, dict) else 0
    data["num_params"] = num_args + num_form

    # Special characters that indicate injection
    data["has_sql_special_chars"] = (
        payload.count("'") + payload.count('"') + payload.count(";")
        + payload.count("--") + payload.count("/*") + payload.count("*/")
    )

    return data


def parse_logs():
    """Parse all log entries and produce features.csv."""
    if not os.path.exists(LOGPATH):
        print(f"No logs found at {LOGPATH}")
        return

    features = []
    with open(LOGPATH) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            feat = extract_features(entry)
            # Carry forward stored predictions for dashboard
            feat["predicted_class"] = entry.get("predicted_class", "benign")
            feat["is_anomaly"] = entry.get("is_anomaly", False)
            feat["event_type"] = entry.get("event_type", "request")
            feat["severity"] = entry.get("severity", "low")
            features.append(feat)

    if not features:
        print("No features extracted — check log format")
        return

    out = os.path.join("logs", "features.csv")
    cols = list(features[0].keys())
    with open(out, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        w.writerows(features)
    print(f"Wrote {len(features)} rows to {out}")


if __name__ == "__main__":
    parse_logs()
