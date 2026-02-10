# log_parser.py
import json, pandas as pd
from urllib.parse import urlparse
import datetime

LOGPATH = "logs/honeypot_logs.jsonl"
OUTCSV = "logs/features.csv"

def extract_features(entry):
    data = {}
    data["time"] = entry.get("time")
    data["ip"] = entry.get("ip")
    data["path"] = entry.get("path","")
    data["path_len"] = len(entry.get("path","") or "")
    data["method"] = entry.get("method","")
    data["ua"] = entry.get("headers",{}).get("User-Agent","")
    data["ua_len"] = len(data["ua"])
    data["data_len"] = len(entry.get("data","") or "")
    payload = (entry.get("data","") or "") + " " + " ".join(entry.get("args",{}).values()) + " " + " ".join(entry.get("form",{}).values())
    payload_lower = payload.lower() if payload else ""
    data["count_sql_tokens"] = sum(payload_lower.count(t) for t in ["select","union","insert","update","drop","--",";"])
    data["count_xss_tokens"] = sum(payload_lower.count(t) for t in ["<script>", "javascript:", "onerror", "<img"])
    data["num_params"] = len(entry.get("args",{})) + len(entry.get("form",{}))
    return data

def parse_all():
    rows = []
    try:
        with open(LOGPATH) as f:
            for line in f:
                entry = json.loads(line)
                rows.append(extract_features(entry))
    except FileNotFoundError:
        print("No logs found at", LOGPATH)
        return
    df = pd.DataFrame(rows)
    if df.empty:
        print("No log entries parsed.")
        return
    df['method_code'] = df['method'].map({'GET':0,'POST':1}).fillna(2)
    df['ip_count'] = df.groupby('ip')['ip'].transform('count')
    df.to_csv(OUTCSV, index=False)
    print("Wrote features to", OUTCSV)

if __name__ == "__main__":
    parse_all()
