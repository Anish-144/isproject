# predict_service.py
import joblib, json, time, os
from log_parser import extract_features, LOGPATH

# load models
iso = joblib.load(os.path.join("models","isolation_forest.joblib"))
rf = joblib.load(os.path.join("models","rf_attack_classifier.joblib"))

def last_log_lines():
    try:
        with open(LOGPATH) as f:
            return f.readlines()
    except FileNotFoundError:
        return []

def feature_vector(entry):
    d = extract_features(entry)
    X = [d["path_len"], d["ua_len"], d["data_len"], d["count_sql_tokens"], d["count_xss_tokens"], d["num_params"], 1 if entry.get("method")=="POST" else 0]
    return X, d

if __name__ == "__main__":
    seen = 0
    while True:
        lines = last_log_lines()
        if len(lines) > seen:
            for line in lines[seen:]:
                e = json.loads(line)
                X, d = feature_vector(e)
                pred_ano = iso.predict([X])[0]
                pred_rf = rf.predict([X])[0]
                labels = {0:"benign",1:"sqli",2:"xss"}
                print(f"{d['time']} - {d['ip']} - {d['path']} - ANOMALY={pred_ano} - CLASS={labels.get(pred_rf,'unknown')}")
            seen = len(lines)
        time.sleep(1)
