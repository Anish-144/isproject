# predict_service.py — Real-time prediction monitor for SecureCorp
import joblib, json, time, os
from log_parser import extract_features, LOGPATH

iso = joblib.load(os.path.join("models", "isolation_forest.joblib"))
rf = joblib.load(os.path.join("models", "rf_attack_classifier.joblib"))

FEATURE_COLS = ["path_len", "ua_len", "data_len", "count_sql_tokens",
                "count_xss_tokens", "num_params", "method_code", "has_sql_special_chars"]

def feature_vector(entry):
    d = extract_features(entry)
    method_code = 1 if entry.get("method") == "POST" else 0
    X = [d["path_len"], d["ua_len"], d["data_len"], d["count_sql_tokens"],
         d["count_xss_tokens"], d["num_params"], method_code,
         d.get("has_sql_special_chars", 0)]
    return X, d

if __name__ == "__main__":
    seen = 0
    labels = {0: "benign", 1: "sqli", 2: "xss"}
    print("Monitoring", LOGPATH, "...")
    while True:
        try:
            with open(LOGPATH) as f:
                lines = f.readlines()
        except FileNotFoundError:
            time.sleep(1)
            continue
        if len(lines) > seen:
            for line in lines[seen:]:
                try:
                    e = json.loads(line)
                except:
                    continue
                X, d = feature_vector(e)
                pred_ano = iso.predict([X])[0]
                pred_rf = rf.predict([X])[0]
                cls = labels.get(int(pred_rf), "unknown")
                print(f"{d['time']} | {d['ip']} | {d['method']} {d['path']} | class={cls} anom={pred_ano}")
            seen = len(lines)
        time.sleep(1)
