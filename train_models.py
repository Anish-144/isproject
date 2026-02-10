# train_models.py
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
import joblib, os

os.makedirs("models", exist_ok=True)
try:
    df = pd.read_csv("logs/features.csv")
except Exception as e:
    print("Could not read features.csv. Run log_parser.py after generating logs. Error:", e)
    raise SystemExit(1)

X = df[["path_len","ua_len","data_len","count_sql_tokens","count_xss_tokens","num_params","method_code"]].fillna(0)

iso = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
iso.fit(X)
joblib.dump(iso, "models/isolation_forest.joblib")
print("Saved models/isolation_forest.joblib")

def label_row(r):
    if r["count_sql_tokens"]>0: return "sqli"
    if r["count_xss_tokens"]>0: return "xss"
    return "benign"

df["label"] = df.apply(label_row, axis=1)
y = df["label"].map({"benign":0,"sqli":1,"xss":2}).fillna(0)

rf = RandomForestClassifier(n_estimators=100, random_state=42)
rf.fit(X, y)
joblib.dump(rf, "models/rf_attack_classifier.joblib")
print("Saved models/rf_attack_classifier.joblib")
