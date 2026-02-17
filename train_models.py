# train_models.py — Train ML models for SecureCorp honeypot
import pandas as pd, joblib, os
from sklearn.ensemble import IsolationForest, RandomForestClassifier

FEATURE_CSV = os.path.join("logs", "features.csv")
MODEL_DIR = "models"
os.makedirs(MODEL_DIR, exist_ok=True)

FEATURE_COLS = [
    "path_len", "ua_len", "data_len",
    "count_sql_tokens", "count_xss_tokens",
    "num_params", "method_code", "has_sql_special_chars"
]


def label_row(r):
    """Label rows for supervised classifier training."""
    sql = r.get("count_sql_tokens", 0)
    xss = r.get("count_xss_tokens", 0)
    special = r.get("has_sql_special_chars", 0)

    # Strong SQL injection signal
    if sql > 0 and special > 0:
        return "sqli"
    if sql >= 2:
        return "sqli"
    if special >= 3 and r.get("method_code", 0) == 1:
        return "sqli"

    # XSS signal
    if xss > 0:
        return "xss"

    return "benign"


def train():
    if not os.path.exists(FEATURE_CSV):
        print(f"No features file at {FEATURE_CSV} — run log_parser.py first")
        return

    df = pd.read_csv(FEATURE_CSV)
    print(f"Loaded {len(df)} rows from {FEATURE_CSV}")

    # Encode method
    df["method_code"] = df["method"].map({"GET": 0, "POST": 1}).fillna(2).astype(int)

    # Ensure all feature columns exist
    for col in FEATURE_COLS:
        if col not in df.columns:
            df[col] = 0

    X = df[FEATURE_COLS].fillna(0)

    # Labels
    df["label_str"] = df.apply(label_row, axis=1)
    label_map = {"benign": 0, "sqli": 1, "xss": 2}
    y = df["label_str"].map(label_map).fillna(0).astype(int)

    print(f"Label distribution:\n{df['label_str'].value_counts().to_string()}")

    # Isolation Forest (unsupervised anomaly detection)
    iso = IsolationForest(n_estimators=100, contamination=0.15, random_state=42)
    iso.fit(X)
    joblib.dump(iso, os.path.join(MODEL_DIR, "isolation_forest.joblib"))
    print("Saved isolation_forest.joblib")

    # Random Forest Classifier (supervised)
    rf = RandomForestClassifier(n_estimators=100, random_state=42)
    rf.fit(X, y)
    joblib.dump(rf, os.path.join(MODEL_DIR, "rf_attack_classifier.joblib"))
    print("Saved rf_attack_classifier.joblib")

    # Quick accuracy check
    preds = rf.predict(X)
    acc = (preds == y).mean()
    print(f"Training accuracy: {acc:.2%}")


if __name__ == "__main__":
    train()
