import json
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from collections import Counter
from datetime import datetime

LOG_FILE = "logs/honeypot_log.json"

def load_data():
    with open(LOG_FILE, "r") as f:
        logs = [json.loads(line) for line in f if line.strip()]
    df = pd.DataFrame(logs)
    print(f"[*] Loaded {len(df)} records")
    return df

def engineer_features(df):
    features = pd.DataFrame()
    DEFAULT_USERS = {"root","admin","administrator","test","guest","pi","ubuntu","user"}
    WEAK_PASSWORDS = {"123456","password","admin","root","12345","qwerty","letmein","monkey"}
    features["username_length"] = df["username"].str.len()
    features["is_default_username"] = df["username"].apply(lambda u: 1 if str(u).lower() in DEFAULT_USERS else 0)
    features["password_length"] = df["password"].str.len()
    features["is_weak_password"] = df["password"].apply(lambda p: 1 if str(p).lower() in WEAK_PASSWORDS else 0)
    ip_counts = df["source_ip"].value_counts().to_dict()
    features["ip_attempt_count"] = df["source_ip"].map(ip_counts)
    features["hour_of_day"] = df["timestamp"].apply(lambda t: datetime.fromisoformat(str(t)).hour)
    features["is_root"] = (df["username"] == "root").astype(int)
    features["combined_weakness"] = features["is_default_username"] * features["is_weak_password"]
    return features

def create_labels(df, features):
    ip_counts = df["source_ip"].value_counts().to_dict()
    labels = []
    for idx, row in df.iterrows():
        ip = row["source_ip"]
        count = ip_counts.get(ip, 0)
        username = str(row["username"]).lower()
        password = str(row["password"]).lower()
        if count >= 8:
            labels.append("brute_force")
        elif username in {"root","admin"} and password in {"password","123456","admin","root"}:
            labels.append("credential_attack")
        else:
            labels.append("suspicious")
    return labels

def run_classifier():
    print("[*] Starting ML Attack Classifier...")
    df = load_data()
    X = engineer_features(df)
    y = create_labels(df, X)
    print("\n[*] Label distribution:")
    for label, count in Counter(y).items():
        print(f"  {label}: {count}")
    if len(set(y)) < 2:
        print("[WARN] Only one attack type found. Generate more attack data first.")
        return
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    print(f"\n[*] Training: {len(X_train)} samples, Testing: {len(X_test)} samples")
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)
    y_pred = model.predict(X_test)
    print("\n[*] Results:")
    print(classification_report(y_test, y_pred))
    print("[*] Feature importance:")
    for feat, imp in sorted(zip(X.columns, model.feature_importances_), key=lambda x: x[1], reverse=True):
        bar = "█" * int(imp * 40)
        print(f"  {feat:<25} {bar} {imp:.3f}")
    print("\n[*] ML classifier complete!")

if __name__ == "__main__":
    run_classifier()
