import os
import joblib
from feature_engineering import parse_nmap, calculate_features
import pandas as pd

# -------------------------------
# CONFIG
# -------------------------------
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
XML_FILE = os.path.join(PROJECT_ROOT, "nmap_scans", "scan1.xml")
MODEL_FILE = os.path.join(PROJECT_ROOT, "model", "rf_model.pkl")

# -------------------------------
# STEP 1: LOAD MODEL
# -------------------------------
if not os.path.exists(MODEL_FILE):
    print("❌ Trained model not found. Run train_model.py first.")
    exit()

model = joblib.load(MODEL_FILE)

# -------------------------------
# STEP 2: PARSE NMAP AND EXTRACT FEATURES
# -------------------------------
hosts = parse_nmap(XML_FILE)

all_features = []
ips = []

for host in hosts:
    features = calculate_features(host)
    all_features.append([
        features["open_ports_count"],
        features["service_count"],
        features["avg_cvss"],
        features["uncommon_ports"],
        features["os_flag"]
    ])
    ips.append(host["ip"])

# Convert to DataFrame for prediction
X_new = pd.DataFrame(all_features, columns=[
    "open_ports_count",
    "service_count",
    "avg_cvss",
    "uncommon_ports",
    "os_flag"
])

# -------------------------------
# STEP 3: PREDICT RISK
# -------------------------------
predictions = model.predict(X_new)

# -------------------------------
# STEP 4: PRINT RESULTS
# -------------------------------
print("\n=== RISK PREDICTION REPORT ===\n")
for ip, risk in zip(ips, predictions):
    print(f"Host: {ip}  -->  Predicted Risk: {risk}")

print("\n✅ Prediction complete.")
