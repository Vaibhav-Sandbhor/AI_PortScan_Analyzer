import os
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import joblib  # for saving model

# -------------------------------
# CONFIG
# -------------------------------
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DATASET_FILE = os.path.join(PROJECT_ROOT, "data", "dataset.csv")
MODEL_FILE = os.path.join(PROJECT_ROOT, "model", "rf_model.pkl")

# -------------------------------
# STEP 1: LOAD DATASET
# -------------------------------
df = pd.read_csv(DATASET_FILE)

# Features and target
X = df[["open_ports_count", "service_count", "avg_cvss", "uncommon_ports", "os_flag"]]
y = df["risk_label"]

# -------------------------------
# STEP 2: SPLIT DATA
# -------------------------------
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# -------------------------------
# STEP 3: TRAIN RANDOM FOREST
# -------------------------------
rf = RandomForestClassifier(n_estimators=100, random_state=42)
rf.fit(X_train, y_train)

# -------------------------------
# STEP 4: EVALUATE MODEL
# -------------------------------
y_pred = rf.predict(X_test)

print("\n=== MODEL EVALUATION ===\n")
print("Accuracy:", round(accuracy_score(y_test, y_pred), 2))
print("\nClassification Report:\n", classification_report(y_test, y_pred))
print("\nConfusion Matrix:\n", confusion_matrix(y_test, y_pred))

# -------------------------------
# STEP 5: SAVE MODEL
# -------------------------------
# Create model folder if not exists
if not os.path.exists(os.path.join(PROJECT_ROOT, "model")):
    os.makedirs(os.path.join(PROJECT_ROOT, "model"))

joblib.dump(rf, MODEL_FILE)
print(f"\n✅ Model saved at: {MODEL_FILE}")
