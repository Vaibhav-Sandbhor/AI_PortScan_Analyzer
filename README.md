# 🔐 AI Port Scan Risk Intelligence Engine v2.0

> 🚀 **Production-Ready AI-Powered Network Risk Assessment Platform**  
> 🧠 Explainable Machine Learning • Hybrid Risk Scoring • FastAPI Backend • Drift Monitoring  

---

## 🌟 Overview

The **AI Port Scan Risk Intelligence Engine** transforms raw **Nmap scan results** into structured, explainable, and actionable security intelligence.

Unlike traditional scanners that only list open ports, this system:

- **Predicts host-level risk using ML (XGBoost + Calibration)**
- **Explains WHY a system is risky using SHAP**
- **Combines ML predictions with a Port Intelligence Database**
- **Detects data drift automatically**
- **Supports automated retraining pipelines**
- **Provides a production-ready FastAPI backend**

> This is not just a scanner — this is a structured **AI-driven Security Intelligence Engine**.

---

# 🏗 Architecture (v2.0)

```text
                Nmap XML Scan
                      ↓
         Feature Engineering (9 Features)
                      ↓
        XGBoost + Probability Calibration
                      ↓
        SHAP Explainability + Hybrid Logic
                      ↓
       ┌──────────────┼──────────────┐
       ↓              ↓              ↓
   Dashboard       Full Report       Admin
  (Frontend)      (Technical)     (Backend Only)
```

---

## 🧠 Machine Learning Stack

### 🔹 Core Model
- **XGBoost Classifier**
- Hyperparameter tuned
- Class-weight balanced
- Cross-validated training

### 🔹 Probability Calibration
- `CalibratedClassifierCV`
- Reliable confidence scoring
- Reduced overconfidence bias
- Improved Brier score

### 🔹 Explainable AI
- **SHAP TreeExplainer**
- Feature contribution breakdown
- Risk impact direction (↑ increases / ↓ decreases risk)
- Transparent decision reasoning

### 🔹 Hybrid Risk Engine
Final risk is determined using:

- ML prediction  
- Port severity override logic  
- Risk amplification rules  
- Justified final decision  

---

## 📊 Feature Engineering (9 Core Features)

| Feature | Purpose |
|----------|----------|
| open_ports_count | Measures attack surface size |
| service_count | Service diversity |
| avg_cvss | Vulnerability severity |
| uncommon_ports | Suspicious port usage |
| os_flag | OS risk profiling |
| port_severity_score | Aggregated port risk |
| high_risk_port_count | Critical exposure level |
| service_entropy | Service randomness |
| cvss_variance | Vulnerability spread |

---

## ⚙️ FastAPI Backend (Production Structured)

### 📡 API Endpoints

| Method | Endpoint | Purpose |
|--------|----------|----------|
| POST | `/scan` | Analyze Nmap XML (Dashboard view) |
| GET | `/report/{scan_id}` | Full technical report with SHAP |
| GET | `/admin/status` | Backend metrics (API key required) |
| GET | `/health` | Health check |
| GET | `/docs` | Swagger API UI |

---

## 🚀 Quick Start

### 1️⃣ Install Dependencies

```bash
pip install -r requirements.txt
pip install -r requirements_api.txt
```

### 2️⃣ Start API Server

```bash
python api.py
```

API runs at:

```
http://localhost:8000
```

Swagger UI:

```
http://localhost:8000/docs
```

### 3️⃣ Analyze a Scan

```bash
curl -X POST "http://localhost:8000/scan" \
  -F "xml_file=@nmap_scans/sample_scan.xml"
```

---

## 🔎 What Makes This Different?

✔ ML-based risk classification  
✔ Explainable AI decisions  
✔ Hybrid ML + Port Intelligence consensus  
✔ Drift detection monitoring  
✔ Auto-retraining pipeline  
✔ Production-ready REST backend  
✔ Clean frontend / admin separation  

> This is not a simple scanner output — this is structured **Risk Intelligence**.

---

## 📈 Model Performance

- **Accuracy:** ~84–90% (dataset dependent)  
- **Weighted F1 Score:** ~0.84+  
- Calibrated probability confidence  
- Reduced Brier score after calibration  
- Stable cross-validation performance  

---

## 🛡 Security Intelligence Capabilities

- Detects high-risk exposure (SMB, RDP, DB ports)
- CVE mapping with real-world examples
- MITRE ATT&CK tactic mapping
- Transparent risk justification
- Host-level security score (0–100)

---

## 🔄 Drift Detection & Retraining

Monitors distribution shifts in:

- `open_ports_count`
- `avg_cvss`
- `service_count`

Uses:
- KS-Test
- Statistical drift %
- Threshold-based alerts

Supports:
- Automated retraining pipeline
- Operational logging
- Model lifecycle management

---

## 📦 Project Structure

```text
AI_PortScan_Analyzer/
│
├── api.py
│
├── scripts/
│   ├── predict_risk.py
│   ├── train_model.py
│   ├── drift_detection.py
│   ├── retrain_pipeline.py
│   └── run_engine.py
│
├── data/
│   ├── port_knowledge.py
│   ├── generate_dataset.py
│
├── model/
├── logs/
│
├── requirements.txt
├── requirements_api.txt
└── README.md
```

---

## 🏷 Version History

### 🔹 v1.0
- Console-based ML risk predictor

### 🔹 v2.0 (Current)
- FastAPI backend
- XGBoost integration
- Probability calibration
- SHAP explainability
- Hybrid scoring engine
- Drift detection
- Auto-retraining pipeline
- Production-ready structure

---

## ⭐ Why This Project Matters

This project demonstrates:

- **Applied Machine Learning**
- **Explainable AI (XAI)**
- **Cybersecurity domain intelligence**
- **Backend API architecture**
- **Model monitoring & lifecycle management**
- **Production-ready system design**

> This is not a toy script — this is a structured **AI-powered security platform**.

---

## 🏁 Status

- ✅ Production Structured  
- ✅ Version 2.0  
- ✅ Explainable AI Enabled  
- ✅ Drift Monitoring Integrated  
- ✅ API Architecture Deployed  

---
