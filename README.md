🔐 AI-Powered Port Scan Analyzer & Attack Surface Prioritizer
📌 Project Overview

This project is an AI-driven cybersecurity tool that analyzes Nmap scan results and automatically prioritizes attack surface risk using machine learning.
It converts raw network scan data into meaningful security insights such as Low, Medium, or High risk for each host.

The system demonstrates a complete end-to-end pipeline:

Network Scanning → Feature Engineering → ML-based Risk Prediction → Explainable Output

🎯 Objectives

Automate analysis of Nmap scan results

Reduce manual effort in port and service risk assessment

Use Machine Learning (Random Forest) to classify host risk

Provide explainable security decisions suitable for SOC & academic use

🧠 Key Features

✔ Parses Nmap XML scan output

✔ Extracts security-relevant features (ports, services, CVSS, OS)

✔ Generates large realistic datasets for ML training

✔ Trains Random Forest risk classification model

✔ Predicts risk for new scans

✔ Master demo script with detailed risk explanation

🏗 Project Architecture
Nmap Scan
   ↓
XML Parsing
   ↓
Feature Engineering
   ↓
Dataset Creation
   ↓
ML Model Training
   ↓
Risk Prediction (Low / Medium / High)

📂 Project Structure
AI_PortScan_Analyzer/
│
├── scripts/
│   ├── parse_nmap.py
│   ├── feature_engineering.py
│   ├── train_model.py
│   ├── predict_risk.py
│   └── master_demo_explained.py
│
├── data/
│   ├── generate_dataset.py
│   └── dataset.csv
│
├── model/
│   └── rf_model.pkl   (ignored in git)
│
├── nmap_scans/
│   └── *.xml          (ignored in git)
│
├── .gitignore
└── README.md

⚙️ Technologies Used

Nmap – Network scanning

Python 3.11+

Pandas – Data processing

Scikit-learn – Machine Learning

Random Forest Classifier

Git & GitHub – Version control

🚀 How to Run the Project
1️⃣ Install Requirements
pip install pandas scikit-learn joblib


Ensure Nmap is installed and added to PATH:

nmap --version

2️⃣ Generate Dataset (100+ rows)
python data/generate_dataset.py

3️⃣ Train ML Model
python scripts/train_model.py

4️⃣ Run Full End-to-End Demo (Recommended)
python scripts/master_demo_explained.py


This will:

Run Nmap scan

Extract features

Load ML model

Predict risk

Explain why risk is High / Medium / Low

📊 Sample Output
Host: 127.0.0.1
OS: Windows
Open Ports: 4
Services: msrpc, microsoft-ds, vmware-auth
Average CVSS: 7.77
Predicted Risk: High
Explanation: High CVSS score, uncommon ports detected

🧪 ML Model Details

Algorithm: Random Forest Classifier

Input Features:

Open ports count

Service count

Average CVSS score

Uncommon ports flag

OS flag

Output: Risk Category (Low / Medium / High)

🎓 Academic Relevance

This project is suitable for:

Final Year Engineering Project

Cybersecurity / AI / Forensics domain

Demonstrates AI + Security integration

Scalable to enterprise networks

🔮 Future Enhancements

CVE database integration (NVD)

Real-time scanning dashboard

SIEM integration

Deep learning-based anomaly detection

Dark web threat intelligence mapping

👤 Author

Vaibhav Sandbhor
Cybersecurity & AI Enthusiast

⭐ GitHub

If you like this project, please ⭐ star the repository!