import csv
import random

OUTPUT_FILE = "data/dataset.csv"

rows = []

for i in range(1, 121):  # 🔥 120 rows
    ip = f"192.168.1.{i}"

    open_ports = random.randint(1, 15)
    service_count = random.randint(1, 8)
    avg_cvss = round(random.uniform(2.0, 9.8), 2)
    uncommon_ports = random.choice([0, 1])
    os_flag = random.choice([0, 1])  # 0 = Linux, 1 = Windows

    # 🎯 Risk labeling logic (IMPORTANT)
    if avg_cvss >= 7.5 or open_ports >= 10:
        risk = "High"
    elif avg_cvss >= 4.5 or open_ports >= 5:
        risk = "Medium"
    else:
        risk = "Low"

    rows.append([
        ip,
        open_ports,
        service_count,
        avg_cvss,
        uncommon_ports,
        os_flag,
        risk
    ])

with open(OUTPUT_FILE, "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow([
        "ip",
        "open_ports_count",
        "service_count",
        "avg_cvss",
        "uncommon_ports",
        "os_flag",
        "risk_label"
    ])
    writer.writerows(rows)

print("✅ Dataset generated successfully:", OUTPUT_FILE)
print("📊 Total rows:", len(rows))
