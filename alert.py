import sqlite3
from datetime import datetime

# Ports to flag as risky
DANGEROUS_PORTS = {21, 23, 3389, 445, 5900, 3306}
ALERT_LOG = "alerts.log"

def scan_alerts():
    conn = sqlite3.connect("shodan_lite.db")
    cursor = conn.cursor()

    cursor.execute("""
        SELECT ip, port, service, product, version, country, cve, scan_time
        FROM services
        ORDER BY scan_time DESC
    """)
    results = cursor.fetchall()
    conn.close()

    alerts = []

    for row in results:
        ip, port, service, product, version, country, cve, scan_time = row

        alert_reasons = []

        # Rule 1: Dangerous Port
        if port in DANGEROUS_PORTS:
            alert_reasons.append(f"⚠️ Dangerous Port {port}")

        # Rule 2: CVE present
        if cve:
            alert_reasons.append(f"🚨 Vulnerability Detected: {cve}")

        # Rule 3: Suspicious country (e.g. non-AU)
        if country and country not in {"Australia", "AU"}:
            alert_reasons.append(f"🌍 Outside Region: {country}")

        if alert_reasons:
            msg = f"[{scan_time}] {ip}:{port} → {' | '.join(alert_reasons)}"
            alerts.append(msg)

    if alerts:
        print("\n".join(alerts))
        with open(ALERT_LOG, "a") as log:
            for alert in alerts:
                log.write(f"{alert}\n")
        print(f"\n✅ {len(alerts)} alert(s) written to {ALERT_LOG}")
    else:
        print("✅ No alerts triggered.")

if __name__ == "__main__":
    scan_alerts()

import alert
alert.scan_alerts()
