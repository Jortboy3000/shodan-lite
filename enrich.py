import sqlite3
import requests

GEOIP_API = "http://ip-api.com/json/"
CVE_MAP = {
    "lighttpd 1.4.45": "CVE-2018-19052",
    "uhttpd 1.0.0": "CVE-2016-7100"
}

def enrich():
    conn = sqlite3.connect("shodan_lite.db")
    cursor = conn.cursor()

    # Get distinct IPs with product/version
    cursor.execute("SELECT DISTINCT ip, product, version FROM services")
    rows = cursor.fetchall()

    for ip, product, version in rows:
        # Skip local/private IPs
        if ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172.16."):
            continue

        # --- GEOIP Lookup ---
        try:
            r = requests.get(GEOIP_API + ip, timeout=4)
            data = r.json()
            country = data.get("country", "")
            city = data.get("city", "")
            isp = data.get("isp", "")
        except:
            country = city = isp = ""

        # --- CVE Match ---
        key = f"{product} {version}".strip()
        cve = CVE_MAP.get(key, "")

        # Update all matching rows
        cursor.execute("""
            UPDATE services
            SET country=?, city=?, isp=?, cve=?
            WHERE ip=? AND product=? AND version=?
        """, (country, city, isp, cve, ip, product, version))

    conn.commit()
    conn.close()
    print("✅ Enrichment complete.")

if __name__ == "__main__":
    enrich()
