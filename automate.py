import os
import subprocess
import datetime
import xml.etree.ElementTree as ET
import sqlite3

# --- Setup ---
timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
masscan_output = f"masscan_{timestamp}.xml"
nmap_output = f"nmap_{timestamp}.xml"
target_file = "targets.txt"
db_file = "shodan_lite.db"

# --- 1. Run Masscan ---

print("[+] Running Masscan...")
masscan_output = f"masscan_{timestamp}.xml"
result = subprocess.run([
    "sudo", "masscan", "192.168.1.0/24", "-p1-1000",
    "--rate", "1000", "-oX", masscan_output
])



# Check if file was created
if not os.path.exists(masscan_output):
    print(f"[-] Error: Masscan did not create {masscan_output}")
    exit(1)

# --- 2. Extract IPs ---
print("[+] Extracting targets from Masscan XML...")
with open(masscan_output, "r") as f:
    lines = f.readlines()
ips = set()
for line in lines:
    if 'addrtype="ipv4"' in line:
        try:
            ip = line.split('addr="')[1].split('"')[0]
            ips.add(ip)
        except IndexError:
            continue
with open(target_file, "w") as f:
    f.write("\n".join(sorted(ips)))
if not ips:
    print("[-] No targets found.")
    exit()

# --- 3. Run Nmap ---
print(f"[+] Running Nmap on {len(ips)} host(s)...")
subprocess.run([
    "sudo", "nmap", "-sV", "-p1-1000", "-iL", target_file,
    f"-oX", nmap_output
])

# --- 4. Parse Nmap XML into SQLite ---
print("[+] Inserting Nmap results into SQLite...")
tree = ET.parse(nmap_output)
root = tree.getroot()
conn = sqlite3.connect(db_file)
cursor = conn.cursor()
cursor.execute('''
CREATE TABLE IF NOT EXISTS services (
    ip TEXT,
    port INTEGER,
    protocol TEXT,
    service TEXT,
    product TEXT,
    version TEXT,
    scan_time TEXT
)
''')
for host in root.findall('host'):
    ip = host.find('address').attrib['addr']
    for port in host.find('ports').findall('port'):
        portid = int(port.attrib['portid'])
        protocol = port.attrib['protocol']
        service_info = port.find('service')
        service = service_info.attrib.get('name', '') if service_info else ''
        product = service_info.attrib.get('product', '') if service_info else ''
        version = service_info.attrib.get('version', '') if service_info else ''
        cursor.execute('''
            INSERT INTO services (ip, port, protocol, service, product, version, scan_time)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (ip, portid, protocol, service, product, version, timestamp))
conn.commit()
conn.close()
print("✅ Scan complete and inserted.")

import enrich
enrich.enrich()
