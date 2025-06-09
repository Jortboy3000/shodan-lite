import xml.etree.ElementTree as ET
import sqlite3

# Parse the XML file
tree = ET.parse('nmap_results.xml')
root = tree.getroot()

# Connect to SQLite DB (creates it if not exists)
conn = sqlite3.connect('shodan_lite.db')
cursor = conn.cursor()

# Create table
cursor.execute('''
CREATE TABLE IF NOT EXISTS services (
    ip TEXT,
    port INTEGER,
    protocol TEXT,
    service TEXT,
    product TEXT,
    version TEXT
)
''')

# Parse each host
for host in root.findall('host'):
    ip = host.find('address').attrib['addr']
    ports = host.find('ports')
    if ports is None:
        continue
    for port in ports.findall('port'):
        portid = int(port.attrib['portid'])
        protocol = port.attrib['protocol']
        service_info = port.find('service')
        if service_info is not None:
            service = service_info.attrib.get('name', '')
            product = service_info.attrib.get('product', '')
            version = service_info.attrib.get('version', '')
        else:
            service = product = version = ''
        # Insert into DB
        cursor.execute('''
            INSERT INTO services (ip, port, protocol, service, product, version)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (ip, portid, protocol, service, product, version))

conn.commit()
conn.close()
print("✅ Parsed and inserted into shodan_lite.db")
