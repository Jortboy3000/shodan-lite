# shodan-lite

I built this system to scan networks and identify which devices are live, what ports are open, and what software is running. It helps me spot outdated or risky systems quickly. Everything runs locally, no need for cloud services or third-party APIs once it’s set up.


**Why?**

I just wanted a way to see exactly what’s running on a network, and know right away if something’s risky or outdated. No subscriptions, no token or credits or other BS.


**This system gives me the full picture:**

1. What devices are online?
2. What ports are open?
3. What services and versions are running?
4. Where the IP is located?(country, city, ISP)
5. If it’s running vulnerable software?
6. Whether it should trigger an alert?


**What it does step-by-step**

It scans the network using masscan. Super fast. Finds live devices and open ports.
Then it uses nmap on those IPs to fingerprint the services and grab version info.
It stores all the data in a local SQLite database.
Then I run an enrichment script that looks up GeoIP info and matches version strings to known CVEs.
Then I run an alert script that checks for dangerous stuff like RDP, Telnet, outdated web servers, or anything outside my country.
**
Tools involved**

masscan (find open ports fast)
nmap (get service names and versions)
sqlite3 (store all the data)
Python (glue everything together, do enrichment, alerting, automation)

**What it's useful for**

Scanning your own infrastructure so you know what’s open
Recon on a target network to find weak points fast
Building a data set of devices running outdated or vulnerable software
Triggering alerts automatically instead of manually checking 100+ hosts
Doing red team work, threat detection, or just learning how network discovery works
