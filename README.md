# shodan-lite
A system I built to scan networks, figure out what devices are live, what ports are open, what software they're running, and whether anything is outdated or risky.  It's basically like Shodan or Censys, but I run it myself, locally. No external dependencies. No rate limits. I control everything.


**Why I built it**

I wanted to be able to see exactly what’s running on a network either, mine or someone else's and automatically know if something’s dangerous or vulnerable. This system gives me the full picture:

What devices are online?
What ports are open?
What services and versions are running?
Where the IP is located?(country, city, ISP)
If it’s running vulnerable software?
Whether it should trigger an alert?

This matters because most people don’t even know what’s exposed until it’s too late. This tells me before something goes wrong.

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
