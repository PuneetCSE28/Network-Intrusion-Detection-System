# CodeAlpha_NetworkIDS

## 📌 Overview
This project is **Task 4: Network Intrusion Detection System**, completed as part of the **CodeAlpha Cyber Security Internship**. It uses **Suricata** (an open-source IDS/IPS engine) with a custom rule set to detect common attack patterns — port scans, ping sweeps, cleartext credential submission, scanner tool signatures, FTP anonymous logins, DNS tunneling indicators, and insecure Telnet traffic — and visualizes the results in a self-contained HTML dashboard.

## ⚠️ Legal & Ethical Use Only
Only deploy this on a network you **own** or have **explicit written permission** to monitor. This repository's included "attack" traffic is entirely **synthetic** — generated offline with `scapy` into a `.pcap` file — so the rules can be demonstrated and tested **without touching any real network or host**. No live scanning, exploitation, or traffic injection is performed by anything in this repo.

## 🎯 Objective
- Set up Suricata as a network-based IDS
- Write custom detection rules and alert thresholds
- Monitor traffic (live interface or offline `.pcap` replay) for suspicious activity
- Discuss response/mitigation options for detected intrusions
- Visualize alerts with a dashboard (protocol/severity breakdown, top talkers, alert table)

## 🛠 Tools & Technologies
- **Suricata 7.x** — IDS/IPS engine
- **Python 3 + scapy** — synthetic test-traffic generation
- **Python 3** — `eve.json` alert parsing → HTML dashboard (no external JS/CSS dependencies)

## 📂 Repository Structure
```
CodeAlpha_NetworkIDS/
├── rules/
│   └── custom.rules            # 10 custom detection signatures
├── config/
│   ├── suricata.yaml           # Suricata config (points to custom.rules only)
│   ├── classification.config   # Standard Suricata classification types
│   └── reference.config        # Standard Suricata reference types
├── scripts/
│   ├── generate_test_traffic.py  # Builds a synthetic .pcap to test the rules
│   └── alert_dashboard.py        # Parses eve.json -> dashboard.html
├── output/
│   ├── test_traffic.pcap       # Synthetic traffic used for the demo run
│   ├── eve.json                # Sample alert log from that run
│   ├── fast.log                # Human-readable alert summary
│   └── dashboard.html          # Generated visual dashboard
└── README.md
```

## 🧩 Custom Detection Rules (`rules/custom.rules`)
| SID | Detects |
|---|---|
| 9000001 | TCP port scan (15+ SYNs from one host in 10s) |
| 9000002 | ICMP ping sweep/flood (20+ pings from one host in 5s) |
| 9000003 | Oversized ICMP packet (>1024 bytes — DoS probe indicator) |
| 9000004 | Cleartext password submitted via HTTP POST |
| 9000005–9000007 | Known scanner tool User-Agents (sqlmap, Nikto, Nmap NSE) |
| 9000008 | FTP anonymous login attempt |
| 9000009 | Unusually long DNS query (possible tunneling/exfiltration) |
| 9000010 | Plaintext Telnet traffic |

All rules are detection-only — none of them block, exploit, or generate attack traffic themselves.

## ▶️ How to Reproduce the Demo (safe, offline)
```bash
# 1. Install Suricata
sudo apt-get install -y suricata

# 2. Generate synthetic test traffic (no real network touched)
pip install scapy --break-system-packages
python3 scripts/generate_test_traffic.py   # writes output/test_traffic.pcap

# 3. Validate the rules load correctly
suricata -T -c config/suricata.yaml -l output/

# 4. Run Suricata against the offline pcap
suricata -c config/suricata.yaml -l output/ -r output/test_traffic.pcap -k none

# 5. Build the dashboard from the resulting alerts
python3 scripts/alert_dashboard.py output/eve.json output/dashboard.html
```
Open `output/dashboard.html` in any browser — it's fully self-contained.

## 🌐 Running on a Live Interface (real monitoring)
To monitor real traffic instead of a pcap file, run Suricata against a live interface (adjust `HOME_NET` in `suricata.yaml` to match your actual network first):
```bash
sudo suricata -c config/suricata.yaml -i eth0 -l output/
```
Then tail alerts as they happen:
```bash
tail -f output/eve.json | grep '"event_type":"alert"'
```

## 🚨 Response Mechanisms (for detected intrusions)
Suricata as configured here runs in **IDS mode** (detect + log only). Options to move toward active response, in increasing order of risk/complexity:
1. **Alerting pipeline** — forward `eve.json` alerts to a SIEM (e.g. via Filebeat → Elasticsearch, or a simple script/webhook to Slack/email) so a human is notified immediately.
2. **Automated blocking (IPS mode)** — Suricata supports inline `NFQUEUE` or `AF_PACKET` IPS mode with `drop` rules, or alerts can trigger a firewall rule (e.g. via `fail2ban` reading `eve.json`, or a script calling `iptables`/`nftables`) to block an offending source IP.
3. **Rate limiting** — for scan/sweep-type alerts, a lightweight response is temporarily rate-limiting the source IP rather than an outright block, reducing false-positive impact.

This repo intentionally stops at detection + logging + dashboarding, since automated blocking on a shared/production network requires careful tuning to avoid blocking legitimate traffic.

## 📊 Dashboard
`output/dashboard.html` shows:
- Total alerts, unique signatures triggered, unique source IPs, high-severity count
- Alerts broken down by signature, severity, and protocol
- Top source IPs by alert count
- A full sortable-by-eye alert table (time, source, destination, protocol, signature, severity)

## 🧠 Tuning Notes (for the report)
- The Telnet rule (`9000010`) also fires once during the port-scan test, since the scan happens to probe port 23 and the rule doesn't require actual Telnet application data — a good real-world example of why rules need iterative tuning against real traffic to reduce false positives (e.g. adding `app-layer-protocol:telnet` or requiring a minimum payload).
- Thresholds (`count`/`seconds` on the scan and sweep rules) were chosen conservatively so a single legitimate retry doesn't trigger an alert — tune these to your actual network's baseline traffic.

## 👤 Author
PuneetCSE28 (Puneet Kumar Bairwa) Completed as part of the **CodeAlpha Cyber Security Internship (Task 4)**.
