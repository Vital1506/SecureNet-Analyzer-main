# 🛰️ SecureNet Analyzer

> A Python/Scapy security-focused network analysis toolkit for packet capture, traffic inspection, live-host discovery, risk signals, IP blocklisting, threat-intelligence ingestion, reporting, and Windows Firewall integration.

[![Python](https://img.shields.io/badge/Python-3.x-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Scapy](https://img.shields.io/badge/Scapy-Packet_Analysis-6D28D9?style=for-the-badge)](https://scapy.net/)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-7C3AED?style=for-the-badge)](#installation)
[![License](https://img.shields.io/badge/License-MIT-4C1D95?style=for-the-badge)](LICENSE)

## What is SecureNet Analyzer?

SecureNet Analyzer is a **command-line cybersecurity toolkit** built with Python and Scapy. It is designed for practical network monitoring and authorized security testing rather than being a full replacement for enterprise packet-analysis software.

### SecureNet Analyzer vs. Wireshark

SecureNet Analyzer covers some of the same basic workflow as Wireshark—especially **packet capture, traffic inspection, filtering, and PCAP export**—but the two projects have different goals.

| Capability | SecureNet Analyzer | Wireshark |
|---|---|---|
| Packet capture | ✅ | ✅ |
| Traffic analysis | ✅ | ✅ |
| Deep protocol dissection | Basic/custom | ✅ Extensive |
| Graphical interface | ❌ CLI | ✅ |
| PCAP export | ✅ | ✅ |
| TXT/HTML reporting | ✅ | Different workflow |
| Live-host discovery | ✅ | Not its primary purpose |
| Custom packet crafting | ✅ | ❌ |
| Security risk signals | ✅ | ❌ |
| Local IP blocklist | ✅ | ❌ |
| STIX2 threat-intel ingestion | ✅ | ❌ |
| Windows Firewall integration | ✅ | ❌ |

**Best way to think about it:** SecureNet Analyzer is a **custom, programmable security-analysis toolkit**, while Wireshark is a mature GUI-based packet and protocol analyzer. SecureNet Analyzer can export PCAP files that you can open in Wireshark for deeper investigation.

## Features

| Capability | Description |
|---|---|
| 📡 **Packet Capture & Analysis** | Capture traffic from a selected interface and inspect IPs, ports, protocols, and packet information |
| 🔍 **Live Host Detection** | Discover live devices with ARP-based discovery and report IP, MAC, and vendor information |
| 🛠 **Custom Packet Crafting** | Build and send custom packets for controlled, authorized testing |
| 🔐 **SHA-256 Authentication** | Protect access using SHA-256 password hashing |
| 💾 **Data Export** | Save captured traffic as PCAP, TXT, or HTML reports |
| 🚨 **Risk Signals** | Detect traffic patterns that contribute to a security risk score |
| 📋 **Local IP Blocklist** | Maintain and score traffic against a local IP blocklist |
| 🔥 **Windows Firewall Integration** | Create or remove inbound/outbound firewall block rules for blocklisted IPs |
| 📡 **Threat Intelligence** | Load STIX2 bundles, extract IP indicators, and optionally add them to the blocklist |
| 🚨 **Threshold Alerting** | Trigger stdout, file, or exit-code alerts when a risk threshold is crossed |
| 🧩 **CLI Automation** | Use from PowerShell, Command Prompt, shell scripts, or Python workflows |

## Technology Stack

- **Python 3.x**
- **Scapy** — packet capture and packet crafting
- **mac-vendor-lookup** — MAC OUI/vendor identification
- **Colorama** — terminal output
- **PCAP** — packet-capture interchange format
- **STIX2** — threat-intelligence bundle ingestion
- **Windows Firewall** — local IP block enforcement on Windows

## Requirements

- Python 3.x
- Dependencies from `requirements.txt`
- Administrator/root privileges for raw packet capture and Windows Firewall operations
- Permission to monitor/test the network being used

## Installation

### Windows PowerShell

From the repository root:

```powershell
cd .\SecureNet-Analyzer-main
py -m venv venv
.\venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
python Main.py -h
```

Run PowerShell/VS Code as **Administrator** when using packet capture or Windows Firewall functionality.

### Linux / macOS

```bash
cd SecureNet-Analyzer-main
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
sudo python3 Main.py -h
```

## Usage

The current CLI requires a mode/option such as `c` or `lh`.

### Show help

```bash
python Main.py -h
```

### Packet capture

Capture 10 packets:

```bash
python Main.py c --pc 10
```

Capture and analyze:

```bash
python Main.py c --pc 10 --a
```

Capture, analyze, and save a security summary:

```bash
python Main.py c --pc 10 --a --s
```

### Save PCAP and reports

```bash
python Main.py c --i WiFi --pc 50 --a --summary --s --p captured_traffic.pcap --t report.txt --html report.html
```

The generated PCAP can then be opened in **Wireshark** for deeper packet/protocol analysis.

### Filters

Supported examples:

```text
src host 10.0.0.1 and dst port 80
tcp and dst host 192.168.1.10
udp and src port 53
dst port 443 and src host 10.0.0.2
icmp
```

### Live-host detection

Use only on an authorized network:

```bash
python Main.py lh --ip 192.168.1.10 --timeout 3 --max-hosts 50
```

## Security Workflow

```text
Network Traffic
      │
      ▼
   Scapy Capture
      │
      ▼
Traffic / Packet Analysis
      │
      ├──► Risk Signals / Score
      ├──► Blocklist Checks
      ├──► Security Summary
      └──► PCAP / TXT / HTML
                     │
                     ▼
                 Wireshark
              (deep inspection)
```

SecureNet Analyzer is intended to provide a **programmable first-stage security analysis workflow**, with Wireshark available as a companion tool for detailed packet investigation.

## Project Structure

```text
SecureNet-Analyzer-main/
└── SecureNet-Analyzer-main/
    ├── Main.py
    ├── requirements.txt
    ├── run.ps1
    ├── run.sh
    ├── test_all.py
    ├── InputExample.txt
    ├── password_hash.txt
    ├── MASTER_PROMPT.md
    ├── README.md
    └── Utils/
```

## Why This Project?

This project provides hands-on practice with:

- Network packet capture using Python and Scapy
- Packet and traffic inspection
- ARP-based host discovery
- Security risk scoring concepts
- IP blocklist management
- Threat-intelligence workflows
- Windows Firewall automation
- PCAP-based investigation workflows
- Integration with Wireshark as a deeper analysis companion

## Incident / Investigation Reporting

SecureNet Analyzer can generate a structured investigation report from a packet-capture session. The report is designed for security analysts and incident-response documentation.

It includes:

- Case ID, analyst, organization, interface, and generation timestamp
- Executive risk summary
- Observed IPs with packet and byte counts
- First-seen and last-seen timestamps
- Observed protocols and ports
- Top communication peers
- Blocklist hits
- Security findings associated with each IP
- Packet-level security-event timeline
- JSON output for automation/SIEM workflows
- Human-readable TXT output
- HTML report suitable for sharing or printing
- SHA-256 hashes for supplied evidence files
- An explicit attribution limitation so an IP is not presented as proof of attacker identity

Example:

```powershell
python Main.py c --i WiFi --pc 100 --a --summary --p case_001.pcap --report-prefix reports\case_001 --case-id CASE-001 --analyst "Security Analyst" --organization "Example SOC"
```

This produces:

```text
reports\case_001_CASE-001.html
reports\case_001_CASE-001.txt
reports\case_001_CASE-001.json
case_001.pcap
```

The JSON file is intended for automation/SIEM ingestion, the TXT file provides a plain-text case record, and the HTML file provides a readable investigation report.

> **Evidence note:** A generated report is supporting documentation, not by itself a legal determination or guaranteed court-admissible evidence. Preserve original captures and follow your organization's evidence-handling procedures.

## Troubleshooting

| Issue | Fix |
|---|---|
| `can't open file 'Main.py'` | Change into the inner `SecureNet-Analyzer-main` directory containing `Main.py` |
| `the following arguments are required: option` | Run `python Main.py -h` and choose a supported mode such as `c` or `lh` |
| Permission denied | Run PowerShell/VS Code as Administrator on Windows or use `sudo` on Linux/macOS |
| Missing dependency | Run `pip install -r requirements.txt` |
| Interface not found | Check the interface name with `python Main.py c --help` |
| No packets captured | Confirm the interface is active and that authorized traffic is flowing; start with a small packet count |

## Authorized Use

> ⚠️ **Authorized use only.** Use this software only in educational labs, on systems/networks you own, or during security assessments for which you have explicit authorization. Unauthorized packet capture, scanning, packet injection, or firewall changes may violate laws, policies, or agreements.

## License

This project is released under the **MIT License**. See [LICENSE](LICENSE) for details.

## Acknowledgements

- [Scapy](https://scapy.net/) — packet capture and packet crafting
- `mac-vendor-lookup` — MAC vendor identification
- [Wireshark](https://www.wireshark.org/) — companion tool for deeper PCAP analysis
- Python — implementation language

## Contact

Questions or issues? Open a GitHub Issue or contact **vitalkarthikeyanmannuri@gmail.com**.

---

**Built for defenders — analyze, understand, and secure responsibly.**
