<div align="center">

# 🛰️ SecureNet Analyzer

**A Python-based network traffic monitoring, live-host detection, and packet analysis toolkit**

[![Python Version](https://img.shields.io/badge/python-3.x-blue?logo=python&style=flat-square)](https://www.python.org)
[![Scapy](https://img.shields.io/badge/built%20with-Scapy-critical?style=flat-square)](https://scapy.net)
[![License](https://img.shields.io/badge/license-Educational%20%2F%20Authorized%20Use%20Only-important?style=flat-square)](#-license)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat-square)](#-contributing)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey?style=flat-square)](#-requirements)

[Features](#-features) •
[Installation](#-installation) •
[Usage](#-usage-examples) •
[Security](#-security-considerations) •
[Legal](#-legal-disclaimer)

</div>

> ⚠️ **Authorized use only.** This tool is intended strictly for educational environments and penetration testing engagements where you have **explicit written authorization**. See the [Legal Disclaimer](#-legal-disclaimer) before doing anything else.

---

## 📖 Overview

**SecureNet Analyzer** captures and analyzes network traffic, detects live devices on a network, and helps surface potential vulnerabilities and unusual traffic patterns. Built on the [**Scapy**](https://scapy.net) packet-crafting library, it combines real-time packet analysis, ARP-based live host detection, custom packet construction, and secure credential handling into a single CLI toolkit.

It's aimed at **network administrators**, **cybersecurity professionals**, and **penetration testers** who need a lightweight, scriptable way to inspect traffic and enumerate devices during authorized assessments.

---

## 📑 Table of Contents

1. [Features](#-features)
2. [Requirements](#-requirements)
3. [Installation](#-installation)
4. [Usage Examples](#-usage-examples)
5. [Security Considerations](#-security-considerations)
6. [Troubleshooting](#-troubleshooting)
7. [Contributing](#-contributing)
8. [Legal Disclaimer](#-legal-disclaimer)
9. [License](#-license)
10. [Acknowledgements](#-acknowledgements)
11. [Contact](#-contact)

---

## ✨ Features

| Capability | Description |
|---|---|
| 📡 **Packet Capture & Analysis** | Capture traffic from any network interface and extract IPs, ports, protocols, and payload details |
| 🔍 **Live Host Detection** | Enumerate live devices via ARP requests, mapping IP, MAC address, and NIC vendor |
| 🛠 **Custom Packet Crafting** | Build and send custom packets for controlled network testing and assessment |
| 🔐 **SHA-256 Authentication** | User login secured with SHA-256 password hashing — no plaintext credential storage |
| 💾 **Data Export** | Export captured traffic to **PCAP** or **TXT** for further analysis (e.g., in Wireshark) |
| 🚨 **Vulnerability Signal Detection** | Flag unusual traffic patterns that may indicate security issues |

---

## 🧰 Requirements

| Requirement | Notes |
|---|---|
| **Python 3.x** | Required to run the tool |
| **Scapy** | Core dependency for packet crafting and capture |
| **Administrator / root privileges** | Required for raw packet capture on any OS |

All Python dependencies are pinned in [`requirements.txt`](requirements.txt).

---

## ⚙️ Installation

### 1. Clone the repository
```bash
git clone https://github.com/<your-username>/SecureNet-Analyzer.git
cd SecureNet-Analyzer
```

### 2. Install dependencies
```bash
pip install -r requirements.txt
```

### 3. Run with elevated privileges
Packet capture requires raw socket access, so the tool must run with elevated permissions:

**Linux / macOS:**
```bash
sudo python3 Main.py [option] [arguments]
```

**Windows:**
Run Command Prompt or PowerShell **as Administrator**, then:
```bash
python Main.py [option] [arguments]
```

---

## 🖥 Usage Examples

SecureNet Analyzer is driven entirely through the CLI.

### Primary Options
| Flag | Description |
|---|---|
| `-c`, `--capture` | Start packet capture and analysis |
| `-lh`, `--live-host` | Perform live host detection on the network |

### Common Arguments
| Flag | Description |
|---|---|
| `--i [interface]` | Network interface to capture from (e.g. `eth0`, `Wi-Fi`) |
| `--pc [number]` | Number of packets to capture |
| `--a` | Analyze captured packets in real time |
| `--s` | Save captured packets |
| `--p [filename]` | Save captured packets in PCAP format |
| `--t [filename]` | Save captured packets in TXT format |
| `--f [filter]` | Filter expression (e.g. `'src host 192.168.1.1 and tcp'`) |
| `--ip [address]` | Target IP address for live host detection |

### Example 1 — Capture & save traffic
```bash
python Main.py -c --i Wi-Fi --pc 10 --a --s --p captured_traffic.pcap
```
Captures 10 packets on the `Wi-Fi` interface, analyzes them in real time, and saves the result as a PCAP file.

### Example 2 — Live host detection
```bash
python Main.py -lh --ip 192.168.1.1
```
Sends ARP requests to identify live devices on the `192.168.1.0/24` network reachable from `192.168.1.1`.

---

## 🔒 Security Considerations

- **Password storage** — credentials are hashed with SHA-256 and never stored in plaintext.
- **Authorized networks only** — only run this tool on networks you own or have explicit written permission to test. Unauthorized traffic analysis may be illegal.
- **ARP spoofing alerts** — live host detection relies on ARP requests, which some network monitoring systems may flag as ARP spoofing activity. Confirm you're operating in an authorized environment before scanning.

---

## 🩹 Troubleshooting

| Issue | Fix |
|---|---|
| **Permission denied during capture** | Re-run with `sudo` (Linux/macOS) or as Administrator (Windows) |
| **Missing dependency errors** | Re-run `pip install -r requirements.txt` and confirm your Python version |
| **Interface not detected** | List available interfaces with `ifconfig` (Linux/macOS) or `ipconfig` (Windows) and match the exact name in `--i` |

---

## 🤝 Contributing

Contributions are welcome via fork and pull request. Please ensure:

- Code is clearly documented
- New features include a usage example in the README
- Changes are tested locally before submitting
- Any new capability that touches live network traffic clearly notes its intended, authorized use case

```bash
git checkout -b feature/my-improvement
# make your changes
git commit -m "Add: description of change"
git push origin feature/my-improvement
```
Then open a Pull Request describing what changed and why.

---

## ⚖️ Legal Disclaimer

> The use of code contained in this repository, either in part or in its entirety, for engaging with targets **without prior, explicit mutual consent**, is **illegal**. It is the **end user's sole responsibility** to comply with all applicable local, state, and federal laws.
>
> The developers assume **no liability** and are **not responsible** for any misuse or damage caused by this code — whether accidental or intentional — including use by any threat actor or unauthorized party to compromise the security, privacy, confidentiality, integrity, or availability of systems or associated resources. **"Compromise"** here refers to exploitation of known or unknown vulnerabilities, including weaknesses in human- or electronically-enabled security controls.
>
> This tool is explicitly intended only for:
> - **Educational environments**, for learning or teaching cybersecurity concepts, and
> - **Authorized penetration testing engagements**, where the system owner has given explicit consent.
>
> The goal is to identify and mitigate vulnerabilities, not exploit them maliciously. **Before using this tool, obtain written authorization** and adhere to all relevant laws and ethical guidelines. Unauthorized use may result in severe legal consequences.

---

## 📄 License

This project is released for **educational and authorized security-testing use only**. See the [Legal Disclaimer](#-legal-disclaimer) above for full terms of acceptable use. If you intend to distribute or reuse this code, retain this disclaimer in full.

---

## 🙏 Acknowledgements

- [**Scapy**](https://scapy.net) — powerful packet crafting and sending functionality
- **Python 3.x** — simplicity and flexibility for network programming
- [**Wireshark**](https://www.wireshark.org) — trusted companion tool for analyzing exported PCAP files

---

## 📬 Contact

Questions or issues? Open a [GitHub Issue](../../issues) or reach out directly at **vitalkarthikeyanmannuri@gmail.com**.

<div align="center">

Built for defenders — use it responsibly. 🛡️

</div>
