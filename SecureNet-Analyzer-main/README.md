# SecureNet Analyzer

**SecureNet Analyzer** is a Python-based network traffic monitoring, live-host detection, and packet analysis toolkit for network administrators, cybersecurity professionals, and penetration testers.

> ⚠️ **Authorized use only.** This tool is intended strictly for educational environments and penetration testing engagements where you have **explicit written authorization**. See the [Legal Disclaimer](#legal-disclaimer) before doing anything else.

[Features](#features) • [Requirements](#requirements) • [Installation](#installation) • [Usage](#usage) • [Security Considerations](#security-considerations) • [Troubleshooting](#troubleshooting) • [Legal Disclaimer](#legal-disclaimer)

---

## Features

| Capability | Description |
|---|---|
| 📡 **Packet Capture & Analysis** | Capture traffic from any network interface and extract IPs, ports, protocols, and payload details |
| 🔍 **Live Host Detection** | Enumerate live devices via ARP requests, mapping IP, MAC address, and NIC vendor |
| 🛠 **Custom Packet Crafting** | Build and send custom packets for controlled network testing and assessment |
| 🔐 **SHA-256 Authentication** | User login secured with SHA-256 password hashing — no plaintext credential storage |
| 💾 **Data Export** | Export captured traffic to **PCAP**, **TXT**, or **HTML** for further analysis (e.g., in Wireshark) |
| 🚨 **Vulnerability Signal Detection** | Flag unusual traffic patterns that may indicate security issues |
| 📋 **Local IP Blocklist** | Track and flag known-bad IPs; blocklist hits influence risk scoring |
| 🔥 **Real Firewall Blocking (Windows)** | Enforce the local blocklist by creating Windows Firewall block rules (inbound + outbound) for each blocked IP |
| 📡 **Threat Intel Ingestion** | Load STIX2 bundles, extract IPv4/IPv6 IOCs, and optionally auto-add them to the blocklist |
| 🚨 **Risk-Threshold Alerting** | Trigger an alert (stdout / file / exit code) when the risk score crosses a threshold |

---

## Requirements

| Requirement | Notes |
|---|---|
| **Python 3.x** | Required to run the tool |
| **Scapy** | Core dependency for packet crafting and capture |
| **mac-vendor-lookup** | MAC address OUI → vendor name lookup |
| **colorama** | Terminal color output (pip installs it with requirements) |
| **Administrator / root privileges** | Required for raw packet capture **and** for firewall block enforcement on Windows |

All Python dependencies are pinned in [`requirements.txt`](requirements.txt).

---

## Installation

### 1. Install dependencies
```bash
pip install -r requirements.txt
```

### 2. Run with elevated privileges
Packet capture requires raw socket access, and firewall block enforcement requires Administrator rights, so the tool must run with elevated permissions when using those features.

**Linux / macOS:**
```bash
sudo python3 Main.py [option] [arguments]
```

**Windows:**
Run Command Prompt or PowerShell **as Administrator**, then:
```bash
python Main.py [option] [arguments]
```

### 3. First-run setup
On first run, the tool prompts you to set a login password. The password is hashed with SHA-256 and stored in `password_hash.txt`. Every subsequent run requires login before any network operation.

For automation or non-interactive use (e.g., blocklist management in scripts), pass `--offline` to skip the login prompt:
```bash
python Main.py block --list-blocks --offline
```

---

## Usage

SecureNet Analyzer is driven entirely through the CLI. The first positional argument selects the **mode**: `c` (capture), `lh` (live-host detection), `block` (blocklist management), `block-activate`, `block-deactivate`, `block-status`, or `intel`.

### Primary modes
| Mode | Description |
|---|---|
| `c` | Start packet capture and analysis |
| `lh` | Perform live host detection on the network |
| `block` | Manage the local IP blocklist |
| `block-activate` | Enforce the local blocklist via Windows Firewall rules |
| `block-deactivate` | Remove Windows Firewall block rules created by this tool |
| `block-status` | Show current firewall block state and cross-check against the local blocklist |
| `intel` | Load a STIX2 threat-intel bundle, extract IOCs, and optionally add them to the blocklist |

### Common arguments
| Flag | Description |
|---|---|
| `--i [interface]` | Network interface to capture from (e.g. `WiFi`, `eth0`). |
| `--pc [number]` | Number of packets to capture (required for capture mode unless using blocklist flags) |
| `--a` | Analyze captured packets in real time |
| `--s` | Save captured packets |
| `--p [filename]` | Save captured packets in **PCAP** format |
| `--t [filename]` | Save captured packets in **TXT** format |
| `--html [filename]` | Save captured packets in **HTML** executive report format |
| `--summary` | Print a concise security summary after capture |
| `--f [filter]` | Filter expression (see [Filter syntax](#filter-syntax)) |
| `--ip [address]` | Target IP address for live host detection |
| `--block [ip]` | Add an IP address to the local blocklist |
| `--unblock [ip]` | Remove an IP address from the local blocklist |
| `--list-blocks` | Show all blocked IPs in the local blocklist |
| `--clear-blocks` | Clear the local blocklist |
| `--offline` | Skip the login prompt (for automation / non-interactive use) |
| `--dry-run` | Simulate firewall blocking without creating real rules (block-activate mode) |
| `--timeout [seconds]` | ARP scan timeout (live-host mode, default 5) |
| `--max-hosts [n]` | Maximum hosts to report (live-host mode, default 254) |
| `--intel-source [path]` | Path to a STIX2 JSON bundle, or `sample` for the bundled sample |
| `--intel-auto-block` | Add discovered IP IOCs to the local blocklist (intel mode) |
| `--alert-on [score]` | Trigger an alert action when risk score reaches this threshold (capture mode) |
| `--alert-file [path]` | Append threshold alerts to this file (capture mode) |
| `--alert-exit` | Exit with code 2 when the threshold is crossed (capture mode) |

### Filter syntax
Filters are case-insensitive and joined with `and`. Supported clauses:

- `src host <ip>` / `dst host <ip>` — source or destination IP (IPv4 or IPv6)
- `src port <n>` / `dst port <n>` — source or destination TCP/UDP port
- `tcp` / `udp` / `icmp` / `icmp6` / `ip` / `ipv6` — protocol

Examples:
```
src host 10.0.0.1 and dst port 80
tcp and dst host 192.168.1.10
udp and src port 53
dst port 443 and src host 10.0.0.2
icmp
```

### Example 1 — Capture, analyze, and save in multiple formats
```bash
python Main.py c --i WiFi --pc 50 --a --summary --s --p captured_traffic.pcap --t report.txt --html report.html
```
Captures 50 packets on the `WiFi` interface, analyzes them in real time, prints a security summary, and saves three outputs: a PCAP (Wireshark-compatible), a TXT report, and an HTML executive report.

### Example 2 — Capture with filtering and threshold alerting
```bash
python Main.py c --pc 100 --f "tcp and dst port 22" --summary --a --alert-on 50 --alert-file alerts.log --alert-exit
```
Captures 100 TCP packets destined for port 22 (SSH), analyzes them, prints a summary, and exits with code 2 (or appends to `alerts.log`) if the risk score reaches 50.

### Example 3 — Live host detection
```bash
python Main.py lh --ip 192.168.1.10 --timeout 3 --max-hosts 50
```
Sends ARP requests to identify live devices on the `192.168.1.0/24` network reachable from `192.168.1.10`, with a 3-second timeout and at most 50 hosts reported.

### Example 4 — Blocklist management
```bash
# Add IPs to the local blocklist
python Main.py block --block 10.0.0.5 --block 192.168.1.99 --offline

# List blocked IPs
python Main.py block --list-blocks --offline

# Remove an IP
python Main.py block --unblock 10.0.0.5 --offline

# Clear the entire blocklist
python Main.py block --clear-blocks --offline
```

Blocked IPs are persisted in `blocked_ips.txt` and factored into risk scoring during capture analysis.

### Example 5 — Enforce blocked IPs via Windows Firewall
```bash
# Dry-run first: see what rules would be created without touching the firewall
python Main.py block-activate --dry-run --offline

# Actually enforce the blocklist (requires Administrator)
python Main.py block-activate --offline

# Check current firewall block state
python Main.py block-status --offline

# Remove the firewall block rules
python Main.py block-deactivate --offline
```

`block-activate` creates one inbound and one outbound Windows Firewall block rule per blocked IP (`SecureNet_Block_In_<ip>` and `SecureNet_Block_Out_<ip>`). Invalid IPs in the blocklist are skipped. Use `--dry-run` to preview without creating real rules.

### Example 6 — Threat intel ingestion
```bash
# Use the bundled sample bundle (offline, no network)
python Main.py intel --intel-source sample --offline

# Load your own STIX2 bundle and auto-add its IP IOCs to the blocklist
python Main.py intel --intel-source my_threats.stix2.json --intel-auto-block --offline
```

The `intel` mode loads a STIX2 JSON bundle, extracts IPv4/IPv6 indicators, prints a summary, and optionally adds valid IP IOCs to the local blocklist. Non-IP indicators (file hashes, URLs, etc.) are counted but not added.

---

## Security Considerations

- **Password storage** — credentials are hashed with SHA-256 and never stored in plaintext.
- **Authorized networks only** — only run this tool on networks you own or have explicit written permission to test. Unauthorized traffic analysis may be illegal.
- **ARP scanning alerts** — live host detection relies on ARP requests, which some network monitoring systems may flag as ARP spoofing activity. Confirm you're operating in an authorized environment before scanning.
- **Blocklist is local/analytical** — the blocklist flags and scores traffic but does not drop or block packets at the network level.

---

## Troubleshooting

| Issue | Fix |
|---|---|
| **Permission denied during capture** | Re-run with `sudo` (Linux/macOS) or as Administrator (Windows) |
| **Missing dependency errors** | Re-run `pip install -r requirements.txt` and confirm your Python version |
| **Interface not found** | List available interfaces by running `python Main.py c --help` (the `--i` description notes how to find them) or use `ifconfig` (Linux/macOS) / `ipconfig` (Windows) and match the exact name in `--i` |
| **No packets captured** | Confirm the interface is up and traffic is flowing; try a larger `--pc` value |
| **Login prompt in automation** | Add `--offline` to skip the interactive login |

---

## Contributing

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

## Legal Disclaimer

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

## License

This project is released under the **MIT License** for educational and authorized security-testing use. See the [Legal Disclaimer](#legal-disclaimer) above for full terms of acceptable use. If you intend to distribute or reuse this code, retain this disclaimer in full.

---

## Acknowledgements

- [**Scapy**](https://scapy.net) — powerful packet crafting and sending functionality
- **mac-vendor-lookup** — MAC address OUI to vendor name lookup
- **Python 3.x** — simplicity and flexibility for network programming
- [**Wireshark**](https://www.wireshark.org) — trusted companion tool for analyzing exported PCAP files

---

## Contact

Questions or issues? Open a GitHub Issue or reach out at **vitalkarthikeyanmannuri@gmail.com**.

---

**Built for defenders — use it responsibly.**