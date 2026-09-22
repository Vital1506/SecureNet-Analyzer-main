# 🛡️ SecureNet Analyzer

<p align="center">
  <strong>Defensive Network Detection & Investigation Toolkit</strong><br>
  Capture traffic • Investigate PCAPs • Detect suspicious behavior • Extract IOCs • Build incident evidence
</p>

<p align="center">

![CI](https://github.com/Vital1506/SecureNet-Analyzer-main/actions/workflows/pylint.yml/badge.svg)
![Python](https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12-blue)
![Security](https://img.shields.io/badge/Focus-Network%20Security-red)
![License](https://img.shields.io/badge/License-MIT-green)

</p>

> **Authorized use only.** SecureNet Analyzer is designed for defensive security work, education, and authorized assessments. Use packet capture, host discovery, and firewall controls only on systems and networks you own or have explicit permission to test.

---

## ⚡ What is SecureNet Analyzer?

**SecureNet Analyzer** is a Python-based network security toolkit that connects packet collection, offline PCAP investigation, behavioral detection, threat intelligence, IOC extraction, incident reporting, and local response controls in one CLI workflow.

### Security Operations Flow

```text
NETWORK / PCAP
      │
      ▼
┌───────────────────────┐
│   Packet Collection   │
│  Live Capture / PCAP  │
└──────────┬────────────┘
           ▼
┌───────────────────────┐
│   Packet & Flow Data  │
│ IP • Port • Protocol  │
└──────────┬────────────┘
           ▼
┌───────────────────────┐
│ Behavioral Detection  │
│ Scan • Beacon Signals │
└──────────┬────────────┘
           ▼
┌───────────────────────┐
│ Investigation Layer   │
│ IOC • Timeline • MITRE│
│ Sessions • Risk Score │
└──────────┬────────────┘
           ▼
┌───────────────────────┐
│ Evidence & Reports    │
│ JSON • TXT • HTML     │
│ SHA-256 • Custody     │
└──────────┬────────────┘
           ▼
┌───────────────────────┐
│ Optional Response     │
│ Blocklist • Firewall  │
└───────────────────────┘
```

The project is intentionally built as a **defensive investigation pipeline**, not as a collection of unrelated scripts.

---

## 🖥️ Project at a glance

| Layer | Current implementation |
|---|---|
| **Collection** | Scapy live packet capture and offline PCAP reading |
| **Analysis** | IPs, protocols, ports, payload signals, risk scoring |
| **Behavior Detection** | Horizontal SYN scan, vertical SYN scan, periodic web beaconing |
| **Investigation** | Timeline, sessions, IOC extraction, MITRE ATT&CK hypothesis mapping |
| **Threat Intelligence** | STIX2 ingestion with IPv4/IPv6 IOC extraction |
| **Evidence** | SHA-256 evidence hashing and custody metadata |
| **Response** | Local blocklist and Windows Firewall enforcement |
| **Security Core** | Salted scrypt credentials, login throttling, bounded PCAP/payload processing, atomic state writes, hash-chained audit logging |
| **Exports** | PCAP, TXT, HTML, JSON |
| **CI** | Regression tests, compile checks, Bandit, pip-audit, Pylint |

---

# ✨ Core capabilities

### 📡 Live packet capture
Capture traffic from a selected interface and optionally analyze, summarize, save, alert, and generate investigation reports.

### 📼 Offline PCAP investigation
Load an existing PCAP without starting a live sniffer. Offline evidence passes through the same analysis and investigation layers.

### 🧠 Behavioral Detection Engine
Current rules include:

| Rule ID | Detection |
|---|---|
| `NET-SCAN-001` | Horizontal TCP SYN scanning |
| `NET-SCAN-002` | Vertical TCP SYN scanning |
| `NET-BEACON-001` | Periodic web beaconing |

Detections include evidence-linked observations such as rule ID, severity, confidence, timestamps, MITRE reference, and packet numbers.

### 🎯 Investigation enrichment
The investigation layer can build:

```text
Observed IP activity
Sessions
Timeline
IOCs
MITRE hypotheses
Case summary
Evidence hashes
Custody metadata
```

### 📡 STIX2 threat intelligence
Load STIX2 bundles, extract IPv4/IPv6 indicators, and optionally add IP indicators to the local blocklist.

### 🔥 Response controls
Maintain a validated local IP blocklist and, on Windows, enforce entries through Windows Firewall.

Real firewall changes are protected by authentication, Administrator checks, explicit confirmation, and audit logging.

---

# 🧩 Architecture

```text
                         ┌───────────────────────┐
                         │     SecureNet CLI     │
                         └───────────┬───────────┘
                                     │
                 ┌───────────────────┼───────────────────┐
                 │                   │                   │
                 ▼                   ▼                   ▼
         ┌──────────────┐    ┌──────────────┐    ┌──────────────┐
         │ Live Capture │    │ Offline PCAP │    │ Threat Intel │
         │     c        │    │    pcap      │    │    intel     │
         └──────┬───────┘    └──────┬───────┘    └──────┬───────┘
                │                   │                   │
                └───────────────────┼───────────────────┘
                                    ▼
                         ┌────────────────────┐
                         │ Packet/State Layer │
                         └─────────┬──────────┘
                                   ▼
                         ┌────────────────────┐
                         │ Analysis & Scoring │
                         └─────────┬──────────┘
                                   ▼
                         ┌────────────────────┐
                         │ Detection Engine   │
                         └─────────┬──────────┘
                                   ▼
                    ┌─────────────────────────────┐
                    │ Investigation Enrichment   │
                    │ IOC • Timeline • Sessions  │
                    │ MITRE • Case Summary       │
                    └──────────────┬──────────────┘
                                   ▼
                    ┌─────────────────────────────┐
                    │ Incident Report Generator   │
                    │ JSON • TXT • HTML           │
                    └──────────────┬──────────────┘
                                   │
                         ┌─────────┴─────────┐
                         ▼                   ▼
                  Evidence + Audit      Optional Response
                  SHA-256 + Custody    Blocklist + Firewall
```

---

# 🛠️ How the project is implemented

## 1. Collection layer

### Live capture

```text
Network interface
      ↓
     Scapy
      ↓
Captured packets
      ↓
Analysis / Alerting / Reporting
```

### Offline PCAP

```text
PCAP file
   ↓
File-size validation
   ↓
Packet-count limit
   ↓
PcapReader
   ↓
Analysis + Detection + Investigation
   ↓
Reports / Evidence
```

Default offline limits:

```text
PCAP file size: 512 MiB
PCAP packets:   500,000
Raw payload:    64 KiB
```

These controls reduce resource-exhaustion risk when handling untrusted evidence files.

---

## 2. Analysis and risk scoring

SecureNet examines packet-level signals such as:

```text
Source IP
Destination IP
Source port
Destination port
Protocol
Traffic relationships
Suspicious patterns
Blocklist hits
Behavioral detections
```

These signals contribute to the security summary and risk score.

---

## 3. Behavioral detection

The detection engine evaluates traffic over **time windows**, rather than treating every individual packet as a separate alert.

Example:

```text
10.0.0.5 → 10.0.0.10:22   SYN
10.0.0.5 → 10.0.0.11:22   SYN
10.0.0.5 → 10.0.0.12:22   SYN
10.0.0.5 → 10.0.0.13:22   SYN
               │
               ▼
      Horizontal scan signal
```

The underlying packet numbers can be retained as evidence for the detection.

---

## 4. Investigation layer

Raw observations are transformed into structured case data:

```text
Packets
  ├── Sessions
  ├── Timeline
  ├── IOCs
  ├── MITRE hypotheses
  └── Case summary
```

### Current IOC types

```text
IPv4
IPv6
Domains
URLs
Ports
```

### MITRE ATT&CK

Mappings are **heuristic investigation hypotheses** derived from observed traffic or payload patterns. They are not proof that an ATT&CK technique was successfully executed.

---

# 🔐 Security architecture

SecureNet is designed with the assumption that the security tool itself must also be protected.

## Authentication

Passwords are stored using salted **scrypt** verifiers.

```text
Password
   ↓
Random salt
   ↓
scrypt KDF
   ↓
Stored verifier

Failed login
   ↓
Progressive delay
   ↓
Maximum 5 attempts
```

Legacy SHA-256 password records are upgraded after a successful authentication.

## Privilege boundaries

```text
Live capture              → authentication required
Live host detection       → authentication required
Blocklist mutation        → authentication required
Firewall enforcement      → authentication + confirmation
Intel auto-block          → authentication required
Read-only offline work   → --offline may be used
```

The `--offline` switch does **not** bypass authentication for state-changing or privileged operations.

## Firewall protection

Real Windows Firewall changes require:

```text
Authenticated user
      +
Administrator privileges
      +
--confirm-firewall
```

Use `--dry-run` before enforcing rules.

## Atomic state writes

Credential and blocklist state changes are written atomically to reduce the risk of corrupted runtime files.

## Tamper-evident audit chain

Security-sensitive actions are written to a local hash-chained audit log:

```text
EVENT 1
  │ previous hash
  ▼
EVENT 2
  │ previous hash
  ▼
EVENT 3
```

Changing an earlier event breaks the chain.

Verify it with:

```bash
python Main.py audit-verify --offline
```

This is **tamper-evident local auditing**, not a replacement for external immutable logging.

## Offline DNS behavior

Reverse-DNS enrichment is disabled by default during report generation.

Enable it explicitly with:

```text
--resolve-hostnames
```

---

# 📂 Repository structure

The GitHub repository contains the project in the inner `SecureNet-Analyzer-main/` directory.

```text
SecureNet-Analyzer-main/
├── README.md
├── .github/
│   └── workflows/
│       ├── pylint.yml
│       └── python-publish.yml
│
└── SecureNet-Analyzer-main/
    ├── Main.py
    ├── requirements.txt
    ├── test_all.py
    ├── run.ps1
    ├── run.sh
    ├── InputExample.txt
    │
    └── Utils/
        ├── analysis.py
        ├── audit.py
        ├── block_engine.py
        ├── blocklist.py
        ├── capture.py
        ├── detection_engine.py
        ├── filters.py
        ├── HostDetector.py
        ├── incident_report.py
        ├── intel.py
        ├── investigation.py
        ├── save.py
        ├── security.py
        └── sample_intel.stix2.json
```

Runtime files such as credentials, blocklists, reports, and audit logs should be treated as deployment data and should not be committed as secrets.

---

# 💻 Installation

## Requirements

- Python 3.10, 3.11, or 3.12
- Scapy
- mac-vendor-lookup
- colorama

## Windows

```powershell
git clone https://github.com/Vital1506/SecureNet-Analyzer-main.git
cd .\SecureNet-Analyzer-main
cd .\SecureNet-Analyzer-main

py -m venv venv
.\venv\Scripts\Activate.ps1

python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python Main.py --help
```

Use an elevated PowerShell / VS Code session for functionality that requires Windows Administrator privileges.

## Linux / macOS

```bash
git clone https://github.com/Vital1506/SecureNet-Analyzer-main.git
cd SecureNet-Analyzer-main/SecureNet-Analyzer-main

python3 -m venv venv
source venv/bin/activate

python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python Main.py --help
```

Use `sudo` only when your operating system requires elevation for the requested operation.

---

# 🎮 CLI command map

| Command | Purpose | Access |
|---|---|---|
| `c` | Live packet capture and analysis | Authenticated |
| `pcap` | Offline PCAP investigation | Offline-safe |
| `lh` | Live host detection | Authenticated |
| `block` | Local blocklist management | Mutations require authentication |
| `block-activate` | Enforce the blocklist with Windows Firewall | Auth + Administrator + confirmation |
| `block-deactivate` | Remove tool-created firewall rules | Auth + Administrator + confirmation |
| `block-status` | Inspect firewall block state | Read-only |
| `audit-verify` | Verify audit-chain integrity | Offline-safe |
| `intel` | Load STIX2 threat intelligence | Read-only unless auto-blocking |

See the exact CLI contract at:

```bash
python Main.py --help
```

---

# 🚀 Usage examples

## 1. Offline PCAP investigation

### Windows

```powershell
python Main.py pcap --input evidence_CASE001.pcap --summary --report-prefix reports\CASE001 --case-id CASE-001 --analyst "Security Analyst" --organization "Example SOC" --offline
```

### Linux / macOS

```bash
python Main.py pcap --input evidence_CASE001.pcap --summary --report-prefix reports/CASE001 --case-id CASE-001 --analyst "Security Analyst" --organization "Example SOC" --offline
```

The investigation can generate:

```text
HTML report
TXT report
JSON case data
```

including detections, sessions, timeline, IOCs, MITRE hypotheses, evidence hashes, and custody metadata.

---

## 2. Live capture

```bash
python Main.py c --i WiFi --pc 50 --a --summary --s --p captured_traffic.pcap
```

---

## 3. Filter traffic

```bash
python Main.py c --pc 100 --f "tcp and dst port 22" --a --summary
```

Supported filter clauses:

```text
src host <ip>
dst host <ip>
src port <n>
dst port <n>
tcp
udp
icmp
icmp6
ip
ipv6
```

Multiple clauses can be joined with `and`.

Example:

```text
src host 10.0.0.5 and dst port 443
```

---

## 4. Live host detection

```bash
python Main.py lh --ip 192.168.1.10 --timeout 3 --max-hosts 50
```

Use only on an authorized network.

---

## 5. Local blocklist

### List without changing state

```bash
python Main.py block --list-blocks --offline
```

### Add an IP

```bash
python Main.py block --block 10.0.0.5
```

### Remove an IP

```bash
python Main.py block --unblock 10.0.0.5
```

### Clear the blocklist

```bash
python Main.py block --clear-blocks
```

All blocklist entries are validated and normalized as IPv4/IPv6 addresses.

---

## 6. Windows Firewall

### Dry run

```bash
python Main.py block-activate --dry-run
```

### Real enforcement

```bash
python Main.py block-activate --confirm-firewall
```

### Status

```bash
python Main.py block-status
```

### Remove SecureNet firewall rules

```bash
python Main.py block-deactivate --confirm-firewall
```

Real changes require authentication and Administrator privileges.

---

## 7. STIX2 threat intelligence

Use the bundled sample:

```bash
python Main.py intel --intel-source sample --offline
```

Load a custom bundle:

```bash
python Main.py intel --intel-source my_threats.stix2.json
```

Enable automatic addition of valid IP indicators to the blocklist:

```bash
python Main.py intel --intel-source my_threats.stix2.json --intel-auto-block
```

Threat-intelligence data should be reviewed before enforcement in production.

---

## 8. Audit verification

```bash
python Main.py audit-verify --offline
```

Expected valid result:

```text
Audit log valid: <N> event(s) verified.
```

---

# 📊 Incident report package

When `--report-prefix` is provided, SecureNet can create:

| Format | Purpose |
|---|---|
| **HTML** | Analyst-friendly investigation report |
| **TXT** | Lightweight case handoff / archive |
| **JSON** | Structured data for automation and SIEM-oriented workflows |

The case package can include:

```text
Case metadata
Observed IP activity
Security events
Behavioral detections
Sessions
Timeline
IOCs
MITRE mappings
Evidence SHA-256 hashes
Custody metadata
Case summary
```

**Important:** findings and MITRE mappings are analyst-supporting signals, not proof of compromise or attribution.

---

# 🧪 Verification & CI

GitHub Actions validates the project against:

```text
Python 3.10
Python 3.11
Python 3.12
```

The pipeline checks:

```text
✅ Automated regression tests
✅ Python compile checks
✅ Bandit security scan
✅ pip-audit dependency audit
✅ Pylint
```

The merged Phase 3 secure-core implementation passed **161 automated tests with 0 failures**, and the post-merge `main` workflow also completed successfully.

---

# 🧭 Development roadmap

### ✅ Phase 1 — Behavioral Detection Foundation
- Horizontal / vertical TCP SYN scan detection
- Periodic web beacon detection
- Evidence-linked findings
- Severity and confidence
- MITRE references

### ✅ Phase 2 — Offline PCAP Investigation
- PCAP investigation mode
- IOC extraction
- Sessions
- Timeline
- Investigation enrichment
- Incident package generation

### ✅ Phase 3 — Secure Core Hardening
- Salted scrypt password storage
- Failed-login throttling
- Authentication boundaries
- PCAP resource limits
- Payload limits
- Atomic state writes
- Tamper-evident audit logging
- Offline DNS isolation
- CI security checks

### 🔜 Next engineering targets

```text
Stateful flow engine
      ↓
DNS / HTTP / TLS metadata
      ↓
Brute-force / slow-scan / exfiltration detections
      ↓
Attack-chain correlation
      ↓
Asset inventory + network graph
      ↓
Case management
      ↓
SOC web dashboard
      ↓
Evidence-grounded AI investigation
```

---

# 🧰 Troubleshooting

| Problem | Solution |
|---|---|
| `can't open file 'Main.py'` | Enter the inner `SecureNet-Analyzer-main` directory |
| `option` argument is required | Run `python Main.py --help` and select a supported mode |
| Permission denied | Use the required OS privileges for the operation |
| Interface not found | Check the interface name and use the exact value |
| PCAP rejected | Check `--max-pcap-mb` and `--max-pcap-packets` |
| Hostname not shown | Reverse DNS is disabled by default; use `--resolve-hostnames` when needed |
| Firewall change refused | Authenticate, use Administrator context, and provide `--confirm-firewall` |
| Audit verification fails | Preserve the current log and investigate the first broken event |

---

# 🔬 Analytical limitations

SecureNet provides **defensive security signals**, not automatic proof of compromise.

- A high risk score is not by itself proof of an attack.
- MITRE mappings are heuristic investigation hypotheses.
- An IP address alone does not establish ownership or attacker attribution.
- Threat-intelligence feeds may contain stale or incorrect indicators.
- Firewall enforcement can block legitimate traffic if a decision is wrong.
- Live capture and discovery depend on operating-system and network permissions.
- The current project is not a full enterprise SIEM, EDR, or forensic evidence-management platform.

For high-assurance investigations, preserve original evidence and use controlled, preferably external and immutable evidence/logging processes in addition to the local features provided here.

---

# 🤝 Contributing

Create a feature branch:

```bash
git checkout -b feature/my-improvement
```

Run verification before opening a pull request:

```bash
python test_all.py
python -m compileall -q Main.py Utils
```

Pull requests should explain the change, security impact, and test evidence.

---

# 📜 Authorized use

This repository is intended for **educational and authorized defensive security use**.

Do not use SecureNet Analyzer against networks, devices, traffic, or systems without explicit permission from the owner. The end user is responsible for complying with applicable laws, contracts, organizational policies, and rules of engagement.

---

# 📄 License

MIT License. See [LICENSE](LICENSE).

---

# 🙌 Acknowledgements

- [Scapy](https://scapy.net/) — packet manipulation and capture
- [Wireshark](https://www.wireshark.org/) — companion PCAP analysis
- mac-vendor-lookup — MAC/OUI vendor enrichment
- colorama — terminal output support

---

## 👤 Author

**Vittal Karthikeyan**

GitHub: [@Vital1506](https://github.com/Vital1506)

Project: [SecureNet-Analyzer-main](https://github.com/Vital1506/SecureNet-Analyzer-main)

---

<p align="center">
  <strong>Built for defenders. Evidence first. Secure by design.</strong>
</p>
