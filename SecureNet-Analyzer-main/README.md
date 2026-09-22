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

**SecureNet Analyzer** is a Python-based network security toolkit that combines packet capture, offline PCAP investigation, behavioral detections, threat-intelligence ingestion, IOC extraction, incident reporting, and local firewall enforcement in one CLI-driven workflow.

The project is designed around a simple security-operations flow:

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
│   Investigation Layer │
│ IOC • Timeline • MITRE│
│ Sessions • Risk Score │
└──────────┬────────────┘
           ▼
┌───────────────────────┐
│   Evidence & Reports  │
│ JSON • TXT • HTML     │
│ SHA-256 • Custody     │
└──────────┬────────────┘
           ▼
┌───────────────────────┐
│ Optional Enforcement  │
│ Local Blocklist       │
│ Windows Firewall      │
└───────────────────────┘
```

The goal is not to create a collection of unrelated security scripts. It is to keep **evidence, detections, investigation context, and response actions connected**.

---

## 🖥️ Project at a glance

| Layer | Current implementation |
|---|---|
| **Collection** | Scapy live packet capture and offline PCAP reading |
| **Analysis** | IP, protocol, ports, payload signals, risk scoring |
| **Behavior Detection** | Horizontal SYN scan, vertical SYN scan, periodic web beaconing |
| **Investigation** | Timeline, sessions, IOC extraction, MITRE ATT&CK hypothesis mapping |
| **Threat Intelligence** | STIX2 ingestion with IPv4/IPv6 IOC extraction |
| **Evidence** | SHA-256 evidence hashing and custody metadata |
| **Response** | Local blocklist and Windows Firewall enforcement |
| **Security Core** | Salted scrypt credentials, login throttling, bounded PCAP/payload processing, atomic state writes, hash-chained audit log |
| **Exports** | PCAP, TXT, HTML, JSON |
| **Automation** | GitHub Actions, compile checks, Bandit, pip-audit, Pylint |

---

## ✨ Core capabilities

### 📡 Live packet capture
Capture traffic from a selected interface and optionally analyze, save, alert, and generate an incident package.

### 📼 Offline PCAP investigation
Open an existing PCAP without starting a live sniffer. The packet investigation path feeds the same analysis, behavioral-detection, IOC, timeline, session, and reporting components.

### 🧠 Behavioral Detection Engine
The current rule pack includes:

| Rule | Detects |
|---|---|
| `NET-SCAN-001` | Horizontal TCP SYN scanning |
| `NET-SCAN-002` | Vertical TCP SYN scanning |
| `NET-BEACON-001` | Periodic web beaconing |

Each detection can carry rule ID, severity, confidence, timestamps, observations, MITRE reference, and packet-number evidence.

### 🎯 Investigation enrichment
SecureNet can build:

- observed IP activity
- packet and byte counts
- peers, ports, and protocols
- chronological timeline events
- aggregated sessions
- IPv4/IPv6/domain/URL/port IOCs
- heuristic MITRE ATT&CK mappings
- case summaries
- evidence hashes
- custody metadata

### 📡 STIX2 threat intelligence
Load a STIX2 bundle, extract valid IPv4/IPv6 IOCs, and optionally add IP IOCs to the local blocklist.

### 🔥 Local response controls
The project can maintain a validated local IP blocklist and, on Windows, use Firewall rules for inbound/outbound enforcement.

Real firewall changes are intentionally protected by:

- authentication
- Administrator checks
- explicit `--confirm-firewall`
- optional `--dry-run`
- audit events

### 🧾 Evidence and audit integrity
The project records SHA-256 hashes for supplied evidence files and maintains a local hash-chained audit log.

Verify the audit chain with:

```bash
python Main.py audit-verify --offline
```

A valid chain is **tamper-evident**; it is not a replacement for an external immutable logging system or a cryptographic signature.

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
                    │ Investigation Enrichment    │
                    │ IOC • Timeline • Sessions   │
                    │ MITRE • Case Summary        │
                    └──────────────┬──────────────┘
                                   ▼
                    ┌─────────────────────────────┐
                    │ Incident Report Generator   │
                    │ JSON • TXT • HTML           │
                    └──────────────┬──────────────┘
                                   │
                         ┌─────────┴─────────┐
                         ▼                   ▼
                  Evidence/Audit       Optional Response
                  SHA-256/Custody      Blocklist/Firewall
```

---

# 🛠️ How the project is implemented

## 1. Packet collection

**Live mode**

```text
Interface
   ↓
Scapy
   ↓
Captured packets
   ↓
Optional real-time analysis
```

**Offline mode**

```text
PCAP file
   ↓
File-size validation
   ↓
Packet-count limit
   ↓
PcapReader
   ↓
Investigation pipeline
```

Offline PCAP processing is deliberately bounded to reduce the risk that a hostile or oversized evidence file consumes excessive memory or CPU.

Default limits:

```text
Maximum PCAP size:     512 MiB
Maximum PCAP packets:  500,000
Maximum raw payload:   64 KiB
```

They can be adjusted explicitly with `--max-pcap-mb` and `--max-pcap-packets`.

---

## 2. Analysis and risk scoring

Packets are examined for network/security signals such as:

```text
Source / Destination IP
Protocol
Source / Destination Port
Traffic relationships
Suspicious patterns
Blocklist hits
Behavioral detections
```

The resulting signals feed the security summary and risk score.

---

## 3. Behavioral detection

The detection engine does not rely only on single packets.

It evaluates **traffic behavior over time windows**.

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

Evidence from the underlying packets is retained so an analyst can understand why a detection was created.

---

## 4. Investigation enrichment

The investigation layer converts raw observations into analyst-friendly structures:

```text
Packets
  ├── Sessions
  ├── Timeline
  ├── IOCs
  ├── MITRE hypotheses
  └── Case summary
```

### IOC types currently extracted

```text
IPv4
IPv6
Domains
URLs
Ports
```

### MITRE mapping

Mappings are **heuristic hypotheses** based on observed traffic/payload signals.

They should be treated as analyst triage information, not proof that a technique was successfully executed.

---

# 🔐 Security architecture

SecureNet itself is treated as an attack surface.

### Authentication

Passwords are stored as salted `scrypt` verifiers rather than plaintext or direct SHA-256 password hashes.

Security controls include:

```text
Password
   ↓
Salt
   ↓
scrypt
   ↓
Stored verifier

Failed attempts
   ↓
Progressive delay
   ↓
Maximum 5 attempts
```

Legacy SHA-256 records can be upgraded after successful authentication.

### Privilege boundaries

Read-only offline workflows can use `--offline`.

State-changing or privileged operations cannot use `--offline` as an authentication bypass:

```text
Capture              → authentication required
Live host detection  → authentication required
Blocklist mutation   → authentication required
Firewall enforcement → authentication + confirmation
Intel auto-block     → authentication required
```

### Firewall safety

Real Windows Firewall changes require:

```text
Authenticated user
      +
Administrator context
      +
--confirm-firewall
```

Use `--dry-run` first when testing firewall behavior.

### Safe state writes

Credential and blocklist state are written atomically to avoid partially-written runtime files.

### Audit integrity

Security-sensitive changes append events to a chained audit log:

```text
EVENT 1
  │ hash
  ▼
EVENT 2
  │ hash
  ▼
EVENT 3
```

Changing an earlier event breaks the chain.

### Offline forensic behavior

Reverse-DNS resolution is **opt-in**.

Normal offline report generation does not need to contact external DNS servers. Use:

```bash
--resolve-hostnames
```

only when hostname enrichment is intentionally required.

---

# 📂 Project structure

```text
SecureNet-Analyzer-main/
├── Main.py
├── requirements.txt
├── test_all.py
├── README.md
├── run.ps1
├── run.sh
├── InputExample.txt
│
├── Utils/
│   ├── analysis.py
│   ├── audit.py
│   ├── block_engine.py
│   ├── blocklist.py
│   ├── capture.py
│   ├── detection_engine.py
│   ├── filters.py
│   ├── HostDetector.py
│   ├── incident_report.py
│   ├── intel.py
│   ├── investigation.py
│   ├── save.py
│   ├── security.py
│   └── sample_intel.stix2.json
│
└── .github/
    └── workflows/
        ├── pylint.yml
        └── python-publish.yml
```

Runtime data such as credentials, blocklists, reports, and audit logs should be treated as deployment data rather than source-controlled project code.

---

# 💻 Installation

## Requirements

- Python 3.10, 3.11, or 3.12
- Scapy
- mac-vendor-lookup
- colorama

### Install

```bash
git clone https://github.com/Vital1506/SecureNet-Analyzer-main.git
cd SecureNet-Analyzer-main/SecureNet-Analyzer-main
python -m pip install -r requirements.txt
```

### Windows

Run PowerShell or Command Prompt as Administrator when using:

- live packet capture that requires elevated access
- Windows Firewall enforcement

Then:

```powershell
python Main.py --help
```

### Linux

When raw packet access requires elevation:

```bash
sudo python3 Main.py --help
```

---

# 🎮 CLI command map

| Command | Purpose | Typical access |
|---|---|---|
| `c` | Live packet capture and analysis | Authenticated |
| `pcap` | Offline PCAP investigation | Offline-safe |
| `lh` | Live host detection | Authenticated |
| `block` | Local blocklist management | Read-only listing can be offline; mutations require auth |
| `block-activate` | Enforce blocklist with Windows Firewall | Auth + Administrator + confirmation for real change |
| `block-deactivate` | Remove tool-created firewall rules | Auth + Administrator + confirmation for real change |
| `block-status` | Inspect current firewall block state | Read-only |
| `audit-verify` | Verify audit-chain integrity | Offline-safe |
| `intel` | Load STIX2 threat intelligence | Read-only unless auto-blocking |

Run:

```bash
python Main.py --help
```

for the current CLI contract.

---

# 🚀 Usage examples

## 1. Offline PCAP investigation

```bash
python Main.py pcap ^
  --input evidence_CASE001.pcap ^
  --summary ^
  --report-prefix reports\CASE001 ^
  --case-id CASE-001 ^
  --analyst "Security Analyst" ^
  --organization "Example SOC" ^
  --offline
```

**PowerShell / CMD users:** the caret continuation shown above is for Windows command shells. For Linux/macOS, use one line or backslash continuation.

This workflow can generate:

```text
reports/CASE001.html
reports/CASE001.txt
reports/CASE001.json
```

and includes investigation context such as:

- security summary
- behavioral detections
- sessions
- timeline
- IOCs
- MITRE hypotheses
- evidence hashes
- custody metadata

---

## 2. Live packet capture

```bash
python Main.py c --i WiFi --pc 50 --a --summary --s --p captured_traffic.pcap
```

This captures 50 packets from the selected interface, analyzes them, prints a security summary, and saves a PCAP.

---

## 3. Filter traffic

```bash
python Main.py c --pc 100 --f "tcp and dst port 22" --a --summary
```

Supported filter expressions include:

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

Use this only on an authorized network.

---

## 5. Local blocklist

### Read-only listing

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

Blocklist values are validated as IP addresses and normalized before storage.

---

## 6. Windows Firewall — dry run first

Preview:

```bash
python Main.py block-activate --dry-run
```

Real enforcement:

```bash
python Main.py block-activate --confirm-firewall
```

Check status:

```bash
python Main.py block-status
```

Remove rules created by SecureNet:

```bash
python Main.py block-deactivate --confirm-firewall
```

Real firewall changes require authentication and Administrator privileges.

---

## 7. STIX2 threat intelligence

Use the bundled sample:

```bash
python Main.py intel --intel-source sample --offline
```

Load your own STIX2 bundle without automatic response:

```bash
python Main.py intel --intel-source my_threats.stix2.json
```

Enable automatic addition of valid IP IOCs to the local blocklist only when you explicitly intend to make that state change:

```bash
python Main.py intel --intel-source my_threats.stix2.json --intel-auto-block
```

Threat-intel content should be treated as untrusted input and reviewed before enforcement in production environments.

---

## 8. Verify audit integrity

```bash
python Main.py audit-verify --offline
```

Expected output when the chain is internally consistent:

```text
Audit log valid: <N> event(s) verified.
```

---

# 📊 Incident report outputs

When `--report-prefix` is provided, SecureNet can generate three report formats.

| Output | Purpose |
|---|---|
| **HTML** | Analyst-friendly report for investigation review |
| **TXT** | Lightweight handoff / archival format |
| **JSON** | Structured data for automation and SIEM-oriented pipelines |

The JSON case data can include:

```text
case metadata
observed IP activity
security events
behavioral detections
sessions
timeline
IOCs
MITRE mappings
evidence hashes
chain-of-custody metadata
case summary
```

---

# 🧪 Verification & quality gates

The repository uses GitHub Actions to validate the project on:

```text
Python 3.10
Python 3.11
Python 3.12
```

The current CI pipeline checks:

```text
✅ Automated regression suite
✅ Python compile checks
✅ Bandit security scan
✅ pip-audit dependency audit
✅ Pylint
```

The Phase 3 secure-core branch passed **161 automated checks with 0 failures** before merge, and the post-merge `main` workflow also completed successfully.

---

# 🧭 Implementation roadmap

SecureNet is being developed incrementally so every phase remains testable.

### ✅ Phase 1 — Behavioral Detection Foundation
- Time-window scan detection
- Periodic web beacon detection
- Detection evidence
- Severity and confidence
- MITRE references

### ✅ Phase 2 — Offline PCAP Investigation
- PCAP investigation mode
- Investigation enrichment
- Timeline
- Sessions
- IOC extraction
- Incident package generation

### ✅ Phase 3 — Secure Core Hardening
- Salted scrypt password storage
- Failed-login throttling
- Protected enforcement actions
- PCAP resource limits
- Payload limits
- Atomic state writes
- Tamper-evident audit logging
- Offline DNS isolation
- CI security scans

### 🔜 Next engineering targets
- Stateful flow engine
- DNS / HTTP / TLS metadata extraction
- Slow-scan and brute-force detections
- DNS tunneling / exfiltration signals
- Attack-chain correlation
- Asset inventory and network graph
- Stronger evidence manifests and digital signatures
- Case-management workflow
- SOC web dashboard
- Evidence-grounded AI investigation

The architecture should evolve in that order: **secure foundation → better telemetry → stronger detections → correlation → case management → user interface → AI**.

---

# 🧰 Troubleshooting

| Problem | Action |
|---|---|
| Permission denied during capture | Run with the required OS privileges |
| Interface not found | Check the interface name and run `python Main.py --help` |
| Login loop | Verify the configured password and check the local credential record |
| Firewall action refused | Authenticate, use Administrator context, and add `--confirm-firewall` for real changes |
| PCAP rejected | Check `--max-pcap-mb` and `--max-pcap-packets` limits |
| Report has no hostname | Reverse-DNS is intentionally disabled by default; use `--resolve-hostnames` when appropriate |
| Dependency problem | Run `python -m pip install -r requirements.txt` |
| Audit verification fails | Preserve the current log, investigate the first broken event, and do not overwrite it blindly |

---

# 🔬 Important analytical limitations

SecureNet provides **defensive detection signals**, not automatic proof of compromise.

In particular:

- A high risk score is not by itself proof of an attack.
- A MITRE ATT&CK mapping is a heuristic investigation hypothesis.
- An IP address alone does not establish ownership or attacker attribution.
- Threat-intel feeds can contain stale, incorrect, or malicious data.
- Firewall enforcement can disrupt legitimate traffic if an IOC or local decision is wrong.
- Live capture and host discovery depend on operating-system and network permissions.
- The current project is **not yet** a full enterprise SIEM, EDR, or forensic evidence-management system.

For high-assurance investigations, preserve original evidence, maintain controlled access, and use an external immutable logging/evidence process in addition to SecureNet's local integrity features.

---

# 🤝 Contributing

1. Create a feature branch.

```bash
git checkout -b feature/my-improvement
```

2. Implement the change.
3. Add or update tests.
4. Run the test suite locally.

```bash
python test_all.py
python -m compileall -q Main.py Utils
```

5. Open a pull request with:
   - what changed
   - why it changed
   - security impact
   - test evidence

Security-sensitive changes should be kept focused and verified through CI before merge.

---

# 📜 Legal disclaimer

This repository is intended for **educational and authorized defensive security use**.

Do not use SecureNet Analyzer against networks, devices, traffic, or systems without explicit permission from the owner. The end user is responsible for complying with applicable laws, contracts, organizational policies, and rules of engagement.

The project authors are not responsible for unauthorized, unlawful, or harmful use of this software.

---

# 📄 License

MIT License.

See the legal disclaimer above for intended use and responsibilities.

---

# 🙌 Acknowledgements

- [Scapy](https://scapy.net/) — packet manipulation and network analysis
- [Wireshark](https://www.wireshark.org/) — PCAP analysis companion
- mac-vendor-lookup — MAC/OUI vendor enrichment
- colorama — terminal color support

---

## 👤 Author

**Vittal Karthikeyan**

GitHub: [@Vital1506](https://github.com/Vital1506)

Project: [SecureNet-Analyzer-main](https://github.com/Vital1506/SecureNet-Analyzer-main)

---

<p align="center">
  <strong>Built for defenders. Evidence first. Secure by design.</strong>
</p>
