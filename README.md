<div align="center">

# 🛰️SecureNet Analyzer

### **Defensive Network Detection • Investigation • Response**

**Capture → Detect → Investigate → Report → Respond**

<p>
  <a href="https://github.com/Vital1506/SecureNet-Analyzer-main/actions/workflows/pylint.yml">
    <img src="https://github.com/Vital1506/SecureNet-Analyzer-main/actions/workflows/pylint.yml/badge.svg" alt="CI">
  </a>
  <img src="https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12-blue" alt="Python">
  <img src="https://img.shields.io/badge/Focus-Network%20Security-red" alt="Network Security">
  <img src="https://img.shields.io/badge/License-MIT-green" alt="MIT License">
</p>

**A security-focused Python/Scapy platform for network visibility, behavioral detection, offline PCAP investigation, IOC extraction, threat intelligence, evidence generation, and controlled response.**

</div>

---

<div align="center">

> ⚠️ **AUTHORIZED SECURITY USE ONLY**  
> Use packet capture, host discovery, traffic analysis, and firewall controls only on systems or networks you own or are explicitly authorized to assess.

</div>

---

<h2 align="center">🖥️ DIGITAL SOC OVERVIEW</h2>

<div align="center">

| 📡 COLLECTION | 🧠 DETECTION | 🔎 INVESTIGATION | 🛡️ RESPONSE |
|:---:|:---:|:---:|:---:|
| Live capture | SYN scan signals | IOC extraction | IP blocklist |
| Offline PCAP | Beacon detection | Timeline | Windows Firewall |
| Scapy | Risk scoring | Sessions | Threat intel |
| Packet evidence | Severity + confidence | MITRE hypotheses | Audit trail |

</div>

### 🔄 Security Pipeline

<div align="center">

```text
┌───────────────┐
│  NETWORK/PCAP │
└───────┬───────┘
        ▼
┌─────────────────────┐
│  COLLECTION LAYER   │
│ Scapy / PcapReader  │
└──────────┬──────────┘
           ▼
┌─────────────────────┐
│ ANALYSIS & SCORING  │
│ IP • Port • Proto   │
└──────────┬──────────┘
           ▼
┌─────────────────────┐
│ DETECTION ENGINE    │
│ Scan • Beacon       │
└──────────┬──────────┘
           ▼
┌─────────────────────┐
│ INVESTIGATION       │
│ IOC • Timeline      │
│ Sessions • MITRE    │
└──────────┬──────────┘
           ▼
┌─────────────────────┐
│ EVIDENCE & REPORTS  │
│ JSON • TXT • HTML   │
│ Hashes • Custody    │
└──────────┬──────────┘
           ▼
┌─────────────────────┐
│ CONTROLLED RESPONSE │
│ Blocklist/Firewall  │
└─────────────────────┘
```

</div>

---

<h2 align="center">⚡ PROJECT AT A GLANCE</h2>

<div align="center">

| Layer | Implementation |
|:---|:---|
| **Collection** | Scapy live packet capture + bounded offline PCAP reading |
| **Analysis** | IP, protocol, ports, payload signals, risk scoring |
| **Detection** | Horizontal SYN scan, vertical SYN scan, periodic web beaconing |
| **Investigation** | Timeline, sessions, IOCs, MITRE ATT&CK hypothesis mapping |
| **Threat Intelligence** | STIX2 ingestion with IPv4/IPv6 IOC extraction |
| **Evidence** | SHA-256 evidence hashes + custody metadata |
| **Response** | Local blocklist + Windows Firewall enforcement |
| **Security Core** | Salted scrypt, login throttling, resource limits, atomic writes, hash-chained audit |
| **Output** | PCAP, TXT, HTML, JSON |
| **Alerting** | Risk-threshold stdout/file alerts with optional non-zero exit |
| **Filtering** | Source/destination host/port and protocol filters |
| **CI** | Regression tests, compile checks, Bandit, pip-audit, Pylint |

</div>

---

<h2 align="center">✨ CORE FEATURES</h2>

<div align="center">

### 📡 LIVE NETWORK VISIBILITY

Capture traffic from an authorized interface and route it into analysis, detection, reporting, and evidence workflows.

### 📼 OFFLINE PCAP FORENSICS

Investigate existing evidence without starting a live sniffer.

```text
PCAP
 ↓
Size validation
 ↓
Packet limit
 ↓
PcapReader
 ↓
Analysis
 ↓
Detection
 ↓
Investigation
 ↓
Evidence package
```

### 🧠 BEHAVIORAL DETECTION

Current detection rules:

| Rule ID | Detects |
|:---:|:---|
| `NET-SCAN-001` | Horizontal TCP SYN scanning |
| `NET-SCAN-002` | Vertical TCP SYN scanning |
| `NET-BEACON-001` | Periodic web beaconing |

Detection records can include **rule ID, severity, confidence, timestamps, observations, MITRE reference, and packet evidence**.

### 🎯 INVESTIGATION ENRICHMENT

```text
Packets
  ├── Sessions
  ├── Timeline
  ├── IOCs
  ├── MITRE hypotheses
  ├── Risk summary
  └── Case metadata
```

### 📡 THREAT INTELLIGENCE

Load STIX2 bundles, extract valid IPv4/IPv6 indicators, and optionally feed IP indicators into the local blocklist.

### 🔥 CONTROLLED RESPONSE

Windows Firewall integration is protected by authentication, Administrator checks, explicit confirmation, and audit events.

### 🚨 THRESHOLD ALERTING

Risk thresholds can trigger alerts to stdout, append alerts to a file, and optionally return exit code `2` for automation.

```bash
python Main.py c --pc 100 --a --summary --alert-on 50 --alert-file alerts.log --alert-exit
```

### 🎛️ TRAFFIC FILTERING

Capture filters support source/destination hosts, ports, and protocols. Multiple clauses can be joined with `and`.

```text
src host 10.0.0.5
dst host 192.168.1.10
src port 443
dst port 22
tcp
udp
icmp
icmp6
ip
ipv6
```

</div>

---

<h2 align="center">🏗️ ARCHITECTURE</h2>

<div align="center">

```text
                         ┌───────────────────────┐
                         │     SecureNet CLI     │
                         └───────────┬───────────┘
                                     │
                ┌────────────────────┼────────────────────┐
                │                    │                    │
                ▼                    ▼                    ▼
        ┌──────────────┐     ┌──────────────┐     ┌──────────────┐
        │ LIVE CAPTURE │     │ OFFLINE PCAP │     │ THREAT INTEL │
        └──────┬───────┘     └──────┬───────┘     └──────┬───────┘
               │                    │                    │
               └────────────────────┼────────────────────┘
                                    ▼
                         ┌─────────────────────┐
                         │ PACKET / STATE DATA │
                         └──────────┬──────────┘
                                    ▼
                         ┌─────────────────────┐
                         │ ANALYSIS & SCORING  │
                         └──────────┬──────────┘
                                    ▼
                         ┌─────────────────────┐
                         │ DETECTION ENGINE    │
                         └──────────┬──────────┘
                                    ▼
                    ┌──────────────────────────────┐
                    │ INVESTIGATION ENRICHMENT     │
                    │ IOC • Timeline • Sessions    │
                    │ MITRE • Risk • Case Summary  │
                    └──────────────┬───────────────┘
                                   ▼
                    ┌──────────────────────────────┐
                    │ INCIDENT REPORT GENERATOR    │
                    │ HTML • TXT • JSON             │
                    └──────────────┬───────────────┘
                                   │
                       ┌───────────┴───────────┐
                       ▼                       ▼
                ┌──────────────┐       ┌──────────────┐
                │ EVIDENCE     │       │ RESPONSE     │
                │ Hash + Audit │       │ Block/Firewall│
                └──────────────┘       └──────────────┘
```

</div>

---

<h2 align="center">🔐 SECURITY ENGINEERING</h2>

<div align="center">

| Control | Implementation |
|:---|:---|
| 🔑 **Authentication** | Salted scrypt password verification |
| 🚦 **Login Protection** | Maximum 5 attempts + progressive delay |
| 📦 **PCAP Safety** | 512 MiB default file limit + 500,000 packet limit |
| 🧩 **Payload Safety** | Raw payload analysis capped at 64 KiB |
| 💾 **State Integrity** | Atomic credential/blocklist writes |
| 🧾 **Audit Integrity** | Local hash-chained audit events |
| 🔥 **Firewall Safety** | Authentication + Administrator + `--confirm-firewall` |
| 🌐 **Offline Isolation** | Reverse DNS enrichment disabled by default |
| 🛡️ **CI Security** | Bandit + pip-audit + tests + compile + Pylint |

</div>

### 🔑 Authentication Flow

<div align="center">

```text
Password
   ↓
Random Salt
   ↓
scrypt KDF
   ↓
Stored Verifier

Failed Login
   ↓
Progressive Delay
   ↓
Maximum 5 Attempts
```

</div>

### 🧾 Tamper-Evident Audit

<div align="center">

```text
EVENT 1 ──hash──► EVENT 2 ──hash──► EVENT 3
                         │
                         ▼
                  audit-verify
```

</div>

Verify:

```bash
python Main.py audit-verify --offline
```

> Local hash chaining provides tamper evidence. It is not a substitute for an external immutable log or digital signature system.

---

<h2 align="center">🛠️ IMPLEMENTATION</h2>

### 01 — Collection

```text
Network Interface
       ↓
Scapy Capture
       ↓
Packets
       ↓
Analysis / Detection / Reporting
```

### 02 — Bounded Offline Investigation

```text
Evidence PCAP
     ↓
Validate Size
     ↓
Limit Packets
     ↓
Stream with PcapReader
     ↓
Analyze
     ↓
Detect
     ↓
Investigate
```

Default limits:

```text
Maximum PCAP size   : 512 MiB
Maximum PCAP packets: 500,000
Maximum raw payload : 64 KiB
```

### 03 — Behavioral Detection

The detection engine evaluates **traffic over time windows**, allowing repeated or distributed observations to become investigation signals instead of treating every packet as an isolated event.

### 04 — Investigation

```text
Traffic
  ↓
Observed IPs / Ports / Protocols
  ↓
Sessions + Timeline
  ↓
IOC Extraction
  ↓
MITRE Hypotheses
  ↓
Incident Case
```

### 05 — Evidence

Generated investigation packages can contain:

```text
Case metadata
Security events
Detections
Sessions
Timeline
IOCs
MITRE mappings
Evidence SHA-256 hashes
Custody metadata
Case summary
```

---

<h2 align="center">📂 PROJECT STRUCTURE</h2>

<div align="center">

```text
SecureNet-Analyzer-main/
│
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

</div>

---

<h2 align="center">🧩 COMPLETE CODE / MODULE MAP</h2>

<div align="center">

| Source file | What the code implements |
|:---|:---|
| `Main.py` | CLI orchestration, authentication, command routing, offline PCAP limits, login throttling, threshold alerts, reporting, blocklist/firewall/intel actions |
| `Utils/capture.py` | Scapy interface discovery, live sniffing, packet callback, packet filtering |
| `Utils/filters.py` | IPv4/IPv6, host, port, and protocol filter parsing and matching |
| `Utils/analysis.py` | IPv4/IPv6/TCP/UDP/ICMP packet parsing, bounded payload extraction, suspicious service-port/payload signals, risk scoring, security summaries |
| `Utils/detection_engine.py` | Time-window horizontal SYN scan, vertical SYN scan, periodic web beacon detection, evidence indexing, severity/confidence summaries |
| `Utils/investigation.py` | IPv4/IPv6/port/domain/URL IOC extraction, DNS/HTTP-aware MITRE hypotheses, sessions, timeline, case summary |
| `Utils/incident_report.py` | Case dataset creation, HTML/TXT/JSON reports, evidence SHA-256 hashing, custody metadata, optional reverse DNS |
| `Utils/save.py` | PCAP export plus TXT/HTML packet and security reports |
| `Utils/intel.py` | Offline STIX2 ingestion, IPv4/IPv6 indicator extraction, intel reporting, optional IP blocklist integration |
| `Utils/blocklist.py` | IP validation/normalization, atomic persistence, add/remove/clear/query, audit events |
| `Utils/block_engine.py` | Windows Firewall rule creation/removal/status, Administrator detection, dry-run, audited enforcement |
| `Utils/security.py` | Salted scrypt hashing/verification, legacy SHA-256 migration, KDF validation, atomic credential storage |
| `Utils/audit.py` | JSON-lines audit records, hash chaining, integrity verification, constant-time hash comparison |
| `Utils/HostDetector.py` | ARP live-host discovery with IP/MAC/vendor enrichment |
| `test_all.py` | Regression and security checks for CLI, analysis, detections, reports, authentication, hardening, alerts, intel and firewall dry-run |
| `run.ps1` | PowerShell launcher forwarding arguments to `Main.py` |
| `run.sh` | POSIX shell launcher forwarding arguments to `Main.py` |

</div>

### Current protocol coverage

```text
IPv4      → ✅
IPv6      → ✅
TCP       → ✅
UDP       → ✅
ICMP      → ✅
DNS       → ✅ investigation/MITRE enrichment
HTTP      → ✅ investigation/MITRE enrichment when Scapy HTTP layers are available
TLS       → ⚠️ no dedicated parser yet
```

The analysis layer also provides protocol/port summaries and selected suspicious payload/service-port detection.

---

<h2 align="center">💻 INSTALLATION</h2>

### Windows

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

Use an elevated PowerShell / VS Code session when the requested operation requires Administrator privileges.

### Package build

The repository includes `pyproject.toml` for reproducible package builds and a `securenet-analyzer` console entry point.

```bash
python -m pip install build
python -m build
```

This creates source and wheel distributions under `dist/`.

### Linux / macOS

```bash
git clone https://github.com/Vital1506/SecureNet-Analyzer-main.git
cd SecureNet-Analyzer-main/SecureNet-Analyzer-main

python3 -m venv venv
source venv/bin/activate

python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python Main.py --help
```

---

<h2 align="center">🎮 CLI COMMAND CENTER</h2>

<div align="center">

| Command | Function | Access |
|:---:|:---|:---|
| `c` | Live packet capture + analysis | Authenticated |
| `pcap` | Offline PCAP investigation | Offline-safe |
| `lh` | Live host detection | Authenticated |
| `block` | Local blocklist management | Mutations require auth |
| `block-activate` | Windows Firewall enforcement | Auth + Admin + confirmation |
| `block-deactivate` | Remove SecureNet firewall rules | Auth + Admin + confirmation |
| `block-status` | Firewall state inspection | Read-only |
| `audit-verify` | Verify audit-chain integrity | Offline-safe |
| `intel` | STIX2 threat intelligence | Read-only unless auto-block |

</div>

Run the exact current CLI contract:

```bash
python Main.py --help
```

### Key options

| Option | Purpose |
|:---|:---|
| `--pc` | Number of packets for live capture |
| `--i` | Capture interface |
| `--f` | Traffic filter expression |
| `--a` | Analyze captured traffic |
| `--summary` | Print a security summary |
| `--s` | Save captured traffic |
| `--p` | Save PCAP output |
| `--t` | Save TXT output |
| `--html` | Save HTML output |
| `--report-prefix` | Generate HTML/TXT/JSON incident reports |
| `--case-id` | Set investigation case ID |
| `--analyst` | Set analyst name in the report |
| `--organization` | Set organization/team in the report |
| `--resolve-hostnames` | Opt in to reverse-DNS report enrichment |
| `--max-pcap-mb` | Set the offline PCAP size limit |
| `--max-pcap-packets` | Set the offline PCAP packet limit |
| `--alert-on` | Set the risk-score alert threshold |
| `--alert-file` | Append threshold alerts to a file |
| `--alert-exit` | Exit with code 2 when the threshold is crossed |
| `--confirm-firewall` | Confirm a real Windows Firewall change |
| `--dry-run` | Preview firewall enforcement without applying rules |
| `--offline` | Allow only offline/read-only-safe workflows to skip login |

---

<h2 align="center">🚀 USAGE</h2>

### Offline PCAP Investigation

```bash
python Main.py pcap --input evidence_CASE001.pcap --summary --report-prefix reports/CASE001 --case-id CASE-001 --analyst "Security Analyst" --organization "Example SOC" --offline
```

### Live Capture

```bash
python Main.py c --i WiFi --pc 50 --a --summary --s --p captured_traffic.pcap
```

### Traffic Filtering

```bash
python Main.py c --pc 100 --f "tcp and dst port 22" --a --summary
```

### Live Host Detection

```bash
python Main.py lh --ip 192.168.1.10 --timeout 3 --max-hosts 50
```

### STIX2 Threat Intelligence

Use the bundled sample:

```bash
python Main.py intel --intel-source sample --offline
```

Automatic IP blocklisting is also available for explicitly authorized response workflows:

```bash
python Main.py intel --intel-source my_threats.stix2.json --intel-auto-block
```

Threat-intelligence content should be reviewed before enforcement.

### Audit Verification

```bash
python Main.py audit-verify --offline
```

---

<h2 align="center">📊 INCIDENT REPORTS</h2>

<div align="center">

| Output | Purpose |
|:---:|:---|
| 🟣 **HTML** | Analyst-friendly investigation report |
| 🔵 **TXT** | Lightweight case handoff / archive |
| 🟢 **JSON** | Structured automation / SIEM-oriented data |

</div>

The JSON case package can contain case metadata, observed IP activity, security events, detections, sessions, timeline data, IOCs, MITRE mappings, evidence hashes, custody metadata, and a case summary.

---

<h2 align="center">🧪 CI / QUALITY GATES</h2>

<div align="center">

```text
PYTHON 3.10 ─┐
PYTHON 3.11 ─┼─► REGRESSION TESTS
PYTHON 3.12 ─┘       │
                      ├── Compile Checks
                      ├── Bandit
                      ├── pip-audit
                      └── Pylint
```

**Phase 3 secure-core verification:** 161 automated checks passed with 0 failures before merge.

**Dependency stack:** Scapy, mac-vendor-lookup, and colorama. Runtime dependencies are installed from `SecureNet-Analyzer-main/requirements.txt`.

</div>

---

<h2 align="center">🧭 DEVELOPMENT ROADMAP</h2>

<div align="center">

| Status | Phase | Focus |
|:---:|:---|:---|
| ✅ | Phase 1 | Behavioral Detection Foundation |
| ✅ | Phase 2 | Offline PCAP Investigation |
| ✅ | Phase 3 | Secure Core Hardening |
| 🔜 | Phase 4 | Stateful Flow Engine |
| 🔶 | Phase 5 | Deeper DNS / HTTP / TLS Intelligence |
| 🔜 | Phase 6 | Advanced Detections + Correlation |
| 🔜 | Phase 7 | Asset Inventory + Network Graph |
| 🔜 | Phase 8 | Case Management |
| 🔜 | Phase 9 | SOC Web Dashboard |
| 🔜 | Phase 10 | Evidence-Grounded AI Investigation |

</div>

> **Current-state note:** DNS and HTTP-aware enrichment already exists in the investigation layer. The roadmap refers to deeper protocol metadata extraction and stronger TLS visibility.\n\n> **Important:** The current application is CLI-driven. A full graphical SOC dashboard is part of the planned evolution, not a claim about the current implementation.

---

<h2 align="center">🔬 ANALYTICAL LIMITATIONS</h2>

<div align="center">

**SecureNet produces defensive investigation signals — not automatic proof of compromise.**

</div>

- A risk score alone is not proof of an attack.
- MITRE mappings are heuristic investigation hypotheses.
- An IP address alone does not establish attacker identity or attribution.
- Threat-intelligence data can be stale, incorrect, or malicious.
- Firewall decisions can disrupt legitimate traffic when an IOC is wrong.
- Live capture and host discovery depend on OS and network permissions.
- The current release is not a full enterprise SIEM, EDR, or forensic evidence-management platform.

---

<h2 align="center">🤝 CONTRIBUTING</h2>

```bash
git checkout -b feature/my-improvement
python test_all.py
python -m compileall -q Main.py Utils
```

Security-sensitive changes should include tests and CI evidence before merge.

---

<div align="center">

## 👤 AUTHOR

**Vittal Karthikeyan**

[GitHub @Vital1506](https://github.com/Vital1506)

[SecureNet Analyzer Repository](https://github.com/Vital1506/SecureNet-Analyzer-main)

**Built for defenders. Evidence first. Secure by design.**

</div>

---

<div align="center">

### 📜 LICENSE

MIT License

</div>
