# SecureNet Analyzer — Current Engineering Specification

## Project identity

- **Name:** SecureNet Analyzer
- **Repository:** `Vital1506/SecureNet-Analyzer-main`
- **Source root:** `SecureNet-Analyzer-main/`
- **Entry point:** `SecureNet-Analyzer-main/Main.py`
- **Core libraries:** Scapy, mac-vendor-lookup, colorama
- **Purpose:** Authorized defensive network capture, offline PCAP investigation, behavioral detection, threat-intelligence ingestion, IOC extraction, incident reporting, and controlled local response.

## Operational constraints

- Use only on systems and networks that you own or are explicitly authorized to assess.
- Live packet capture and ARP discovery may require Administrator/root privileges.
- Firewall enforcement is Windows-only and requires authentication, Administrator privileges, and explicit confirmation for real changes.
- `--offline` is an authentication bypass only for read-only/offline-safe operations; it never bypasses authentication for state-changing or privileged operations.
- Threat-intelligence bundles are treated as untrusted input.

## Command surface

```text
python Main.py <option> [flags]

c                 Live packet capture and analysis
pcap              Offline PCAP investigation
lh                Live host discovery through ARP
block             Local IP blocklist management
block-activate    Enforce blocklist through Windows Firewall
block-deactivate  Remove SecureNet Windows Firewall rules
block-status      Inspect SecureNet firewall block state
audit-verify      Verify the local hash-chained audit log
intel             Load offline STIX2 threat intelligence
```

### Common options

| Option | Purpose |
|---|---|
| `--i <iface>` | Capture interface |
| `--pc <n>` | Positive live-capture packet count |
| `--a` | Per-packet analysis |
| `--s` | Enable saving when an output target is supplied |
| `--p <file>` | PCAP output |
| `--t <file>` | TXT output |
| `--html <file>` | HTML output |
| `--summary` | Security summary |
| `--f <expr>` | Explicit traffic filter |
| `--ip <addr>` | IPv4 target for ARP host discovery |
| `--block <ip>` | Add blocklist entry |
| `--unblock <ip>` | Remove blocklist entry |
| `--list-blocks` | List blocklist |
| `--clear-blocks` | Clear blocklist |
| `--offline` | Skip authentication only for offline/read-only-safe workflows |
| `--confirm-firewall` | Confirm a real Windows Firewall change |
| `--dry-run` | Preview firewall response without executing firewall commands |
| `--timeout <s>` | Positive ARP timeout |
| `--max-hosts <n>` | 1–254 ARP host results |
| `--intel-source <p>` | STIX2 JSON path or `sample` |
| `--intel-auto-block` | Add valid IP IOCs to blocklist |
| `--alert-on <n>` | Alert when risk score reaches 0–100 threshold |
| `--alert-file <f>` | Append threshold alerts to a file |
| `--alert-exit` | Exit code 2 when a threshold is crossed |
| `--report-prefix <p>` | Generate HTML/TXT/JSON incident reports |
| `--case-id <id>` | Investigation case identifier |
| `--analyst <name>` | Analyst metadata |
| `--organization <name>` | Organization metadata |
| `--resolve-hostnames` | Opt into reverse-DNS report enrichment |
| `--max-pcap-mb <n>` | Positive offline PCAP size limit |
| `--max-pcap-packets <n>` | Positive offline PCAP packet limit |

## Filter grammar

The filter language is intentionally smaller than Wireshark's full display-filter grammar:

```text
src host <IPv4/IPv6>
dst host <IPv4/IPv6>
src port <1-65535>
dst port <1-65535>
tcp
udp
icmp
icmp6
ip
ipv6
```

Clauses are joined with case-insensitive `and`.

Unsupported or malformed filter conditions are rejected instead of silently ignored.

## Authentication and secure state

- Passwords use salted `scrypt` verifiers.
- Legacy direct SHA-256 records are supported only for migration and are upgraded after successful authentication.
- Password input must be at least 12 characters during setup.
- Login is limited to 5 attempts with progressive delay.
- Password records are bounded and written atomically.
- Blocklist state is validated, normalized, and written atomically.
- Security-sensitive changes append to a local hash-chained audit log.

## PCAP / evidence safety

- Offline PCAP size is bounded by `--max-pcap-mb`.
- Offline PCAP packet count is bounded by `--max-pcap-packets`.
- Packet payload analysis is capped at 64 KiB.
- Investigation payload decoding uses the same bounded approach.
- Reverse DNS is disabled unless `--resolve-hostnames` is supplied.
- Evidence files can be SHA-256 hashed into incident reports.
- Incident case IDs are sanitized before being incorporated into output filenames.

## Analysis and investigation

### Packet analysis

Supports:
- IPv4
- IPv6
- TCP
- UDP
- ICMP
- ICMPv6
- source/destination ports
- blocklist hits
- suspicious service-port targeting
- selected suspicious payload patterns

### Behavioral detection

Current rule pack:

| Rule | Purpose |
|---|---|
| `NET-SCAN-001` | Horizontal TCP SYN scan |
| `NET-SCAN-002` | Vertical TCP SYN scan |
| `NET-BEACON-001` | Periodic web beaconing |

Findings include severity, confidence, timestamps, observations, MITRE references, and packet evidence.

### Investigation enrichment

Current enrichment includes:
- IPv4/IPv6 IOCs
- domains
- URLs
- ports
- DNS-aware mapping
- HTTP-aware mapping when Scapy HTTP layers are available
- MITRE ATT&CK hypotheses
- IPv4/IPv6 sessions
- enriched timeline
- case summaries

TLS does not yet have a dedicated parser.

## Threat intelligence

STIX2 ingestion is offline-first.

The loader:
- accepts a JSON object containing an `objects` array or a JSON object list
- bounds the input file to 32 MiB
- bounds objects to 100,000
- validates object structure
- extracts valid IPv4/IPv6 indicators
- counts non-IP indicators
- optionally adds valid IP indicators to the local blocklist

## Firewall safety

Real enforcement is fail-closed unless the process is running with confirmed Windows Administrator privileges.

Dry-run mode:
- does not execute firewall subprocesses
- reports what would be changed
- can be used safely from CI/Linux for behavior tests

PowerShell runs without execution-policy bypass.

SecureNet firewall rules use predictable names:

```text
SecureNet_Block_In_<ip>
SecureNet_Block_Out_<ip>
```

Firewall deactivation discovers SecureNet-owned rules directly rather than depending on the current local blocklist.

## Reporting

Incident reporting can generate:
- HTML
- TXT
- JSON

Packages can include:
- case metadata
- observed IP activity
- security events
- detections
- sessions
- timeline
- IOCs
- MITRE mappings
- evidence hashes
- custody metadata
- risk summary

## Verification

Run:

```bash
python test_all.py
python -m compileall -q Main.py Utils
```

CI additionally runs:
- Python 3.10 / 3.11 / 3.12
- Bandit
- pip-audit
- Pylint

## Engineering roadmap

Implemented:
1. Behavioral detection foundation
2. Offline PCAP investigation
3. Secure core hardening

Next:
4. Stateful flow engine
5. Deeper protocol metadata, especially TLS
6. More behavioral detections and attack-chain correlation
7. Asset inventory and network graph
8. Case-management workflow
9. SOC web dashboard
10. Evidence-grounded AI investigation

## Non-goals

- Full Wireshark filter compatibility
- IPv6 ARP-style live discovery
- Linux/macOS firewall enforcement in the current release
- Claiming that detections prove compromise or attribution

## Legal

Use only for authorized defensive security work. See `README.md`, `SECURITY.md`, and `LICENSE`.
