# SecureNet Analyzer — Master Prompt

## Project identity
- **Name:** SecureNet Analyzer
- **Repository:** `project-execution-guide/SecureNet-Analyzer-main/`
- **Entry point:** `Main.py` (CLI, Python 3)
- **Core libs:** `scapy`, `mac-vendor-lookup`
- **Purpose (one line):** Authorized network traffic capture, live-host enumeration, packet analysis, and security reporting toolkit for defenders and pentesters.

## Operational intent and constraints
- This tool is for **educational environments and authorized penetration testing only**.
- It must **never** be used on networks without explicit written authorization.
- Raw packet capture requires **Administrator / root privileges**.
- Passwords are stored only as **SHA-256 hashes** in `password_hash.txt`.
- Blocked IPs are stored in `blocked_ips.txt`.

## Command surface (authoritative)
```
python Main.py <option> [flags]

option:
  c                 Capture and analyze packets
  lh                Live host detection via ARP
  block             Local IP blocklist management
  block-activate    Enforce blocked IPs via firewall (Windows)
  block-deactivate  Remove firewall block rules
  block-status      Show firewall block state
  intel             Load/fetch threat intel, extract IOCs, optionally add to blocklist

Common flags:
  --i <iface>          Interface to capture from
  --pc <n>            Packet count (capture mode)
  --a                  Real-time per-packet analysis
  --s                  Save captured packets
  --p <file>          Save as PCAP
  --t <file>          Save as TXT report
  --html <file>       Save as HTML executive report
  --summary           Print security summary after capture
  --f <expr>          Filter expression
  --ip <addr>         Target IP for live host detection
  --block <ip>        Add IP to blocklist
  --unblock <ip>      Remove IP from blocklist
  --list-blocks       Show blocklist
  --clear-blocks      Clear blocklist
  --offline           Skip login prompt (automation)
  --dry-run           Simulate firewall blocking without creating real rules
  --timeout <s>       ARP scan timeout (live-host mode)
  --max-hosts <n>     Maximum hosts to report (live-host mode)
  --intel-source <p>  STIX2 JSON bundle path, or 'sample' for bundled sample
  --intel-auto-block  Add discovered IP IOCs to the local blocklist
  --alert-on <n>      Trigger alert action when risk score >= threshold
  --alert-file <f>    Append threshold alerts to this file
  --alert-exit        Exit with code 2 when threshold is crossed
```

Filter expression grammar (case-insensitive, `and`-joined):
```
src host <ip> | dst host <ip>
src port <n> | dst port <n>
tcp | udp | icmp | icmp6 | ip | ipv6
```
Examples:
- `src host 10.0.0.1 and dst port 80`
- `tcp and dst host 192.168.1.10`

## Functional requirements
1. **Authentication**
   - First run with no `password_hash.txt` → set password flow.
   - Every run → login before any network operation.
   - SHA-256 only; no plaintext.

2. **Capture mode (`c`)**
   - Sniff `n` packets on `--i` if provided, otherwise default interface.
   - Apply `--f` filter; `all` means no filter.
   - `--a` prints per-packet analysis.
   - `--summary` prints risk summary.
   - `--s` with `--p`, `--t`, or `--html` saves output.
   - If `--s` is set but none of `--p/--t/--html` is given, print a helpful message.

3. **Live host mode (`lh`)**
   - ARP-broadcast to `/24` of `--ip`.
   - Print IP, MAC, vendor for each reply.
   - Require `--ip`.

4. **Blocklist mode (`block`)**
   - `--block`, `--unblock`, `--list-blocks`, `--clear-blocks`.
   - Blocked IPs persist in `blocked_ips.txt`.
   - Blocked IPs influence risk scoring during analysis.

5. **Firewall block enforcement (`block-activate` / `block-deactivate` / `block-status`)**
   - `block-activate` creates Windows Firewall rules (one per IP, inbound + outbound, action=block, profile=any) for every IP in the local blocklist.
   - `block-deactivate` removes those rules.
   - `block-status` reports active SecureNet block rules and cross-checks against the local blocklist.
   - Requires Administrator privileges.
   - `--dry-run` simulates without creating real rules.
   - Rule naming: `SecureNet_Block_In_<ip>` and `SecureNet_Block_Out_<ip>`.
   - Invalid IPs in the blocklist are skipped during enforcement.

6. **Threat intel (`intel`)**
   - Loads a STIX2 JSON bundle (or the bundled sample via `--intel-source sample`).
   - Extracts IPv4 and IPv6 indicators from `ipv4-addr:value` / `ipv6-addr:value` patterns.
   - Prints a terminal summary: bundle objects, indicator count, IPv4/IPv6 IOC counts, other indicator count.
   - `--intel-auto-block` adds valid IP IOCs to the local blocklist (invalid IPs are rejected).
   - Non-IP indicators (file hashes, URLs, etc.) are counted but not added to the blocklist.
   - Offline-first: no network fetch; supply your own bundle path via `--intel-source`.

7. **Analysis**

   Per packet, detect:
   - TCP SYN to sensitive ports (22, 23, 3389, 445, 5900, 8080) → service probing.
   - Payload keywords: `cmd.exe`, `powershell`, `wget`, `curl`, `bash -i`, `nc`, `rm -rf`, `passwd`, `select`, `drop table`, `<script>`, `base64`, `eval(`, `system(`.
   - Any traffic to sensitive ports → admin-port traffic note.
   - Source or destination IP in blocklist → blocked-hit note.

   Risk scoring:
   - +20 per suspicious finding.
   - +35 per blocked IP involved (src or dst).
   - Capped at 100.
   - Levels: LOW <25, MEDIUM 25-49, HIGH 50-79, CRITICAL 80+.

6. **Export**
   - PCAP: raw Scapy `wrpcap`.
   - TXT: human-readable report with summary, protocol counts, alerts, per-packet details.
   - HTML: styled executive report, escaped payloads, full packet table.

7. **Risk-threshold alerting (capture mode)**
   - `--alert-on <n>` triggers an action when `risk_score >= n`.
   - Without `--alert-file`, prints an `ALERT:` line to stdout.
   - With `--alert-file`, appends a structured line to that file.
   - `--alert-exit` causes exit code 2 when the threshold is crossed.
   - If no threshold is crossed, the CLI exits normally (0).

## Non-functional requirements
- No duplicate scans: each packet's analysis is computed once and reused for `--a`, `--summary`, TXT, and HTML.
- Interface names must be validated against Scapy's interface list before capture.
- All output paths must create missing parent directories safely.
- Graceful handling of permission errors and empty captures.
- Importable modules; no side effects on import.

## Acceptance criteria
- `python -c "import Main"` loads without error (modulo runtime auth).
- `python Main.py --help` prints the full option table including new modes and flags.
- All seven modes have working `--help`: `c`, `lh`, `block`, `block-activate`, `block-deactivate`, `block-status`, `intel`.
- `python Main.py block --list-blocks` works without capture privileges.
- Filter parser handles `src host`, `dst host`, `src port`, `dst port`, and protocol names.
- HTML export is invokable via `--html` and produces a valid `.html` file.
- Analysis is computed once per packet across all output paths.
- `block-activate --dry-run` reports what it would do without creating real rules.
- `intel --intel-source sample` extracts IOCs from the bundled sample and reports them.
- `intel --intel-auto-block` adds only valid IP IOCs; invalid IPs are rejected.
- Firewall block status reports active rules and cross-checks the local blocklist.
- Capture mode accepts `--alert-on`, `--alert-file`, and `--alert-exit` without error.

## Out of scope for now
- Full Wireshark-filter syntax parity.
- IPv6 live-host scanning beyond what ARP supports.
- Persistent configuration files beyond password and blocklist.
- Linux/macOS firewall enforcement (block engine is Windows-first via netsh/PowerShell).

## Legal reminder
See `README.md` Legal Disclaimer and `LICENSE`. This project is MIT-licensed but intended for authorized use only.
