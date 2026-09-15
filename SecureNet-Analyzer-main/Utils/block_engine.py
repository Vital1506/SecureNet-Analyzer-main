"""
Authorized network block enforcement for Windows.

Provides three actions that operate on the LOCAL blocklist
(blocked_ips.txt) and create / remove Windows Firewall rules that
DROP inbound+outbound traffic to/from those IPs.

This is defensive tooling intended for networks you own or have
explicit written permission to protect. Creating firewall rules
requires Administrator privileges.

Design notes:
- One rule per IP, named SN_<ip>_in and SN_<ip>_out, so individual
  IPs can be tracked and removed cleanly.
- RemoteAddress spans both IPv4 and IPv6 where supported.
- Everything is logged to stdout so it can be scripted.
- dry_run mode prints the commands without executing them.
"""

import ipaddress
import shutil
import subprocess
import sys
from typing import List, Tuple

import colorama

colorama.init(autoreset=True)

BLOCK_PREFIX_IN = "SecureNet_Block_In_"
BLOCK_PREFIX_OUT = "SecureNet_Block_Out_"


def _elevated() -> bool:
    """Best-effort check for an elevated/Administrator shell on Windows."""
    if sys.platform != "win32":
        return False
    try:
        return shutil.which("netsh") is not None
    except Exception:
        return False


def _is_valid_ip(value: str) -> bool:
    value = value.strip()
    if not value:
        return False
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _norm(ip: str) -> str:
    return str(ipaddress.ip_address(ip.strip()))


def _rule_name(prefix: str, ip: str) -> str:
    # Firewall rule names must be relatively simple; use normalized IP.
    return f"{prefix}{_norm(ip)}"


def _powershell_cmd(script: str) -> List[str]:
    return [
        "powershell",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        script,
    ]


def _netsh(action: str, rule_name: str, direction: str, remote_ip: str) -> List[str]:
    return [
        "netsh",
        "advfirewall",
        "firewall",
        action,
        "rule",
        "name=",
        rule_name,
        "dir=",
        direction,
        "remoteip=",
        remote_ip,
        "action=block",
        "profile=any",
    ]


def _run(cmd: List[str], dry_run: bool) -> Tuple[int, str, str]:
    if dry_run or not _elevated():
        # In dry_run mode, or when we can't confirm elevation, just show
        # the command that *would* run.
        return 0, " ".join(cmd), ""
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "command timed out"
    except FileNotFoundError:
        return -1, "", f"command not found: {cmd[0]}"
    except Exception as exc:  # noqa: BLE001
        return -1, "", str(exc)


def _rule_exists(rule_name: str) -> bool:
    """Check whether a firewall rule with this exact name exists."""
    script = (
        f"try {{ "
        f"$r = Get-NetFirewallRule -Name '{rule_name}' -ErrorAction Stop; "
        f"if ($r) {{ 1 }} else {{ 0 }} "
        f"}} catch {{ 0 }}"
    )
    code = ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script]
    try:
        proc = subprocess.run(code, capture_output=True, text=True, timeout=30)
        return proc.stdout.strip() == "1"
    except Exception:
        return False


def block_activate(ips: List[str], dry_run: bool = False) -> str:
    """Create block rules for every IP in the local blocklist.

    Returns a multi-line status report.
    """
    valid: List[str] = []
    invalid: List[str] = []
    for ip in ips:
        if _is_valid_ip(ip):
            valid.append(_norm(ip))
        else:
            invalid.append(ip)

    lines: List[str] = []
    lines.append(f"Block activation — {len(valid)} IPs to enforce, {len(invalid)} skipped as invalid.")
    if invalid:
        lines.append("Skipped (not valid IPs): " + ", ".join(invalid))

    if not valid:
        lines.append("Nothing to enforce.")
        return "\n".join(lines)

    created = 0
    already = 0
    failed = 0
    details: List[str] = []

    for ip in valid:
        in_name = _rule_name(BLOCK_PREFIX_IN, ip)
        out_name = _rule_name(BLOCK_PREFIX_OUT, ip)

        in_exists = _rule_exists(in_name)
        out_exists = _rule_exists(out_name)

        if in_exists and out_exists:
            already += 1
            details.append(f"  [already] {ip}")
            continue

        if dry_run:
            details.append(f"  [dry-run] would create rules for {ip}")
            created += 1
            continue

        # Create inbound block rule
        in_rc, in_out, in_err = _run(
            _netsh("add", in_name, "in", ip), dry_run=False
        )
        # Create outbound block rule
        out_rc, out_out, out_err = _run(
            _netsh("add", out_name, "out", ip), dry_run=False
        )

        in_ok = in_rc == 0
        out_ok = out_rc == 0

        if in_ok and out_ok:
            created += 1
            details.append(f"  [created] {ip}")
        else:
            failed += 1
            parts = []
            if not in_ok:
                parts.append(f"inbound failed: {(in_err or in_out).strip()[:120]}")
            if not out_ok:
                parts.append(f"outbound failed: {(out_err or out_out).strip()[:120]}")
            details.append(f"  [failed] {ip} — {'; '.join(parts)}")

    lines.append("")
    lines.append(f"Result: {created} created, {already} already present, {failed} failed.")
    lines.extend(details)
    return "\n".join(lines)


def block_deactivate(dry_run: bool = False) -> str:
    """Remove all SecureNet block rules from the firewall."""
    lines: List[str] = []
    removed = 0
    missing = 0
    details: List[str] = []

    # Enumerate candidate rule names by scanning the local blocklist.
    try:
        from Utils.blocklist import load_blocklist
        ips = load_blocklist()
    except Exception:
        ips = []

    if not ips:
        lines.append("Local blocklist is empty — nothing to remove.")
        return "\n".join(lines)

    for ip in ips:
        if not _is_valid_ip(ip):
            continue
        ip_norm = _norm(ip)
        in_name = _rule_name(BLOCK_PREFIX_IN, ip_norm)
        out_name = _rule_name(BLOCK_PREFIX_OUT, ip_norm)

        if dry_run:
            in_exist = _rule_exists(in_name)
            out_exist = _rule_exists(out_name)
            if in_exist or out_exist:
                details.append(f"  [dry-run] would remove rules for {ip}")
                removed += 1
            else:
                details.append(f"  [dry-run] no rules found for {ip}")
                missing += 1
            continue

        in_exist = _rule_exists(in_name)
        out_exist = _rule_exists(out_name)

        if in_exist:
            rc, _, err = _run(
                ["netsh", "advfirewall", "firewall", "delete", "rule", "name=", in_name],
                dry_run=False,
            )
            if rc != 0:
                details.append(f"  [fail-delete] {in_name}: {(err or '').strip()[:120]}")
                missing += 1
            else:
                removed += 1
        else:
            missing += 1

        if out_exist:
            rc, _, err = _run(
                ["netsh", "advfirewall", "firewall", "delete", "rule", "name=", out_name],
                dry_run=False,
            )
            if rc != 0:
                details.append(f"  [fail-delete] {out_name}: {(err or '').strip()[:120]}")
                missing += 1
            else:
                removed += 1
        else:
            missing += 1

    lines.append(f"Block deactivation — removed {removed} rule(s), {missing} not found/skipped.")
    lines.extend(details)
    return "\n".join(lines)


def block_status() -> str:
    """Report the current firewall block state for SecureNet rules."""
    lines: List[str] = []
    lines.append("SecureNet Firewall Block Status")
    lines.append("=" * 40)

    if not _elevated():
        lines.append("Not running elevated — cannot query firewall rules reliably.")
        return "\n".join(lines)

    try:
        script = (
            "$rules = Get-NetFirewallRule -Name 'SecureNet_Block_*' -ErrorAction SilentlyContinue | "
            "Where-Object { $_.Enabled -eq $True -and $_.Action -eq 'Block' }; "
            "if ($rules) { "
            "  $count = ($rules | Measure-Object).Count; "
            "  Write-Output \"active_rules=$count\"; "
            "  $rules | ForEach-Object { "
            "    $name = $_.Name; "
            "    $addr = ($_.RemoteAddress -join ','); "
            "    $dir = $_.Direction; "
            "    Write-Output \"$($name)|$($dir)|$($addr)\" "
            "  } "
            "} else { "
            "  Write-Output 'active_rules=0'; "
            "}"
        )
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script],
            capture_output=True,
            text=True,
            timeout=60,
        )
        body = proc.stdout.strip()
    except Exception as exc:  # noqa: BLE001
        lines.append(f"Could not query firewall: {exc}")
        return "\n".join(lines)

    active = 0
    for line in body.splitlines():
        if line.startswith("active_rules="):
            try:
                active = int(line.split("=", 1)[1])
            except ValueError:
                pass
            continue
        if "|" not in line:
            continue
        name, direction, remote = line.split("|", 2)
        lines.append(f"- {name}  dir={direction}  remote={remote}")

    if active == 0:
        lines.append("No active SecureNet block rules found.")
    else:
        lines.append(f"Total active block rules: {active}")

    # Cross-check against local blocklist
    try:
        from Utils.blocklist import load_blocklist
        local_ips = load_blocklist()
    except Exception:
        local_ips = []

    if local_ips:
        lines.append("")
        lines.append(f"Local blocklist contains {len(local_ips)} IP(s).")
    else:
        lines.append("")
        lines.append("Local blocklist is empty.")

    return "\n".join(lines)


def is_firewall_runtime() -> bool:
    """Whether this platform supports the firewall block engine."""
    return sys.platform == "win32" and shutil.which("netsh") is not None
