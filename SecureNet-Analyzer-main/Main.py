import argparse
import os
import sys
import time
from getpass import getpass

from scapy.error import Scapy_Exception
from scapy.utils import PcapReader

from Utils.blocklist import (
    add_ip_to_blocklist,
    clear_blocklist,
    load_blocklist,
    remove_ip_from_blocklist,
    BLOCKLIST_FILE,
)
from Utils.capture import list_interfaces, start_capture
from Utils.filters import parse_filter_string
from Utils.analysis import analyze_packet, get_security_summary, build_packet_analysis
from Utils.save import save_to_txt, save_to_pcap, save_to_html
from Utils.HostDetector import detect_live_hosts
from Utils.block_engine import (
    block_activate,
    block_deactivate,
    block_status,
    is_firewall_runtime,
)
from Utils.intel import run_intel
from Utils.incident_report import generate_incident_report
from Utils.audit import verify_audit_log
from Utils.security import (
    PASSWORD_FILE,
    hash_password,
    load_password_record,
    save_password_record,
    verify_password as verify_password_record,
)

MAX_PCAP_MB_DEFAULT = 512
MAX_PCAP_PACKETS_DEFAULT = 500_000
MAX_LOGIN_ATTEMPTS = 5


def verify_password(input_password):
    """Verify the configured password and transparently upgrade legacy SHA-256."""
    record = load_password_record()
    if record is None:
        return False
    valid, legacy = verify_password_record(input_password, record)
    if valid and legacy:
        save_password_record(hash_password(input_password))
    return valid


def set_password():
    password = getpass("Set a new password: ")
    if len(password) < 12:
        print("Password must be at least 12 characters long.")
        sys.exit(1)
    confirm_password = getpass("Confirm password: ")

    if password != confirm_password:
        print("Passwords do not match.")
        sys.exit(1)

    save_password_record(hash_password(password))
    print("Password set successfully.")


def login():
    if not os.path.exists(PASSWORD_FILE):
        print("No password set. Please set a new password.")
        set_password()

    for attempt in range(1, MAX_LOGIN_ATTEMPTS + 1):
        password = getpass("Enter password: ")
        if verify_password(password):
            print("Login successful.")
            return
        print("Incorrect password.")
        if attempt < MAX_LOGIN_ATTEMPTS:
            time.sleep(attempt)

    print("Too many failed login attempts. Exiting.")
    sys.exit(1)


def _requires_auth(args):
    """Return whether this action must authenticate even when --offline is set."""
    if args.option in {"c", "lh", "block-activate", "block-deactivate"}:
        return True
    if args.option == "block":
        return bool(args.block or args.unblock or args.clear_blocks)
    if args.option == "intel":
        return bool(args.intel_auto_block)
    return False


def _read_pcap_bounded(path, max_mb, max_packets):
    """Read a PCAP with explicit file and packet resource limits."""
    if max_mb <= 0 or max_packets <= 0:
        raise ValueError("PCAP resource limits must be positive.")
    file_size = os.path.getsize(path)
    max_bytes = max_mb * 1024 * 1024
    if file_size > max_bytes:
        raise ValueError(
            f"PCAP is {file_size / (1024 * 1024):.1f} MiB; maximum is {max_mb} MiB."
        )

    packets = []
    truncated = False
    reader = PcapReader(path)
    try:
        for packet in reader:
            if len(packets) >= max_packets:
                truncated = True
                break
            packets.append(packet)
    finally:
        reader.close()
    return packets, truncated, file_size


def _security_summary_table(summary):
    lines = [
        "",
        "Security Summary:",
        f"  Risk Level:          {summary['risk_level']}",
        f"  Risk Score:          {summary['risk_score']}/100",
        f"  Suspicious Events:   {summary['suspicious_events']}",
        f"  Blocked IP Hits:     {summary['blocked_hits']}",
        f"  Most Active Source:  {summary['most_active_source']}",
        f"  Most Active Dest:    {summary['most_active_destination']}",
        f"  Most Common Port:    {summary['most_common_port']}",
        f"  Behavioral Detections:{summary.get('behavioral_detections', 0)}",
    ]
    return "\n".join(lines)


def _handle_threshold_alert(summary, args):
    """Emit a risk-threshold alert and return whether the threshold was crossed."""
    if args.alert_on is None or summary["risk_score"] < args.alert_on:
        return False

    alert_msg = (
        f"\nALERT: Risk score {summary['risk_score']}/100 "
        f"meets/exceeds threshold {args.alert_on}."
    )
    print(alert_msg)

    if args.alert_file:
        with open(args.alert_file, "a", encoding="utf-8") as handle:
            handle.write(
                f"{summary['risk_level']} | score={summary['risk_score']} | "
                f"events={summary['suspicious_events']} | blocked={summary['blocked_hits']} | "
                f"sources={summary['most_active_source']} | "
                f"dests={summary['most_active_destination']} | "
                f"port={summary['most_common_port']}\n"
            )
        print(f"Alert logged to {args.alert_file}")

    if args.alert_exit:
        sys.exit(2)

    return True


def start_application(args):
    # ---- Blocklist management (local list) ----
    if args.option == "block":
        if args.block:
            for ip in args.block:
                if add_ip_to_blocklist(ip):
                    print(f"Added {ip} to local blocklist.")
                else:
                    print(f"{ip} is already in the local blocklist.")

        if args.unblock:
            for ip in args.unblock:
                if remove_ip_from_blocklist(ip):
                    print(f"Removed {ip} from local blocklist.")
                else:
                    print(f"{ip} was not in the local blocklist.")

        if args.list_blocks:
            blocked = load_blocklist()
            print("Local blocklist:")
            if blocked:
                for ip in blocked:
                    print(f"- {ip}")
            else:
                print("- empty")
            return

        if args.clear_blocks:
            clear_blocklist()
            print("Local blocklist cleared.")
            return

        if not args.block and not args.unblock and not args.list_blocks and not args.clear_blocks:
            print("Use --block, --unblock, --list-blocks, or --clear-blocks with the block command.")
        return

    # ---- Real firewall block control ----
    if args.option == "block-activate":
        blocked = load_blocklist()
        if not blocked:
            print("Local blocklist is empty. Add IPs first with: Main.py block --block <ip>")
            sys.exit(1)
        if not args.dry_run and not args.confirm_firewall:
            print("Refusing firewall change without --confirm-firewall.")
            sys.exit(1)
        state = block_activate(blocked, dry_run=args.dry_run)
        print(state)
        return

    if args.option == "block-deactivate":
        if not args.dry_run and not args.confirm_firewall:
            print("Refusing firewall change without --confirm-firewall.")
            sys.exit(1)
        state = block_deactivate(dry_run=args.dry_run)
        print(state)
        return

    if args.option == "block-status":
        print(block_status())
        return

    # ---- Audit verification ----
    if args.option == "audit-verify":
        valid, count, detail = verify_audit_log()
        if valid:
            print(f"Audit log valid: {count} event(s) verified.")
        else:
            print(f"Audit log verification FAILED: {detail}")
            sys.exit(1)
        return

    # ---- Live host detection ----
    if args.option == "lh":
        if args.ip:
            detect_live_hosts(args.ip, timeout=args.timeout, max_hosts=args.max_hosts)
        else:
            print("Provide IP using --ip")
            sys.exit(1)

    # ---- Offline PCAP investigation ----
    if args.option == "pcap":
        if not args.input:
            print("Provide --input <pcap> for PCAP investigation.")
            sys.exit(1)

        try:
            packets, truncated, file_size = _read_pcap_bounded(
                args.input, args.max_pcap_mb, args.max_pcap_packets
            )
        except (OSError, ValueError, EOFError, Scapy_Exception) as exc:
            print(f"Unable to read PCAP: {exc}")
            sys.exit(1)

        if truncated:
            print(
                f"PCAP analysis capped at {args.max_pcap_packets} packets; "
                "remaining packets were not analyzed."
            )
        print(f"Loaded PCAP: {file_size / (1024 * 1024):.2f} MiB")

        if not packets:
            print("PCAP contains no packets.")
            return

        if args.summary or args.alert_on is not None:
            summary = get_security_summary(packets)
            print(_security_summary_table(summary))
            _handle_threshold_alert(summary, args)

        if args.a:
            print(f"\nAnalyzing {len(packets)} packets...")
            for packet in packets:
                analyze_packet(packet)

        if args.s:
            if args.p:
                save_to_pcap(packets, args.p)
            elif args.t:
                save_to_txt(packets, args.t)
            elif args.html:
                save_to_html(packets, args.html)
            else:
                print("Use --p, --t, or --html to save the analyzed PCAP.")

        if args.report_prefix:
            report_paths = generate_incident_report(
                packets,
                args.report_prefix,
                case_id=args.case_id,
                analyst=args.analyst,
                organization=args.organization,
                interface=f"PCAP: {os.path.abspath(args.input)}",
                evidence_files=[args.input],
                resolve_hostnames=args.resolve_hostnames,
            )
            print("\nIncident report generated:")
            print(f"  HTML: {report_paths['html']}")
            print(f"  TXT:  {report_paths['txt']}")
            print(f"  JSON: {report_paths['json']}")
        return

    # ---- External threat intel ----
    if args.option == "intel":
        run_intel(args)
        return

    # ---- Capture mode ----
    if args.option == "c":
        if args.i:
            if args.i not in list_interfaces():
                print(f"Interface '{args.i}' not found. Available: {', '.join(list_interfaces())}")
                sys.exit(1)

        filter_criteria = parse_filter_string(args.f)
        captured_packets = start_capture(args.pc, filter_criteria, args.i)

        if not captured_packets:
            print("No packets captured.")
            return

        if args.summary or args.alert_on is not None:
            summary = get_security_summary(captured_packets)
            print(_security_summary_table(summary))
            _handle_threshold_alert(summary, args)

        if args.a:
            print(f"\nAnalyzing {len(captured_packets)} packets...")
            for packet in captured_packets:
                analyze_packet(packet)

        if args.s:
            if args.p:
                save_to_pcap(captured_packets, args.p)
            elif args.t:
                save_to_txt(captured_packets, args.t)
            elif args.html:
                save_to_html(captured_packets, args.html)
            else:
                print("Use --p, --t, or --html to save captured packets.")

        if args.report_prefix:
            evidence_files = []
            if args.p:
                evidence_files.append(args.p)
            elif args.t:
                evidence_files.append(args.t)
            elif args.html:
                evidence_files.append(args.html)

            report_paths = generate_incident_report(
                captured_packets,
                args.report_prefix,
                case_id=args.case_id,
                analyst=args.analyst,
                organization=args.organization,
                interface=args.i or "Default interface",
                evidence_files=evidence_files,
                resolve_hostnames=args.resolve_hostnames,
            )
            print("\nIncident report generated:")
            print(f"  HTML: {report_paths['html']}")
            print(f"  TXT:  {report_paths['txt']}")
            print(f"  JSON: {report_paths['json']}")


def main():
    parser = argparse.ArgumentParser(
        description="SecureNet Analyzer - network traffic monitoring, live-host detection, packet analysis, and authorized blocking toolkit"
    )

    parser.add_argument(
        "option",
        choices=["c", "pcap", "lh", "block", "block-activate", "block-deactivate", "block-status", "audit-verify", "intel"],
        help=(
            "c: live capture | pcap: offline PCAP investigation | lh: live-host detection | block: local blocklist management | "
            "block-activate: enforce blocked IPs via firewall | block-deactivate: remove firewall rules | "
            "block-status: show firewall block state | intel: fetch/load threat intel and add IOCs"
        ),
    )
    parser.add_argument("--f", default="all", help="Filter expression (e.g. 'src host 10.0.0.1 and dst port 80')")
    parser.add_argument("--pc", type=int, help="Number of packets to capture")
    parser.add_argument("--input", type=str, help="Input PCAP file for offline investigation mode")
    parser.add_argument("--a", action="store_true", help="Analyze captured packets in real time")
    parser.add_argument("--s", action="store_true", help="Save captured packets")
    parser.add_argument("--t", type=str, help="Save captured packets in TXT format")
    parser.add_argument("--p", type=str, help="Save captured packets in PCAP format")
    parser.add_argument("--html", type=str, help="Save captured packets in HTML report format")
    parser.add_argument("--summary", action="store_true", help="Print a concise security summary for captured packets")
    parser.add_argument("--i", type=str, help="Network interface to capture from (e.g. eth0, Wi-Fi)")
    parser.add_argument("--ip", type=str, help="Target IP address for live host detection")
    parser.add_argument("--block", action="append", default=[], help="Add an IP address to the local blocklist")
    parser.add_argument("--unblock", action="append", default=[], help="Remove an IP address from the local blocklist")
    parser.add_argument("--list-blocks", action="store_true", help="Show all blocked IPs in the local blocklist")
    parser.add_argument("--clear-blocks", action="store_true", help="Clear the local blocklist")
    parser.add_argument("--offline", action="store_true", help="Skip login only for read-only/offline-safe workflows.")
    parser.add_argument("--confirm-firewall", action="store_true", help="Explicitly confirm a real Windows Firewall change.")
    parser.add_argument("--dry-run", action="store_true", help="Simulate firewall blocking without creating real rules")
    parser.add_argument("--timeout", type=int, default=5, help="ARP scan timeout in seconds (live-host mode)")
    parser.add_argument("--max-hosts", type=int, default=254, help="Maximum hosts to report (live-host mode)")
    parser.add_argument("--intel-source", type=str, help="Path to a STIX2 JSON intel file, or 'sample' for bundled sample")
    parser.add_argument("--intel-auto-block", action="store_true", help="Add discovered IOCs to the local blocklist")
    parser.add_argument("--alert-on", type=int, help="Exit / log when risk score reaches this threshold")
    parser.add_argument("--alert-file", type=str, help="Append threshold alerts to this file")
    parser.add_argument("--alert-exit", action="store_true", help="Exit with code 2 when threshold is crossed")
    parser.add_argument("--report-prefix", type=str, help="Generate incident HTML/TXT/JSON reports using this output prefix")
    parser.add_argument("--case-id", default="UNASSIGNED", help="Case or incident identifier for reporting")
    parser.add_argument("--analyst", default="Not specified", help="Analyst name for the report")
    parser.add_argument("--organization", default="Not specified", help="Organization/team name for the report")
    parser.add_argument("--resolve-hostnames", action="store_true", help="Opt in to reverse-DNS lookups while generating reports")
    parser.add_argument("--max-pcap-mb", type=int, default=MAX_PCAP_MB_DEFAULT, help="Maximum offline PCAP file size in MiB")
    parser.add_argument("--max-pcap-packets", type=int, default=MAX_PCAP_PACKETS_DEFAULT, help="Maximum offline PCAP packets to analyze")

    args = parser.parse_args()

    if args.option == "c" and args.pc is None:
        parser.error("c mode requires --pc <packet count>")

    if args.max_pcap_mb <= 0 or args.max_pcap_packets <= 0:
        parser.error("--max-pcap-mb and --max-pcap-packets must be positive")
    if args.option == "c" and (args.pc is None or args.pc <= 0):
        parser.error("--pc must be a positive integer")
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    if args.max_hosts <= 0:
        parser.error("--max-hosts must be positive")
    if args.alert_on is not None and not 0 <= args.alert_on <= 100:
        parser.error("--alert-on must be between 0 and 100")
    if args.alert_file and args.alert_on is None:
        parser.error("--alert-file requires --alert-on")
    if args.alert_exit and args.alert_on is None:
        parser.error("--alert-exit requires --alert-on")

    if args.option == "pcap" and not args.input:
        print("Provide --input <pcap> for PCAP investigation.")
        sys.exit(1)

    if _requires_auth(args):
        if args.offline:
            print("Authentication required for this operation; --offline cannot bypass it.")
            sys.exit(1)
        login()
    start_application(args)


if __name__ == "__main__":
    main()
