import argparse
import hashlib
import os
import sys
from getpass import getpass

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

PASSWORD_FILE = "password_hash.txt"


def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


def verify_password(input_password):
    if os.path.exists(PASSWORD_FILE):
        with open(PASSWORD_FILE, 'r') as f:
            stored_hash = f.read().strip()
            return stored_hash == hash_password(input_password)
    return False


def set_password():
    password = getpass("Set a new password: ")
    confirm_password = getpass("Confirm password: ")

    if password != confirm_password:
        print("Passwords do not match.")
        sys.exit(1)

    with open(PASSWORD_FILE, 'w') as f:
        f.write(hash_password(password))

    print("Password set successfully.")


def login():
    if not os.path.exists(PASSWORD_FILE):
        print("No password set. Please set a new password.")
        set_password()

    while True:
        password = getpass("Enter password: ")
        if verify_password(password):
            print("Login successful.")
            break
        else:
            print("Incorrect password. Try again.")


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
    ]
    return "\n".join(lines)


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
        state = block_activate(blocked, dry_run=args.dry_run)
        print(state)
        return

    if args.option == "block-deactivate":
        state = block_deactivate(dry_run=args.dry_run)
        print(state)
        return

    if args.option == "block-status":
        print(block_status())
        return

    # ---- Live host detection ----
    if args.option == "lh":
        if args.ip:
            detect_live_hosts(args.ip, timeout=args.timeout, max_hosts=args.max_hosts)
        else:
            print("Provide IP using --ip")
            sys.exit(1)

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

        if args.alert_on is not None and summary["risk_score"] >= args.alert_on:
            alert_msg = (
                f"\nALERT: Risk score {summary['risk_score']}/100 meets/exceeds threshold {args.alert_on}."
            )
            print(alert_msg)
            if args.alert_file:
                with open(args.alert_file, "a", encoding="utf-8") as f:
                    f.write(f"{summary['risk_level']} | score={summary['risk_score']} | "
                            f"events={summary['suspicious_events']} | blocked={summary['blocked_hits']} | "
                            f"sources={summary['most_active_source']} | dests={summary['most_active_destination']} | "
                            f"port={summary['most_common_port']}\n")
                print(f"Alert logged to {args.alert_file}")
            if args.alert_exit:
                sys.exit(2)

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


def main():
    parser = argparse.ArgumentParser(
        description="SecureNet Analyzer - network traffic monitoring, live-host detection, packet analysis, and authorized blocking toolkit"
    )

    parser.add_argument(
        "option",
        choices=["c", "lh", "block", "block-activate", "block-deactivate", "block-status", "intel"],
        help=(
            "c: capture | lh: live-host detection | block: local blocklist management | "
            "block-activate: enforce blocked IPs via firewall | block-deactivate: remove firewall rules | "
            "block-status: show firewall block state | intel: fetch/load threat intel and add IOCs"
        ),
    )
    parser.add_argument("--f", default="all", help="Filter expression (e.g. 'src host 10.0.0.1 and dst port 80')")
    parser.add_argument("--pc", type=int, help="Number of packets to capture")
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
    parser.add_argument("--offline", action="store_true", help="Skip login prompt. For automation / non-interactive use.")
    parser.add_argument("--dry-run", action="store_true", help="Simulate firewall blocking without creating real rules")
    parser.add_argument("--timeout", type=int, default=5, help="ARP scan timeout in seconds (live-host mode)")
    parser.add_argument("--max-hosts", type=int, default=254, help="Maximum hosts to report (live-host mode)")
    parser.add_argument("--intel-source", type=str, help="Path to a STIX2 JSON intel file, or 'sample' for bundled sample")
    parser.add_argument("--intel-auto-block", action="store_true", help="Add discovered IOCs to the local blocklist")
    parser.add_argument("--alert-on", type=int, help="Exit / log when risk score reaches this threshold")
    parser.add_argument("--alert-file", type=str, help="Append threshold alerts to this file")
    parser.add_argument("--alert-exit", action="store_true", help="Exit with code 2 when threshold is crossed")

    args = parser.parse_args()

    if args.option == "c" and not args.pc and not args.block and not args.unblock and not args.list_blocks and not args.clear_blocks:
        print("Provide --pc (packet count)")
        sys.exit(1)

    if not args.offline:
        login()
    start_application(args)


if __name__ == "__main__":
    main()
