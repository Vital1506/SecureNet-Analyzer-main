import argparse
import hashlib
import os
import sys
from getpass import getpass
from Utils.capture import start_capture
from Utils.filters import parse_filter_string
from Utils.analysis import analyze_packet
from Utils.save import save_to_txt, save_to_pcap
from Utils.HostDetector import detect_live_hosts

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


def start_application(args):
    if args.option == "c":
        filter_criteria = parse_filter_string(args.f)
        captured_packets = start_capture(args.pc, filter_criteria)

        if not captured_packets:
            print("No packets captured.")
            return

        if args.a:
            print(f"\nAnalyzing {args.pc} packets...")
            for packet in captured_packets:
                analyze_packet(packet)

        if args.s:
            if args.p:
                save_to_pcap(captured_packets, args.p)
            elif args.t:
                save_to_txt(captured_packets, args.t)

    elif args.option == "lh":
        if args.ip:
            detect_live_hosts(args.ip)
        else:
            print("Provide IP using --ip")
            sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description="Network Sniffer Application")

    parser.add_argument("option", choices=["c", "lh"])
    parser.add_argument("--f", default="all")
    parser.add_argument("--pc", type=int)
    parser.add_argument("--a", action="store_true")
    parser.add_argument("--s", action="store_true")
    parser.add_argument("--t", type=str)
    parser.add_argument("--p", type=str)
    parser.add_argument("--ip", type=str)

    args = parser.parse_args()

    if args.option == "c" and not args.pc:
        print("Provide --pc (packet count)")
        sys.exit(1)

    login()
    start_application(args)


if __name__ == "__main__":
    main()
