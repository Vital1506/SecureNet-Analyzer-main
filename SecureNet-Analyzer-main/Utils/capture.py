import sys

from scapy.all import conf, sniff
from Utils.filters import packet_filter


def list_interfaces():
    """Return a list of available network interface names."""
    try:
        return [iface.name for iface in conf.ifaces.values()]
    except Exception:
        return []


def packet_callback(packet, filter_criteria, captured_packets):
    if filter_criteria is None or packet_filter(packet, filter_criteria):
        captured_packets.append(packet)
        print(packet.summary())


def start_capture(packet_count=10, filter_criteria=None, interface=None):
    captured_packets = []

    if interface:
        print(f"Starting packet capture on interface '{interface}'...")
    else:
        print("Starting packet capture on default active interface...")

    try:
        sniff(
            iface=interface,
            prn=lambda pkt: packet_callback(pkt, filter_criteria, captured_packets),
            count=packet_count,
            store=0
        )

        print("Packet capture complete.")
        return captured_packets

    except PermissionError:
        print("Permission denied. Run as Administrator / with sudo.")
        sys.exit(1)
    except Exception as e:
        print("Capture error:", e)

    return captured_packets
