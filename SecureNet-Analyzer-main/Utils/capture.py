from scapy.all import sniff
from Utils.filters import packet_filter


def packet_callback(packet, filter_criteria, captured_packets):
    if filter_criteria is None or packet_filter(packet, filter_criteria):
        captured_packets.append(packet)
        print(packet.summary())


def start_capture(packet_count=10, filter_criteria=None):
    captured_packets = []

    print("Starting packet capture on default active interface...")

    try:
        sniff(
            prn=lambda pkt: packet_callback(pkt, filter_criteria, captured_packets),
            count=packet_count,
            store=0
        )

        print("Packet capture complete...")
        return captured_packets

    except PermissionError:
        print("Run VS Code as Administrator.")
    except Exception as e:
        print("Capture error:", e)

    return captured_packets
