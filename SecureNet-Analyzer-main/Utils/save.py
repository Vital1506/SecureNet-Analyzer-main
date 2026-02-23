from scapy.all import wrpcap


def save_to_txt(captured_packets, filename):
    with open(filename, 'w') as f:
        for packet in captured_packets:
            f.write(packet.summary() + '\n')

    print(f"Packets saved to {filename}")


def save_to_pcap(captured_packets, filename):
    wrpcap(filename, captured_packets)
    print(f"Packets saved to {filename}")
