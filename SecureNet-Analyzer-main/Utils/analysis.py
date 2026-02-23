from scapy.all import IP, TCP, UDP, ICMP, IPv6, Raw


def extract_packet_info(packet):
    packet_info = {}

    if IP in packet:
        packet_info['src_ip'] = packet[IP].src
        packet_info['dst_ip'] = packet[IP].dst
        packet_info['protocol'] = packet[IP].proto
    elif IPv6 in packet:
        packet_info['src_ip'] = packet[IPv6].src
        packet_info['dst_ip'] = packet[IPv6].dst
        packet_info['protocol'] = packet[IPv6].nh

    if TCP in packet:
        packet_info['protocol_name'] = 'TCP'
        packet_info['src_port'] = packet[TCP].sport
        packet_info['dst_port'] = packet[TCP].dport
    elif UDP in packet:
        packet_info['protocol_name'] = 'UDP'
        packet_info['src_port'] = packet[UDP].sport
        packet_info['dst_port'] = packet[UDP].dport
    elif ICMP in packet:
        packet_info['protocol_name'] = 'ICMP'

    return packet_info


def extract_payload_data(packet):
    if Raw in packet:
        return packet[Raw].load.decode(errors='ignore')
    return ""


def analyze_packet(packet):
    packet_info = extract_packet_info(packet)
    payload_data = extract_payload_data(packet)

    print("\nPacket Info:")
    print(f"Source IP: {packet_info.get('src_ip')}")
    print(f"Destination IP: {packet_info.get('dst_ip')}")
    print(f"Protocol: {packet_info.get('protocol_name')}")

    if 'src_port' in packet_info and 'dst_port' in packet_info:
        print(f"Source Port: {packet_info.get('src_port')}")
        print(f"Destination Port: {packet_info.get('dst_port')}")

    if payload_data:
        print(f"Payload Data: {payload_data[:100]}...")

    print("-" * 50)
