from collections import Counter
from datetime import datetime

from scapy.all import IP, TCP, UDP, ICMP, IPv6, Raw

from Utils.blocklist import is_blocked_ip
from Utils.detection_engine import run_detections

MAX_ANALYSIS_PAYLOAD_BYTES = 64 * 1024


def calculate_risk_score(captured_packets):
    packet_score = 0
    for packet in captured_packets:
        payload_data = extract_payload_data(packet)
        findings = detect_suspicious_activity(packet, payload_data)
        packet_score += len(findings) * 20

        packet_info = extract_packet_info(packet)
        src_ip = packet_info.get('src_ip')
        dst_ip = packet_info.get('dst_ip')
        if src_ip and is_blocked_ip(src_ip):
            packet_score += 35
        if dst_ip and is_blocked_ip(dst_ip):
            packet_score += 35

    score = min(packet_score, 70)
    severity_weights = {'LOW': 8, 'MEDIUM': 16, 'HIGH': 28, 'CRITICAL': 40}
    for detection in run_detections(captured_packets):
        weight = severity_weights.get(detection['severity'], 10)
        score += weight + round(12 * detection['confidence'])

    return min(score, 100)


def get_security_summary(captured_packets):
    packet_info_list = [extract_packet_info(packet) for packet in captured_packets]
    source_ips = Counter(info.get('src_ip') for info in packet_info_list if info.get('src_ip'))
    dest_ips = Counter(info.get('dst_ip') for info in packet_info_list if info.get('dst_ip'))
    suspicious_events = 0
    blocked_hits = 0
    top_ports = Counter()

    for packet in captured_packets:
        payload_data = extract_payload_data(packet)
        findings = detect_suspicious_activity(packet, payload_data)
        suspicious_events += len(findings)

        packet_info = extract_packet_info(packet)
        src_ip = packet_info.get('src_ip')
        dst_ip = packet_info.get('dst_ip')
        if src_ip and is_blocked_ip(src_ip):
            blocked_hits += 1
        if dst_ip and is_blocked_ip(dst_ip):
            blocked_hits += 1

        if 'src_port' in packet_info:
            top_ports[packet_info.get('src_port')] += 1
        if 'dst_port' in packet_info:
            top_ports[packet_info.get('dst_port')] += 1

    detections = run_detections(captured_packets)
    risk_score = calculate_risk_score(captured_packets)
    highest_confidence = max((item['confidence'] for item in detections), default=0.0)
    if risk_score >= 80:
        risk_level = 'CRITICAL'
    elif risk_score >= 50:
        risk_level = 'HIGH'
    elif risk_score >= 25:
        risk_level = 'MEDIUM'
    else:
        risk_level = 'LOW'

    return {
        'total_packets': len(captured_packets),
        'risk_score': risk_score,
        'risk_level': risk_level,
        'suspicious_events': suspicious_events,
        'blocked_hits': blocked_hits,
        'most_active_source': source_ips.most_common(1)[0][0] if source_ips else 'N/A',
        'most_active_destination': dest_ips.most_common(1)[0][0] if dest_ips else 'N/A',
        'most_common_port': top_ports.most_common(1)[0][0] if top_ports else 'N/A',
        'behavioral_detections': len(detections),
        'detection_rules': sorted({item['rule_id'] for item in detections}),
        'highest_detection_confidence': highest_confidence,
    }


def _is_syn(packet_info):
    """Return True when the TCP flags indicate a SYN packet."""
    flags = packet_info.get('tcp_flags')
    if flags is None:
        return False
    try:
        flag_int = int(flags)
    except (TypeError, ValueError):
        return False
    return bool(flag_int & 0x02)


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
        packet_info['tcp_flags'] = packet[TCP].flags
    elif UDP in packet:
        packet_info['protocol_name'] = 'UDP'
        packet_info['src_port'] = packet[UDP].sport
        packet_info['dst_port'] = packet[UDP].dport
    elif ICMP in packet:
        packet_info['protocol_name'] = 'ICMP'
    elif IPv6 in packet and packet[IPv6].nh == 58:
        packet_info['protocol_name'] = 'ICMPv6'

    return packet_info


def extract_payload_data(packet):
    """Decode at most a bounded amount of application payload for analysis."""
    if Raw not in packet:
        return ""
    payload = packet[Raw].load
    if not isinstance(payload, bytes):
        payload = bytes(payload)
    truncated = len(payload) > MAX_ANALYSIS_PAYLOAD_BYTES
    payload = payload[:MAX_ANALYSIS_PAYLOAD_BYTES]
    decoded = payload.decode(errors="ignore")
    return f"{decoded}\n[PAYLOAD TRUNCATED]" if truncated else decoded


def get_packet_timestamp(packet):
    try:
        return datetime.fromtimestamp(float(packet.time)).strftime('%Y-%m-%d %H:%M:%S UTC')
    except (TypeError, ValueError):
        return 'N/A'


def detect_suspicious_activity(packet, payload_data):
    findings = []
    packet_info = extract_packet_info(packet)

    if packet_info.get('protocol_name') == 'TCP' and _is_syn(packet_info) and packet_info.get('dst_port') in {22, 23, 3389, 445, 5900, 8080}:
        findings.append('Possible service probing detected on an administrative or sensitive port.')

    if payload_data:
        suspicious_keywords = [
            'cmd.exe', 'powershell', 'wget ', 'curl ', 'bash -i', 'nc ',
            'rm -rf', 'passwd', 'select ', 'drop table', '<script>',
            'base64', 'eval(', 'system('
        ]
        lowered = payload_data.lower()
        for keyword in suspicious_keywords:
            if keyword.lower() in lowered:
                findings.append(f"Suspicious payload pattern detected: {keyword}")
                break

    if packet_info.get('dst_port') in {22, 23, 3389, 445, 5900, 8080}:
        findings.append('Traffic targeted common administrative or service ports.')

    return findings


def analyze_packet(packet):
    result = build_packet_analysis(packet)
    print_packet_analysis(result)


def build_packet_analysis(packet):
    """Analyze a packet once and return a reusable result dict."""
    packet_info = extract_packet_info(packet)
    payload_data = extract_payload_data(packet)
    findings = detect_suspicious_activity(packet, payload_data)

    source_ip = packet_info.get('src_ip')
    destination_ip = packet_info.get('dst_ip')
    blocked_ips = []

    for ip in [source_ip, destination_ip]:
        if ip and is_blocked_ip(ip):
            blocked_ips.append(ip)

    return {
        'packet': packet,
        'packet_info': packet_info,
        'payload_data': payload_data,
        'findings': findings,
        'blocked_ips': blocked_ips,
        'timestamp': get_packet_timestamp(packet),
    }


def print_packet_analysis(result):
    packet_info = result['packet_info']
    source_ip = packet_info.get('src_ip')
    destination_ip = packet_info.get('dst_ip')

    print("\nPacket Info:")
    print(f"Timestamp: {result['timestamp']}")
    print(f"Source IP: {source_ip}")
    print(f"Destination IP: {destination_ip}")
    print(f"Protocol: {packet_info.get('protocol_name')}")

    if 'src_port' in packet_info and 'dst_port' in packet_info:
        print(f"Source Port: {packet_info.get('src_port')}")
        print(f"Destination Port: {packet_info.get('dst_port')}")

    if result['payload_data']:
        print(f"Payload Data: {result['payload_data'][:100]}...")

    if result['blocked_ips']:
        print("Blocklist Status: blocklisted IP activity detected.")
        for ip in result['blocked_ips']:
            print(f"- {ip} is in the local blocklist.")

    if result['findings']:
        print("Security Notes:")
        for item in result['findings']:
            print(f"- {item}")

    print("-" * 50)
