import re
from collections import Counter, defaultdict
from datetime import datetime, timezone

from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.dns import DNS, DNSQR
try:
    from scapy.layers.http import HTTPRequest, HTTPResponse
except ImportError:
    HTTPRequest = HTTPResponse = None

from Utils.detection_engine import (
    index_detections_by_packet,
    run_detections,
    summarize_detections,
)

MITRE_RULES = (
    ("T1046", "Network Service Scanning", "Behavioral scanning pattern detected"),
    ("T1071.001", "Web Protocols", "HTTP request/response metadata observed"),
    ("T1071.004", "DNS", "DNS query/response activity observed"),
    ("T1021.001", "Remote Services: Remote Desktop Protocol", "Traffic targeting TCP/3389"),
    ("T1021.002", "Remote Services: SMB/Windows Admin Shares", "Traffic targeting TCP/445"),
    ("T1021.004", "Remote Services: SSH", "Traffic targeting TCP/22"),
    ("T1021.006", "Windows Remote Management", "Traffic targeting TCP/5985 or 5986"),
    ("T1059.001", "Command and Scripting Interpreter: PowerShell", "PowerShell keyword in observed payload"),
    ("T1059.003", "Windows Command Shell", "cmd.exe keyword in observed payload"),
    ("T1105", "Ingress Tool Transfer", "wget/curl keyword in observed payload"),
    ("T1190", "Exploit Public-Facing Application", "Suspicious exploit-like payload pattern observed"),
)

MAX_INVESTIGATION_PAYLOAD_BYTES = 64 * 1024

SUSPICIOUS_PATTERNS = {
    "T1059.001": re.compile(r"powershell", re.I),
    "T1059.003": re.compile(r"cmd\.exe|\\cmd\.exe", re.I),
    "T1105": re.compile(r"\b(?:wget|curl)\b", re.I),
    "T1059": re.compile(r"\bbash\s+-i\b|\bnc\s+", re.I),
    "T1190": re.compile(r"<script>|drop\s+table|select\s+.+\s+from|eval\(|system\(", re.I),
}


def utc_timestamp(packet):
    try:
        return datetime.fromtimestamp(float(packet.time), timezone.utc).isoformat()
    except (TypeError, ValueError, OSError):
        return "N/A"


def extract_iocs(packet, payload=""):
    iocs = {"ipv4": [], "ipv6": [], "domains": [], "urls": [], "ports": []}
    for value in (getattr(packet[IP], "src", None), getattr(packet[IP], "dst", None)) if IP in packet else ():
        if value:
            iocs["ipv4"].append(value)
    if packet.haslayer("IPv6"):
        iocs["ipv6"].extend([packet["IPv6"].src, packet["IPv6"].dst])
    if TCP in packet:
        iocs["ports"].extend([int(packet[TCP].sport), int(packet[TCP].dport)])
    elif UDP in packet:
        iocs["ports"].extend([int(packet[UDP].sport), int(packet[UDP].dport)])
    text = payload or ""
    for match in re.findall(r"https?://[^\s<>\"]+", text, re.I):
        iocs["urls"].append(match.rstrip(".,);]"))
    for match in re.findall(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,63}\b", text, re.I):
        if match.lower() not in {"example.com", "localhost.localdomain"}:
            iocs["domains"].append(match)
    return {k: sorted(set(v)) for k, v in iocs.items()}


def mitre_mappings(packet, payload=""):
    mappings = []
    dst_port = None
    if TCP in packet:
        dst_port = int(packet[TCP].dport)
    elif UDP in packet:
        dst_port = int(packet[UDP].dport)

    port_map = {
        22: ("T1021.004", "Remote Services: SSH"),
        3389: ("T1021.001", "Remote Services: Remote Desktop Protocol"),
        445: ("T1021.002", "Remote Services: SMB/Windows Admin Shares"),
        5985: ("T1021.006", "Windows Remote Management"),
        5986: ("T1021.006", "Windows Remote Management"),
    }
    if dst_port in port_map:
        tid, name = port_map[dst_port]
        mappings.append({"technique_id": tid, "technique": name, "reason": f"Traffic targeted TCP/{dst_port}"})

    if packet.haslayer(DNS) or packet.haslayer(DNSQR):
        mappings.append({
            "technique_id": "T1071.004",
            "technique": "Application Layer Protocol: DNS",
            "reason": "DNS activity observed",
        })

    if (HTTPRequest and packet.haslayer(HTTPRequest)) or (HTTPResponse and packet.haslayer(HTTPResponse)):
        mappings.append({
            "technique_id": "T1071.001",
            "technique": "Application Layer Protocol: Web Protocols",
            "reason": "HTTP metadata observed",
        })

    for tid, pattern in SUSPICIOUS_PATTERNS.items():
        if pattern.search(payload or ""):
            name = next((n for i, n, _ in MITRE_RULES if i == tid), "Command/Scripting or Transfer Activity")
            mappings.append({
                "technique_id": tid,
                "technique": name,
                "reason": "Suspicious payload pattern matched",
            })

    unique = {}
    for item in mappings:
        unique[(item["technique_id"], item["reason"])] = item
    return list(unique.values())


def build_sessions(packets):
    sessions = defaultdict(lambda: {
        "packets": 0,
        "bytes": 0,
        "first_seen": None,
        "last_seen": None,
        "protocol": "Unknown",
        "src": None,
        "dst": None,
        "src_port": None,
        "dst_port": None,
    })
    for packet in packets:
        if IP in packet:
            network_layer = packet[IP]
        elif IPv6 in packet:
            network_layer = packet[IPv6]
        else:
            continue

        src = network_layer.src
        dst = network_layer.dst
        proto, sport, dport = "Unknown", None, None
        if TCP in packet:
            proto, sport, dport = "TCP", int(packet[TCP].sport), int(packet[TCP].dport)
        elif UDP in packet:
            proto, sport, dport = "UDP", int(packet[UDP].sport), int(packet[UDP].dport)
        key = (src, dst, proto, sport, dport)
        ts = utc_timestamp(packet)
        item = sessions[key]
        item.update({"src": src, "dst": dst, "protocol": proto, "src_port": sport, "dst_port": dport})
        item["packets"] += 1
        item["bytes"] += len(packet)
        item["first_seen"] = ts if not item["first_seen"] else min(item["first_seen"], ts)
        item["last_seen"] = ts if not item["last_seen"] else max(item["last_seen"], ts)
    return list(sessions.values())


def build_timeline(packets, detections=None):
    detections = run_detections(packets) if detections is None else detections
    detection_index = index_detections_by_packet(detections)
    timeline = []

    for number, packet in enumerate(packets, 1):
        payload = ""
        if packet.haslayer("Raw"):
            raw_payload = packet["Raw"].load
            if not isinstance(raw_payload, bytes):
                raw_payload = bytes(raw_payload)
            payload = raw_payload[:MAX_INVESTIGATION_PAYLOAD_BYTES].decode(errors="ignore")

        mappings = mitre_mappings(packet, payload)
        iocs = extract_iocs(packet, payload)
        detection_ids = detection_index.get(number, [])

        if mappings or any(iocs.values()) or detection_ids:
            if IP in packet:
                src = packet[IP].src
                dst = packet[IP].dst
            elif IPv6 in packet:
                src = packet[IPv6].src
                dst = packet[IPv6].dst
            else:
                src = dst = "N/A"
            timeline.append({
                "timestamp": utc_timestamp(packet),
                "packet": number,
                "source_ip": src,
                "destination_ip": dst,
                "protocol": (
                    "TCP" if TCP in packet
                    else "UDP" if UDP in packet
                    else "ICMPv6" if IPv6 in packet and packet[IPv6].nh == 58
                    else "ICMP" if ICMP in packet
                    else "Other"
                ),
                "mitre": mappings,
                "detections": detection_ids,
                "iocs": iocs,
            })

    return sorted(timeline, key=lambda x: x["timestamp"])


def build_case_summary(packets, detections=None):
    detections = run_detections(packets) if detections is None else detections
    timeline = build_timeline(packets, detections)
    techniques = Counter()
    ioc_counts = Counter()

    for event in timeline:
        for item in event["mitre"]:
            techniques[item["technique_id"]] += 1
        for kind, values in event["iocs"].items():
            if values:
                ioc_counts[kind] += len(values)

    detection_summary = summarize_detections(detections)
    return {
        "timeline_events": len(timeline),
        "mitre_techniques": dict(techniques.most_common()),
        "ioc_counts": dict(ioc_counts),
        "detections": detection_summary["total"],
        "detection_severity": detection_summary["severity"],
        "detection_rules": detection_summary["rules"],
        "rule_pack_version": detection_summary["rule_pack_version"],
    }
