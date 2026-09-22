"""Behavioral network detection primitives for SecureNet Analyzer.

The engine is intentionally evidence-oriented: detections describe observed
traffic patterns and point back to packet numbers instead of asserting
attacker identity or intent.
"""

from collections import defaultdict
from datetime import datetime, timezone
from statistics import mean, pstdev

from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6


RULE_PACK_VERSION = "1.0.0"

DEFAULT_RULES = {
    "NET-SCAN-001": {
        "name": "Horizontal TCP SYN Scan",
        "severity": "MEDIUM",
        "window_seconds": 60,
        "min_syn_packets": 15,
        "min_unique_destinations": 10,
        "mitre": "T1046",
    },
    "NET-SCAN-002": {
        "name": "Vertical TCP SYN Scan",
        "severity": "MEDIUM",
        "window_seconds": 60,
        "min_syn_packets": 10,
        "min_unique_ports": 8,
        "mitre": "T1046",
    },
    "NET-BEACON-001": {
        "name": "Periodic Network Beaconing",
        "severity": "MEDIUM",
        "min_packets": 6,
        "min_span_seconds": 20,
        "max_jitter_ratio": 0.20,
        "min_mean_interval_seconds": 2,
        "mitre": "T1071.001",
    },
}


def _timestamp(packet):
    try:
        return datetime.fromtimestamp(float(packet.time), timezone.utc).isoformat()
    except (TypeError, ValueError, OSError):
        return "N/A"


def _network_info(packet, number):
    info = {
        "packet": number,
        "timestamp": _timestamp(packet),
        "epoch": None,
        "src": None,
        "dst": None,
        "protocol": "Other",
        "sport": None,
        "dport": None,
        "syn": False,
    }
    try:
        info["epoch"] = float(packet.time)
    except (TypeError, ValueError):
        return info

    if IP in packet:
        info["src"] = packet[IP].src
        info["dst"] = packet[IP].dst
    elif IPv6 in packet:
        info["src"] = packet[IPv6].src
        info["dst"] = packet[IPv6].dst

    if TCP in packet:
        info["protocol"] = "TCP"
        info["sport"] = int(packet[TCP].sport)
        info["dport"] = int(packet[TCP].dport)
        info["syn"] = bool(int(packet[TCP].flags) & 0x02)
    elif UDP in packet:
        info["protocol"] = "UDP"
        info["sport"] = int(packet[UDP].sport)
        info["dport"] = int(packet[UDP].dport)

    return info


def _base_finding(rule_id, rule, first_event, last_event, evidence_packets):
    return {
        "finding_id": f"{rule_id}-{first_event['packet']:05d}",
        "rule_id": rule_id,
        "rule_pack_version": RULE_PACK_VERSION,
        "name": rule["name"],
        "severity": rule["severity"],
        "confidence": 0.0,
        "first_seen": first_event["timestamp"],
        "last_seen": last_event["timestamp"],
        "source_ip": first_event["src"],
        "destination_ips": [],
        "destination_ports": [],
        "evidence_packets": sorted(set(evidence_packets)),
        "mitre": [rule["mitre"]],
        "observations": [],
    }


def detect_horizontal_syn_scans(packets):
    rule = DEFAULT_RULES["NET-SCAN-001"]
    events = [_network_info(packet, i) for i, packet in enumerate(packets, 1)]
    groups = defaultdict(list)

    for event in events:
        if (
            event["protocol"] == "TCP"
            and event["syn"]
            and event["src"]
            and event["dst"]
            and event["epoch"] is not None
        ):
            groups[event["src"]].append(event)

    findings = []
    for src, source_events in groups.items():
        source_events.sort(key=lambda item: item["epoch"])
        for start, start_event in enumerate(source_events):
            window = []
            start_time = start_event["epoch"]
            for event in source_events[start:]:
                if event["epoch"] - start_time > rule["window_seconds"]:
                    break
                window.append(event)

            unique_destinations = sorted({event["dst"] for event in window})
            if len(window) < rule["min_syn_packets"]:
                continue
            if len(unique_destinations) < rule["min_unique_destinations"]:
                continue

            first_event = window[0]
            last_event = window[-1]
            confidence = min(
                0.99,
                0.55
                + 0.02 * (len(window) - rule["min_syn_packets"])
                + 0.02 * (len(unique_destinations) - rule["min_unique_destinations"]),
            )
            finding = _base_finding(
                "NET-SCAN-001",
                rule,
                first_event,
                last_event,
                [event["packet"] for event in window],
            )
            finding["confidence"] = round(confidence, 2)
            finding["destination_ips"] = unique_destinations
            finding["destination_ports"] = sorted({event["dport"] for event in window})
            finding["observations"] = [
                f"{len(window)} TCP SYN packets observed from {src}",
                f"{len(unique_destinations)} unique destinations observed",
                f"activity occurred within {round(last_event['epoch'] - first_event['epoch'], 2)} seconds",
            ]
            findings.append(finding)
            break

    return findings


def detect_vertical_syn_scans(packets):
    rule = DEFAULT_RULES["NET-SCAN-002"]
    events = [_network_info(packet, i) for i, packet in enumerate(packets, 1)]
    groups = defaultdict(list)

    for event in events:
        if (
            event["protocol"] == "TCP"
            and event["syn"]
            and event["src"]
            and event["dst"]
            and event["dport"] is not None
            and event["epoch"] is not None
        ):
            groups[(event["src"], event["dst"])].append(event)

    findings = []
    for (src, dst), pair_events in groups.items():
        pair_events.sort(key=lambda item: item["epoch"])
        for start, start_event in enumerate(pair_events):
            window = []
            start_time = start_event["epoch"]
            for event in pair_events[start:]:
                if event["epoch"] - start_time > rule["window_seconds"]:
                    break
                window.append(event)

            unique_ports = sorted({event["dport"] for event in window})
            if len(window) < rule["min_syn_packets"]:
                continue
            if len(unique_ports) < rule["min_unique_ports"]:
                continue

            first_event = window[0]
            last_event = window[-1]
            confidence = min(
                0.99,
                0.55
                + 0.02 * (len(window) - rule["min_syn_packets"])
                + 0.025 * (len(unique_ports) - rule["min_unique_ports"]),
            )
            finding = _base_finding(
                "NET-SCAN-002",
                rule,
                first_event,
                last_event,
                [event["packet"] for event in window],
            )
            finding["confidence"] = round(confidence, 2)
            finding["destination_ips"] = [dst]
            finding["destination_ports"] = unique_ports
            finding["observations"] = [
                f"{len(window)} TCP SYN packets observed from {src} to {dst}",
                f"{len(unique_ports)} unique destination ports observed",
                f"activity occurred within {round(last_event['epoch'] - first_event['epoch'], 2)} seconds",
            ]
            findings.append(finding)
            break

    return findings


def detect_periodic_beaconing(packets):
    rule = DEFAULT_RULES["NET-BEACON-001"]
    events = [_network_info(packet, i) for i, packet in enumerate(packets, 1)]
    groups = defaultdict(list)

    for event in events:
        if (
            event["protocol"] in {"TCP", "UDP"}
            and event["src"]
            and event["dst"]
            and event["dport"] in {80, 443, 8080, 8443}
            and event["epoch"] is not None
        ):
            groups[(event["src"], event["dst"], event["protocol"], event["dport"])].append(event)

    findings = []
    for (src, dst, protocol, dport), flow_events in groups.items():
        flow_events.sort(key=lambda item: item["epoch"])
        if len(flow_events) < rule["min_packets"]:
            continue

        times = [event["epoch"] for event in flow_events]
        intervals = [
            later - earlier for earlier, later in zip(times, times[1:])
            if later > earlier
        ]
        if len(intervals) < rule["min_packets"] - 1:
            continue

        average_interval = mean(intervals)
        span = times[-1] - times[0]
        if span < rule["min_span_seconds"]:
            continue
        if average_interval < rule["min_mean_interval_seconds"]:
            continue

        jitter_ratio = pstdev(intervals) / average_interval if average_interval else 1.0
        if jitter_ratio > rule["max_jitter_ratio"]:
            continue

        confidence = min(
            0.97,
            0.60
            + max(0.0, rule["max_jitter_ratio"] - jitter_ratio)
            + min(0.17, (len(flow_events) - rule["min_packets"]) * 0.02),
        )
        finding = _base_finding(
            "NET-BEACON-001",
            rule,
            flow_events[0],
            flow_events[-1],
            [event["packet"] for event in flow_events],
        )
        finding["confidence"] = round(confidence, 2)
        finding["destination_ips"] = [dst]
        finding["destination_ports"] = [dport]
        finding["observations"] = [
            f"{len(flow_events)} repeated {protocol} connections observed",
            f"mean interval: {round(average_interval, 2)} seconds",
            f"interval jitter ratio: {round(jitter_ratio, 3)}",
            f"observed over {round(span, 2)} seconds",
        ]
        findings.append(finding)

    return findings


def run_detections(packets):
    findings = []
    findings.extend(detect_horizontal_syn_scans(packets))
    findings.extend(detect_vertical_syn_scans(packets))
    findings.extend(detect_periodic_beaconing(packets))
    return sorted(findings, key=lambda item: (item["first_seen"], item["finding_id"]))


def index_detections_by_packet(detections):
    index = defaultdict(list)
    for finding in detections:
        for packet_number in finding["evidence_packets"]:
            index[packet_number].append(finding["finding_id"])
    return {key: sorted(value) for key, value in index.items()}


def summarize_detections(detections):
    severity_counts = defaultdict(int)
    rule_counts = defaultdict(int)

    for finding in detections:
        severity_counts[finding["severity"]] += 1
        rule_counts[finding["rule_id"]] += 1

    return {
        "total": len(detections),
        "severity": dict(sorted(severity_counts.items())),
        "rules": dict(sorted(rule_counts.items())),
        "rule_pack_version": RULE_PACK_VERSION,
    }
