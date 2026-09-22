import html
import os

from scapy.all import wrpcap

from Utils.blocklist import load_blocklist
from Utils.analysis import (
    build_packet_analysis,
    extract_packet_info,
    extract_payload_data,
    get_packet_timestamp,
    detect_suspicious_activity,
    get_security_summary,
)


def get_protocol_summary(captured_packets, blocked_ips=None):
    protocol_counts = {}
    suspicious_alerts = []
    blocked_ips = set(load_blocklist()) if blocked_ips is None else set(blocked_ips)

    for packet in captured_packets:
        result = build_packet_analysis(packet, blocked_ips=blocked_ips)
        protocol = result['packet_info'].get('protocol_name', 'Unknown')
        protocol_counts[protocol] = protocol_counts.get(protocol, 0) + 1
        suspicious_alerts.extend(result['findings'])

    return protocol_counts, suspicious_alerts


def format_packet_report(packet, index, blocked_ips=None):
    result = build_packet_analysis(packet, blocked_ips=blocked_ips)
    packet_info = result['packet_info']
    payload_data = result['payload_data']
    protocol_name = packet_info.get('protocol_name', 'Unknown')
    findings = result['findings']

    lines = [
        f"Packet #{index}",
        f"Timestamp: {get_packet_timestamp(packet)}",
        f"Summary: {packet.summary()}",
        f"Source IP: {packet_info.get('src_ip', 'N/A')}",
        f"Destination IP: {packet_info.get('dst_ip', 'N/A')}",
        f"Protocol: {protocol_name}",
    ]

    if 'src_port' in packet_info:
        lines.append(f"Source Port: {packet_info.get('src_port')}")
    if 'dst_port' in packet_info:
        lines.append(f"Destination Port: {packet_info.get('dst_port')}")

    if payload_data:
        lines.append(f"Payload Data: {payload_data[:500]}")

    if findings:
        lines.append("Security Notes:")
        for item in findings:
            lines.append(f"- {item}")

    lines.append("-" * 60)
    return "\n".join(lines) + "\n"


def save_to_txt(captured_packets, filename):
    filename = _ensure_directory(filename)

    blocked_ips = load_blocklist()
    protocol_counts, suspicious_alerts = get_protocol_summary(captured_packets, blocked_ips=blocked_ips)
    summary = get_security_summary(captured_packets)

    with open(filename, 'w', encoding='utf-8') as f:
        f.write("SecureNet Analyzer Security Report\n")
        f.write("=" * 60 + "\n")
        f.write(f"Total Packets: {summary['total_packets']}\n")
        f.write(f"Risk Level: {summary['risk_level']}\n")
        f.write(f"Risk Score: {summary['risk_score']}/100\n")
        f.write(f"Suspicious Events: {summary['suspicious_events']}\n")
        f.write(f"Blocked IP Hits: {summary['blocked_hits']}\n")
        f.write(f"Most Active Source: {summary['most_active_source']}\n")
        f.write(f"Most Active Destination: {summary['most_active_destination']}\n")
        f.write(f"Most Common Port: {summary['most_common_port']}\n\n")

        f.write("Protocol Summary:\n")
        if protocol_counts:
            for proto, count in protocol_counts.items():
                f.write(f"- {proto}: {count}\n")
        else:
            f.write("- No protocols identified\n")

        if suspicious_alerts:
            f.write("\nSecurity Alerts:\n")
            for alert in sorted(set(suspicious_alerts)):
                f.write(f"- {alert}\n")
        else:
            f.write("\nSecurity Alerts:\n- No suspicious activity detected\n")

        f.write("\nPacket Details:\n")

        if not captured_packets:
            f.write("No packets were captured.\n")
            print(f"Packets saved to {filename}")
            return

        for index, packet in enumerate(captured_packets, start=1):
            f.write(format_packet_report(packet, index, blocked_ips=blocked_ips))

    print(f"Packets saved to {filename}")


def _ensure_directory(filename):
    directory = os.path.dirname(os.path.abspath(filename))
    if directory and not os.path.exists(directory):
        os.makedirs(directory, exist_ok=True)
    return os.path.abspath(filename)


def save_to_html(captured_packets, filename):
    filename = _ensure_directory(filename)

    blocked_ips = load_blocklist()
    protocol_counts, suspicious_alerts = get_protocol_summary(
        captured_packets, blocked_ips=blocked_ips
    )
    summary = get_security_summary(captured_packets)
    rows = []

    for index, packet in enumerate(captured_packets, start=1):
        result = build_packet_analysis(packet, blocked_ips=blocked_ips)
        packet_info = result['packet_info']
        payload_data = result['payload_data']
        findings = result['findings']
        packet_rows = [
            f"<tr><th>{index}</th>",
            f"<td>{html.escape(get_packet_timestamp(packet))}</td>",
            f"<td>{html.escape(packet.summary())}</td>",
            f"<td>{html.escape(packet_info.get('src_ip', 'N/A'))}</td>",
            f"<td>{html.escape(packet_info.get('dst_ip', 'N/A'))}</td>",
            f"<td>{html.escape(packet_info.get('protocol_name', 'Unknown'))}</td>",
            f"<td>{html.escape(str(packet_info.get('src_port', 'N/A')))}</td>",
            f"<td>{html.escape(str(packet_info.get('dst_port', 'N/A')))}</td>",
            f"<td>{html.escape(payload_data[:250])}</td>",
            f"<td>{html.escape('; '.join(findings) if findings else 'None')}</td></tr>"
        ]
        rows.append(''.join(packet_rows))

    protocol_html = ''.join(
        f"<li><strong>{html.escape(proto)}</strong>: {count}</li>" for proto, count in protocol_counts.items()
    ) or '<li>No protocols identified</li>'

    alerts_html = ''.join(
        f"<li>{html.escape(alert)}</li>" for alert in sorted(set(suspicious_alerts))
    ) or '<li>No suspicious activity detected</li>'

    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8" />
        <title>SecureNet Analyzer Executive Report</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 30px; background: #f5f7fb; color: #1f2937; }}
            h1, h2 {{ color: #111827; }}
            .card {{ background: white; border-radius: 8px; padding: 20px; margin-bottom: 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
            table {{ border-collapse: collapse; width: 100%; background: white; }}
            th, td {{ border: 1px solid #d1d5db; padding: 8px; text-align: left; vertical-align: top; }}
            th {{ background: #e5e7eb; }}
            ul {{ margin: 0; padding-left: 18px; }}
            .risk {{ font-size: 18px; font-weight: bold; }}
        </style>
    </head>
    <body>
        <h1>SecureNet Analyzer Executive Security Report</h1>
        <div class="card">
            <p><strong>Total Packets:</strong> {summary['total_packets']}</p>
            <p><strong>Risk Level:</strong> <span class="risk">{summary['risk_level']}</span></p>
            <p><strong>Risk Score:</strong> {summary['risk_score']}/100</p>
            <p><strong>Suspicious Events:</strong> {summary['suspicious_events']}</p>
            <p><strong>Blocked IP Hits:</strong> {summary['blocked_hits']}</p>
            <p><strong>Most Active Source:</strong> {summary['most_active_source']}</p>
            <p><strong>Most Active Destination:</strong> {summary['most_active_destination']}</p>
            <p><strong>Most Common Port:</strong> {summary['most_common_port']}</p>
            <h2>Protocol Summary</h2>
            <ul>{protocol_html}</ul>
            <h2>Security Alerts</h2>
            <ul>{alerts_html}</ul>
        </div>
        <div class="card">
            <h2>Packet Details</h2>
            <table>
                <thead>
                    <tr>
                        <th>#</th><th>Timestamp</th><th>Summary</th><th>Source IP</th><th>Destination IP</th><th>Protocol</th><th>Source Port</th><th>Destination Port</th><th>Payload</th><th>Security Notes</th>
                    </tr>
                </thead>
                <tbody>
                    {''.join(rows) if rows else '<tr><td colspan="10">No packets were captured.</td></tr>'}
                </tbody>
            </table>
        </div>
    </body>
    </html>
    """

    with open(filename, 'w', encoding='utf-8') as f:
        f.write(html_content)

    print(f"HTML report saved to {filename}")


def save_to_pcap(captured_packets, filename):
    filename = _ensure_directory(filename)

    wrpcap(filename, captured_packets)
    print(f"Packets saved to {filename}")
