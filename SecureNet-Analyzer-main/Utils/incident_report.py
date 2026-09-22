import hashlib
import html
import json
import os
import socket
from collections import Counter, defaultdict
from datetime import datetime, timezone

from Utils.analysis import build_packet_analysis, get_security_summary
from Utils.investigation import build_sessions, build_timeline, build_case_summary


def _timestamp(packet):
    try:
        return datetime.fromtimestamp(float(packet.time), timezone.utc).isoformat()
    except (TypeError, ValueError, OSError):
        return "N/A"


def _sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "N/A"


def build_incident_dataset(packets):
    hosts = defaultdict(lambda: {
        "packets": 0, "bytes": 0, "first_seen": None, "last_seen": None,
        "protocols": Counter(), "ports": Counter(), "peers": Counter(),
        "findings": Counter(), "blocklist_hits": 0
    })
    events = []

    for number, packet in enumerate(packets, 1):
        result = build_packet_analysis(packet)
        info = result["packet_info"]
        src = info.get("src_ip")
        dst = info.get("dst_ip")
        protocol = info.get("protocol_name", "Unknown")
        timestamp = _timestamp(packet)
        size = len(packet)
        findings = result["findings"]

        for ip, direction in ((src, "source"), (dst, "destination")):
            if not ip:
                continue
            host = hosts[ip]
            host["packets"] += 1
            host["bytes"] += size
            host["protocols"][protocol] += 1
            host["first_seen"] = timestamp if not host["first_seen"] else min(host["first_seen"], timestamp)
            host["last_seen"] = timestamp if not host["last_seen"] else max(host["last_seen"], timestamp)
            peer = dst if direction == "source" else src
            if peer:
                host["peers"][peer] += 1
            port = info.get("src_port") if direction == "source" else info.get("dst_port")
            if port is not None:
                host["ports"][str(port)] += 1
            for finding in findings:
                host["findings"][finding] += 1
            if ip in result["blocked_ips"]:
                host["blocklist_hits"] += 1

        if findings or result["blocked_ips"]:
            events.append({
                "packet": number,
                "timestamp": timestamp,
                "source_ip": src or "N/A",
                "destination_ip": dst or "N/A",
                "protocol": protocol,
                "source_port": info.get("src_port", "N/A"),
                "destination_port": info.get("dst_port", "N/A"),
                "bytes": size,
                "blocklist_hits": result["blocked_ips"],
                "findings": findings,
            })

    records = []
    for ip, host in hosts.items():
        records.append({
            "ip": ip,
            "hostname": _hostname(ip),
            "packets": host["packets"],
            "bytes": host["bytes"],
            "first_seen": host["first_seen"],
            "last_seen": host["last_seen"],
            "protocols": dict(host["protocols"].most_common()),
            "ports": dict(host["ports"].most_common()),
            "top_peers": dict(host["peers"].most_common(10)),
            "blocklist_hits": host["blocklist_hits"],
            "findings": dict(host["findings"].most_common()),
        })

    records.sort(key=lambda x: (x["blocklist_hits"], x["packets"]), reverse=True)
    return {
        "summary": get_security_summary(packets),
        "hosts": records,
        "events": events,
        "sessions": build_sessions(packets),
        "timeline": build_timeline(packets),
        "case_summary": build_case_summary(packets),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "attribution_warning": "This report describes observed network activity. An IP address alone does not establish ownership or attacker attribution."
    }


# pylint: disable=too-many-arguments,too-many-positional-arguments
def generate_incident_report(packets, prefix, case_id="UNASSIGNED",
                             analyst="Not specified",
                             organization="Not specified",
                             interface="Default interface",
                             evidence_files=None):
    dataset = build_incident_dataset(packets)
    evidence_files = evidence_files or []
    prefix = os.path.abspath(prefix)
    os.makedirs(os.path.dirname(prefix) or ".", exist_ok=True)

    base = f"{prefix}_{case_id.replace(' ', '_')}"
    paths = {
        "json": base + ".json",
        "txt": base + ".txt",
        "html": base + ".html"
    }

    evidence = []
    for path in evidence_files:
        if path and os.path.exists(path):
            evidence.append({
                "path": os.path.abspath(path),
                "size_bytes": os.path.getsize(path),
                "sha256": _sha256(path)
            })

    chain_of_custody = [{
        "timestamp": dataset["generated_at"],
        "action": "REPORT_GENERATED",
        "actor": analyst,
        "case_id": case_id,
        "evidence": [item["path"] for item in evidence],
        "note": "Automated report generation record; preserve original evidence and formal custody records separately."
    }]

    report = {
        "metadata": {
            "case_id": case_id,
            "analyst": analyst,
            "organization": organization,
            "interface": interface or "Default interface",
            "generated_at": dataset["generated_at"],
            "scope": "Observed network traffic from this capture session",
            "attribution_warning": dataset["attribution_warning"]
        },
        "summary": dataset["summary"],
        "observed_ips": dataset["hosts"],
        "security_events": dataset["events"],
        "sessions": dataset["sessions"],
        "timeline": dataset["timeline"],
        "case_summary": dataset["case_summary"],
        "evidence": evidence,
        "chain_of_custody": chain_of_custody
    }

    with open(paths["json"], "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2)

    summary = dataset["summary"]
    with open(paths["txt"], "w", encoding="utf-8") as handle:
        handle.write("SECURENET ANALYZER - INCIDENT / NETWORK ACTIVITY REPORT\n")
        handle.write("=" * 78 + "\n")
        handle.write(f"Case ID: {case_id}\nAnalyst: {analyst}\nOrganization: {organization}\n")
        handle.write(f"Interface: {interface or 'Default interface'}\nGenerated: {dataset['generated_at']}\n\n")
        handle.write("EXECUTIVE SUMMARY\n" + "-" * 78 + "\n")
        for key in ("total_packets", "risk_level", "risk_score", "suspicious_events", "blocked_hits",
                    "most_active_source", "most_active_destination", "most_common_port"):
            handle.write(f"{key}: {summary.get(key)}\n")
        handle.write("\nIMPORTANT LIMITATION\n" + dataset["attribution_warning"] + "\n\n")
        handle.write("OBSERVED IP ACTIVITY\n" + "-" * 78 + "\n")

        for host in dataset["hosts"]:
            handle.write(f"IP: {host['ip']}\n")
            handle.write(f"Hostname: {host['hostname']}\n")
            handle.write(f"Packets: {host['packets']} | Bytes: {host['bytes']}\n")
            handle.write(f"First seen: {host['first_seen']} | Last seen: {host['last_seen']}\n")
            handle.write(f"Blocklist hits: {host['blocklist_hits']}\n")
            handle.write(f"Protocols: {host['protocols']}\n")
            handle.write(f"Ports: {host['ports']}\n")
            handle.write(f"Top peers: {host['top_peers']}\n")
            if host["findings"]:
                handle.write("Findings:\n")
                for finding, count in host["findings"].items():
                    handle.write(f"  - {finding} ({count})\n")
            handle.write("-" * 78 + "\n")

        handle.write("\nSECURITY EVENTS\n" + "-" * 78 + "\n")
        if dataset["events"]:
            for event in dataset["events"]:
                handle.write(
                    f"Packet {event['packet']} | {event['timestamp']} | "
                    f"{event['source_ip']} -> {event['destination_ip']} | "
                    f"{event['protocol']} | {event['source_port']} -> {event['destination_port']} | "
                    f"{event['bytes']} bytes\n"
                )
                for finding in event["findings"]:
                    handle.write(f"  Finding: {finding}\n")
                if event["blocklist_hits"]:
                    handle.write(f"  Blocklist: {', '.join(event['blocklist_hits'])}\n")
        else:
            handle.write("No configured security detections were triggered.\n")

        handle.write("\nINVESTIGATION ENRICHMENT\n" + "-" * 78 + "\n")
        handle.write(f"Timeline events: {dataset['case_summary']['timeline_events']}\n")
        handle.write(f"MITRE ATT&CK techniques: {dataset['case_summary']['mitre_techniques']}\n")
        handle.write(f"IOC counts: {dataset['case_summary']['ioc_counts']}\n\n")
        handle.write("TIMELINE\n" + "-" * 78 + "\n")
        for event in dataset["timeline"]:
            techniques = ", ".join(x["technique_id"] for x in event["mitre"]) or "None"
            handle.write(f"{event['timestamp']} | Packet {event['packet']} | {event['source_ip']} -> {event['destination_ip']} | MITRE: {techniques}\n")
        handle.write("\nCHAIN OF CUSTODY\n" + "-" * 78 + "\n")
        for entry in chain_of_custody:
            handle.write(f"{entry['timestamp']} | {entry['action']} | {entry['actor']} | {entry['note']}\n")
        handle.write("\nEVIDENCE INTEGRITY\n" + "-" * 78 + "\n")
        for item in evidence:
            handle.write(f"File: {item['path']}\nSize: {item['size_bytes']} bytes\nSHA-256: {item['sha256']}\n")
        if not evidence:
            handle.write("No evidence files supplied.\n")

    host_rows = []
    for host in dataset["hosts"]:
        findings = "<br>".join(
            f"{html.escape(name)} ({count})" for name, count in host["findings"].items()
        ) or "None"
        host_rows.append(
            f"<tr><td>{html.escape(host['ip'])}</td><td>{html.escape(host['hostname'])}</td>"
            f"<td>{host['packets']}</td><td>{host['bytes']}</td>"
            f"<td>{html.escape(str(host['first_seen']))}</td><td>{html.escape(str(host['last_seen']))}</td>"
            f"<td>{host['blocklist_hits']}</td><td>{html.escape(', '.join(host['protocols']) or 'N/A')}</td>"
            f"<td>{findings}</td></tr>"
        )

    event_rows = []
    for event in dataset["events"]:
        findings = "<br>".join(html.escape(x) for x in event["findings"]) or "None"
        blocklist = html.escape(", ".join(event["blocklist_hits"])) if event["blocklist_hits"] else "None"
        event_rows.append(
            f"<tr><td>{event['packet']}</td><td>{html.escape(event['timestamp'])}</td>"
            f"<td>{html.escape(event['source_ip'])}</td><td>{html.escape(event['destination_ip'])}</td>"
            f"<td>{html.escape(event['protocol'])}</td><td>{event['source_port']}</td><td>{event['destination_port']}</td>"
            f"<td>{event['bytes']}</td><td>{findings}</td><td>{blocklist}</td></tr>"
        )

    timeline_rows = []
    for event in dataset["timeline"]:
        techniques = "<br>".join(html.escape(x["technique_id"] + " — " + x["technique"]) for x in event["mitre"]) or "None"
        timeline_rows.append(
            f"<tr><td>{html.escape(event['timestamp'])}</td><td>{event['packet']}</td>"
            f"<td>{html.escape(event['source_ip'])}</td><td>{html.escape(event['destination_ip'])}</td><td>{techniques}</td></tr>"
        )

    evidence_rows = [
        f"<tr><td>{html.escape(x['path'])}</td><td>{x['size_bytes']}</td><td><code>{x['sha256']}</code></td></tr>"
        for x in evidence
    ]

    html_content = f"""<!doctype html>
<html><head><meta charset="utf-8">
<title>SecureNet Analyzer - {html.escape(case_id)}</title>
<style>
body{{font-family:Arial,sans-serif;background:#f4f6f8;color:#17202a;margin:0}}
main{{max-width:1500px;margin:30px auto;padding:0 20px}}
.card{{background:#fff;border-radius:10px;padding:22px;margin:18px 0;box-shadow:0 2px 8px rgba(0,0,0,.08)}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px}}
.metric{{padding:15px;background:#eef2f7;border-radius:8px}}
.metric b{{display:block;font-size:12px;color:#667085;margin-bottom:6px}}
table{{width:100%;border-collapse:collapse;font-size:13px}}
th,td{{border:1px solid #d9dee5;padding:8px;text-align:left;vertical-align:top}}
th{{background:#e9edf2}}
.note{{background:#fff7e6;border-left:4px solid #d99000;padding:12px}}
code{{word-break:break-all}}
</style></head><body><main>
<div class="card"><h1>SecureNet Analyzer — Incident / Network Activity Report</h1>
<p><b>Case:</b> {html.escape(case_id)} &nbsp; <b>Generated:</b> {html.escape(dataset["generated_at"])}</p>
<div class="grid">
<div class="metric"><b>Risk</b>{html.escape(summary["risk_level"])}</div>
<div class="metric"><b>Score</b>{summary["risk_score"]}/100</div>
<div class="metric"><b>Packets</b>{summary["total_packets"]}</div>
<div class="metric"><b>Suspicious events</b>{summary["suspicious_events"]}</div>
<div class="metric"><b>Blocklist hits</b>{summary["blocked_hits"]}</div>
</div>
<p><b>Analyst:</b> {html.escape(analyst)}<br><b>Organization:</b> {html.escape(organization)}<br>
<b>Interface:</b> {html.escape(interface or "Default interface")}</p>
<div class="note"><b>Attribution limitation:</b> {html.escape(dataset["attribution_warning"])}</div></div>

<div class="card"><h2>Observed IP Activity</h2>
<table><thead><tr><th>IP</th><th>Hostname</th><th>Packets</th><th>Bytes</th><th>First seen</th><th>Last seen</th><th>Blocklist hits</th><th>Protocols</th><th>Findings</th></tr></thead>
<tbody>{''.join(host_rows) or '<tr><td colspan="9">No IP activity observed.</td></tr>'}</tbody></table></div>

<div class="card"><h2>Security Events</h2>
<table><thead><tr><th>Packet</th><th>Timestamp</th><th>Source</th><th>Destination</th><th>Protocol</th><th>Src Port</th><th>Dst Port</th><th>Bytes</th><th>Findings</th><th>Blocklist</th></tr></thead>
<tbody>{''.join(event_rows) or '<tr><td colspan="10">No security events generated.</td></tr>'}</tbody></table></div>

<div class="card"><h2>Investigation Enrichment</h2>
<div class="grid"><div class="metric"><b>Timeline events</b>{dataset["case_summary"]["timeline_events"]}</div>
<div class="metric"><b>MITRE techniques</b>{len(dataset["case_summary"]["mitre_techniques"])}</div>
<div class="metric"><b>IOC categories</b>{len(dataset["case_summary"]["ioc_counts"])}</div></div>
<p><b>MITRE mapping is heuristic:</b> technique IDs are detection hypotheses based on observed metadata/payload patterns, not proof of adversary intent.</p>
<h3>Incident Timeline</h3>
<table><thead><tr><th>Timestamp</th><th>Packet</th><th>Source</th><th>Destination</th><th>MITRE ATT&CK</th></tr></thead>
<tbody>{''.join(timeline_rows) or '<tr><td colspan="5">No enriched timeline events.</td></tr>'}</tbody></table></div>

<div class="card"><h2>Evidence Integrity</h2>
<p>SHA-256 hashes are recorded for supplied evidence files. Preserve originals according to your organization's evidence-preservation procedures.</p>
<table><thead><tr><th>File</th><th>Size</th><th>SHA-256</th></tr></thead>
<tbody>{''.join(evidence_rows) or '<tr><td colspan="3">No evidence files supplied.</td></tr>'}</tbody></table></div>
</main></body></html>"""

    with open(paths["html"], "w", encoding="utf-8") as handle:
        handle.write(html_content)

    return paths
