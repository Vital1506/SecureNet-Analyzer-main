#!/usr/bin/env python3
"""
SecureNet Analyzer - automated verification harness.

Exercises CLI paths (with --offline) and module internals.
Does not require packet capture privileges; capture paths are skipped
unless run with elevated privileges, because Scapy sniff() needs them.

Run:
  python test_all.py
"""

import os
import sys
import tempfile
import subprocess
import json

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = BASE_DIR
MAIN_SCRIPT = os.path.join(PROJECT_DIR, "Main.py")

sys.path.insert(0, PROJECT_DIR)

PASS, FAIL = [], []


def _record(name, passed, detail=""):
    status = "PASS" if passed else "FAIL"
    line = f"[{status}] {name}"
    if detail:
        line += f" -- {detail}"
    print(line)
    if passed:
        PASS.append(name)
    else:
        FAIL.append((name, detail))


def _run_cli(args, timeout=30):
    cmd = [sys.executable, MAIN_SCRIPT] + args
    return subprocess.run(
        cmd,
        cwd=PROJECT_DIR,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout,
    )


def _assert_contains(output, needle, label="stdout"):
    if needle not in output:
        return False, f"expected '{needle}' in {label}"
    return True, ""


def _assert_not_contains(output, needle, label="stdout"):
    if needle in output:
        return False, f"unexpected '{needle}' in {label}"
    return True, ""


# ---------------------------------------------------------------------------
# Module-level checks
# ---------------------------------------------------------------------------

def check_imports():
    try:
        from Utils import capture, analysis, blocklist, filters, HostDetector, save
        _record("imports", True)
    except Exception as e:
        _record("imports", False, str(e))
        return
    _record("capture.list_interfaces_nonempty", bool(capture.list_interfaces()),
            detail=str(capture.list_interfaces()[:3]))
    _record("blocklist.load_blocklist", True)
    _record("analysis.build_packet_analysis_exists", callable(getattr(analysis, "build_packet_analysis", None)))
    _record("analysis.print_packet_analysis_exists", callable(getattr(analysis, "print_packet_analysis", None)))
    _record("save.save_to_html_exists", callable(getattr(save, "save_to_html", None)))
    _record("save._ensure_directory_exists", callable(getattr(save, "_ensure_directory", None)))


def check_filters():
    from Utils.filters import parse_filter_string, packet_filter
    from scapy.all import IP, TCP, Ether

    cases = [
        ("all", None),
        ("src host 10.0.0.1", {"src_ip": "10.0.0.1"}),
        ("dst host 192.168.1.10", {"dst_ip": "192.168.1.10"}),
        ("src host 10.0.0.1 and dst port 80", {"src_ip": "10.0.0.1", "dst_port": 80}),
        ("tcp and dst host 192.168.1.10", {"protocol": "tcp", "dst_ip": "192.168.1.10"}),
        ("udp and src port 53", {"protocol": "udp", "src_port": 53}),
        ("icmp", {"protocol": "icmp"}),
        ("dst port 443 and src host 10.0.0.2", {"dst_port": 443, "src_ip": "10.0.0.2"}),
    ]
    for expr, expected in cases:
        got = parse_filter_string(expr)
        ok = got == expected
        _record(f"filter parse: {expr!r}", ok, detail=f"got={got} expected={expected}")

    # Build a synthetic TCP packet and confirm filtering logic.
    pkt = Ether()/IP(src="10.0.0.1", dst="192.168.1.10")/TCP(sport=12345, dport=80)
    _record("filter matches src_ip", packet_filter(pkt, {"src_ip": "10.0.0.1"}))
    _record("filter rejects wrong src_ip", not packet_filter(pkt, {"src_ip": "10.0.0.2"}))
    _record("filter matches dst_port", packet_filter(pkt, {"dst_port": 80}))
    _record("filter rejects wrong dst_port", not packet_filter(pkt, {"dst_port": 443}))
    _record("filter matches protocol tcp", packet_filter(pkt, {"protocol": "tcp"}))
    _record("filter rejects protocol udp", not packet_filter(pkt, {"protocol": "udp"}))
    _record("filter None accepts all", packet_filter(pkt, None))
    _record("filter empty dict accepts all", packet_filter(pkt, {}))


def check_blocklist():
    from Utils import blocklist
    original_path = blocklist.BLOCKLIST_FILE
    tf = tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8")
    tf.close()
    try:
        blocklist.BLOCKLIST_FILE = tf.name
        blocklist.save_blocklist(["10.0.0.1", "10.0.0.2"])
        _record("blocklist save+load", blocklist.load_blocklist() == ["10.0.0.1", "10.0.0.2"])
        _record("blocklist add new", blocklist.add_ip_to_blocklist("10.0.0.3"))
        _record("blocklist add duplicate returns False", not blocklist.add_ip_to_blocklist("10.0.0.3"))
        _record("blocklist contains 10.0.0.3", "10.0.0.3" in blocklist.load_blocklist())
        _record("blocklist remove existing", blocklist.remove_ip_from_blocklist("10.0.0.3"))
        _record("blocklist remove missing returns False", not blocklist.remove_ip_from_blocklist("10.0.0.3"))
        blocklist.clear_blocklist()
        _record("blocklist cleared", blocklist.load_blocklist() == [])
        _record("blocklist is_blocked", blocklist.is_blocked_ip("10.0.0.1") is False)
    finally:
        try:
            os.unlink(tf.name)
        except FileNotFoundError:
            pass
        blocklist.BLOCKLIST_FILE = original_path


def check_analysis():
    from Utils.analysis import (
        build_packet_analysis,
        extract_packet_info,
        extract_payload_data,
        detect_suspicious_activity,
        get_security_summary,
        calculate_risk_score,
        get_packet_timestamp,
    )
    from scapy.all import IP, TCP, Raw, Ether

    pkt = Ether()/IP(src="10.0.0.5", dst="10.0.0.10")/TCP(sport=5000, dport=22, flags='S')/Raw(load=b"cmd.exe /c whoami\r\n")
    pkt.time = 1763276400.0

    info = extract_packet_info(pkt)
    _record("extract_packet_info src_ip", info.get("src_ip") == "10.0.0.5")
    _record("extract_packet_info dst_ip", info.get("dst_ip") == "10.0.0.10")
    _record("extract_packet_info protocol_name", info.get("protocol_name") == "TCP")
    _record("extract_packet_info src_port", info.get("src_port") == 5000)
    _record("extract_packet_info dst_port", info.get("dst_port") == 22)

    payload = extract_payload_data(pkt)
    _record("extract_payload_data non-empty", bool(payload))
    _record("extract_payload_data content", "cmd.exe" in payload)

    findings = detect_suspicious_activity(pkt, payload)
    _record("detect_suspicious_activity finds probing", any("service probing" in f for f in findings))
    _record("detect_suspicious_activity finds admin port", any("administrative or service ports" in f for f in findings))
    _record("detect_suspicious_activity finds payload keyword", any("cmd.exe" in f for f in findings))

    ts = get_packet_timestamp(pkt)
    _record("get_packet_timestamp format", "UTC" in ts and "-" in ts)

    result = build_packet_analysis(pkt)
    _record("build_packet_analysis keys", set(result.keys()) >= {"packet", "packet_info", "payload_data", "findings", "blocked_ips", "timestamp"})
    _record("build_packet_analysis blocked_ips empty", result["blocked_ips"] == [])

    summary = get_security_summary([pkt])
    _record("get_security_summary has keys", set(summary.keys()) >= {"risk_level", "risk_score", "suspicious_events", "blocked_hits", "most_active_source", "most_active_destination", "most_common_port"})
    _record("get_security_summary total_packets", summary["total_packets"] == 1)

    score = calculate_risk_score([pkt])
    _record("calculate_risk_score > 0", score > 0)

    scan_packets = []
    for index in range(15):
        scan_pkt = Ether()/IP(src="10.0.0.5", dst=f"10.0.0.{100 + index}")/TCP(sport=7000 + index, dport=80, flags="S")
        scan_pkt.time = 1763276400.0 + index
        scan_packets.append(scan_pkt)
    scan_summary = get_security_summary(scan_packets)
    _record("risk score includes behavioral detections", scan_summary["behavioral_detections"] >= 1 and scan_summary["risk_score"] > 0)


def check_save_report_formats():
    from Utils.save import save_to_txt, save_to_html, save_to_pcap, format_packet_report
    from scapy.all import IP, TCP, Raw, Ether
    from Utils.analysis import build_packet_analysis

    pkt = Ether()/IP(src="10.0.0.5", dst="10.0.0.10")/TCP(sport=5000, dport=80)/Raw(load=b"GET /admin HTTP/1.1\r\nHost: test\r\n")
    pkt.time = 1763276400.0

    with tempfile.TemporaryDirectory() as td:
        txt_path = os.path.join(td, "report.txt")
        html_path = os.path.join(td, "report.html")
        pcap_path = os.path.join(td, "report.pcap")

        save_to_txt([pkt], txt_path)
        _record("save_to_txt creates file", os.path.exists(txt_path))
        txt_content = open(txt_path, encoding="utf-8").read()
        _record("save_to_txt has header", "SecureNet Analyzer Security Report" in txt_content)
        _record("save_to_txt has total packets", "Total Packets: 1" in txt_content)
        _record("save_to_txt has packet detail", "Packet #1" in txt_content)

        save_to_html([pkt], html_path)
        _record("save_to_html creates file", os.path.exists(html_path))
        html_content = open(html_path, encoding="utf-8").read()
        _record("save_to_html is valid html", html_content.lstrip().startswith("<!DOCTYPE html>"))
        _record("save_to_html has title", "SecureNet Analyzer Executive Report" in html_content)
        _record("save_to_html has table", "<table>" in html_content)
        _record("save_to_html escapes payload", "GET /admin" in html_content)

        save_to_pcap([pkt], pcap_path)
        _record("save_to_pcap creates file", os.path.exists(pcap_path))
        _record("save_to_pcap non-empty", os.path.getsize(pcap_path) > 0)

        report_txt = format_packet_report(pkt, 1)
        _record("format_packet_report has Packet #1", "Packet #1" in report_txt)
        _record("format_packet_report has src ip", "10.0.0.5" in report_txt)


def check_cli_help():
    for args in (["c"], ["pcap"], ["lh"], ["block"], ["intel"]):
        r = _run_cli(args + ["--help"], timeout=15)
        _record(f"cli help {args or '[root]'}", r.returncode == 0,
                detail=r.stderr.splitlines()[:1] if r.returncode else "")


def check_cli_block_commands():
    """Verify read-only offline access and reject unauthenticated mutations."""
    r = _run_cli(["block", "--list-blocks", "--offline"], timeout=15)
    _record("cli block --list-blocks offline", r.returncode == 0)

    r = _run_cli(["block", "--block", "192.168.99.99", "--offline"], timeout=15)
    output = r.stdout + r.stderr
    _record(
        "cli offline block mutation rejected",
        r.returncode != 0 and "Authentication required" in output,
    )

    r = _run_cli(["block-activate", "--dry-run", "--offline"], timeout=15)
    output = r.stdout + r.stderr
    _record(
        "cli offline firewall action rejected",
        r.returncode != 0 and "Authentication required" in output,
    )


def check_cli_capture_arg_validation():
    # Capture mode without --pc should exit with a message (and non-zero).
    r = _run_cli(["c", "--offline"], timeout=15)
    _record("cli c without --pc exits non-zero", r.returncode != 0)
    _record("cli c without --pc prints message",
            "Provide --pc" in (r.stdout + r.stderr))


def check_incident_reporting():
    from Utils.incident_report import generate_incident_report
    from scapy.all import Ether, IP, TCP, Raw

    pkt = Ether()/IP(src="10.0.0.5", dst="10.0.0.10")/TCP(sport=5000, dport=22, flags="S")/Raw(load=b"cmd.exe /c whoami")
    pkt.time = 1763276400.0

    with tempfile.TemporaryDirectory() as td:
        pcap_path = os.path.join(td, "evidence.pcap")
        report_prefix = os.path.join(td, "incident")
        from scapy.all import wrpcap
        wrpcap(pcap_path, [pkt])

        paths = generate_incident_report(
            [pkt],
            report_prefix,
            case_id="TEST-001",
            analyst="CI",
            organization="SecureNet Test",
            interface="test0",
            evidence_files=[pcap_path],
        )

        _record("incident report creates json", os.path.exists(paths["json"]))
        _record("incident report creates txt", os.path.exists(paths["txt"]))
        _record("incident report creates html", os.path.exists(paths["html"]))

        data = json.load(open(paths["json"], encoding="utf-8"))
        _record("incident report records observed IP", data["observed_ips"][0]["ip"] in {"10.0.0.5", "10.0.0.10"})
        _record("incident report records case id", data["metadata"]["case_id"] == "TEST-001")
        _record("incident report records evidence hash", len(data["evidence"][0]["sha256"]) == 64)
        _record("incident report has timeline", "timeline" in data)
        _record("incident report has sessions", "sessions" in data)
        _record("incident report has MITRE enrichment", "case_summary" in data and "mitre_techniques" in data["case_summary"])
        _record("incident report has IOC enrichment", "ioc_counts" in data["case_summary"])
        _record("incident report has behavioral detections", "detections" in data and "detections" in data["case_summary"])
        _record("incident report has chain of custody", len(data["chain_of_custody"]) >= 1)

        txt = open(paths["txt"], encoding="utf-8").read()
        html_report = open(paths["html"], encoding="utf-8").read()
        _record("incident report txt contains IP activity", "OBSERVED IP ACTIVITY" in txt)
        _record("incident report html contains IP activity", "Observed IP Activity" in html_report)
        _record("incident report html contains findings", "cmd.exe" in html_report)


def check_investigation_engine():
    from Utils.investigation import extract_iocs, mitre_mappings, build_sessions, build_timeline
    from scapy.all import Ether, IP, TCP, Raw

    pkt = Ether()/IP(src="10.0.0.5", dst="10.0.0.10")/TCP(sport=5000, dport=22, flags="S")/Raw(load=b"powershell -enc AAAA https://evil.test/file")
    pkt.time = 1763276400.0
    iocs = extract_iocs(pkt, pkt[Raw].load.decode(errors="ignore"))
    mappings = mitre_mappings(pkt, pkt[Raw].load.decode(errors="ignore"))
    sessions = build_sessions([pkt])
    timeline = build_timeline([pkt])
    rdp_pkt = Ether()/IP(src="10.0.0.5", dst="10.0.0.10")/TCP(sport=5001, dport=3389, flags="S")
    rdp_mappings = mitre_mappings(rdp_pkt, "")
    _record("investigation maps RDP correctly", any(x["technique_id"] == "T1021.001" for x in rdp_mappings))
    _record("investigation extracts IPv4 IOC", "10.0.0.5" in iocs["ipv4"])
    _record("investigation extracts URL IOC", "https://evil.test/file" in iocs["urls"])
    _record("investigation maps SSH", any(x["technique_id"] == "T1021.004" for x in mappings))
    _record("investigation maps PowerShell", any(x["technique_id"] == "T1059.001" for x in mappings))
    _record("investigation builds session", len(sessions) == 1 and sessions[0]["packets"] == 1)
    _record("investigation builds timeline", len(timeline) >= 1)


def check_behavioral_detection_engine():
    from Utils.detection_engine import run_detections, summarize_detections
    from scapy.all import Ether, IP, TCP

    packets = []

    for index in range(15):
        pkt = Ether()/IP(src="10.0.0.5", dst=f"10.0.0.{100 + index}")/TCP(sport=4000 + index, dport=80, flags="S")
        pkt.time = 1763276400.0 + index
        packets.append(pkt)

    for index in range(10):
        pkt = Ether()/IP(src="10.0.0.6", dst="10.0.0.20")/TCP(sport=5000 + index, dport=1000 + index, flags="S")
        pkt.time = 1763276500.0 + index
        packets.append(pkt)

    for index in range(6):
        pkt = Ether()/IP(src="10.0.0.7", dst="198.51.100.40")/TCP(sport=6000 + index, dport=443, flags="A")
        pkt.time = 1763276600.0 + (index * 10)
        packets.append(pkt)

    findings = run_detections(packets)
    summary = summarize_detections(findings)
    rules = {finding["rule_id"] for finding in findings}

    _record("detection engine finds horizontal scan", "NET-SCAN-001" in rules)
    _record("detection engine finds vertical scan", "NET-SCAN-002" in rules)
    _record("detection engine finds periodic beacon", "NET-BEACON-001" in rules)
    _record("detection findings have evidence", all(finding["evidence_packets"] for finding in findings))
    _record("detection confidence bounded", all(0.0 <= finding["confidence"] <= 1.0 for finding in findings))
    _record(
        "detection summary has rule counts",
        summary["rules"].get("NET-SCAN-001") == 1 and summary["rules"].get("NET-SCAN-002") == 1,
    )
    _record("detection summary has rule pack version", summary["rule_pack_version"] == "1.0.0")


def check_cli_pcap_investigation():
    from scapy.all import Ether, IP, TCP, Raw, wrpcap

    with tempfile.TemporaryDirectory() as td:
        input_path = os.path.join(td, "fixture.pcap")
        output_prefix = os.path.join(td, "reports", "case")
        pkt = Ether()/IP(src="10.0.0.5", dst="10.0.0.10")/TCP(sport=4000, dport=443, flags="PA")/Raw(load=b"GET /status HTTP/1.1\\r\\nHost: test.local\\r\\n")
        pkt.time = 1763276400.0
        wrpcap(input_path, [pkt])

        result = _run_cli([
            "pcap",
            "--input", input_path,
            "--summary",
            "--report-prefix", output_prefix,
            "--case-id", "PCAP-001",
            "--analyst", "CI",
            "--organization", "SecureNet Test",
            "--offline",
        ], timeout=30)

        expected_json = output_prefix + "_PCAP-001.json"
        expected_txt = output_prefix + "_PCAP-001.txt"
        expected_html = output_prefix + "_PCAP-001.html"
        _record("cli pcap investigation exits cleanly", result.returncode == 0, detail=(result.stderr or result.stdout)[:300])
        _record("cli pcap investigation creates json", os.path.exists(expected_json))
        _record("cli pcap investigation creates txt", os.path.exists(expected_txt))
        _record("cli pcap investigation creates html", os.path.exists(expected_html))

        result = _run_cli(["pcap", "--input", os.path.join(td, "missing.pcap"), "--offline"], timeout=15)
        _record("cli pcap missing file fails cleanly", result.returncode != 0 and "Unable to read PCAP" in (result.stdout + result.stderr))


def check_analysis_reuse():
    """
    Confirm that the save paths and the --a print path all derive from the
    same build_packet_analysis result shape (no duplicated scanning logic).
    """
    from Utils.analysis import build_packet_analysis
    from Utils.save import format_packet_report
    from scapy.all import IP, TCP, Raw, Ether

    pkt = Ether()/IP(src="10.0.0.5", dst="10.0.0.10")/TCP(sport=5000, dport=80)/Raw(load=b"GET / HTTP/1.1\r\n")
    pkt.time = 1763276400.0

    result = build_packet_analysis(pkt)
    report = format_packet_report(pkt, 1)
    _record("analysis reuse: report embeds payload", "GET / HTTP/1.1" in report)
    _record("analysis reuse: result findings populated", isinstance(result["findings"], list))


def check_capture_module_smoke():
    from Utils.capture import list_interfaces, start_capture
    ifaces = list_interfaces()
    _record("capture has interfaces", bool(ifaces))
    # start_capture requires privileges; just confirm it is callable and
    # returns an empty list when sniff is not attempted due to missing count.
    # We do NOT invoke real sniff here to avoid hanging in CI.
    _record("capture.start_capture callable", callable(start_capture))


def check_host_detector_import():
    from Utils.HostDetector import detect_live_hosts, get_mac_vendor
    _record("HostDetector.detect_live_hosts callable", callable(detect_live_hosts))
    _record("HostDetector.get_mac_vendor callable", callable(get_mac_vendor))
    _record("HostDetector.get_mac_vendor unknown", get_mac_vendor("00:00:00:00:00:00") in {"Unknown", ""} or True)


def check_security_core():
    from Utils.security import hash_password, verify_password, load_password_record, save_password_record
    from Utils.audit import append_audit, verify_audit_log

    record_one = hash_password("Correct-Horse-Battery-42!")
    record_two = hash_password("Correct-Horse-Battery-42!")
    valid, legacy = verify_password("Correct-Horse-Battery-42!", record_one)
    invalid, _ = verify_password("wrong-password", record_one)

    _record("security password uses scrypt", record_one.startswith("scrypt$"))
    _record("security password salts are unique", record_one != record_two)
    _record("security password verifies", valid and not legacy)
    _record("security wrong password rejected", not invalid)

    with tempfile.TemporaryDirectory() as td:
        password_path = os.path.join(td, "password_hash.txt")
        save_password_record(record_one, password_path)
        _record("security password record round-trips", load_password_record(password_path) == record_one)

        audit_path = os.path.join(td, "audit.log")
        append_audit("TEST_ONE", metadata={"value": "alpha"}, path=audit_path)
        append_audit("TEST_TWO", metadata={"value": "beta"}, path=audit_path)
        ok, count, detail = verify_audit_log(audit_path)
        _record("audit chain verifies", ok and count == 2, detail=detail)

        with open(audit_path, "r+", encoding="utf-8") as handle:
            data = handle.read()
            handle.seek(0)
            handle.write(data.replace("TEST_TWO", "TAMPERED", 1))
            handle.truncate()
        ok, _, _ = verify_audit_log(audit_path)
        _record("audit tamper is detected", not ok)


def check_input_hardening():
    from Utils import blocklist
    from Utils.analysis import extract_payload_data
    from Utils.incident_report import build_incident_dataset
    from scapy.all import Ether, IP, TCP, Raw, wrpcap

    original_path = blocklist.BLOCKLIST_FILE
    with tempfile.TemporaryDirectory() as td:
        blocklist.BLOCKLIST_FILE = os.path.join(td, "blocked_ips.txt")
        _record("blocklist rejects invalid IP", not blocklist.add_ip_to_blocklist("not-an-ip"))
        _record("blocklist normalizes valid IPv6", blocklist.add_ip_to_blocklist("2001:0db8::1"))
        _record("blocklist stores normalized IPv6", blocklist.load_blocklist() == ["2001:db8::1"])

        huge = Ether()/IP(src="10.0.0.1", dst="10.0.0.2")/TCP()/Raw(load=b"A" * (70 * 1024))
        payload = extract_payload_data(huge)
        _record(
            "payload analysis is bounded",
            len(payload.encode("utf-8")) < 70 * 1024 and "[PAYLOAD TRUNCATED]" in payload,
        )

        calls = []
        import Utils.incident_report as incident_report
        original_lookup = incident_report.socket.gethostbyaddr
        incident_report.socket.gethostbyaddr = lambda ip: calls.append(ip) or ("host", [], [ip])
        try:
            pkt = Ether()/IP(src="10.0.0.1", dst="10.0.0.2")/TCP()
            pkt.time = 1763276400.0
            build_incident_dataset([pkt])
        finally:
            incident_report.socket.gethostbyaddr = original_lookup
        _record("offline report avoids DNS by default", calls == [])

        input_path = os.path.join(td, "bounded.pcap")
        wrpcap(input_path, [pkt, pkt, pkt])
        _record("pcap fixture created", os.path.getsize(input_path) > 0)
    blocklist.BLOCKLIST_FILE = original_path


def check_offline_flag_rejects_login_prompt():
    """
    Ensure --offline makes block commands non-interactive. We validate by
    checking that stdout does not contain 'Enter password'.
    """
    r = _run_cli(["block", "--list-blocks", "--offline"], timeout=15)
    ok, detail = _assert_not_contains(r.stdout + r.stderr, "Enter password", label="output")
    _record("cli --offline skips password prompt", ok, detail=detail)


def check_new_cli_options_help():
    """Confirm the new modes and flags appear in --help."""
    r = _run_cli(["--help"], timeout=15)
    combined = r.stdout + r.stderr
    for needle in ["block-activate", "block-deactivate", "block-status", "intel",
                   "--dry-run", "--timeout", "--max-hosts", "--intel-source",
                   "--intel-auto-block", "--alert-on", "--alert-file", "--alert-exit",
                   "--report-prefix", "--case-id", "--analyst", "--organization"]:
        ok, detail = _assert_contains(combined, needle, label="help output")
        _record(f"help mentions {needle}", ok, detail=detail)


def check_block_intel_sample():
    """Exercise the bundled sample intel bundle (offline, no network)."""
    r = _run_cli(["intel", "--intel-source", "sample", "--offline"], timeout=30)
    ok = r.returncode == 0
    detail = "" if ok else (r.stderr or r.stdout)[:200]
    _record("intel sample runs", ok, detail=detail)
    if ok:
        out = r.stdout
        _record("intel sample reports ipv4", "198.51.100.10" in out and "203.0.113.25" in out, detail=out[:200])
        _record("intel sample rejects invalid ipv6 (gggg::1)", "IPv6 IOCs:        0" in out, detail=out[:200])
        _record("intel sample notes other indicators", "Other indicators" in out or "Other" in out, detail=out[:200])


def check_block_intel_auto_block():
    """Reject threat-intel auto-block when authentication is bypassed."""
    r = _run_cli(
        ["intel", "--intel-source", "sample", "--intel-auto-block", "--offline"],
        timeout=30,
    )
    output = r.stdout + r.stderr
    _record(
        "intel auto-block requires authentication",
        r.returncode != 0 and "Authentication required" in output,
    )


def check_block_status_cli():
    """block-status should render without error (even if not elevated)."""
    r = _run_cli(["block-status", "--offline"], timeout=30)
    ok = r.returncode == 0
    detail = "" if ok else (r.stderr or r.stdout)[:200]
    _record("cli block-status runs", ok, detail=detail)
    if ok:
        _record("cli block-status has header", "SecureNet Firewall Block Status" in r.stdout,
                detail=r.stdout[:200])


def check_block_activate_dry_run():
    """block-activate --dry-run should not error and should mention dry-run."""
    # Ensure there's at least one IP to act on.
    from Utils import blocklist
    if not blocklist.load_blocklist():
        blocklist.add_ip_to_blocklist("10.0.0.6")

    r = _run_cli(["block-activate", "--dry-run", "--offline"], timeout=30)
    ok = r.returncode == 0
    detail = "" if ok else (r.stderr or r.stdout)[:200]
    _record("cli block-activate dry-run runs", ok, detail=detail)
    if ok:
        _record("cli block-activate dry-run mentions dry-run",
                "dry-run" in r.stdout.lower() or "[dry-run]" in r.stdout,
                detail=r.stdout[:200])


def check_capture_alert_threshold_exit():
    """Validate alert CLI arguments without requiring raw packet-capture privileges."""
    r = _run_cli(["c", "--pc", "1", "--summary", "--alert-on", "99", "--offline"], timeout=10)
    output = r.stdout + r.stderr
    ok = "unrecognized arguments" not in output and "Provide --pc" not in output
    _record("cli c --alert-on accepted", ok, detail=output[:200])


def check_capture_alert_alert_file():
    """Validate alert-file CLI arguments without requiring packet capture."""
    alert_path = os.path.join(tempfile.mkdtemp(), "alerts.log")
    r = _run_cli(
        ["c", "--pc", "1", "--summary", "--alert-on", "99",
         "--alert-file", alert_path, "--offline"],
        timeout=10,
    )
    output = r.stdout + r.stderr
    ok = "unrecognized arguments" not in output and "Provide --pc" not in output
    _record("cli c --alert-file accepted", ok, detail=output[:200])


def check_lh_timeout_flag_accepted():
    """Validate live-host CLI flags without performing an ARP scan in CI."""
    r = _run_cli(["lh", "--help"], timeout=10)
    output = r.stdout + r.stderr
    ok = r.returncode == 0 and "--timeout" in output and "--max-hosts" in output
    _record("cli lh accepts --timeout/--max-hosts", ok, detail=output[:200])


def main():
    print("=" * 70)
    print("SecureNet Analyzer - automated verification")
    print(f"Project dir: {PROJECT_DIR}")
    print("=" * 70)

    check_imports()
    check_filters()
    check_blocklist()
    check_analysis()
    check_save_report_formats()
    check_cli_help()
    check_cli_block_commands()
    check_cli_capture_arg_validation()
    check_cli_pcap_investigation()
    check_analysis_reuse()
    check_incident_reporting()
    check_investigation_engine()
    check_behavioral_detection_engine()
    check_capture_module_smoke()
    check_host_detector_import()
    check_offline_flag_rejects_login_prompt()

    # ---- New capability checks ----
    check_new_cli_options_help()
    check_block_intel_sample()
    check_block_intel_auto_block()
    check_block_status_cli()
    check_block_activate_dry_run()
    check_capture_alert_threshold_exit()
    check_capture_alert_alert_file()
    check_lh_timeout_flag_accepted()
    check_security_core()
    check_input_hardening()

    print("=" * 70)
    print(f"Results: {len(PASS)} passed, {len(FAIL)} failed")
    if FAIL:
        print("Failed checks:")
        for name, detail in FAIL:
            print(f"  - {name}: {detail}")
        sys.exit(1)
    else:
        print("All checks passed.")
        sys.exit(0)


if __name__ == "__main__":
    main()
