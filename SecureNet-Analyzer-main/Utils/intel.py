"""
Threat intelligence ingestion for SecureNet Analyzer.

Loads a STIX2 JSON bundle (or the bundled sample), extracts IPv4/IPv6
indicators, and optionally adds them to the local blocklist.

This module is intentionally offline-first: no network fetch is performed.
An operator can supply their own STIX2 bundle path via --intel-source, or
use '--intel-source sample' to exercise the bundled sample data.

Input format expected: a STIX2 Bundle JSON where indicators may have
a 'pattern' field containing an IP address pattern, e.g.
  [file:hashes.MD5 = 'd41d8cd98f00b204e9800998ecf8427e']
  [ipv4-addr:value = '192.0.2.1']
  [ipv6-addr:value = '2001:db8::1']

Only IPv4/IPv6 indicator patterns are extracted and added to the
local blocklist. Other indicator types are counted and reported but
not added (the blocklist is IP-only).
"""

import ipaddress
import json
import os
import re
import sys
from typing import Any, Dict, List, Tuple

import colorama

colorama.init(autoreset=True)

IPV4_PATTERN = re.compile(r"ipv4-addr:value\s*=\s*'([^']+)'", re.IGNORECASE)
IPV6_PATTERN = re.compile(r"ipv6-addr:value\s*=\s*'([^']+)'", re.IGNORECASE)

SAMPLE_STIX_PATH = os.path.join(os.path.dirname(__file__), "sample_intel.stix2.json")


def _is_valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _extract_ips_from_indicator(indicator: Dict[str, Any]) -> Tuple[List[str], List[str]]:
    """Return (ipv4_list, ipv6_list) found in one indicator object."""
    pattern = indicator.get("pattern") or ""
    ipv4: List[str] = []
    ipv6: List[str] = []

    for match in IPV4_PATTERN.findall(pattern):
        if _is_valid_ip(match):
            ipv4.append(str(ipaddress.ip_address(match)))
    for match in IPV6_PATTERN.findall(pattern):
        if _is_valid_ip(match):
            ipv6.append(str(ipaddress.ip_address(match)))

    return ipv4, ipv6


def load_stix_bundle(path: str) -> List[Dict[str, Any]]:
    """Load a STIX2 bundle JSON file and return the list of objects."""
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    if isinstance(data, dict) and "objects" in data:
        return data["objects"]

    if isinstance(data, list):
        return data

    raise ValueError(
        "Unsupported STIX2 bundle format. Expected an object with an 'objects' list, or a JSON array."
    )


def extract_iocs(bundle_path: str) -> Dict[str, Any]:
    """Extract IOC summary from a STIX2 bundle.

    Returns a dict with:
      - total_objects
      - total_indicators
      - ipv4_set
      - ipv6_set
      - other_count (indicators that were not IP-based)
      - source_path
    """
    objects = load_stix_bundle(bundle_path)

    total_objects = len(objects)
    indicators = [obj for obj in objects if obj.get("type") == "indicator"]
    total_indicators = len(indicators)

    ipv4_set: set = set()
    ipv6_set: set = set()
    other_count = 0

    for ind in indicators:
        ipv4, ipv6 = _extract_ips_from_indicator(ind)
        ipv4_set.update(ipv4)
        ipv6_set.update(ipv6)
        if not ipv4 and not ipv6:
            other_count += 1

    return {
        "total_objects": total_objects,
        "total_indicators": total_indicators,
        "ipv4_set": sorted(ipv4_set),
        "ipv6_set": sorted(ipv6_set),
        "other_count": other_count,
        "source_path": bundle_path,
    }


def print_intel_report(iocs: Dict[str, Any]) -> None:
    """Print a terminal report of the extracted IOCs."""
    print("")
    print("Threat Intel Summary")
    print("=" * 40)
    print(f"Source:           {iocs['source_path']}")
    print(f"Bundle objects:   {iocs['total_objects']}")
    print(f"Indicators:       {iocs['total_indicators']}")
    print(f"IPv4 IOCs:        {len(iocs['ipv4_set'])}")
    print(f"IPv6 IOCs:        {len(iocs['ipv6_set'])}")
    print(f"Other indicators: {iocs['other_count']} (not added to blocklist)")
    print("")

    if iocs["ipv4_set"]:
        print("IPv4 indicators:")
        for ip in iocs["ipv4_set"]:
            print(f"  - {ip}")
        print("")

    if iocs["ipv6_set"]:
        print("IPv6 indicators:")
        for ip in iocs["ipv6_set"]:
            print(f"  - {ip}")
        print("")


def run_intel(args) -> None:
    """Entry point for the 'intel' CLI option."""
    if args.intel_source == "sample" or not args.intel_source:
        if os.path.exists(SAMPLE_STIX_PATH):
            bundle_path = SAMPLE_STIX_PATH
            print(f"Using bundled sample intel: {bundle_path}")
        else:
            print("No bundled sample intel found and no --intel-source supplied.")
            print("Provide a STIX2 JSON bundle path with --intel-source <path>.")
            sys.exit(1)
    else:
        bundle_path = args.intel_source
        if not os.path.exists(bundle_path):
            print(f"Intel source not found: {bundle_path}")
            sys.exit(1)

    iocs = extract_iocs(bundle_path)
    print_intel_report(iocs)

    total_iocs = len(iocs["ipv4_set"]) + len(iocs["ipv6_set"])
    if args.intel_auto_block:
        if total_iocs == 0:
            print("No IP-based IOCs to add.")
            return

        from Utils.blocklist import add_ip_to_blocklist, load_blocklist

        added = 0
        already = 0
        for ip in iocs["ipv4_set"]:
            if add_ip_to_blocklist(ip):
                added += 1
            else:
                already += 1
        for ip in iocs["ipv6_set"]:
            if add_ip_to_blocklist(ip):
                added += 1
            else:
                already += 1

        print(f"Intel auto-block result: {added} added, {already} already present.")
        print(f"Local blocklist now has {len(load_blocklist())} IP(s).")
    else:
        print("To add these IOCs to the local blocklist, re-run with --intel-auto-block.")
