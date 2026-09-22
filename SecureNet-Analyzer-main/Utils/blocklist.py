"""Validated and atomic local IP blocklist storage."""

import ipaddress
import os

from Utils.audit import append_audit
from Utils.security import atomic_write_text

BLOCKLIST_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), "blocked_ips.txt")


def _normalize_ip(value):
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError:
        return None


def load_blocklist():
    """Load, validate, normalize, and deduplicate local IP entries."""
    if not os.path.exists(BLOCKLIST_FILE):
        return []

    entries = []
    seen = set()
    try:
        with open(BLOCKLIST_FILE, "r", encoding="utf-8") as file:
            for line in file:
                normalized = _normalize_ip(line)
                if normalized and normalized not in seen:
                    seen.add(normalized)
                    entries.append(normalized)
    except OSError:
        return []
    return entries


def save_blocklist(blocked_ips):
    """Atomically persist only valid normalized IP addresses."""
    normalized = []
    seen = set()
    for ip in blocked_ips:
        value = _normalize_ip(ip)
        if value and value not in seen:
            seen.add(value)
            normalized.append(value)

    content = "".join(f"{ip}\n" for ip in normalized)
    atomic_write_text(BLOCKLIST_FILE, content)


def add_ip_to_blocklist(ip):
    """Validate and add one IP, recording a tamper-evident audit event."""
    clean_ip = _normalize_ip(ip)
    if not clean_ip:
        return False

    blocked = load_blocklist()
    if clean_ip in blocked:
        return False

    blocked.append(clean_ip)
    save_blocklist(blocked)
    append_audit("BLOCKLIST_ADD", metadata={"ip": clean_ip})
    return True


def remove_ip_from_blocklist(ip):
    """Remove one normalized IP and record the change."""
    clean_ip = _normalize_ip(ip)
    if not clean_ip:
        return False

    blocked = load_blocklist()
    if clean_ip not in blocked:
        return False

    blocked.remove(clean_ip)
    save_blocklist(blocked)
    append_audit("BLOCKLIST_REMOVE", metadata={"ip": clean_ip})
    return True


def clear_blocklist():
    """Clear all local blocklist entries and audit the operation."""
    previous = load_blocklist()
    save_blocklist([])
    append_audit("BLOCKLIST_CLEAR", metadata={"removed_count": len(previous)})
    return bool(previous)


def is_blocked_ip(ip):
    """Return whether an IP is present in normalized blocklist state."""
    clean_ip = _normalize_ip(ip)
    return clean_ip in set(load_blocklist()) if clean_ip else False
