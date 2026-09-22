"""Tamper-evident local audit logging for SecureNet Analyzer."""

import hashlib
import json
import os
from datetime import datetime, timezone

from Utils.security import atomic_write_text

AUDIT_FILE = "audit.log"
AUDIT_VERSION = 1


def _canonical(record):
    payload = dict(record)
    payload.pop("event_hash", None)
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _last_hash(path):
    try:
        with open(path, "r", encoding="utf-8") as handle:
            last = None
            for line in handle:
                if line.strip():
                    last = json.loads(line)
            return last.get("event_hash", "GENESIS") if last else "GENESIS"
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return "GENESIS"


def append_audit(action, actor="local", metadata=None, path=AUDIT_FILE):
    """Append a hash-chained audit event.

    The chain is tamper-evident, not a replacement for an external immutable
    logging system or a cryptographic signature.
    """
    record = {
        "version": AUDIT_VERSION,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "action": str(action),
        "actor": str(actor),
        "metadata": metadata or {},
        "previous_hash": _last_hash(path),
    }
    record["event_hash"] = hashlib.sha256(_canonical(record).encode("utf-8")).hexdigest()

    directory = os.path.dirname(os.path.abspath(path)) or "."
    os.makedirs(directory, exist_ok=True)
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=True, ensure_ascii=True) + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    return record


def verify_audit_log(path=AUDIT_FILE):
    """Return (valid, checked_events, error)."""
    previous_hash = "GENESIS"
    checked = 0
    try:
        with open(path, "r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, 1):
                if not line.strip():
                    continue
                record = json.loads(line)
                if record.get("previous_hash") != previous_hash:
                    return False, checked, f"broken previous_hash at line {line_number}"
                event_hash = record.get("event_hash")
                if not event_hash:
                    return False, checked, f"missing event_hash at line {line_number}"
                expected = hashlib.sha256(
                    _canonical(record).encode("utf-8")
                ).hexdigest()
                if not hmac_compare(event_hash, expected):
                    return False, checked, f"invalid event_hash at line {line_number}"
                previous_hash = event_hash
                checked += 1
    except FileNotFoundError:
        return True, 0, ""
    except (OSError, json.JSONDecodeError) as exc:
        return False, checked, str(exc)
    return True, checked, ""


def hmac_compare(left, right):
    """Constant-time comparison helper for audit digests."""
    import hmac
    return hmac.compare_digest(str(left), str(right))
