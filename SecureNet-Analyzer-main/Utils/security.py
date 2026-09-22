"""Security primitives for SecureNet Analyzer.

Password storage uses scrypt with a unique random salt. Legacy SHA-256
password files can be verified once and transparently upgraded.
"""

import base64
import binascii
import hashlib
import hmac
import os
import re
import tempfile

PROJECT_ROOT = os.path.dirname(os.path.dirname(__file__))
PASSWORD_FILE = os.path.join(PROJECT_ROOT, "password_hash.txt")
SCRYPT_PREFIX = "scrypt"
_SCRYPT_N = 2**17
_SCRYPT_R = 8
_SCRYPT_P = 1
_SALT_BYTES = 16
_DK_BYTES = 64
_MAX_SCRYPT_N = 2**17
_SCRYPT_MAXMEM = 256 * 1024 * 1024
_MAX_SCRYPT_R = 32
_MAX_SCRYPT_P = 8
_MAX_SALT_BYTES = 64
_MIN_DK_BYTES = 16


def _b64(data):
    return base64.b64encode(data).decode("ascii")


def _unb64(value):
    return base64.b64decode(value.encode("ascii"), validate=True)


def hash_password(password):
    """Return a versioned scrypt password record."""
    if not isinstance(password, str) or not password:
        raise ValueError("Password must be a non-empty string.")
    salt = os.urandom(_SALT_BYTES)
    derived = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=_SCRYPT_N,
        r=_SCRYPT_R,
        p=_SCRYPT_P,
        dklen=_DK_BYTES,
    )
    return "$".join([
        SCRYPT_PREFIX,
        str(_SCRYPT_N),
        str(_SCRYPT_R),
        str(_SCRYPT_P),
        _b64(salt),
        _b64(derived),
    ])


def _verify_scrypt(password, record):
    parts = record.split("$")
    if len(parts) != 6 or parts[0] != SCRYPT_PREFIX:
        return False
    try:
        n, r, p = (int(parts[index]) for index in (1, 2, 3))
        salt = _unb64(parts[4])
        expected = _unb64(parts[5])
        if (n < 2**10 or n > _MAX_SCRYPT_N or r < 1 or r > _MAX_SCRYPT_R or
                p < 1 or p > _MAX_SCRYPT_P):
            return False
        if len(salt) > _MAX_SALT_BYTES or len(expected) < _MIN_DK_BYTES or len(expected) > 128:
            return False
        if not salt or not expected:
            return False
        actual = hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt,
            n=n,
            r=r,
            p=p,
            dklen=len(expected),
            maxmem=_SCRYPT_MAXMEM,
        )
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError, binascii.Error):
        return False


def verify_password(password, record):
    """Verify a password record.

    Returns (valid, legacy_sha256). The second value indicates whether a
    successful legacy SHA-256 verification should be transparently upgraded.
    """
    if not isinstance(password, str) or not isinstance(record, str):
        return False, False

    if record.startswith(f"{SCRYPT_PREFIX}$"):
        return _verify_scrypt(password, record), False

    if re.fullmatch(r"[0-9a-fA-F]{64}", record):
        legacy = hashlib.sha256(password.encode("utf-8")).hexdigest()
        return hmac.compare_digest(legacy, record), True

    return False, False


def atomic_write_text(path, content, mode=0o600):
    """Atomically replace a UTF-8 text file and request restrictive perms."""
    directory = os.path.dirname(os.path.abspath(path)) or "."
    os.makedirs(directory, exist_ok=True)
    fd, temp_path = tempfile.mkstemp(prefix=".securenet-", dir=directory, text=True)
    try:
        try:
            os.chmod(temp_path, mode)
        except OSError:
            pass
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, path)
    except Exception:
        try:
            os.unlink(temp_path)
        except FileNotFoundError:
            pass
        raise


def save_password_record(record, path=PASSWORD_FILE):
    """Persist a password verifier without exposing partial writes."""
    atomic_write_text(path, record + "\n")


def load_password_record(path=PASSWORD_FILE):
    """Load a password verifier, returning None when it does not exist."""
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return handle.read().strip()
    except FileNotFoundError:
        return None
