"""Signed approvals — HMAC-SHA256, pure standard library.

A grant record is a JSON-serializable mapping; its signature is the
HMAC-SHA256 of the record's canonical JSON (sorted keys, no whitespace)
under a 32-byte signing key. Verification is constant time
(``hmac.compare_digest``) and fails closed on any malformation — a tampered
field, a wrong key, or a non-string signature all simply fail.

Keys are generated with the stdlib ``secrets`` module and stored as hex.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from pathlib import Path

__all__ = [
    "ApprovalError",
    "canonical",
    "generate_key",
    "load_key",
    "sign",
    "sign_grant",
    "verify",
    "verify_grant",
]

KEY_BYTES = 32
SIGNATURE_FIELD = "signature"


class ApprovalError(ValueError):
    """Invalid key or signature material (fail closed)."""


def generate_key() -> str:
    """A fresh signing key as hex (write it to a file with mode 0o600)."""
    return secrets.token_hex(KEY_BYTES)


def load_key(path) -> bytes:
    """Load a hex signing key from a file (exactly 32 bytes)."""
    text = Path(path).read_text(encoding="utf-8").strip()
    try:
        key = bytes.fromhex(text)
    except ValueError:
        raise ApprovalError("key file is not valid hex")
    if len(key) != KEY_BYTES:
        raise ApprovalError(f"key must be exactly {KEY_BYTES} bytes")
    return key


def canonical(record: dict) -> str:
    """Canonical JSON: sorted keys, no whitespace — the signed form."""
    return json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)


def sign(record: dict, key: bytes) -> str:
    """HMAC-SHA256 signature (hex) over the record's canonical JSON."""
    _require_key(key)
    return hmac.new(key, canonical(record).encode("utf-8"), hashlib.sha256).hexdigest()


def verify(record: dict, signature: str, key: bytes) -> bool:
    """Constant-time signature check; any malformation → False."""
    if not isinstance(signature, str):
        return False
    try:
        expected = sign(record, key)
    except (ApprovalError, TypeError, ValueError):
        return False
    return hmac.compare_digest(expected, signature)


def sign_grant(record: dict, key: bytes) -> dict:
    """Return the grant with its signature embedded."""
    if SIGNATURE_FIELD in record:
        raise ApprovalError("record already carries a signature")
    grant = dict(record)
    grant[SIGNATURE_FIELD] = sign(record, key)
    return grant


def verify_grant(grant: dict, key: bytes) -> bool:
    """Verify a grant's embedded signature (fail closed)."""
    if not isinstance(grant, dict):
        return False
    signature = grant.get(SIGNATURE_FIELD)
    if not isinstance(signature, str):
        return False
    record = {k: v for k, v in grant.items() if k != SIGNATURE_FIELD}
    return verify(record, signature, key)


def _require_key(key: bytes) -> None:
    if not isinstance(key, (bytes, bytearray)) or len(key) != KEY_BYTES:
        raise ApprovalError(f"key must be exactly {KEY_BYTES} bytes")
