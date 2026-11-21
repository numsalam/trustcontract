"""Append-only, hash-chained audit log — JSONL, tamper-evident.

Every record is one JSON line::

    {"seq": 1, "ts": 1732196464.123, "event": "grant.added", ...,
     "prev": "<sha256 hex>", "hash": "<sha256 hex>"}

where ``hash`` is the SHA-256 of the record's canonical JSON without its
``hash`` field, and ``prev`` is the previous record's hash (all-zero for
the first record). Verification walks the chain, so any edit, deletion, or
reordering after the fact is detected. Appends are single-writer, bounded
in size, and refuse reserved field names.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from pathlib import Path

__all__ = ["AuditError", "AuditLog"]

MAX_FIELDS = 32
MAX_RECORD_BYTES = 64 * 1024
MAX_TAIL = 1000
_RESERVED = ("seq", "ts", "event", "prev", "hash")
_EVENT = re.compile(r"^[a-z][a-z0-9.]{0,63}$")
_ZERO = "0" * 64


class AuditError(ValueError):
    """Invalid audit input or corrupt log (fail closed)."""


def _canonical(record: dict) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)


class AuditLog:
    def __init__(self, path):
        self.path = Path(path)

    # -- append ------------------------------------------------------------

    def append(self, event: str, **fields) -> dict:
        """Append one record; returns the record as written."""
        if not _EVENT.match(event or ""):
            raise AuditError("event must match ^[a-z][a-z0-9.]{0,63}$")
        if len(fields) > MAX_FIELDS:
            raise AuditError(f"at most {MAX_FIELDS} fields per record")
        clash = sorted(set(fields) & set(_RESERVED))
        if clash:
            raise AuditError(f"fields may not use reserved names: {', '.join(clash)}")
        last = self._last()
        record = {
            "seq": (last["seq"] + 1) if last else 1,
            "ts": round(time.time(), 3),
            "event": event,
            **fields,
        }
        record["prev"] = last["hash"] if last else _ZERO
        body = _canonical(record)
        if len(body) > MAX_RECORD_BYTES:
            raise AuditError(f"record too large (>{MAX_RECORD_BYTES} bytes canonical)")
        record["hash"] = hashlib.sha256(body.encode("utf-8")).hexdigest()
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, sort_keys=True) + "\n")
        return record

    def _last(self) -> dict | None:
        """The last record, for chaining; a corrupt tail fails closed."""
        if not self.path.exists():
            return None
        last = None
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    last = line
        if last is None:
            return None
        try:
            record = json.loads(last)
        except ValueError:
            raise AuditError("audit log is corrupt: last line is not valid JSON")
        if not isinstance(record, dict) or not isinstance(record.get("seq"), int) \
                or not isinstance(record.get("hash"), str):
            raise AuditError("audit log is corrupt: last record is malformed")
        return record

    # -- read --------------------------------------------------------------

    def records(self) -> list:
        """All records, strictly parsed (corrupt lines raise AuditError)."""
        out = []
        if not self.path.exists():
            return out
        for n, line in enumerate(self.path.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                continue
            try:
                out.append(json.loads(line))
            except ValueError:
                raise AuditError(f"line {n}: not valid JSON")
        return out

    def verify(self) -> tuple:
        """Walk the hash chain → (ok, detail)."""
        try:
            recs = self.records()
        except AuditError as exc:
            return False, str(exc)
        prev = _ZERO
        for expect, rec in enumerate(recs, 1):
            where = f"record {expect}"
            if not isinstance(rec, dict):
                return False, f"{where}: not a JSON object"
            if rec.get("seq") != expect:
                return False, f"{where}: bad seq ({rec.get('seq')!r})"
            if rec.get("prev") != prev:
                return False, f"{where}: broken chain link"
            body = {k: v for k, v in rec.items() if k != "hash"}
            digest = hashlib.sha256(_canonical(body).encode("utf-8")).hexdigest()
            if rec.get("hash") != digest:
                return False, f"{where}: hash mismatch"
            prev = rec["hash"]
        return True, f"ok: {len(recs)} records"

    def tail(self, n: int = 20) -> list:
        """The last n records (n bounded to 1..1000)."""
        if not isinstance(n, int) or not 1 <= n <= MAX_TAIL:
            raise AuditError(f"n must be an integer in 1..{MAX_TAIL}")
        return self.records()[-n:]
