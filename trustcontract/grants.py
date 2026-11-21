"""Grant store — signed, expiring, optionally one-shot capability grants.

Grants persist as a single JSON file (``{"grants": [...]}``). Fail closed
in both directions: a missing or empty store yields zero grants, and a
corrupt store yields zero grants AND refuses modifications — a half-written
or tampered file can never silently widen access. Every grant carries an
HMAC signature; a grant whose signature does not verify is ignored
everywhere (find, consume, revoke) and reported as ``invalid-signature``.
"""

from __future__ import annotations

import json
import secrets
import time
from pathlib import Path

from .approvals import sign_grant, verify_grant

__all__ = ["GrantStore", "GrantStoreError"]

MAX_NOTE = 500
MAX_GRANTS = 10000
MAX_LIFETIME = 10 * 366 * 24 * 3600  # ~10 years
MAX_USES = 1000


class GrantStoreError(ValueError):
    """Grant store is corrupt or the operation is invalid (fail closed)."""


class GrantStore:
    """Persistent, signed grants for (principal, capability) pairs."""

    def __init__(self, path, key: bytes):
        self.path = Path(path)
        self.key = key
        self._grants, self._ok = self._load()

    @property
    def corrupt(self) -> bool:
        """True when the store file exists but cannot be trusted."""
        return not self._ok

    # -- persistence -----------------------------------------------------

    def _load(self):
        if not self.path.exists():
            return [], True
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return [], False
        if not isinstance(data, dict) or not isinstance(data.get("grants"), list):
            return [], False
        grants = data["grants"]
        if len(grants) > MAX_GRANTS or not all(isinstance(g, dict) for g in grants):
            return [], False
        return grants, True

    def _save(self) -> None:
        if not self._ok:
            raise GrantStoreError("grant store is corrupt; refusing to modify it")
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_text(
            json.dumps({"grants": self._grants}, indent=2) + "\n", encoding="utf-8"
        )
        tmp.replace(self.path)  # atomic on POSIX

    def _require_ok(self) -> None:
        if not self._ok:
            raise GrantStoreError("grant store is corrupt; refusing to modify it")

    # -- operations --------------------------------------------------------

    def add(
        self,
        principal: str,
        capability: str,
        granted_by: str,
        expires_at: float,
        max_uses: int = 1,
        note: str = "",
        confirmation: str | None = None,
        now: float | None = None,
    ) -> dict:
        """Create, sign, and persist a new grant; returns the signed grant."""
        self._require_ok()
        now = time.time() if now is None else now
        for label, value in (
            ("principal", principal),
            ("capability", capability),
            ("granted_by", granted_by),
        ):
            if not isinstance(value, str) or not 1 <= len(value) <= 100:
                raise GrantStoreError(f"{label} must be a string of 1..100 chars")
        if not isinstance(note, str) or len(note) > MAX_NOTE:
            raise GrantStoreError(f"note must be a string of at most {MAX_NOTE} chars")
        if not isinstance(max_uses, int) or not 1 <= max_uses <= MAX_USES:
            raise GrantStoreError(f"max_uses must be an integer in 1..{MAX_USES}")
        if not isinstance(expires_at, (int, float)) or not now < expires_at <= now + MAX_LIFETIME:
            raise GrantStoreError("expires_at must be in the future, at most ~10 years out")
        if confirmation is not None and (not isinstance(confirmation, str) or len(confirmation) > 100):
            raise GrantStoreError("confirmation must be a string of at most 100 chars")
        if len(self._grants) >= MAX_GRANTS:
            raise GrantStoreError(f"grant store is full ({MAX_GRANTS} grants)")
        record = {
            "id": "g_" + secrets.token_hex(6),
            "principal": principal,
            "capability": capability,
            "granted_by": granted_by,
            "granted_at": round(now, 3),
            "expires_at": round(expires_at, 3),
            "uses": max_uses,
            "max_uses": max_uses,
            "note": note,
        }
        if confirmation is not None:
            record["confirmation"] = confirmation
        grant = sign_grant(record, self.key)
        self._grants.append(grant)
        self._save()
        return grant

    def find(self, principal: str, capability: str, now: float | None = None) -> dict | None:
        """The newest valid, unexpired, unused grant for this pair, or None."""
        now = time.time() if now is None else now
        best = None
        for grant in self._grants:
            if not verify_grant(grant, self.key):
                continue
            if grant.get("principal") != principal or grant.get("capability") != capability:
                continue
            if grant.get("expires_at", 0) <= now or grant.get("uses", 0) < 1:
                continue
            if best is None or grant.get("granted_at", 0) > best.get("granted_at", 0):
                best = grant
        return best

    def consume(self, grant_id: str, now: float | None = None) -> bool:
        """Spend one use of a grant (a one-shot grant dies on use)."""
        if not self._ok or not isinstance(grant_id, str):
            return False
        now = time.time() if now is None else now
        for idx, grant in enumerate(self._grants):
            if grant.get("id") != grant_id or not verify_grant(grant, self.key):
                continue
            if grant.get("expires_at", 0) <= now or grant.get("uses", 0) < 1:
                return False
            record = {k: v for k, v in grant.items() if k != "signature"}
            record["uses"] = record["uses"] - 1
            self._grants[idx] = sign_grant(record, self.key)
            self._save()
            return True
        return False

    def revoke(self, grant_id: str) -> bool:
        """Revoke a grant (only grants with valid signatures are touched)."""
        if not self._ok or not isinstance(grant_id, str):
            return False
        for idx, grant in enumerate(self._grants):
            if grant.get("id") != grant_id or not verify_grant(grant, self.key):
                continue
            record = {k: v for k, v in grant.items() if k != "signature"}
            record["uses"] = 0
            record["revoked"] = True
            self._grants[idx] = sign_grant(record, self.key)
            self._save()
            return True
        return False

    def purge_expired(self, now: float | None = None) -> int:
        """Drop dead grants (expired, used-up, bad signature); returns count."""
        if not self._ok:
            return 0
        now = time.time() if now is None else now
        keep, removed = [], 0
        for grant in self._grants:
            dead = (
                not verify_grant(grant, self.key)
                or grant.get("expires_at", 0) <= now
                or grant.get("uses", 0) < 1
            )
            if dead:
                removed += 1
            else:
                keep.append(grant)
        if removed:
            self._grants = keep
            self._save()
        return removed

    def list(self, now: float | None = None) -> list:
        """All grants with a computed status for display."""
        now = time.time() if now is None else now
        out = []
        for grant in self._grants:
            entry = dict(grant)
            if not verify_grant(grant, self.key):
                entry["status"] = "invalid-signature"
            elif grant.get("revoked"):
                entry["status"] = "revoked"
            elif grant.get("expires_at", 0) <= now:
                entry["status"] = "expired"
            elif grant.get("uses", 0) < 1:
                entry["status"] = "used-up"
            else:
                entry["status"] = "valid"
            out.append(entry)
        return out
