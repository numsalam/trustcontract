"""Declarative capability contracts.

A contract is the single source of truth for what a capability may do, how
risky it is, what a human must acknowledge to approve it, and what a grant
for it should look like (lifetime, uses). Contracts are loaded from YAML
(or JSON) and validated eagerly — an invalid contract file fails at load
time, never at decision time (fail closed).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from .consequences import Consequences, ConsequenceError
from .yaml_min import YamlMinError, loads

__all__ = [
    "DEFAULTS",
    "Contract",
    "ContractError",
    "RISKS",
    "load_contracts",
    "load_contracts_file",
]

RISKS = ("low", "medium", "high", "critical")
DEFAULTS = ("allow", "ask", "deny")
MAX_EXPIRY = 10 * 366 * 24 * 3600  # sane ceiling: ~10 years
MAX_USES = 1000
_NAME = re.compile(r"^[a-z0-9][a-z0-9._-]{0,99}$")


class ContractError(ValueError):
    """Invalid contract definition (fail closed)."""


@dataclass(frozen=True)
class Contract:
    """One declared capability.

    default  ``allow`` — permitted without a grant (still audited).
             ``ask``   — denied until a human grants it; requesting
                         escalates with the contract's acknowledgments.
             ``deny``  — denied; only a pre-existing grant overrides.
    locked   hard deny — no grant can ever enable the capability.
    """

    name: str
    description: str = ""
    risk: str = "medium"
    default: str = "ask"
    locked: bool = False
    consequences: Consequences = field(default_factory=Consequences)
    expiry_seconds: int = 3600  # suggested grant lifetime
    max_uses: int = 1  # suggested grant uses (1 = one-shot)

    def acknowledgments(self) -> tuple:
        """Acknowledgment requirements for approving this capability."""
        return self.consequences.requirements(self.risk)

    @classmethod
    def from_dict(cls, data) -> "Contract":
        if not isinstance(data, dict):
            raise ContractError("each contract must be a mapping")
        name = data.get("name")
        if not isinstance(name, str) or not _NAME.match(name):
            raise ContractError("contract name must match ^[a-z0-9][a-z0-9._-]{0,99}$")
        description = data.get("description", "")
        if not isinstance(description, str) or len(description) > 500:
            raise ContractError("description must be a string of at most 500 chars")
        risk = data.get("risk", "medium")
        if risk not in RISKS:
            raise ContractError(f"risk must be one of: {', '.join(RISKS)}")
        default = data.get("default", "ask")
        if default not in DEFAULTS:
            raise ContractError(f"default must be one of: {', '.join(DEFAULTS)}")
        locked = data.get("locked", False)
        if not isinstance(locked, bool):
            raise ContractError("locked must be a boolean")
        expiry = data.get("expiry_seconds", 3600)
        if not isinstance(expiry, int) or not 1 <= expiry <= MAX_EXPIRY:
            raise ContractError(f"expiry_seconds must be an integer in 1..{MAX_EXPIRY}")
        max_uses = data.get("max_uses", 1)
        if not isinstance(max_uses, int) or not 1 <= max_uses <= MAX_USES:
            raise ContractError(f"max_uses must be an integer in 1..{MAX_USES}")
        try:
            consequences = Consequences.from_dict(data.get("consequences"))
        except ConsequenceError as exc:
            raise ContractError(f"{name}: {exc}")
        return cls(name, description, risk, default, locked, consequences, expiry, max_uses)


def load_contracts(text: str) -> dict:
    """Load contracts from YAML/JSON text → {name: Contract}.

    Duplicate names and anything malformed are rejected (fail closed).
    """
    try:
        data = loads(text)
    except YamlMinError as exc:
        raise ContractError(f"YAML parse error: {exc}")
    if not isinstance(data, dict) or "contracts" not in data:
        raise ContractError("top level must be a mapping with a 'contracts' list")
    entries = data["contracts"]
    if not isinstance(entries, list):
        raise ContractError("'contracts' must be a list")
    contracts: dict = {}
    for entry in entries:
        contract = Contract.from_dict(entry)
        if contract.name in contracts:
            raise ContractError(f"duplicate contract name: {contract.name}")
        contracts[contract.name] = contract
    return contracts


def load_contracts_file(path) -> dict:
    """Load contracts from a YAML/JSON file path."""
    return load_contracts(Path(path).read_text(encoding="utf-8"))
