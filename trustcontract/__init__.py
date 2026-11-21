"""TrustContract — declarative capability contracts, signed approvals, and a
tamper-evident audit log. Pure Python, zero dependencies, fail closed.

Extracted from the permission/approval pattern proven twice in the wild:
Numa's approval queue (life-agent) and SKILLSEED's permission-gated skills.

Quick use::

    from trustcontract import (
        AuditLog, DecisionEngine, GrantStore, Request,
        load_contracts_file, load_key,
    )

    contracts = load_contracts_file("contracts.yaml")
    grants = GrantStore("grants.json", load_key("key.hex"))
    audit = AuditLog("audit.jsonl")
    engine = DecisionEngine(contracts, grants, audit)
    decision = engine.evaluate(Request(principal="numa", capability="file.write"))
"""

__version__ = "0.1.0"

from .approvals import (
    ApprovalError,
    canonical,
    generate_key,
    load_key,
    sign,
    sign_grant,
    verify,
    verify_grant,
)
from .audit import AuditError, AuditLog
from .contract import (
    DEFAULTS,
    RISKS,
    Contract,
    ContractError,
    load_contracts,
    load_contracts_file,
)
from .consequences import Acknowledgment, ConsequenceError, Consequences
from .engine import ALLOW, DENY, ESCALATE, Decision, DecisionEngine, Request
from .grants import GrantStore, GrantStoreError
from .yaml_min import YamlMinError, loads, loads_min

__all__ = [
    "ALLOW",
    "DENY",
    "ESCALATE",
    "Acknowledgment",
    "ApprovalError",
    "AuditError",
    "AuditLog",
    "Contract",
    "ContractError",
    "ConsequenceError",
    "Consequences",
    "Decision",
    "DecisionEngine",
    "DEFAULTS",
    "GrantStore",
    "GrantStoreError",
    "Request",
    "RISKS",
    "YamlMinError",
    "canonical",
    "generate_key",
    "load_contracts",
    "load_contracts_file",
    "load_key",
    "loads",
    "loads_min",
    "sign",
    "sign_grant",
    "verify",
    "verify_grant",
]
