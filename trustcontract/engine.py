"""Decision engine — evaluate requests against contracts and grants.

The decision model, fail closed at every step:

1. unknown capability       → deny  (undeclared capabilities never run)
2. contract locked          → deny  (no grant can ever override a lock)
3. valid signed grant       → allow (the grant id is cited in the decision)
4. contract default "allow" → allow
5. contract default "ask"   → escalate (approval required; the contract's
                               acknowledgments are attached)
6. contract default "deny"  → deny

Every evaluation is appended to the audit log. The engine never executes
anything — it only decides. Consuming a one-shot grant is explicit
(``consume``) so read-only checks never burn approvals.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from .contract import Contract
from .grants import GrantStore

__all__ = ["ALLOW", "DENY", "ESCALATE", "Decision", "DecisionEngine", "Request"]

ALLOW, DENY, ESCALATE = "allow", "deny", "escalate"


@dataclass(frozen=True)
class Request:
    """A principal asking to exercise a capability."""

    principal: str
    capability: str
    args: dict = field(default_factory=dict)
    context: dict = field(default_factory=dict)

    def __post_init__(self):
        for label, value in (("principal", self.principal), ("capability", self.capability)):
            if not isinstance(value, str) or not 1 <= len(value) <= 100:
                raise ValueError(f"{label} must be a string of 1..100 chars")
        for label, value in (("args", self.args), ("context", self.context)):
            if not isinstance(value, dict):
                raise ValueError(f"{label} must be a mapping")


@dataclass(frozen=True)
class Decision:
    """The outcome of one evaluation."""

    outcome: str  # allow | deny | escalate
    reason: str
    capability: str
    acknowledgments: tuple = ()
    grant_id: str | None = None


class DecisionEngine:
    """Contracts + grants + audit → decisions."""

    def __init__(self, contracts: dict, grants: GrantStore, audit):
        self.contracts = contracts
        self.grants = grants
        self.audit = audit

    def evaluate(self, request: Request, now: float | None = None) -> Decision:
        now = time.time() if now is None else now
        decision = self._decide(request, now)
        self.audit.append(
            "request.evaluated",
            principal=request.principal,
            capability=request.capability,
            outcome=decision.outcome,
            reason=decision.reason,
            grant_id=decision.grant_id or "",
        )
        return decision

    def consume(self, request: Request, now: float | None = None) -> bool:
        """Spend one use of the grant that authorizes this request."""
        now = time.time() if now is None else now
        grant = self.grants.find(request.principal, request.capability, now=now)
        if grant is None:
            return False
        if not self.grants.consume(grant["id"], now=now):
            return False
        self.audit.append(
            "grant.consumed",
            principal=request.principal,
            capability=request.capability,
            grant_id=grant["id"],
        )
        return True

    # -- internals ---------------------------------------------------------

    def _decide(self, request: Request, now: float) -> Decision:
        contract = self.contracts.get(request.capability)
        if contract is None:
            return Decision(DENY, "undeclared capability", request.capability)
        if contract.locked:
            return Decision(DENY, "capability is locked", request.capability)
        grant = self.grants.find(request.principal, request.capability, now=now)
        if grant is not None:
            return Decision(
                ALLOW, "authorized by grant", request.capability, grant_id=grant["id"]
            )
        if contract.default == "allow":
            return Decision(ALLOW, "allowed by contract", request.capability)
        if contract.default == "ask":
            return Decision(
                ESCALATE,
                "approval required",
                request.capability,
                acknowledgments=contract.acknowledgments(),
            )
        return Decision(DENY, "denied by contract", request.capability)
