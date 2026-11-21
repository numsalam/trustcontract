"""Consequence Engine — pre-execution consequence enumeration.

Contracts declare what a capability does to the world; this module turns
that declaration into the acknowledgment requirements a human must see
before approving an escalation. Everything is declarative and
deterministic: a capability never asks for less acknowledgment than its
declaration implies, and unknown values are rejected at load time
(fail closed).

Extracted from the permission/approval pattern proven twice — Numa's
approval queue (life-agent) and SKILLSEED's permission-gated skills:
state-changing operations require an explicit human decision, and
irreversible ones require the human to say so.
"""

from __future__ import annotations

from dataclasses import dataclass

__all__ = [
    "Acknowledgment",
    "BLAST_RADIUS",
    "ConsequenceError",
    "Consequences",
    "REVERSIBILITY",
    "SIDE_EFFECTS",
]

REVERSIBILITY = ("reversible", "manual", "irreversible")
BLAST_RADIUS = ("process", "single-host", "multi-host", "public")
SIDE_EFFECTS = (
    "filesystem",
    "network",
    "process",
    "credential",
    "deletion",
    "money",
    "public-content",
)


class ConsequenceError(ValueError):
    """Invalid consequence declaration (fail closed)."""


@dataclass(frozen=True)
class Acknowledgment:
    """One thing a human must acknowledge before approving.

    kind ``notice`` — the approver must see the text.
    kind ``typed``  — the approver must echo the capability name
                      (required for critical-risk capabilities).
    """

    kind: str  # "notice" | "typed"
    text: str


@dataclass(frozen=True)
class Consequences:
    """What a capability does to the world.

    Defaults are deliberately conservative: an undeclared contract is
    ``manual`` to undo and ``process``-scoped — acknowledgments only appear
    on escalations (approvals), never on ``allow`` decisions, so the safe
    default costs nothing in the common case.
    """

    side_effects: tuple[str, ...] = ()
    reversibility: str = "manual"
    blast_radius: str = "process"

    @classmethod
    def from_dict(cls, data) -> "Consequences":
        if data is None:
            return cls()
        if not isinstance(data, dict):
            raise ConsequenceError("consequences must be a mapping")
        effects = data.get("side_effects", [])
        if not isinstance(effects, list) or not all(isinstance(e, str) for e in effects):
            raise ConsequenceError("side_effects must be a list of strings")
        unknown = sorted(set(effects) - set(SIDE_EFFECTS))
        if unknown:
            raise ConsequenceError(f"unknown side effects: {', '.join(unknown)}")
        reversibility = data.get("reversibility", "manual")
        if reversibility not in REVERSIBILITY:
            raise ConsequenceError(f"reversibility must be one of: {', '.join(REVERSIBILITY)}")
        blast = data.get("blast_radius", "process")
        if blast not in BLAST_RADIUS:
            raise ConsequenceError(f"blast_radius must be one of: {', '.join(BLAST_RADIUS)}")
        return cls(tuple(effects), reversibility, blast)

    def requirements(self, risk: str) -> tuple[Acknowledgment, ...]:
        """Acknowledgment requirements implied by this declaration + risk."""
        reqs: list[Acknowledgment] = []
        if self.reversibility == "irreversible":
            reqs.append(Acknowledgment("notice", "This action cannot be undone."))
        elif self.reversibility == "manual":
            reqs.append(Acknowledgment("notice", "This action can only be undone manually."))
        if self.blast_radius in ("multi-host", "public"):
            reqs.append(Acknowledgment("notice", "Effects extend beyond this host."))
        if self.blast_radius == "public":
            reqs.append(Acknowledgment("notice", "Effects are publicly visible."))
        for effect, text in (
            ("credential", "This action uses stored credentials."),
            ("deletion", "This action can delete data."),
            ("money", "This action can move or spend money."),
        ):
            if effect in self.side_effects:
                reqs.append(Acknowledgment("notice", text))
        if risk == "critical":
            reqs.append(Acknowledgment("typed", "Type the capability name to confirm."))
        return tuple(reqs)
