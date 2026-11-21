"""TrustContract command line interface.

Files resolve under --home (default ~/.trustcontract) unless overridden
per flag: contracts.yaml, grants.json, audit.jsonl, key.hex.

Exit codes: 0 allowed / ok, 1 denied / verification failed,
2 escalation required, 3 error.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import sys
import time
from pathlib import Path

from .approvals import generate_key, load_key
from .audit import AuditLog
from .contract import load_contracts_file
from .engine import DecisionEngine, Request
from .grants import GrantStore

EXIT_ALLOW, EXIT_DENY, EXIT_ESCALATE, EXIT_ERROR = 0, 1, 2, 3


# -- path + store helpers ---------------------------------------------------


def _home(args) -> Path:
    return Path(getattr(args, "home", "~/.trustcontract")).expanduser()


def _resolve(args, attr: str, name: str) -> Path:
    explicit = getattr(args, attr, None)
    return Path(explicit).expanduser() if explicit else _home(args) / name


def _load_contracts(args) -> dict:
    path = _resolve(args, "contracts", "contracts.yaml")
    if not path.exists():
        raise ValueError(f"contracts file not found: {path}")
    return load_contracts_file(path)


def _load_key(args) -> bytes:
    path = _resolve(args, "key", "key.hex")
    if not path.exists():
        raise ValueError(f"signing key not found: {path} (run: trustcontract init-key)")
    return load_key(path)


def _grants_store(args, key: bytes) -> GrantStore:
    return GrantStore(_resolve(args, "grants", "grants.json"), key)


def _audit_log(args) -> AuditLog:
    return AuditLog(_resolve(args, "audit", "audit.jsonl"))


def _decision_dict(decision) -> dict:
    return {
        "outcome": decision.outcome,
        "reason": decision.reason,
        "capability": decision.capability,
        "grant_id": decision.grant_id,
        "acknowledgments": [
            {"kind": a.kind, "text": a.text} for a in decision.acknowledgments
        ],
    }


# -- commands ----------------------------------------------------------------


def _cmd_init_key(args) -> int:
    path = Path(args.path).expanduser() if args.path else _home(args) / "key.hex"
    if path.exists():
        raise ValueError(f"key already exists: {path} (delete it first to rotate)")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(generate_key() + "\n", encoding="utf-8")
    path.chmod(0o600)
    print(f"wrote signing key: {path}")
    return 0


def _cmd_contracts(args) -> int:
    contracts = _load_contracts(args)
    entries = sorted(contracts.values(), key=lambda c: c.name)
    if args.json:
        print(json.dumps([dataclasses.asdict(c) for c in entries], indent=2))
        return 0
    if not entries:
        print("no contracts")
        return 0
    for c in entries:
        lock = " [locked]" if c.locked else ""
        print(f"{c.name}{lock}")
        print(
            f"  default={c.default} risk={c.risk}"
            f" reversibility={c.consequences.reversibility}"
            f" blast={c.consequences.blast_radius}"
            f" expiry={c.expiry_seconds}s uses={c.max_uses}"
        )
        if c.description:
            print(f"  {c.description}")
    return 0


def _cmd_request(args) -> int:
    contracts = _load_contracts(args)
    key = _load_key(args)
    grants = _grants_store(args, key)
    engine = DecisionEngine(contracts, grants, _audit_log(args))
    request = Request(
        principal=args.principal,
        capability=args.capability,
        args=json.loads(args.args) if args.args else {},
        context=json.loads(args.context) if args.context else {},
    )
    decision = engine.evaluate(request)
    consumed = bool(args.consume and decision.outcome == "allow" and engine.consume(request))
    if grants.corrupt:
        print("warning: grant store is corrupt; no grants were honored", file=sys.stderr)
    if args.json:
        print(json.dumps({**_decision_dict(decision), "consumed": consumed}, indent=2))
    else:
        print(f"{decision.outcome}: {decision.reason}")
        if decision.grant_id:
            print(f"  grant: {decision.grant_id}")
        for ack in decision.acknowledgments:
            print(f"  acknowledge [{ack.kind}]: {ack.text}")
        if consumed:
            print("  grant consumed (one use spent)")
    return {"allow": EXIT_ALLOW, "deny": EXIT_DENY, "escalate": EXIT_ESCALATE}[decision.outcome]


def _cmd_approve(args) -> int:
    contracts = _load_contracts(args)
    contract = contracts.get(args.capability)
    if contract is None:
        raise ValueError(f"undeclared capability: {args.capability}")
    if contract.locked:
        raise ValueError(f"{args.capability} is locked; it cannot be granted")
    typed = [a for a in contract.acknowledgments() if a.kind == "typed"]
    if typed and args.confirm != args.capability:
        raise ValueError(
            f"typed confirmation required for {args.capability}:"
            f" pass --confirm {args.capability}"
        )
    key = _load_key(args)
    grants = _grants_store(args, key)
    expiry = args.expiry if args.expiry is not None else contract.expiry_seconds
    uses = args.uses if args.uses is not None else contract.max_uses
    now = time.time()
    grant = grants.add(
        principal=args.principal,
        capability=args.capability,
        granted_by=args.by or args.principal,
        expires_at=now + expiry,
        max_uses=uses,
        note=args.note or "",
        confirmation=args.confirm,
        now=now,
    )
    _audit_log(args).append(
        "grant.added",
        principal=args.principal,
        capability=args.capability,
        granted_by=grant["granted_by"],
        grant_id=grant["id"],
        expires_at=grant["expires_at"],
        uses=uses,
    )
    print(f"granted {args.capability} to {args.principal}")
    print(f"  id: {grant['id']}  expires_at: {grant['expires_at']}  uses: {uses}")
    return 0


def _cmd_revoke(args) -> int:
    key = _load_key(args)
    grants = _grants_store(args, key)
    if grants.revoke(args.grant_id):
        _audit_log(args).append("grant.revoked", grant_id=args.grant_id)
        print(f"revoked {args.grant_id}")
        return 0
    print(f"no revocable grant {args.grant_id}")
    return 1


def _cmd_grants(args) -> int:
    key = _load_key(args)
    grants = _grants_store(args, key)
    if grants.corrupt:
        print("error: grant store is corrupt; refusing to display", file=sys.stderr)
        return EXIT_ERROR
    entries = grants.list()
    if args.json:
        print(json.dumps(entries, indent=2))
        return 0
    if not entries:
        print("no grants")
        return 0
    for g in entries:
        print(
            f"{g['id']}  {g['status']:>18}  {g['principal']} -> {g['capability']}"
            f"  uses={g.get('uses')}/{g.get('max_uses')}  expires_at={g.get('expires_at')}"
        )
    return 0


def _cmd_purge(args) -> int:
    key = _load_key(args)
    grants = _grants_store(args, key)
    removed = grants.purge_expired()
    if removed:
        _audit_log(args).append("grants.purged", removed=removed)
    print(f"purged {removed} grant(s)")
    return 0


def _cmd_verify(args) -> int:
    ok, detail = _audit_log(args).verify()
    print(detail)
    return 0 if ok else 1


def _cmd_tail(args) -> int:
    for rec in _audit_log(args).tail(args.n):
        print(json.dumps(rec, sort_keys=True))
    return 0


# -- parser -------------------------------------------------------------------


def _shared(p) -> None:
    p.add_argument("--home", default="~/.trustcontract", help=argparse.SUPPRESS)
    p.add_argument("--contracts", help="contracts YAML/JSON path")
    p.add_argument("--grants", help="grants JSON path")
    p.add_argument("--audit", help="audit JSONL path")
    p.add_argument("--key", help="signing key path")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="trustcontract",
        description="Declarative capability contracts, signed approvals, tamper-evident audit",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("init-key", help="generate a signing key")
    p.add_argument("path", nargs="?", help="key file path (default <home>/key.hex)")
    _shared(p)
    p.set_defaults(fn=_cmd_init_key)

    p = sub.add_parser("contracts", help="list contracts (validates the file)")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    _shared(p)
    p.set_defaults(fn=_cmd_contracts)

    p = sub.add_parser("request", help="evaluate a request against contracts + grants")
    p.add_argument("--principal", required=True)
    p.add_argument("--capability", required=True)
    p.add_argument("--args", help="request arguments as JSON")
    p.add_argument("--context", help="request context as JSON")
    p.add_argument("--consume", action="store_true", help="spend one grant use on allow")
    p.add_argument("--json", action="store_true")
    _shared(p)
    p.set_defaults(fn=_cmd_request)

    p = sub.add_parser("approve", help="grant a capability to a principal")
    p.add_argument("--principal", required=True)
    p.add_argument("--capability", required=True)
    p.add_argument("--by", help="who is approving (default: the principal)")
    p.add_argument("--expiry", type=int, help="grant lifetime seconds (default: contract)")
    p.add_argument("--uses", type=int, help="allowed uses (default: contract)")
    p.add_argument("--note", default="", help="why (bounded to 500 chars)")
    p.add_argument("--confirm", help="typed confirmation for critical capabilities")
    _shared(p)
    p.set_defaults(fn=_cmd_approve)

    p = sub.add_parser("revoke", help="revoke a grant by id")
    p.add_argument("--grant-id", required=True)
    _shared(p)
    p.set_defaults(fn=_cmd_revoke)

    p = sub.add_parser("grants", help="list grants with status")
    p.add_argument("--json", action="store_true")
    _shared(p)
    p.set_defaults(fn=_cmd_grants)

    p = sub.add_parser("purge", help="drop expired/used-up/invalid grants")
    _shared(p)
    p.set_defaults(fn=_cmd_purge)

    p = sub.add_parser("verify", help="verify the audit hash chain")
    _shared(p)
    p.set_defaults(fn=_cmd_verify)

    p = sub.add_parser("tail", help="show the last n audit records")
    p.add_argument("--n", type=int, default=20)
    _shared(p)
    p.set_defaults(fn=_cmd_tail)

    return parser


def main(argv=None) -> int:
    """CLI entry point; returns the exit code."""
    args = _parser().parse_args(argv)
    try:
        return args.fn(args)
    except (ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":  # pragma: no cover - exercised via subprocess in tests
    sys.exit(main())
