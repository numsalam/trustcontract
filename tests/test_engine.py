import time

import pytest

from trustcontract.approvals import generate_key
from trustcontract.audit import AuditLog
from trustcontract.contract import load_contracts
from trustcontract.engine import DecisionEngine, Request
from trustcontract.grants import GrantStore

CONTRACTS = (
    "contracts:\n"
    "  - name: file.read\n"
    "    default: allow\n"
    "    risk: low\n"
    "    consequences:\n"
    "      reversibility: reversible\n"
    "  - name: file.write\n"
    "    default: ask\n"
    "    risk: high\n"
    "  - name: file.delete\n"
    "    default: deny\n"
    "    risk: high\n"
    "  - name: db.drop\n"
    "    default: deny\n"
    "    locked: true\n"
    "    risk: critical\n"
    "    consequences:\n"
    "      reversibility: irreversible\n"
)


@pytest.fixture
def env(tmp_path):
    key = bytes.fromhex(generate_key())
    contracts = load_contracts(CONTRACTS)
    grants = GrantStore(tmp_path / "grants.json", key)
    audit = AuditLog(tmp_path / "audit.jsonl")
    engine = DecisionEngine(contracts, grants, audit)
    return engine, grants, audit, key


def test_unknown_capability_denied(env):
    engine, _, _, _ = env
    d = engine.evaluate(Request("numa", "nope.nope"))
    assert d.outcome == "deny" and d.reason == "undeclared capability"


def test_locked_denied_even_with_grant(env):
    engine, grants, _, _ = env
    now = time.time()
    grants.add("numa", "db.drop", "numa", now + 60, now=now)
    d = engine.evaluate(Request("numa", "db.drop"))
    assert d.outcome == "deny" and d.reason == "capability is locked"


def test_default_allow(env):
    engine, _, _, _ = env
    d = engine.evaluate(Request("numa", "file.read"))
    assert d.outcome == "allow" and d.reason == "allowed by contract"


def test_default_ask_escalates_with_acknowledgments(env):
    engine, _, _, _ = env
    d = engine.evaluate(Request("numa", "file.write"))
    assert d.outcome == "escalate"
    assert [a.text for a in d.acknowledgments] == [
        "This action can only be undone manually."
    ]


def test_default_deny(env):
    engine, _, _, _ = env
    d = engine.evaluate(Request("numa", "file.delete"))
    assert d.outcome == "deny" and d.reason == "denied by contract"


def test_grant_allows(env):
    engine, grants, _, _ = env
    now = time.time()
    grant = grants.add("numa", "file.write", "numa", now + 60, now=now)
    d = engine.evaluate(Request("numa", "file.write"))
    assert d.outcome == "allow" and d.grant_id == grant["id"]


def test_one_shot_lifecycle(env):
    engine, grants, _, _ = env
    now = time.time()
    grants.add("numa", "file.write", "numa", now + 60, now=now)
    request = Request("numa", "file.write")
    assert engine.evaluate(request).outcome == "allow"
    assert engine.consume(request) is True
    assert engine.evaluate(request).outcome == "escalate"


def test_every_evaluation_audited(env):
    engine, _, audit, _ = env
    engine.evaluate(Request("numa", "file.read"))
    engine.evaluate(Request("numa", "file.write"))
    events = [r["event"] for r in audit.records()]
    assert events == ["request.evaluated", "request.evaluated"]


def test_consume_audited(env):
    engine, grants, audit, _ = env
    now = time.time()
    grants.add("numa", "file.write", "numa", now + 60, now=now)
    engine.consume(Request("numa", "file.write"))
    assert audit.records()[-1]["event"] == "grant.consumed"


def test_request_validation():
    with pytest.raises(ValueError):
        Request("", "file.read")
    with pytest.raises(ValueError):
        Request("numa", "")
    with pytest.raises(ValueError):
        Request("numa", "file.read", args="not a dict")
    with pytest.raises(ValueError):
        Request("x" * 101, "file.read")


def test_critical_typed_acknowledgment(tmp_path):
    contracts = load_contracts(
        "contracts:\n"
        "  - name: shell.exec\n"
        "    risk: critical\n"
        "    default: ask\n"
        "    consequences:\n"
        "      reversibility: irreversible\n"
    )
    key = bytes.fromhex(generate_key())
    engine = DecisionEngine(
        contracts, GrantStore(tmp_path / "g.json", key), AuditLog(tmp_path / "a.jsonl")
    )
    d = engine.evaluate(Request("numa", "shell.exec"))
    assert d.outcome == "escalate"
    assert [a.kind for a in d.acknowledgments] == ["notice", "typed"]
