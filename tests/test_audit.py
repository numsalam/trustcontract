import json

import pytest

from trustcontract.audit import AuditError, AuditLog


def test_append_and_verify(tmp_path):
    audit = AuditLog(tmp_path / "audit.jsonl")
    rec = audit.append(
        "request.evaluated",
        principal="numa",
        capability="file.write",
        outcome="escalate",
    )
    assert rec["seq"] == 1
    ok, detail = audit.verify()
    assert ok and "1 records" in detail


def test_chain(tmp_path):
    audit = AuditLog(tmp_path / "audit.jsonl")
    audit.append("grant.added", grant_id="g_1")
    audit.append("grant.consumed", grant_id="g_1")
    audit.append("grant.revoked", grant_id="g_1")
    ok, detail = audit.verify()
    assert ok and "3 records" in detail
    recs = audit.records()
    assert [r["seq"] for r in recs] == [1, 2, 3]
    assert recs[1]["prev"] == recs[0]["hash"]


def test_tamper_detected(tmp_path):
    path = tmp_path / "audit.jsonl"
    audit = AuditLog(path)
    audit.append("grant.added", grant_id="g_1")
    audit.append("grant.consumed", grant_id="g_1")
    lines = path.read_text().splitlines()
    rec = json.loads(lines[0])
    rec["grant_id"] = "g_tampered"
    lines[0] = json.dumps(rec, sort_keys=True)
    path.write_text("\n".join(lines) + "\n")
    ok, detail = AuditLog(path).verify()
    assert not ok and "record 1" in detail


def test_deletion_detected(tmp_path):
    path = tmp_path / "audit.jsonl"
    audit = AuditLog(path)
    audit.append("grant.added", grant_id="g_1")
    audit.append("grant.consumed", grant_id="g_1")
    lines = path.read_text().splitlines()
    path.write_text(lines[1] + "\n")  # drop the first record
    ok, _ = AuditLog(path).verify()
    assert not ok


def test_reorder_detected(tmp_path):
    path = tmp_path / "audit.jsonl"
    audit = AuditLog(path)
    audit.append("grant.added", grant_id="g_1")
    audit.append("grant.consumed", grant_id="g_2")
    lines = path.read_text().splitlines()
    path.write_text("\n".join(reversed(lines)) + "\n")
    ok, _ = AuditLog(path).verify()
    assert not ok


def test_bad_event_name(tmp_path):
    audit = AuditLog(tmp_path / "audit.jsonl")
    with pytest.raises(AuditError, match="event"):
        audit.append("Not An Event")


def test_reserved_fields(tmp_path):
    audit = AuditLog(tmp_path / "audit.jsonl")
    with pytest.raises(AuditError, match="reserved"):
        audit.append("x", hash="nope")


def test_too_many_fields(tmp_path):
    audit = AuditLog(tmp_path / "audit.jsonl")
    fields = {f"f{i}": i for i in range(33)}
    with pytest.raises(AuditError, match="fields"):
        audit.append("x", **fields)


def test_corrupt_line_detected(tmp_path):
    path = tmp_path / "audit.jsonl"
    path.write_text("not json\n")
    ok, detail = AuditLog(path).verify()
    assert not ok


def test_append_refuses_corrupt_tail(tmp_path):
    path = tmp_path / "audit.jsonl"
    path.write_text("not json\n")
    with pytest.raises(AuditError, match="corrupt"):
        AuditLog(path).append("x")


def test_tail(tmp_path):
    audit = AuditLog(tmp_path / "audit.jsonl")
    for i in range(5):
        audit.append("x", i=i)
    assert [r["seq"] for r in audit.tail(2)] == [4, 5]
    with pytest.raises(AuditError):
        audit.tail(0)


def test_empty_verify(tmp_path):
    ok, detail = AuditLog(tmp_path / "nonexistent.jsonl").verify()
    assert ok and "0 records" in detail
