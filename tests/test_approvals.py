import pytest

from trustcontract.approvals import (
    ApprovalError,
    canonical,
    generate_key,
    load_key,
    sign,
    sign_grant,
    verify,
    verify_grant,
)


def test_generate_key():
    key = generate_key()
    assert len(key) == 64  # 32 bytes as hex
    assert key != generate_key()


def test_load_key_roundtrip(tmp_path):
    path = tmp_path / "key.hex"
    path.write_text(generate_key() + "\n")
    key = load_key(path)
    assert isinstance(key, bytes) and len(key) == 32


def test_load_key_bad_hex(tmp_path):
    path = tmp_path / "key.hex"
    path.write_text("not hex")
    with pytest.raises(ApprovalError, match="hex"):
        load_key(path)


def test_load_key_bad_length(tmp_path):
    path = tmp_path / "key.hex"
    path.write_text("ab" * 16)  # 16 bytes
    with pytest.raises(ApprovalError, match="32"):
        load_key(path)


def test_sign_verify_roundtrip():
    key = bytes.fromhex(generate_key())
    record = {"a": 1, "b": "two"}
    assert verify(record, sign(record, key), key)


def test_tampered_record_fails():
    key = bytes.fromhex(generate_key())
    sig = sign({"a": 1}, key)
    assert not verify({"a": 2}, sig, key)


def test_wrong_key_fails():
    key = bytes.fromhex(generate_key())
    other = bytes.fromhex(generate_key())
    assert not verify({"a": 1}, sign({"a": 1}, key), other)


def test_non_string_signature_fails():
    key = bytes.fromhex(generate_key())
    assert not verify({"a": 1}, None, key)
    assert not verify({"a": 1}, 123, key)


def test_bad_key_rejected():
    with pytest.raises(ApprovalError):
        sign({"a": 1}, b"short")


def test_sign_grant_embeds_signature():
    key = bytes.fromhex(generate_key())
    grant = sign_grant({"id": "g_1"}, key)
    assert "signature" in grant
    assert verify_grant(grant, key)


def test_sign_grant_refuses_resigned():
    key = bytes.fromhex(generate_key())
    grant = sign_grant({"id": "g_1"}, key)
    with pytest.raises(ApprovalError, match="already"):
        sign_grant(grant, key)


def test_verify_grant_missing_signature():
    key = bytes.fromhex(generate_key())
    assert not verify_grant({"id": "g_1"}, key)
    assert not verify_grant("not a dict", key)


def test_verify_grant_tampered():
    key = bytes.fromhex(generate_key())
    grant = sign_grant({"id": "g_1", "uses": 1}, key)
    grant["uses"] = 5
    assert not verify_grant(grant, key)


def test_canonical_deterministic():
    assert canonical({"a": 1, "b": 2}) == canonical({"b": 2, "a": 1})
