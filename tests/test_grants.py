import json
import time

import pytest

from trustcontract.approvals import generate_key
from trustcontract.grants import GrantStore, GrantStoreError


@pytest.fixture
def key():
    return bytes.fromhex(generate_key())


def test_add_and_find(tmp_path, key):
    store = GrantStore(tmp_path / "grants.json", key)
    now = time.time()
    grant = store.add("numa", "file.write", "numa", now + 60, now=now)
    assert grant["id"].startswith("g_")
    found = store.find("numa", "file.write", now=now + 1)
    assert found is not None and found["id"] == grant["id"]


def test_find_wrong_pair(tmp_path, key):
    store = GrantStore(tmp_path / "grants.json", key)
    now = time.time()
    store.add("numa", "file.write", "numa", now + 60, now=now)
    assert store.find("other", "file.write", now=now) is None
    assert store.find("numa", "file.read", now=now) is None


def test_expired_grant_not_found(tmp_path, key):
    store = GrantStore(tmp_path / "grants.json", key)
    now = time.time()
    store.add("numa", "file.write", "numa", now + 60, now=now)
    assert store.find("numa", "file.write", now=now + 61) is None


def test_one_shot_consume(tmp_path, key):
    store = GrantStore(tmp_path / "grants.json", key)
    now = time.time()
    grant = store.add("numa", "file.write", "numa", now + 60, max_uses=1, now=now)
    assert store.consume(grant["id"], now=now + 1) is True
    assert store.find("numa", "file.write", now=now + 2) is None
    assert store.consume(grant["id"], now=now + 3) is False


def test_multi_use(tmp_path, key):
    store = GrantStore(tmp_path / "grants.json", key)
    now = time.time()
    grant = store.add("numa", "file.write", "numa", now + 60, max_uses=2, now=now)
    assert store.consume(grant["id"], now=now + 1)
    assert store.find("numa", "file.write", now=now + 2) is not None
    assert store.consume(grant["id"], now=now + 3)
    assert store.find("numa", "file.write", now=now + 4) is None


def test_revoke(tmp_path, key):
    store = GrantStore(tmp_path / "grants.json", key)
    now = time.time()
    grant = store.add("numa", "file.write", "numa", now + 60, now=now)
    assert store.revoke(grant["id"]) is True
    assert store.find("numa", "file.write", now=now + 1) is None
    assert store.revoke("g_nonexistent") is False


def test_forged_signature_skipped(tmp_path, key):
    path = tmp_path / "grants.json"
    store = GrantStore(path, key)
    now = time.time()
    store.add("numa", "file.write", "numa", now + 60, now=now)
    # tamper with the stored record behind the store's back
    data = json.loads(path.read_text())
    data["grants"][0]["uses"] = 99
    path.write_text(json.dumps(data))
    store2 = GrantStore(path, key)
    assert store2.find("numa", "file.write", now=now + 1) is None
    assert store2.list(now=now + 1)[0]["status"] == "invalid-signature"


def test_corrupt_store_fail_closed(tmp_path, key):
    path = tmp_path / "grants.json"
    path.write_text("{ not json")
    store = GrantStore(path, key)
    assert store.corrupt is True
    assert store.find("numa", "file.write") is None
    with pytest.raises(GrantStoreError, match="corrupt"):
        store.add("numa", "file.write", "numa", time.time() + 60)


def test_purge(tmp_path, key):
    store = GrantStore(tmp_path / "grants.json", key)
    now = time.time()
    store.add("numa", "file.write", "numa", now + 60, now=now)
    store.add("numa", "file.read", "numa", now + 60, now=now)
    assert store.purge_expired(now=now + 61) == 2
    assert store.list(now=now + 62) == []


def test_list_statuses(tmp_path, key):
    store = GrantStore(tmp_path / "grants.json", key)
    now = time.time()
    g1 = store.add("numa", "file.write", "numa", now + 60, now=now)
    g2 = store.add("numa", "file.read", "numa", now + 60, now=now)
    store.revoke(g2["id"])
    statuses = {g["id"]: g["status"] for g in store.list(now=now + 1)}
    assert statuses[g1["id"]] == "valid"
    assert statuses[g2["id"]] == "revoked"


def test_add_validation(tmp_path, key):
    store = GrantStore(tmp_path / "grants.json", key)
    now = time.time()
    with pytest.raises(GrantStoreError):
        store.add("", "file.write", "numa", now + 60, now=now)
    with pytest.raises(GrantStoreError):
        store.add("numa", "file.write", "numa", now - 1, now=now)  # past expiry
    with pytest.raises(GrantStoreError):
        store.add("numa", "file.write", "numa", now + 60, max_uses=0, now=now)
    with pytest.raises(GrantStoreError):
        store.add("numa", "file.write", "numa", now + 60, note="x" * 501, now=now)


def test_persistence_across_instances(tmp_path, key):
    path = tmp_path / "grants.json"
    now = time.time()
    GrantStore(path, key).add("numa", "file.write", "numa", now + 60, now=now)
    store = GrantStore(path, key)
    assert store.find("numa", "file.write", now=now + 1) is not None
