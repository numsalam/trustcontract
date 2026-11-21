import pathlib

import pytest

from trustcontract.contract import (
    Contract,
    ContractError,
    load_contracts,
    load_contracts_file,
)

EXAMPLES = pathlib.Path(__file__).resolve().parent.parent / "examples" / "contracts.yaml"

YAML = (
    "contracts:\n"
    "  - name: file.read\n"
    "    description: Read files\n"
    "    risk: low\n"
    "    default: allow\n"
    "    consequences:\n"
    "      side_effects:\n"
    "        - filesystem\n"
    "      reversibility: reversible\n"
    "      blast_radius: process\n"
    "  - name: file.write\n"
    "    default: ask\n"
    "    expiry_seconds: 60\n"
    "    max_uses: 3\n"
)


def test_load_minimal_defaults():
    contracts = load_contracts("contracts:\n  - name: a.b\n")
    c = contracts["a.b"]
    assert c.risk == "medium"
    assert c.default == "ask"
    assert c.locked is False
    assert c.expiry_seconds == 3600
    assert c.max_uses == 1
    assert c.consequences.reversibility == "manual"


def test_load_full():
    contracts = load_contracts(YAML)
    assert set(contracts) == {"file.read", "file.write"}
    r = contracts["file.read"]
    assert r.description == "Read files"
    assert r.consequences.side_effects == ("filesystem",)
    w = contracts["file.write"]
    assert w.expiry_seconds == 60
    assert w.max_uses == 3


def test_acknowledgments_passthrough():
    contracts = load_contracts(YAML)
    assert contracts["file.read"].acknowledgments() == ()  # reversible + low risk


def test_duplicate_rejected():
    with pytest.raises(ContractError, match="duplicate"):
        load_contracts("contracts:\n  - name: a\n  - name: a\n")


def test_missing_contracts_key():
    with pytest.raises(ContractError, match="contracts"):
        load_contracts("other: 1")


def test_contracts_not_list():
    with pytest.raises(ContractError, match="list"):
        load_contracts("contracts: 5")


def test_entry_not_mapping():
    with pytest.raises(ContractError, match="mapping"):
        load_contracts("contracts:\n  - 5")


def test_bad_name():
    with pytest.raises(ContractError, match="name"):
        load_contracts("contracts:\n  - name: Bad Name\n")


def test_bad_risk():
    with pytest.raises(ContractError, match="risk"):
        load_contracts("contracts:\n  - name: a\n    risk: extreme\n")


def test_bad_default():
    with pytest.raises(ContractError, match="default"):
        load_contracts("contracts:\n  - name: a\n    default: maybe\n")


def test_bad_expiry():
    with pytest.raises(ContractError, match="expiry"):
        load_contracts("contracts:\n  - name: a\n    expiry_seconds: 0\n")


def test_bad_max_uses():
    with pytest.raises(ContractError, match="max_uses"):
        load_contracts("contracts:\n  - name: a\n    max_uses: 0\n")


def test_consequence_error_wrapped():
    with pytest.raises(ContractError, match="a: reversibility"):
        load_contracts(
            "contracts:\n  - name: a\n    consequences:\n      reversibility: maybe\n"
        )


def test_locked():
    contracts = load_contracts("contracts:\n  - name: a\n    locked: true\n")
    assert contracts["a"].locked is True


def test_load_contracts_file(tmp_path):
    path = tmp_path / "contracts.yaml"
    path.write_text(YAML)
    assert set(load_contracts_file(path)) == {"file.read", "file.write"}


def test_example_contracts_load():
    contracts = load_contracts_file(EXAMPLES)
    assert {
        "file.read",
        "file.write",
        "shell.exec",
        "http.fetch",
        "payment.send",
        "db.drop",
    } <= set(contracts)
    assert contracts["db.drop"].locked is True
    assert contracts["payment.send"].consequences.blast_radius == "public"
    assert "money" in contracts["payment.send"].consequences.side_effects


def test_contract_is_frozen():
    c = Contract(name="a")
    with pytest.raises(AttributeError):
        c.risk = "low"
