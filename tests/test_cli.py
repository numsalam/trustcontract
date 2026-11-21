import json
import pathlib
import subprocess
import sys

import pytest

from trustcontract.cli import main

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
    "  - name: shell.exec\n"
    "    default: ask\n"
    "    risk: critical\n"
    "    consequences:\n"
    "      reversibility: irreversible\n"
    "  - name: db.drop\n"
    "    default: deny\n"
    "    locked: true\n"
    "    risk: critical\n"
)


@pytest.fixture
def home(tmp_path):
    return tmp_path / "home"


def _base(home, contracts_path):
    return ["--home", str(home), "--contracts", str(contracts_path)]


def _write_contracts(tmp_path):
    path = tmp_path / "contracts.yaml"
    path.write_text(CONTRACTS)
    return path


def test_full_lifecycle(home, tmp_path, capsys):
    contracts = _write_contracts(tmp_path)
    base = _base(home, contracts)

    assert main(["init-key", *base]) == 0
    assert (home / "key.hex").exists()
    assert main(["contracts", *base]) == 0

    # undeclared capability → deny
    assert main(["request", "--principal", "numa", "--capability", "nope", *base]) == 1
    # ask → escalate (exit 2) with acknowledgments
    assert (
        main(["request", "--principal", "numa", "--capability", "file.write", *base]) == 2
    )
    out = capsys.readouterr().out
    assert "approval required" in out
    assert "acknowledge" in out

    # approve → one-shot grant
    assert (
        main(
            [
                "approve",
                "--principal",
                "numa",
                "--capability",
                "file.write",
                "--note",
                "test",
                *base,
            ]
        )
        == 0
    )
    # allow without consuming (read-only check does not burn the grant)
    assert (
        main(["request", "--principal", "numa", "--capability", "file.write", *base]) == 0
    )
    assert "authorized by grant" in capsys.readouterr().out
    # allow + consume (spends the one-shot grant)
    assert (
        main(
            [
                "request",
                "--principal",
                "numa",
                "--capability",
                "file.write",
                "--consume",
                *base,
            ]
        )
        == 0
    )
    # grant spent → escalate again
    assert (
        main(["request", "--principal", "numa", "--capability", "file.write", *base]) == 2
    )

    # audit chain valid, grants listed
    assert main(["verify", *base]) == 0
    assert main(["grants", *base]) == 0


def test_typed_confirmation_required(home, tmp_path, capsys):
    contracts = _write_contracts(tmp_path)
    base = _base(home, contracts)
    assert main(["init-key", *base]) == 0
    # without confirm → error
    assert (
        main(["approve", "--principal", "numa", "--capability", "shell.exec", *base]) == 3
    )
    assert "typed confirmation" in capsys.readouterr().err
    # wrong confirm → error
    assert (
        main(
            [
                "approve",
                "--principal",
                "numa",
                "--capability",
                "shell.exec",
                "--confirm",
                "wrong",
                *base,
            ]
        )
        == 3
    )
    # right confirm → granted, then allowed
    assert (
        main(
            [
                "approve",
                "--principal",
                "numa",
                "--capability",
                "shell.exec",
                "--confirm",
                "shell.exec",
                *base,
            ]
        )
        == 0
    )
    assert (
        main(["request", "--principal", "numa", "--capability", "shell.exec", *base]) == 0
    )


def test_locked_not_grantable(home, tmp_path, capsys):
    contracts = _write_contracts(tmp_path)
    base = _base(home, contracts)
    assert main(["init-key", *base]) == 0
    assert (
        main(["approve", "--principal", "numa", "--capability", "db.drop", *base]) == 3
    )
    assert "locked" in capsys.readouterr().err
    assert main(["request", "--principal", "numa", "--capability", "db.drop", *base]) == 1


def test_verify_detects_tampering(home, tmp_path):
    contracts = _write_contracts(tmp_path)
    base = _base(home, contracts)
    assert main(["init-key", *base]) == 0
    assert (
        main(["request", "--principal", "numa", "--capability", "file.read", *base]) == 0
    )
    (home / "audit.jsonl").write_text("tampered\n")
    assert main(["verify", *base]) == 1


def test_json_output(home, tmp_path, capsys):
    contracts = _write_contracts(tmp_path)
    base = _base(home, contracts)
    assert main(["init-key", *base]) == 0
    capsys.readouterr()  # drain init-key output before the JSON check
    assert (
        main(
            [
                "request",
                "--principal",
                "numa",
                "--capability",
                "file.write",
                "--json",
                *base,
            ]
        )
        == 2
    )
    data = json.loads(capsys.readouterr().out)
    assert data["outcome"] == "escalate"
    assert data["acknowledgments"][0]["kind"] == "notice"


def test_module_invocation(tmp_path):
    """`python3 -m trustcontract.cli` must run main(), not just import it."""
    repo_root = pathlib.Path(__file__).resolve().parent.parent
    contracts = tmp_path / "contracts.yaml"
    contracts.write_text("contracts:\n  - name: a\n    default: allow\n    risk: low\n")
    home = tmp_path / "home"
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "trustcontract.cli",
            "init-key",
            "--home",
            str(home),
            "--contracts",
            str(contracts),
        ],
        capture_output=True,
        text=True,
        cwd=repo_root,
    )
    assert proc.returncode == 0
    assert "wrote signing key" in proc.stdout
    assert (home / "key.hex").exists()
