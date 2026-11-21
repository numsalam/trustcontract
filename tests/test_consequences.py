import pytest

from trustcontract.consequences import Acknowledgment, ConsequenceError, Consequences


def test_defaults():
    c = Consequences()
    assert c.reversibility == "manual"
    assert c.blast_radius == "process"
    assert c.side_effects == ()


def test_from_dict_full():
    c = Consequences.from_dict(
        {
            "side_effects": ["filesystem", "deletion"],
            "reversibility": "irreversible",
            "blast_radius": "multi-host",
        }
    )
    assert c.side_effects == ("filesystem", "deletion")
    assert c.reversibility == "irreversible"
    assert c.blast_radius == "multi-host"


def test_from_dict_none():
    assert Consequences.from_dict(None) == Consequences()


def test_unknown_side_effect():
    with pytest.raises(ConsequenceError, match="unknown side"):
        Consequences.from_dict({"side_effects": ["nuclear"]})


def test_bad_reversibility():
    with pytest.raises(ConsequenceError, match="reversibility"):
        Consequences.from_dict({"reversibility": "maybe"})


def test_bad_blast_radius():
    with pytest.raises(ConsequenceError, match="blast"):
        Consequences.from_dict({"blast_radius": "galaxy"})


def test_non_mapping():
    with pytest.raises(ConsequenceError, match="mapping"):
        Consequences.from_dict(["nope"])


def test_requirements_reversible_low():
    assert Consequences(reversibility="reversible").requirements("low") == ()


def test_requirements_manual_notice():
    reqs = Consequences(reversibility="manual").requirements("low")
    assert reqs == (Acknowledgment("notice", "This action can only be undone manually."),)


def test_requirements_irreversible():
    reqs = Consequences(reversibility="irreversible").requirements("low")
    assert reqs[0].text == "This action cannot be undone."


def test_requirements_blast_radius():
    multi = Consequences(reversibility="reversible", blast_radius="multi-host")
    assert [a.text for a in multi.requirements("low")] == [
        "Effects extend beyond this host."
    ]
    public = Consequences(reversibility="reversible", blast_radius="public")
    assert [a.text for a in public.requirements("low")] == [
        "Effects extend beyond this host.",
        "Effects are publicly visible.",
    ]


def test_requirements_side_effects():
    c = Consequences(
        side_effects=("credential", "deletion", "money"),
        reversibility="reversible",
    )
    assert [a.text for a in c.requirements("low")] == [
        "This action uses stored credentials.",
        "This action can delete data.",
        "This action can move or spend money.",
    ]


def test_requirements_critical_typed_last():
    reqs = Consequences(reversibility="reversible").requirements("critical")
    assert reqs[-1].kind == "typed"
    assert reqs[-1].text == "Type the capability name to confirm."
