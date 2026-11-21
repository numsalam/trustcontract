import pytest

from trustcontract.yaml_min import YamlMinError, loads, loads_min


def test_scalars():
    assert loads_min("a: 1")["a"] == 1
    assert loads_min("a: 1.5")["a"] == 1.5
    assert loads_min("a: 1.5e3")["a"] == 1500.0
    assert loads_min("a: -5")["a"] == -5
    assert loads_min("a: true")["a"] is True
    assert loads_min("a: false")["a"] is False
    assert loads_min("a: null")["a"] is None
    assert loads_min("a: ~")["a"] is None
    assert loads_min("a: hello")["a"] == "hello"
    assert loads_min('a: "hello world"')["a"] == "hello world"
    assert loads_min("a: 'it''s'")["a"] == "it's"


def test_nested_map():
    doc = "a:\n  b:\n    c: 1\n  d: two\n"
    assert loads_min(doc) == {"a": {"b": {"c": 1}, "d": "two"}}


def test_list_of_scalars():
    assert loads_min("a:\n  - 1\n  - two\n  - null\n  - -5") == {
        "a": [1, "two", None, -5]
    }


def test_list_of_mappings():
    doc = (
        "contracts:\n"
        "  - name: file.read\n"
        "    risk: low\n"
        "  - name: file.write\n"
        "    risk: high\n"
        "    locked: false\n"
    )
    assert loads_min(doc) == {
        "contracts": [
            {"name": "file.read", "risk": "low"},
            {"name": "file.write", "risk": "high", "locked": False},
        ]
    }


def test_deep_nesting_under_list_item():
    doc = (
        "contracts:\n"
        "  - name: a\n"
        "    consequences:\n"
        "      side_effects:\n"
        "        - filesystem\n"
        "        - network\n"
        "      reversibility: irreversible\n"
    )
    assert loads_min(doc) == {
        "contracts": [
            {
                "name": "a",
                "consequences": {
                    "side_effects": ["filesystem", "network"],
                    "reversibility": "irreversible",
                },
            }
        ]
    }


def test_comments_and_blanks():
    doc = '# top comment\na: 1  # trailing\n# middle\n\nb: "x # not a comment"\n'
    assert loads_min(doc) == {"a": 1, "b": "x # not a comment"}


def test_empty_document():
    assert loads_min("") is None
    assert loads_min("# only a comment\n\n") is None


def test_top_level_list():
    assert loads_min("- a\n- b") == ["a", "b"]


def test_tabs_rejected():
    with pytest.raises(YamlMinError, match="tabs"):
        loads_min("a:\n\tb: 1")


def test_flow_style_rejected():
    with pytest.raises(YamlMinError, match="flow"):
        loads_min("a: [1, 2]")


def test_duplicate_key_rejected():
    with pytest.raises(YamlMinError, match="duplicate"):
        loads_min("a: 1\na: 2")


def test_unexpected_indentation():
    with pytest.raises(YamlMinError, match="unexpected"):
        loads_min("a: 1\n  b: 2")


def test_mapping_line_without_colon():
    with pytest.raises(YamlMinError, match="key"):
        loads_min("a: 1\njust text")


def test_nested_inline_list_rejected():
    with pytest.raises(YamlMinError, match="nested inline"):
        loads_min("a:\n  - - b")


def test_unterminated_quote_rejected():
    with pytest.raises(YamlMinError, match="unterminated"):
        loads_min('a: "unterminated')


def test_list_item_inside_mapping():
    with pytest.raises(YamlMinError):
        loads_min("a: 1\n- b")


def test_loads_agrees_with_min():
    doc = "contracts:\n  - name: a\n    risk: low\n    locked: true\n"
    assert loads(doc) == loads_min(doc)
