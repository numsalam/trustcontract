"""Minimal YAML subset parser — zero dependencies.

TrustContract contract files are declarative YAML. To stay dependency-free
this module implements the small subset those files need:

- nested mappings by 2-space indentation
- block lists with ``- `` items (scalars, or mappings started inline)
- ``#`` comments (full-line and trailing) and blank lines
- scalars: int, float, bool, null, single/double-quoted strings, plain strings

Anything outside the subset — tabs for indentation, flow style ``[a, b]``,
anchors, nested inline lists — raises :class:`YamlMinError` with a line
number. Parsing fails closed; it never guesses.

If PyYAML happens to be installed it is preferred (full syntax); the
built-in parser is the guaranteed fallback, so the library has no required
dependencies either way.
"""

from __future__ import annotations

import json
import re

try:  # pragma: no cover - depends on the environment
    import yaml as _pyyaml  # type: ignore
except ImportError:  # pragma: no cover
    _pyyaml = None

__all__ = ["YamlMinError", "loads", "loads_min"]


class YamlMinError(ValueError):
    """Input is outside the supported YAML subset (fail closed)."""


_INT = re.compile(r"^[+-]?\d+$")
_FLOAT = re.compile(r"^[+-]?(\d+\.\d*|\.\d+)([eE][+-]?\d+)?$")


def loads(text: str):
    """Parse YAML text: PyYAML when available, else the minimal subset."""
    if _pyyaml is not None:
        return _pyyaml.safe_load(text)
    return loads_min(text)


def loads_min(text: str):
    """Parse using only the minimal subset parser (never PyYAML)."""
    items = _lines(text)
    if not items:
        return None
    n0, indent0, _ = items[0]
    if indent0 != 0:
        raise YamlMinError(f"line {n0}: top-level indentation must be 0")
    value, i = _block(items, 0, 0)
    if i != len(items):
        raise YamlMinError(f"line {items[i][0]}: unexpected indentation")
    return value


# -- line handling ---------------------------------------------------------


def _lines(text: str):
    """Split into (lineno, indent, content); comments and blanks dropped."""
    out = []
    for n, raw in enumerate(text.splitlines(), 1):
        line = _strip_comment(raw)
        if not line.strip():
            continue
        leading = line[: len(line) - len(line.lstrip())]
        if "\t" in leading:
            raise YamlMinError(f"line {n}: tabs are not valid indentation")
        out.append((n, len(leading), line.strip()))
    return out


def _strip_comment(line: str) -> str:
    """Drop a trailing # comment (never inside quotes)."""
    in_s = in_d = False
    for i, ch in enumerate(line):
        if ch == "'" and not in_d:
            in_s = not in_s
        elif ch == '"' and not in_s:
            in_d = not in_d
        elif ch == "#" and not in_s and not in_d and (i == 0 or line[i - 1] in " \t"):
            return line[:i]
    return line


# -- structure -------------------------------------------------------------


def _block(items, i: int, indent: int):
    if items[i][2] == "-" or items[i][2].startswith("- "):
        return _list(items, i, indent)
    return _map(items, i, indent)


def _map(items, i: int, indent: int):
    result = {}
    while i < len(items) and items[i][1] == indent:
        n, _, content = items[i]
        if content == "-" or content.startswith("- "):
            raise YamlMinError(f"line {n}: list item inside a mapping")
        key, rest = _key(content, n)
        if key in result:
            raise YamlMinError(f"line {n}: duplicate key {key!r}")
        if rest:
            result[key] = _scalar(rest, n)
            i += 1
        elif i + 1 < len(items) and items[i + 1][1] > indent:
            result[key], i = _block(items, i + 1, items[i + 1][1])
        else:
            result[key] = None
            i += 1
    return result, i


def _list(items, i: int, indent: int):
    result = []
    while (
        i < len(items)
        and items[i][1] == indent
        and (items[i][2] == "-" or items[i][2].startswith("- "))
    ):
        n, _, content = items[i]
        rest = content[1:].strip()
        if not rest:
            if i + 1 < len(items) and items[i + 1][1] > indent:
                value, i = _block(items, i + 1, items[i + 1][1])
            else:
                value, i = None, i + 1
            result.append(value)
        elif _is_key_line(rest):
            # "- key: value" starts a mapping item; its keys live at indent + 2
            synth = items[:i] + [(n, indent + 2, rest)] + items[i + 1 :]
            value, i = _map(synth, i, indent + 2)
            result.append(value)
        else:
            result.append(_scalar(rest, n))
            i += 1
    return result, i


# -- keys and scalars ------------------------------------------------------


def _key(content: str, n: int):
    """Split 'key: rest' or 'key:' into (key, rest); fail closed otherwise."""
    in_s = in_d = False
    for i, ch in enumerate(content):
        if ch == "'" and not in_d:
            in_s = not in_s
        elif ch == '"' and not in_s:
            in_d = not in_d
        elif ch == ":" and not in_s and not in_d:
            if i == len(content) - 1:
                return _scalar(content[:i].strip(), n), ""
            if content[i + 1] == " ":
                return _scalar(content[:i].strip(), n), content[i + 1 :].strip()
    raise YamlMinError(f"line {n}: expected 'key: value'")


def _is_key_line(text: str) -> bool:
    try:
        _key(text, 0)
    except YamlMinError:
        return False
    return True


def _scalar(text: str, n: int):
    if not text:
        return ""
    if text.startswith(("[", "{")):
        raise YamlMinError(f"line {n}: flow style is not supported")
    if text.startswith("- "):
        raise YamlMinError(f"line {n}: nested inline lists are not supported")
    if text[0] in ('"', "'"):
        if len(text) < 2 or text[-1] != text[0]:
            raise YamlMinError(f"line {n}: unterminated quoted string")
        if text[0] == '"':
            try:
                return json.loads(text)
            except ValueError:
                raise YamlMinError(f"line {n}: bad double-quoted string")
        return text[1:-1].replace("''", "'")
    low = text.lower()
    if low in ("null", "~"):
        return None
    if low == "true":
        return True
    if low == "false":
        return False
    if _INT.match(text):
        return int(text)
    if _FLOAT.match(text):
        return float(text)
    return text
