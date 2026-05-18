"""Tests for the evidence-line helpers hoisted to
:mod:`core.inventory.reachability`: ``enclosing_function`` and
``parse_evidence_entry``.

Both started in ``packages/sca/reachability/_host_reachability.py``;
hoisted because /validate, /agentic, /understand all need the
same primitives. These tests duplicate (intentionally) the SCA
suite's coverage of ``enclosing_function`` so the substrate is
self-tested at its own level.
"""

from __future__ import annotations

from typing import Any, Dict, List


from core.inventory.call_graph import extract_call_graph_python
from core.inventory.reachability import (
    InternalFunction,
    enclosing_function,
    parse_evidence_entry,
)


def _file(path: str, source: str) -> Dict[str, Any]:
    import ast
    cg = extract_call_graph_python(source).to_dict()
    items: List[Dict[str, Any]] = []
    try:
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                items.append({
                    "name": node.name,
                    "kind": "function",
                    "line_start": node.lineno,
                    "line_end": getattr(node, "end_lineno", None),
                })
    except SyntaxError:
        pass
    return {
        "path": path, "language": "python",
        "items": items, "call_graph": cg,
    }


def _inv(*files: Dict[str, Any]) -> Dict[str, Any]:
    return {"files": list(files)}


# ---------------------------------------------------------------------------
# enclosing_function
# ---------------------------------------------------------------------------


def test_enclosing_function_simple():
    inv = _inv(_file("src/a.py",
        "def helper():\n"
        "    pass\n"
        "def main():\n"
        "    helper()\n"
    ))
    assert enclosing_function(inv, "src/a.py", 4) == \
        InternalFunction("src/a.py", "main", 3)


def test_enclosing_function_nested_picks_innermost():
    """Inner def's body resolves to inner; outer def's body
    resolves to outer."""
    inv = _inv(_file("src/a.py",
        "def outer():\n"          # 1
        "    def inner():\n"      # 2
        "        x = 1\n"          # 3 — inside inner
        "    inner()\n"            # 4 — inside outer (inner already closed)
    ))
    assert enclosing_function(inv, "src/a.py", 3) == \
        InternalFunction("src/a.py", "inner", 2)
    assert enclosing_function(inv, "src/a.py", 4) == \
        InternalFunction("src/a.py", "outer", 1)


def test_enclosing_function_module_level_returns_none():
    inv = _inv(_file("src/a.py",
        "x = 1\n"                  # 1 — module level
        "def f():\n"                # 2
        "    return x\n"            # 3 — inside f
    ))
    assert enclosing_function(inv, "src/a.py", 1) is None
    assert enclosing_function(inv, "src/a.py", 3) == \
        InternalFunction("src/a.py", "f", 2)


def test_enclosing_function_unknown_path_returns_none():
    inv = _inv(_file("src/a.py", "def f():\n    pass\n"))
    assert enclosing_function(inv, "nope.py", 5) is None


def test_enclosing_function_handles_missing_items():
    """Defensive: file record without an items field should not
    crash."""
    inv = {"files": [{"path": "src/a.py", "language": "python"}]}
    assert enclosing_function(inv, "src/a.py", 5) is None


def test_enclosing_function_skips_non_function_items():
    """Globals / classes / macros in the items list shouldn't
    confuse the lookup — we skip everything that isn't kind='function'
    (or kind missing, which defaults to function)."""
    inv = {"files": [{
        "path": "src/a.py",
        "language": "python",
        "items": [
            {"name": "GLOBAL_VAR", "kind": "global",
             "line_start": 1, "line_end": 1},
            {"name": "f", "kind": "function",
             "line_start": 2, "line_end": 5},
        ],
    }]}
    assert enclosing_function(inv, "src/a.py", 3) == \
        InternalFunction("src/a.py", "f", 2)


def test_enclosing_function_skips_items_with_invalid_lines():
    """An item with ``line_start <= 0`` shouldn't be matched."""
    inv = {"files": [{
        "path": "src/a.py",
        "language": "python",
        "items": [
            {"name": "broken", "kind": "function",
             "line_start": 0, "line_end": None},
            {"name": "real", "kind": "function",
             "line_start": 5, "line_end": 10},
        ],
    }]}
    assert enclosing_function(inv, "src/a.py", 7) == \
        InternalFunction("src/a.py", "real", 5)


def test_enclosing_function_open_ended_when_line_end_missing():
    """When ``line_end`` is missing, treat the range as
    open-ended — last def started before our line wins."""
    inv = {"files": [{
        "path": "src/a.py",
        "language": "python",
        "items": [
            {"name": "f", "kind": "function",
             "line_start": 1, "line_end": None},
            {"name": "g", "kind": "function",
             "line_start": 5, "line_end": None},
        ],
    }]}
    assert enclosing_function(inv, "src/a.py", 7) == \
        InternalFunction("src/a.py", "g", 5)


# ---------------------------------------------------------------------------
# parse_evidence_entry
# ---------------------------------------------------------------------------


def test_parse_evidence_entry_simple():
    assert parse_evidence_entry("src/a.py:42") == ("src/a.py", 42)


def test_parse_evidence_entry_preserves_colons_in_path():
    """Windows-style ``C:\\path:line`` should rsplit on the
    LAST colon."""
    assert parse_evidence_entry("C:\\src\\a.py:42") == \
        ("C:\\src\\a.py", 42)


def test_parse_evidence_entry_no_colon_returns_none():
    assert parse_evidence_entry("just-a-string") == (None, 0)


def test_parse_evidence_entry_non_int_line_returns_none():
    assert parse_evidence_entry("src/a.py:notanumber") == (None, 0)


def test_parse_evidence_entry_empty_path_returns_none():
    assert parse_evidence_entry(":42") == (None, 0)


def test_parse_evidence_entry_empty_line_returns_none():
    assert parse_evidence_entry("src/a.py:") == (None, 0)


def test_parse_evidence_entry_non_string_returns_none():
    assert parse_evidence_entry(None) == (None, 0)
    assert parse_evidence_entry(42) == (None, 0)
    assert parse_evidence_entry(["src/a.py", 42]) == (None, 0)
