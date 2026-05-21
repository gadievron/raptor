"""Tests for ``packages.sca.reachability._host_reachability``.

The helper underwrites every per-ecosystem function-level
module's ``called_in_dead_code`` decision. Two pieces:

  * :func:`enclosing_function` — given an inventory + (path, line),
    pick the InternalFunction whose body contains the line.
  * :func:`is_host_dead` — given a host, decide whether it has any
    callers in the project's static call graph.
  * :func:`classify_called_or_dead` — orchestrates the per-finding
    decision, returning either ``likely_called`` or
    ``called_in_dead_code``.

Pin the design points:

  * Nested defs: innermost match wins.
  * Module-level evidence (line not in any function): host is None,
    treated as NOT dead — module-level code runs unconditionally
    on import.
  * Entry-point names (``main``, ``_main``, ``Main``): always
    treated as alive even with no callers.
  * Public-named hosts: always treated as alive (we can't tell
    public-API from framework-invoked entry points without
    project-specific knowledge).
  * Private-named hosts (``_helper``, ``__internal``): dead iff
    no callers (1-hop AND transitive).
  * Test-file callers don't count by default.
  * Mixed evidence: ANY live host → likely_called; ALL dead →
    called_in_dead_code.
"""

from __future__ import annotations

from typing import Any, Dict, List


from core.inventory.call_graph import extract_call_graph_python
from core.inventory.reachability import InternalFunction
from packages.sca.reachability._host_reachability import (
    all_call_sites_in_dead_code,
    classify_called_or_dead,
    enclosing_function,
    is_host_dead,
)


def _file(path: str, source: str) -> Dict[str, Any]:
    """Build one file record. Auto-derives function items from
    AST."""
    import ast
    cg = extract_call_graph_python(source).to_dict()
    items: List[Dict[str, Any]] = []
    try:
        tree = ast.parse(source)
    except SyntaxError:
        tree = None
    if tree is not None:
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                items.append({
                    "name": node.name,
                    "kind": "function",
                    "line_start": node.lineno,
                    "line_end": getattr(node, "end_lineno", None),
                })
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
        "def helper():\n"        # line 1
        "    pass\n"
        "def main():\n"           # line 3
        "    helper()\n"          # line 4
    ))
    host = enclosing_function(inv, "src/a.py", 4)
    assert host == InternalFunction("src/a.py", "main", 3)


def test_enclosing_function_nested_picks_innermost():
    inv = _inv(_file("src/a.py",
        "def outer():\n"          # 1
        "    def inner():\n"      # 2
        "        x = 1\n"          # 3 — inside inner
        "    inner()\n"            # 4 — inside outer (NOT inner)
    ))
    inner_host = enclosing_function(inv, "src/a.py", 3)
    outer_host = enclosing_function(inv, "src/a.py", 4)
    assert inner_host == InternalFunction("src/a.py", "inner", 2)
    assert outer_host == InternalFunction("src/a.py", "outer", 1)


def test_enclosing_function_module_level_returns_none():
    """A line at module scope (outside any def) returns None —
    indicates no enclosing function."""
    inv = _inv(_file("src/a.py",
        "import os\n"             # 1 — module level
        "x = 1\n"                  # 2 — module level
        "def f():\n"               # 3
        "    return x\n"           # 4 — inside f
    ))
    host_module = enclosing_function(inv, "src/a.py", 2)
    host_inside = enclosing_function(inv, "src/a.py", 4)
    assert host_module is None
    assert host_inside == InternalFunction("src/a.py", "f", 3)


def test_enclosing_function_unknown_path_returns_none():
    inv = _inv(_file("src/a.py", "def f():\n    pass\n"))
    assert enclosing_function(inv, "nope.py", 5) is None


def test_enclosing_function_handles_missing_items():
    """Defensive: file record with no items field shouldn't crash."""
    inv = {"files": [{"path": "src/a.py", "language": "python"}]}
    assert enclosing_function(inv, "src/a.py", 5) is None


# ---------------------------------------------------------------------------
# is_host_dead — alive cases
# ---------------------------------------------------------------------------


def test_host_with_caller_is_alive():
    inv = _inv(_file("src/a.py",
        "def _helper():\n"
        "    pass\n"
        "def main():\n"
        "    _helper()\n"
    ))
    helper = InternalFunction("src/a.py", "_helper", 1)
    # _helper is private but main calls it; main is an entry point
    # name, so _helper has a live caller transitively.
    assert is_host_dead(inv, helper) is False


def test_main_is_always_alive():
    """Even with no callers, ``main`` is treated as alive — the
    language runtime invokes it."""
    inv = _inv(_file("src/a.py",
        "def main():\n"
        "    pass\n"
    ))
    main = InternalFunction("src/a.py", "main", 1)
    assert is_host_dead(inv, main) is False


def test_public_named_host_with_no_callers_is_alive():
    """Public-named hosts (no leading underscore) are treated as
    alive even with no static callers — we can't distinguish public
    API from framework-invoked code without project-specific
    knowledge."""
    inv = _inv(_file("src/a.py",
        "def public_helper():\n"
        "    pass\n"
    ))
    fn = InternalFunction("src/a.py", "public_helper", 1)
    assert is_host_dead(inv, fn) is False


# ---------------------------------------------------------------------------
# is_host_dead — dead cases
# ---------------------------------------------------------------------------


def test_private_named_host_with_no_callers_is_dead():
    inv = _inv(_file("src/a.py",
        "def _legacy_unzip():\n"
        "    pass\n"
    ))
    fn = InternalFunction("src/a.py", "_legacy_unzip", 1)
    assert is_host_dead(inv, fn) is True


def test_dunder_named_host_with_no_callers_is_dead():
    inv = _inv(_file("src/a.py",
        "def __internal():\n"
        "    pass\n"
    ))
    fn = InternalFunction("src/a.py", "__internal", 1)
    assert is_host_dead(inv, fn) is True


def test_test_file_callers_dont_keep_host_alive():
    """A private host called only from a test file is still
    considered dead — test-only callers don't count toward
    production reachability."""
    inv = _inv(
        _file("src/a.py",
            "def _helper():\n"
            "    pass\n"
        ),
        _file("tests/test_a.py",
            "from src.a import _helper\n"
            "def test_h():\n"
            "    _helper()\n"
        ),
    )
    helper = InternalFunction("src/a.py", "_helper", 1)
    assert is_host_dead(inv, helper) is True


def test_uncertain_caller_keeps_host_alive():
    """If a file uses getattr() and mentions the host's tail name,
    the host has an uncertain caller — we treat that as alive
    (conservative)."""
    inv = _inv(
        _file("src/a.py",
            "def _helper():\n"
            "    pass\n"
        ),
        _file("src/dynamic.py",
            "import importlib\n"
            "def runtime_dispatch():\n"
            "    fn = getattr(some_obj, '_helper')\n"
            "    fn()\n"
        ),
    )
    helper = InternalFunction("src/a.py", "_helper", 1)
    assert is_host_dead(inv, helper) is False


# ---------------------------------------------------------------------------
# all_call_sites_in_dead_code
# ---------------------------------------------------------------------------


def test_all_dead_returns_true():
    """Every call site lives in a private host with no callers."""
    inv = _inv(_file("src/a.py",
        "import json\n"
        "def _legacy():\n"
        "    json.dumps({})\n"   # line 3
    ))
    assert all_call_sites_in_dead_code(inv, ["src/a.py:3"]) is True


def test_any_live_returns_false():
    """ANY call site in a live host → false."""
    inv = _inv(_file("src/a.py",
        "import json\n"
        "def _dead():\n"
        "    json.dumps({})\n"   # line 3
        "def main():\n"
        "    json.dumps({})\n"   # line 5 (in main, alive)
    ))
    assert all_call_sites_in_dead_code(
        inv, ["src/a.py:3", "src/a.py:5"]
    ) is False


def test_module_level_evidence_returns_false():
    """A call at module scope runs at import time and IS exercised
    — never dead code."""
    inv = _inv(_file("src/a.py",
        "import json\n"
        "json.dumps({})\n"        # line 2 — module level
    ))
    assert all_call_sites_in_dead_code(inv, ["src/a.py:2"]) is False


def test_empty_evidence_returns_false():
    inv = _inv(_file("src/a.py", "def f():\n    pass\n"))
    assert all_call_sites_in_dead_code(inv, []) is False


def test_unparseable_evidence_skipped():
    """A malformed entry doesn't crash — gets skipped. Other
    entries decide the verdict."""
    inv = _inv(_file("src/a.py",
        "import json\n"
        "def _legacy():\n"
        "    json.dumps({})\n"
    ))
    assert all_call_sites_in_dead_code(
        inv, ["malformed-no-colon", "src/a.py:3"]
    ) is True


def test_only_unparseable_evidence_returns_false():
    """No evaluable entries → conservative False."""
    inv = _inv(_file("src/a.py", "def f():\n    pass\n"))
    assert all_call_sites_in_dead_code(
        inv, ["malformed", "also-malformed"]
    ) is False


# ---------------------------------------------------------------------------
# classify_called_or_dead
# ---------------------------------------------------------------------------


def test_classify_returns_likely_called_when_alive():
    inv = _inv(_file("src/a.py",
        "import json\n"
        "def main():\n"
        "    json.dumps({})\n"
    ))
    result = classify_called_or_dead(
        inv, ["src/a.py:3"],
        likely_called_reason="main calls json.dumps",
        affected_summary="json.dumps",
    )
    assert result.verdict == "likely_called"
    assert result.confidence.level == "high"
    assert result.confidence.reason == "main calls json.dumps"


def test_classify_returns_dead_when_all_hosts_dead():
    inv = _inv(_file("src/a.py",
        "import json\n"
        "def _legacy():\n"
        "    json.dumps({})\n"
    ))
    result = classify_called_or_dead(
        inv, ["src/a.py:3"],
        likely_called_reason="should not appear in dead-code result",
        affected_summary="json.dumps",
    )
    assert result.verdict == "called_in_dead_code"
    assert result.confidence.level == "medium"
    assert "json.dumps" in result.confidence.reason
    assert "dead code" in result.confidence.reason


def test_classify_evidence_truncated_to_five():
    """Both branches truncate evidence to the first 5 entries."""
    inv = _inv(_file("src/a.py",
        "import json\n"
        "def main():\n"           # 2 — alive
        "    json.dumps({})\n"   # 3
        "    json.dumps({})\n"   # 4
        "    json.dumps({})\n"   # 5
        "    json.dumps({})\n"   # 6
        "    json.dumps({})\n"   # 7
        "    json.dumps({})\n"   # 8
    ))
    evidence = [f"src/a.py:{ln}" for ln in (3, 4, 5, 6, 7, 8)]
    result = classify_called_or_dead(
        inv, evidence,
        likely_called_reason="r",
        affected_summary="json.dumps",
    )
    assert len(result.evidence) == 5
