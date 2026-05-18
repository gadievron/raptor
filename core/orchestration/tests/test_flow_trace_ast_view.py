"""Tests for ``core.orchestration.flow_trace_ast_view`` — per-step
AST-view enrichment for /understand --trace's flow-trace-*.json
output."""

from __future__ import annotations

from pathlib import Path

from core.orchestration.flow_trace_ast_view import (
    _parse_definition,
    enrich_with_ast_view,
)


def _project(tmp_path: Path, files: dict) -> Path:
    for rel, contents in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(contents)
    return tmp_path


# ---------------------------------------------------------------------------
# _parse_definition — the only non-trivial pure helper
# ---------------------------------------------------------------------------


class TestParseDefinition:
    def test_valid_file_and_line(self):
        assert _parse_definition("src/x.py:42") == ("src/x.py", 42)

    def test_nested_path(self):
        assert _parse_definition("a/b/c.py:1") == ("a/b/c.py", 1)

    def test_line_zero_rejected(self):
        # enclosing_function requires line >= 1.
        assert _parse_definition("x.py:0") is None

    def test_negative_line_rejected(self):
        assert _parse_definition("x.py:-5") is None

    def test_external_reference_rejected(self):
        # ``psycopg2.cursor.execute()`` — no :line.
        assert _parse_definition("psycopg2.cursor.execute()") is None

    def test_empty_string(self):
        assert _parse_definition("") is None

    def test_whitespace_stripped(self):
        assert _parse_definition("  src/x.py:42  ") == ("src/x.py", 42)

    def test_non_numeric_line_rejected(self):
        assert _parse_definition("x.py:abc") is None


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_enrich_steps_with_definitions(tmp_path):
    target = _project(tmp_path, {
        "src/auth.py": (
            "def check(user, pw):\n"           # 1
            "    if user is None:\n"            # 2
            "        return -1\n"               # 3
            "    h = compute(pw)\n"             # 4
            "    return 0\n"                    # 5
        ),
    })
    trace = {
        "id": "TRACE-001",
        "steps": [
            {"step": 1, "type": "entry", "call_site": None,
             "definition": "src/auth.py:1"},
            {"step": 2, "type": "call", "call_site": "src/auth.py:4",
             "definition": "src/auth.py:1"},
        ],
    }
    n = enrich_with_ast_view(trace, target)
    assert n == 2
    for s in trace["steps"]:
        assert "ast_view" in s
        assert s["ast_view"]["function"] == "check"
        assert s["ast_view"]["language"] == "python"


# ---------------------------------------------------------------------------
# External / sink steps that don't resolve
# ---------------------------------------------------------------------------


def test_external_definition_skipped(tmp_path):
    """Sink steps often point at external deps
    (``psycopg2.cursor.execute()``) — those don't parse as
    ``file:line``, so the step is left unenriched."""
    target = _project(tmp_path, {"src/x.py": "def f(): return 1\n"})
    trace = {
        "steps": [
            {"step": 1, "type": "sink", "call_site": "src/x.py:1",
             "definition": "psycopg2.cursor.execute()"},
        ],
    }
    n = enrich_with_ast_view(trace, target)
    assert n == 0
    assert "ast_view" not in trace["steps"][0]


def test_in_tree_definition_not_in_inventory(tmp_path):
    """A definition that parses but whose function isn't in the
    inventory (e.g. stale trace or moved code) gets skipped."""
    target = _project(tmp_path, {"src/x.py": "def f(): return 1\n"})
    trace = {
        "steps": [
            {"step": 1, "type": "call", "call_site": "src/x.py:1",
             "definition": "src/x.py:999"},  # line outside any function
        ],
    }
    n = enrich_with_ast_view(trace, target)
    assert n == 0


# ---------------------------------------------------------------------------
# Defence in depth: path traversal in definition
# ---------------------------------------------------------------------------


def test_path_traversal_in_definition_rejected(tmp_path):
    """LLM-emitted traces may carry injected entries with file paths
    that escape target_root. Reject those — never enrich a file
    outside the project."""
    target = _project(tmp_path, {"src/x.py": "def f(): return 1\n"})
    trace = {
        "steps": [
            {"step": 1, "type": "call", "call_site": "src/x.py:1",
             "definition": "../../../etc/passwd:1"},
        ],
    }
    n = enrich_with_ast_view(trace, target)
    assert n == 0
    assert "ast_view" not in trace["steps"][0]


def test_absolute_path_in_definition_rejected(tmp_path):
    target = _project(tmp_path, {"src/x.py": "def f(): return 1\n"})
    trace = {
        "steps": [
            {"step": 1, "type": "call", "call_site": "src/x.py:1",
             "definition": "/etc/passwd:1"},
        ],
    }
    n = enrich_with_ast_view(trace, target)
    assert n == 0


# ---------------------------------------------------------------------------
# Idempotency + overwrite policy
# ---------------------------------------------------------------------------


def test_existing_ast_view_preserved(tmp_path):
    target = _project(tmp_path, {"src/x.py": "def f(): return 1\n"})
    pre_existing = {"function": "preset", "schema_version": 999}
    trace = {
        "steps": [
            {"step": 1, "definition": "src/x.py:1",
             "ast_view": pre_existing},
        ],
    }
    enrich_with_ast_view(trace, target)
    assert trace["steps"][0]["ast_view"] is pre_existing


def test_idempotent_re_run(tmp_path):
    target = _project(tmp_path, {"src/x.py": "def f(): return 1\n"})
    trace = {
        "steps": [{"step": 1, "definition": "src/x.py:1"}],
    }
    enrich_with_ast_view(trace, target)
    first = trace["steps"][0]["ast_view"]
    enrich_with_ast_view(trace, target)
    assert trace["steps"][0]["ast_view"] is first


# ---------------------------------------------------------------------------
# Trace shape edge cases
# ---------------------------------------------------------------------------


def test_empty_steps(tmp_path):
    target = _project(tmp_path, {"src/x.py": "def f(): return 1\n"})
    assert enrich_with_ast_view({"steps": []}, target) == 0
    assert enrich_with_ast_view({}, target) == 0


def test_non_dict_trace(tmp_path):
    target = _project(tmp_path, {"src/x.py": "def f(): return 1\n"})
    assert enrich_with_ast_view([], target) == 0  # type: ignore[arg-type]
    assert enrich_with_ast_view("not a dict", target) == 0  # type: ignore[arg-type]


def test_non_dict_steps_skipped(tmp_path):
    target = _project(tmp_path, {"src/x.py": "def f(): return 1\n"})
    trace = {
        "steps": [
            "not a dict",            # type: ignore[list-item]
            {"step": 2, "definition": "src/x.py:1"},
            None,                    # type: ignore[list-item]
            42,                      # type: ignore[list-item]
        ],
    }
    n = enrich_with_ast_view(trace, target)
    assert n == 1
    assert "ast_view" in trace["steps"][1]


def test_step_without_definition(tmp_path):
    target = _project(tmp_path, {"src/x.py": "def f(): return 1\n"})
    trace = {
        "steps": [
            {"step": 1, "type": "entry"},  # no definition
        ],
    }
    n = enrich_with_ast_view(trace, target)
    assert n == 0


def test_step_with_null_definition(tmp_path):
    """``definition`` can be explicitly None (e.g. for some entry
    steps where the LLM hasn't recorded a line). Should skip
    gracefully."""
    target = _project(tmp_path, {"src/x.py": "def f(): return 1\n"})
    trace = {
        "steps": [
            {"step": 1, "type": "entry", "definition": None},
        ],
    }
    n = enrich_with_ast_view(trace, target)
    assert n == 0


# ---------------------------------------------------------------------------
# Inventory injection (caller already built one)
# ---------------------------------------------------------------------------


def test_inventory_injection_avoids_rebuild(tmp_path):
    """The libexec shim builds the inventory once and shares across
    all trace files. Pin that the injected inventory is used."""
    target = _project(tmp_path, {"src/x.py": "def f(): return 1\n"})
    from core.inventory.builder import build_inventory
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        inv = build_inventory(str(target), td)
        trace = {"steps": [{"step": 1, "definition": "src/x.py:1"}]}
        n = enrich_with_ast_view(trace, target, inventory=inv)
        assert n == 1
