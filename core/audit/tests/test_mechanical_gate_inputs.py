"""AST-based gates D / E-4 must receive RAW source, never the prompt rendering.

``ctx["source"]`` is the prompt rendering — every line carries a
``{n:4d}  `` number prefix (``context._read_source``), which
``ast.parse`` rejects, so a gate fed the rendering silently returns
``[]`` (double vacuity: the gate runs, pays its cost, and can never
produce an annotation). The orchestrator call sites hand the gates
the raw span (the gap's own extracted source, else the disk read the
structural checkers use).
"""

from __future__ import annotations

import ast
from pathlib import Path

from core.audit.mechanical_gates import (
    detect_constant_dangerous_calls,
    extract_type_constraints,
)

_ORCH = Path(__file__).resolve().parents[1] / "orchestrator.py"
_GATES = ("detect_constant_dangerous_calls", "extract_type_constraints")


def _gate_calls() -> dict[str, list[ast.Call]]:
    tree = ast.parse(_ORCH.read_text())
    calls: dict[str, list[ast.Call]] = {name: [] for name in _GATES}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if isinstance(node.func, ast.Name):
            fname = node.func.id
        elif isinstance(node.func, ast.Attribute):
            fname = node.func.attr
        else:
            continue
        if fname in _GATES:
            calls[fname].append(node)
    return calls


def _is_prompt_rendering(arg: ast.expr) -> bool:
    """ctx["source"] / ctx.get("source") — the numbered rendering."""
    if (
        isinstance(arg, ast.Subscript)
        and isinstance(arg.value, ast.Name)
        and arg.value.id == "ctx"
        and isinstance(arg.slice, ast.Constant)
        and arg.slice.value == "source"
    ):
        return True
    return (
        isinstance(arg, ast.Call)
        and isinstance(arg.func, ast.Attribute)
        and arg.func.attr == "get"
        and isinstance(arg.func.value, ast.Name)
        and arg.func.value.id == "ctx"
        and bool(arg.args)
        and isinstance(arg.args[0], ast.Constant)
        and arg.args[0].value == "source"
    )


class TestNumberedSourceNeverFeedsAstGates:
    def test_gate_call_sites_take_raw_source(self):
        calls = _gate_calls()
        for name in _GATES:
            assert calls[name], f"{name} has no orchestrator call site"
            for call in calls[name]:
                assert call.args, f"{name} called without positional source"
                assert not _is_prompt_rendering(call.args[0]), (
                    f"{name} is fed ctx['source'] — the numbered prompt "
                    f"rendering ast.parse rejects (gate silently vacuous)"
                )

    # ── the mechanism the call-site pin protects ─────────────────────

    def test_constant_call_gate_needs_parseable_source(self):
        raw = "import os\nCMD = 'ls'\ndef handler(user):\n    os.system(CMD)\n"
        numbered = "\n".join(
            f"{i + 1:4d}  {ln}" for i, ln in enumerate(raw.splitlines())
        )
        assert detect_constant_dangerous_calls(numbered, "a.py") == []
        hits = detect_constant_dangerous_calls(raw, "a.py")
        assert hits and hits[0]["call"] == "os.system"

    def test_type_constraint_gate_needs_parseable_source(self):
        raw = "def g(port: int, name: str):\n    pass\n"
        numbered = "\n".join(
            f"{i + 1:4d}  {ln}" for i, ln in enumerate(raw.splitlines())
        )
        assert extract_type_constraints(numbered, "a.py", "g") == []
        hits = extract_type_constraints(raw, "a.py", "g")
        assert hits and hits[0]["param"] == "port"
