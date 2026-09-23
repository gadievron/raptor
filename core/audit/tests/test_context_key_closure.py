"""Producer↔renderer closure for review-context enrichment keys.

The review prompt is assembled from a ``ctx`` dict: orchestrator prep
computes enrichment keys (some behind paid tool round-trips) and
``format_context_for_prompt`` renders them. The two sides were
hand-maintained with no closure oracle — 15 computed keys (including
a per-function Joern CPG query and the five-family evidence fusion)
had no renderer section at all: the run paid for dead output, and the
module contract ("structured annotations injected into the
per-function context before the LLM review") was silently vacuous.

Both directions are DERIVED mechanically from the runtime AST — no
hand-kept key list:

1. every ctx key any runtime core/audit module writes is read
   somewhere in runtime core/audit (renderer or another consumer);
2. every key the renderer reads is produced somewhere.

Ctx-shaped variables are recognised by naming convention (``ctx``,
``cc_ctx``, ``ref_review_ctx``, ... — any name ending in ``ctx``),
which is the convention every producer/consumer site uses.
"""

from __future__ import annotations

import ast
from pathlib import Path

_AUDIT = Path(__file__).resolve().parents[1]

#: Keys written by a runtime module but consumed OUTSIDE the ctx-dict
#: convention this test derives (each entry needs a named consumer).
_WRITE_EXCEPTIONS: frozenset[str] = frozenset()

#: Renderer-read keys produced outside core/audit (none today).
_READ_EXCEPTIONS: frozenset[str] = frozenset()


def _is_ctx_name(node: ast.expr) -> bool:
    return isinstance(node, ast.Name) and node.id.lower().endswith("ctx")


def _sub_key(node: ast.expr) -> str | None:
    if (
        isinstance(node, ast.Subscript)
        and _is_ctx_name(node.value)
        and isinstance(node.slice, ast.Constant)
        and isinstance(node.slice.value, str)
    ):
        return node.slice.value
    return None


def _method_key(node: ast.expr, methods: tuple[str, ...]) -> str | None:
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and _is_ctx_name(node.func.value)
        and node.func.attr in methods
        and node.args
        and isinstance(node.args[0], ast.Constant)
        and isinstance(node.args[0].value, str)
    ):
        return node.args[0].value
    return None


def _scan() -> tuple[dict[str, set[str]], dict[str, set[str]]]:
    writes: dict[str, set[str]] = {}
    reads: dict[str, set[str]] = {}
    for path in sorted(_AUDIT.glob("*.py")):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, (ast.Assign, ast.AugAssign)):
                targets = (
                    node.targets if isinstance(node, ast.Assign)
                    else [node.target]
                )
                for t in targets:
                    key = _sub_key(t)
                    if key:
                        writes.setdefault(key, set()).add(path.name)
                    if (
                        _is_ctx_name(t)
                        and isinstance(node, ast.Assign)
                        and isinstance(node.value, ast.Dict)
                    ):
                        for k in node.value.keys:
                            if isinstance(k, ast.Constant) and isinstance(
                                k.value, str,
                            ):
                                writes.setdefault(
                                    k.value, set(),
                                ).add(path.name)
            elif isinstance(node, ast.Call):
                key = _method_key(node, ("setdefault",))
                if key:
                    writes.setdefault(key, set()).add(path.name)
                    reads.setdefault(key, set()).add(path.name)
                    continue
                key = _method_key(node, ("get", "pop"))
                if key:
                    reads.setdefault(key, set()).add(path.name)
            elif isinstance(node, ast.Subscript):
                key = _sub_key(node)
                if key and isinstance(node.ctx, ast.Load):
                    reads.setdefault(key, set()).add(path.name)
    return writes, reads


def _renderer_reads() -> set[str]:
    tree = ast.parse((_AUDIT / "context.py").read_text())
    keys: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name in (
            "format_context_for_prompt", "_format_glance_prompt",
        ):
            for sub in ast.walk(node):
                key = _sub_key(sub) or _method_key(sub, ("get", "pop"))
                if key:
                    keys.add(key)
    return keys


class TestContextKeyClosure:
    def test_every_written_key_has_a_reader(self):
        writes, reads = _scan()
        dead = {
            k: sorted(v)
            for k, v in writes.items()
            if k not in reads and k not in _WRITE_EXCEPTIONS
        }
        assert dead == {}, (
            f"ctx keys computed but never consumed (paid dead work / "
            f"silent dead integration): {dead}"
        )

    def test_every_renderer_key_has_a_producer(self):
        writes, _ = _scan()
        orphans = sorted(
            k for k in _renderer_reads()
            if k not in writes and k not in _READ_EXCEPTIONS
        )
        assert orphans == [], (
            f"renderer sections with no producer anywhere in runtime "
            f"core/audit (vacuous sections): {orphans}"
        )

    def test_the_fifteen_adjudicated_keys_render(self):
        # The regression pin for the filed defect: ctx carrying every
        # once-dead enrichment key renders a marker for each (or, for
        # the deleted key, is no longer produced anywhere).
        from core.audit.context import format_context_for_prompt

        keys = [
            "entry_point_provenance",
            "capability_displacement", "co_accessor_analysis",
            "intra_function_analysis", "fused_evidence",
            "smt_pre_evidence", "exploit_feedback", "threat_model",
        ]
        ctx = {
            "file": "a.c", "function": "f",
            "line_start": 1, "line_end": 5,
            "source": "int f(void) { return 0; }",
        }
        for i, k in enumerate(keys):
            ctx[k] = f"CLOSUREMARKER_{i}"
        ctx["is_security_decision"] = True
        ctx["feeds_security_decision"] = True
        ctx["constant_dangerous_calls"] = [
            {"call": "os.system", "line": 3, "args": ["CMD='ls'"]},
        ]
        ctx["type_constraints"] = [
            {"param": "port", "type": "int",
             "constraint_note": "numeric/boolean"},
        ]
        ctx["universal_preconditions"] = [
            {"param": "buf", "conditions": "buf != NULL",
             "n_callers": "2", "arg_verified": "true"},
        ]
        ctx["interprocedural_guards"] = {
            "callee_function": "f", "callee_file": "a.c",
            "total_callers": 3, "guarded_callers": 1,
            "unguarded_callers": 2, "all_callers_guarded": False,
        }
        ctx["live_sinks"] = ["system"]
        out = format_context_for_prompt(ctx)
        missing = [k for i, k in enumerate(keys)
                   if f"CLOSUREMARKER_{i}" not in out]
        assert missing == [], f"markers not rendered: {missing}"
        assert "security decision point" in out.lower()
        assert "SECURITY CONSEQUENCE" in out
        assert "os.system" in out
        assert "TYPE CONSTRAINTS" in out
        assert "UNIVERSAL CALLER CONSTRAINT" in out
        assert "2 do NOT" in out
        assert "system" in out

    def test_structured_evidence_twin_no_longer_computed(self):
        # The adjudicated delete: the structured evidence rendering
        # was produced beside the prose form with no consumer.
        writes, _ = _scan()
        assert "mechanical_evidence_structured" not in writes
