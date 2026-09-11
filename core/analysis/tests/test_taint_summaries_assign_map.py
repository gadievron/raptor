"""Precomputed assignment-map equivalence and perf-shape tests for
:mod:`core.analysis.taint_summaries`."""
from __future__ import annotations

import ast

import core.analysis.taint_summaries as ts_mod
from core.analysis.python_module_callgraph import (
    build_python_module_callgraph,
)

# Representative module: parameter pass-through, sanitizer call,
# augmented assignment, annotated assignment, walrus, a for-target
# def (no Assign shape), and a call-graph hop between functions.
_FIXTURE_SRC = (
    "def sanitize(v):\n"
    "    out = html.escape(v)\n"
    "    return out\n"
    "def f(x, xs):\n"
    "    y = x\n"
    "    y += 'suffix'\n"
    "    z: str = y\n"
    "    if (w := z):\n"
    "        emit(w)\n"
    "    for item in xs:\n"
    "        emit(item)\n"
    "    return sanitize(z)\n"
)


def test_analysis_result_matches_expected_output():
    cg = build_python_module_callgraph(_FIXTURE_SRC)
    assert cg is not None
    summaries = ts_mod.build_taint_summaries(cg, _FIXTURE_SRC)

    s_san = summaries["sanitize"]
    assert s_san.param_taints_return(0)
    assert ("html.escape", 0) in s_san.return_sanitizers_for_param(0)

    s_f = summaries["f"]
    # x flows through y/y+=/z/walrus into emit() and into sanitize().
    assert s_f.param_taints_return(0)
    assert ("emit", 0, 0) in s_f.call_arg_taint
    assert ("sanitize", 0, 0) in s_f.call_arg_taint
    # xs flows into emit() via the for-target (no Assign AST shape —
    # the uses-merge fallback path).
    assert ("emit", 0, 1) in s_f.call_arg_taint
    assert not s_f.summary_unknown
    assert not s_f.summary_unconverged


def test_precomputed_map_equivalent_to_per_query_lookup():
    # The map must return exactly what the reference per-(lineno,
    # name) AST-walk helper returns, for every def site.
    tree = ast.parse(_FIXTURE_SRC)
    for fn_ast in tree.body:
        amap = ts_mod._build_assignment_value_map(fn_ast)
        for (lineno, name), found in amap.items():
            assert ts_mod._find_assignment_value_at(
                fn_ast, lineno, name,
            ) == found
        # And the reference finds nothing the map lacks.
        for node in ast.walk(fn_ast):
            lineno = getattr(node, "lineno", None)
            if lineno is None:
                continue
            for name in ("out", "y", "z", "w", "x", "xs", "item", "v"):
                ref = ts_mod._find_assignment_value_at(fn_ast, lineno, name)
                assert amap.get((lineno, name)) == ref


def test_fixed_point_loop_no_longer_walks_ast_per_query(monkeypatch):
    # The per-query full-AST-walk helper must not run during summary
    # construction any more — the loop reads the one-shot map.
    calls = {"n": 0}
    original = ts_mod._find_assignment_value_at

    def counting(*args, **kwargs):
        calls["n"] += 1
        return original(*args, **kwargs)

    monkeypatch.setattr(ts_mod, "_find_assignment_value_at", counting)
    cg = build_python_module_callgraph(_FIXTURE_SRC)
    assert cg is not None
    summaries = ts_mod.build_taint_summaries(cg, _FIXTURE_SRC)
    assert summaries["f"].param_taints_return(0)
    assert calls["n"] == 0
