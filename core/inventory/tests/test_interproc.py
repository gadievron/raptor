"""Phase 14 — inter-procedural evaluate_finding tests.

Exercises the synthetic-binding builder and the end-to-end verdict
flip through the resolver. Covers the design's named cases:
sanitizer-in-helper, sanitizer-only-on-some-branches, bypass via
non-sanitizing callee, recursive/transitive sanitization, and the
multi-arg positional-mapping correctness that distinguishes a
sanitized parameter from an unsanitized sibling.
"""
from __future__ import annotations

import ast

from core.inventory.cfg_builder import build_python_cfg
from core.inventory.finding_resolver import (
    ResolvedFinding,
    resolve_finding,
)
from core.inventory.callgraph import build_python_module_callgraph
from core.inventory.interproc import synthetic_sanitizer_bindings
from core.inventory.taint_summaries import build_taint_summaries
from core.inventory.sanitizer_cut import (
    VERDICT_NO_SUPPRESS,
    VERDICT_SUPPRESS,
    evaluate_finding,
)


# ---------------------------------------------------------------------------
# Helpers — build the (cfg, fn_ast, summaries) triple for one function
# ---------------------------------------------------------------------------


def _bindings_for(src: str, fn_name: str, cwe: str = "CWE-79"):
    cg = build_python_module_callgraph(src)
    assert cg is not None
    summaries = build_taint_summaries(cg, src)
    tree = ast.parse(src)
    fn_ast = next(
        n for n in ast.walk(tree)
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
        and n.name == fn_name
    )
    cfg = build_python_cfg(src, fn_name)
    assert cfg is not None
    bindings = synthetic_sanitizer_bindings(
        cfg, fn_ast, summaries, cwe, "python",
    )
    return cfg, bindings


def _evaluate(src, fn_name, source_symbols, sink_arg, sink_line, cwe="CWE-79"):
    cfg, bindings = _bindings_for(src, fn_name, cwe)
    sink = next(n for n in cfg.nodes() if n.lineno == sink_line)
    return evaluate_finding(
        cfg, [cfg.entry_node], sink,
        cwe=cwe, language="python",
        source_symbols=source_symbols, sink_arg=sink_arg,
        extra_bindings=bindings,
    )


# ---------------------------------------------------------------------------
# Binding generation
# ---------------------------------------------------------------------------


class TestBindingGeneration:
    def test_helper_sanitizer_produces_binding(self):
        src = (
            "def _sanitize(s):\n"
            "    return html.escape(s)\n"
            "def handle(x):\n"
            "    y = _sanitize(x)\n"
            "    render(y)\n"
        )
        _, bindings = _bindings_for(src, "handle")
        assert len(bindings) == 1
        b = next(iter(bindings))
        assert b.callable == "_sanitize"
        assert b.input_symbols == frozenset({"x"})
        assert b.output_symbols == frozenset({"y"})

    def test_passthrough_helper_no_binding(self):
        # Helper returns its arg unchanged — no sanitization.
        src = (
            "def _passthrough(s):\n"
            "    return s\n"
            "def handle(x):\n"
            "    y = _passthrough(x)\n"
            "    render(y)\n"
        )
        _, bindings = _bindings_for(src, "handle")
        assert bindings == frozenset()

    def test_some_branches_helper_no_binding(self):
        # Helper sanitizes only on one branch — the direct-return
        # path means the param can reach return unsanitized.
        src = (
            "def _maybe(s, cond):\n"
            "    if cond:\n"
            "        return html.escape(s)\n"
            "    return s\n"
            "def handle(x, c):\n"
            "    y = _maybe(x, c)\n"
            "    render(y)\n"
        )
        _, bindings = _bindings_for(src, "handle")
        assert bindings == frozenset()

    def test_non_sanitizer_callable_in_chain_no_binding(self):
        # Helper wraps the escaped value in an unknown callable —
        # can't prove the wrapper preserves sanitization.
        src = (
            "def _wrap(s):\n"
            "    return wrap(html.escape(s))\n"
            "def handle(x):\n"
            "    y = _wrap(x)\n"
            "    render(y)\n"
        )
        _, bindings = _bindings_for(src, "handle")
        assert bindings == frozenset()

    def test_wrong_cwe_no_binding(self):
        # html.escape sanitizes xss (CWE-79), not sqli (CWE-89).
        src = (
            "def _sanitize(s):\n"
            "    return html.escape(s)\n"
            "def handle(x):\n"
            "    y = _sanitize(x)\n"
            "    run_query(y)\n"
        )
        _, bindings = _bindings_for(src, "handle", cwe="CWE-89")
        assert bindings == frozenset()

    def test_multiarg_helper_maps_correct_position(self):
        # Helper sanitizes param 1 (b). The binding's input_symbols
        # must be the arg passed at position 1, not 0.
        src = (
            "def _san(a, b):\n"
            "    return html.escape(b)\n"
            "def handle(p, q):\n"
            "    y = _san(p, q)\n"
            "    render(y)\n"
        )
        _, bindings = _bindings_for(src, "handle")
        assert len(bindings) == 1
        b = next(iter(bindings))
        # position 1 of the call _san(p, q) is q
        assert b.input_symbols == frozenset({"q"})

    def test_transitive_sanitizer_produces_binding(self):
        # outer returns inner's result; inner sanitizes. The chain
        # is transitive via Phase 13 summaries.
        src = (
            "def inner(s):\n"
            "    return html.escape(s)\n"
            "def outer(s):\n"
            "    return inner(s)\n"
            "def handle(x):\n"
            "    y = outer(x)\n"
            "    render(y)\n"
        )
        _, bindings = _bindings_for(src, "handle")
        assert len(bindings) == 1
        assert next(iter(bindings)).callable == "outer"

    def test_dynamic_helper_no_binding(self):
        # Helper uses getattr — summary_unknown → no binding.
        src = (
            "def _dyn(o, name, s):\n"
            "    return getattr(o, name)(s)\n"
            "def handle(o, n, x):\n"
            "    y = _dyn(o, n, x)\n"
            "    render(y)\n"
        )
        _, bindings = _bindings_for(src, "handle")
        assert bindings == frozenset()

    def test_same_symbol_into_sanitized_and_unsanitized_no_binding(self):
        # Review #1: helper sanitizes param a but passes param b
        # through unchanged. Called with the SAME symbol x in both
        # positions, x reaches the return unsanitized via b — so no
        # binding may be synthesised (would be a false suppression one
        # inter-proc level deeper than the wrong-variable case).
        src = (
            "def helper(a, b):\n"
            "    return html.escape(a) + b\n"
            "def handle(x):\n"
            "    y = helper(x, x)\n"
            "    render(y)\n"
        )
        _, bindings = _bindings_for(src, "handle")
        assert bindings == frozenset()

    def test_distinct_symbols_into_multiarg_helper_binds_sanitized(self):
        # Sibling of the above: distinct symbols, only the sanitized
        # position's symbol is bound (the unsanitized b-symbol does not
        # poison the binding for a's symbol).
        src = (
            "def helper(a, b):\n"
            "    return html.escape(a)\n"  # b never reaches return
            "def handle(p, q):\n"
            "    y = helper(p, q)\n"
            "    render(y)\n"
        )
        _, bindings = _bindings_for(src, "handle")
        assert len(bindings) == 1
        assert next(iter(bindings)).input_symbols == frozenset({"p"})

    def test_two_same_callee_calls_one_line_bind_by_column(self):
        # Review #3: two calls to the SAME helper on one source line.
        # Each synthetic binding must attach to its own call's args —
        # resolved by (lineno, col_offset), not ast.walk order, which
        # would map both to the first call.
        src = (
            "def san(s):\n"
            "    return html.escape(s)\n"
            "def handle(p, q):\n"
            "    y = san(p) if san(q) else None\n"
            "    render(y)\n"
        )
        _, bindings = _bindings_for(src, "handle")
        assert {b.input_symbols for b in bindings} == {
            frozenset({"p"}), frozenset({"q"}),
        }


# ---------------------------------------------------------------------------
# End-to-end verdicts
# ---------------------------------------------------------------------------


class TestVerdicts:
    def test_sanitizer_in_helper_suppresses(self):
        src = (
            "def _sanitize(s):\n"
            "    return html.escape(s)\n"
            "def handle(x):\n"
            "    y = _sanitize(x)\n"
            "    render(y)\n"
        )
        result = _evaluate(src, "handle", ["x"], "y", 5)
        assert result.verdict == VERDICT_SUPPRESS, result.reason

    def test_bypass_via_passthrough_no_suppress(self):
        src = (
            "def _passthrough(s):\n"
            "    return s\n"
            "def handle(x):\n"
            "    y = _passthrough(x)\n"
            "    render(y)\n"
        )
        result = _evaluate(src, "handle", ["x"], "y", 5)
        assert result.verdict == VERDICT_NO_SUPPRESS, result.reason

    def test_some_branches_helper_no_suppress(self):
        src = (
            "def _maybe(s, cond):\n"
            "    if cond:\n"
            "        return html.escape(s)\n"
            "    return s\n"
            "def handle(x, c):\n"
            "    y = _maybe(x, c)\n"
            "    render(y)\n"
        )
        result = _evaluate(src, "handle", ["x"], "y", 7)
        assert result.verdict == VERDICT_NO_SUPPRESS, result.reason

    def test_transitive_sanitization_suppresses(self):
        src = (
            "def inner(s):\n"
            "    return html.escape(s)\n"
            "def outer(s):\n"
            "    return inner(s)\n"
            "def handle(x):\n"
            "    y = outer(x)\n"
            "    render(y)\n"
        )
        result = _evaluate(src, "handle", ["x"], "y", 7)
        assert result.verdict == VERDICT_SUPPRESS, result.reason

    def test_same_symbol_dual_position_not_suppressed(self):
        # End-to-end of the review #1 repro: taint reaches the sink via
        # the unsanitized param, so the finding must survive.
        src = (
            "def helper(a, b):\n"
            "    return html.escape(a) + b\n"
            "def handle(x):\n"
            "    y = helper(x, x)\n"
            "    render(y)\n"
        )
        result = _evaluate(src, "handle", ["x"], "y", 5)
        assert result.verdict == VERDICT_NO_SUPPRESS, result.reason

    def test_wrong_variable_via_helper_not_suppressed(self):
        # Helper sanitizes other, but the sink reads user. The
        # synthetic binding's output (z) doesn't match the sink_arg
        # (user) → condition 3 fails → no suppression.
        src = (
            "def _sanitize(s):\n"
            "    return html.escape(s)\n"
            "def handle(user, other):\n"
            "    z = _sanitize(other)\n"
            "    render(user)\n"
        )
        result = _evaluate(src, "handle", ["user", "other"], "user", 5)
        assert result.verdict != VERDICT_SUPPRESS, result.reason


# ---------------------------------------------------------------------------
# Resolver integration — inter_proc_bindings populated end to end
# ---------------------------------------------------------------------------


class TestResolverIntegration:
    def test_resolver_populates_inter_proc_bindings(self, tmp_path):
        src = (
            "def _sanitize(s):\n"
            "    return html.escape(s)\n"
            "def handle(x):\n"
            "    y = _sanitize(x)\n"
            "    render(y)\n"
        )
        f = tmp_path / "app.py"
        f.write_text(src, encoding="utf-8")
        finding = {
            "cwe": "CWE-79", "file_path": str(f),
            "source_line": 3, "sink_line": 5, "language": "python",
        }
        resolved = resolve_finding(finding)
        assert isinstance(resolved, ResolvedFinding)
        assert len(resolved.inter_proc_bindings) == 1
        # And the gate flips with them.
        result = evaluate_finding(
            resolved.cfg, [resolved.source_node], resolved.sink_node,
            cwe=resolved.cwe, language=resolved.language,
            source_symbols=resolved.source_symbols,
            sink_arg=resolved.sink_arg,
            extra_bindings=resolved.inter_proc_bindings,
        )
        assert result.verdict == VERDICT_SUPPRESS

    def test_resolver_no_helper_empty_bindings(self, tmp_path):
        src = (
            "def handle(x):\n"
            "    y = html.escape(x)\n"
            "    render(y)\n"
        )
        f = tmp_path / "app.py"
        f.write_text(src, encoding="utf-8")
        finding = {
            "cwe": "CWE-79", "file_path": str(f),
            "source_line": 1, "sink_line": 3, "language": "python",
        }
        resolved = resolve_finding(finding)
        assert isinstance(resolved, ResolvedFinding)
        assert resolved.inter_proc_bindings == frozenset()

    def test_cpp_finding_has_empty_inter_proc_bindings(self, tmp_path):
        src = (
            "extern char *g_markup_escape_text(const char *, long);\n"
            "extern void render(const char *);\n"
            "void handle(const char *x) {\n"
            "    const char *y = g_markup_escape_text(x, -1);\n"
            "    render(y);\n"
            "}\n"
        )
        f = tmp_path / "app.c"
        f.write_text(src, encoding="utf-8")
        finding = {
            "cwe": "CWE-79", "file_path": str(f),
            "source_line": 3, "sink_line": 5, "language": "c",
        }
        resolved = resolve_finding(finding)
        # C/C++ resolution either succeeds (tree-sitter present) with
        # empty inter_proc_bindings, or fails cleanly. Either way no
        # crash and no Python inter-proc bindings.
        if isinstance(resolved, ResolvedFinding):
            assert resolved.inter_proc_bindings == frozenset()
