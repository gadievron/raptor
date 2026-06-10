"""Phase 4 tests — value-bound suppression gate.

These pin the closure of the value-binding soundness hole: the
original vertex-cut proved control-flow but not value-flow, so it
would suppress

    def handle(user, other):
        safe_other = html.escape(other)
        render(user.name)

as a "sanitized XSS" because removing the html.escape node makes
the sink unreachable. The sanitizer, however, never touched
``user.name``.

Phase 4's gate evaluates four conditions per binding:

  1. ``binding.callable`` matches the catalog (already filtered by
     :func:`match_sanitizers_in_cfg`).
  2. ``binding.input_symbols`` intersects the taint front at
     ``binding.node``'s IN.
  3. ``sink_arg`` is in ``binding.output_symbols`` AND
     ``binding.node`` is a reaching definer of ``sink_arg`` at the
     sink.
  4. Removing every binding that satisfies (2) AND (3) from the
     graph cuts every source → sink path.

When all four hold → ``VERDICT_SUPPRESS``. When (1) and (4) hold
over the full match set but the value-bound subset doesn't cut →
``VERDICT_CANDIDATE_ONLY``. When even the full-set control-flow
cut fails → ``VERDICT_NO_SUPPRESS``.

These tests also cover back-compat — when callers omit
``source_symbols`` / ``sink_arg``, the function falls back to
control-flow-only Phase 7 behaviour and emits
``VERDICT_SUPPRESS`` / ``VERDICT_NO_SUPPRESS`` only.
"""
from __future__ import annotations

from unittest import mock

from core.inventory.cfg_builder import (
    PyCFGNode,
    build_cpp_callgraph,
    build_python_cfg,
)
from core.inventory.sanitizer_cut import (
    VERDICT_CANDIDATE_ONLY,
    VERDICT_NO_SUPPRESS,
    VERDICT_SUPPRESS,
    SanitizerCutResult,
    evaluate_finding,
)


# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------


def _cfg(src, func="handle"):
    cfg = build_python_cfg(src, func)
    assert cfg is not None
    return cfg


def _node_with_call(cfg, call_name):
    return next(
        n for n in cfg.nodes()
        if isinstance(n, PyCFGNode) and call_name in n.calls
    )


def _stub_edge_index(binary_path, edges):
    from core.inventory.binary_oracle_edges import (
        BinaryCallEdge,
        BinaryEdgeIndex,
    )
    return BinaryEdgeIndex(
        binary_path=str(binary_path),
        edges=[BinaryCallEdge(c, e, str(binary_path)) for c, e in edges],
        callees={e for _, e in edges},
    )


# ---------------------------------------------------------------------------
# Verdict consistency on SanitizerCutResult
# ---------------------------------------------------------------------------


class TestVerdictDefaulting:
    """Phase 7 constructors pass only ``suppress`` and reason; the
    verdict field defaults from ``__post_init__``. New callers may
    pass verdict explicitly; the post-init validator catches
    inconsistencies."""

    def test_legacy_suppress_true_defaults_to_suppress_verdict(self):
        r = SanitizerCutResult(
            suppress=True, reason="ok",
            cut_set=frozenset(), candidate_callables=frozenset(),
        )
        assert r.verdict == VERDICT_SUPPRESS

    def test_legacy_suppress_false_defaults_to_no_suppress(self):
        r = SanitizerCutResult(
            suppress=False, reason="ok",
            cut_set=frozenset(), candidate_callables=frozenset(),
        )
        assert r.verdict == VERDICT_NO_SUPPRESS

    def test_explicit_candidate_only_with_suppress_false(self):
        r = SanitizerCutResult(
            suppress=False, reason="cf cut holds, value unproven",
            cut_set=frozenset(), candidate_callables=frozenset(),
            verdict=VERDICT_CANDIDATE_ONLY,
        )
        assert r.verdict == VERDICT_CANDIDATE_ONLY
        assert r.suppress is False

    def test_suppress_true_with_explicit_no_suppress_raises(self):
        import pytest
        with pytest.raises(ValueError, match="suppress=True"):
            SanitizerCutResult(
                suppress=True, reason="x",
                cut_set=frozenset(), candidate_callables=frozenset(),
                verdict=VERDICT_NO_SUPPRESS,
            )

    def test_suppress_false_with_explicit_suppress_raises(self):
        import pytest
        with pytest.raises(ValueError, match="suppress=True"):
            SanitizerCutResult(
                suppress=False, reason="x",
                cut_set=frozenset(), candidate_callables=frozenset(),
                verdict=VERDICT_SUPPRESS,
            )


# ---------------------------------------------------------------------------
# The wrong-variable case — the whole point of the arc
# ---------------------------------------------------------------------------


class TestWrongVariableCase:
    """``safe_other = html.escape(other); render(user.name)`` — the
    canonical wrong-variable case. The shipped Phase 7 incorrectly
    suppresses this; Phase 4 must NOT."""

    def test_phase_4_refuses_to_suppress_wrong_variable_case(self):
        src = (
            "def handle(user, other):\n"
            "    safe_other = html.escape(other)\n"
            "    render(user.name)\n"
        )
        cfg = _cfg(src)
        sink = _node_with_call(cfg, "render")
        result = evaluate_finding(
            cfg, [cfg.entry_node], sink,
            cwe="CWE-79", language="python",
            source_symbols={"user", "other"},
            sink_arg="user",
        )
        # Control-flow cut holds (removing html.escape disconnects
        # the sink); value-bound cut FAILS (sanitizer's output
        # safe_other doesn't reach sink_arg user). → candidate_only.
        assert result.verdict == VERDICT_CANDIDATE_ONLY
        assert result.suppress is False
        assert "candidate_only" in result.reason

    def test_phase_7_legacy_path_still_falsely_suppresses(self):
        """Documents the unsoundness when value context is omitted.
        The shipped Phase 7 behaviour — preserved for back-compat
        so existing tests pass — would suppress this. Phase 7 of
        the value-binding arc (smt_barrier wire-up behind flag)
        will switch the default to the value-bound path."""
        src = (
            "def handle(user, other):\n"
            "    safe_other = html.escape(other)\n"
            "    render(user.name)\n"
        )
        cfg = _cfg(src)
        sink = _node_with_call(cfg, "render")
        result = evaluate_finding(
            cfg, [cfg.entry_node], sink,
            cwe="CWE-79", language="python",
            # No source_symbols / sink_arg — legacy control-flow only.
        )
        assert result.verdict == VERDICT_SUPPRESS
        assert result.suppress is True


# ---------------------------------------------------------------------------
# True positive: value binding actually holds
# ---------------------------------------------------------------------------


class TestTruePositives:
    """Cases where the value-binding gate fires correctly and we
    DO suppress."""

    def test_same_symbol_straight_line_suppresses(self):
        """``y = html.escape(x); render(y)`` — x flows in, y flows
        out, sink reads y. All four conditions hold."""
        src = (
            "def handle(x):\n"
            "    y = html.escape(x)\n"
            "    render(y)\n"
        )
        cfg = _cfg(src)
        sink = _node_with_call(cfg, "render")
        result = evaluate_finding(
            cfg, [cfg.entry_node], sink,
            cwe="CWE-79", language="python",
            source_symbols={"x"},
            sink_arg="y",
        )
        assert result.verdict == VERDICT_SUPPRESS
        assert result.suppress is True
        assert "value-bound" in result.reason

    def test_symmetric_sanitize_both_branches_suppresses(self):
        """Sanitizer in BOTH branches; the value-bound cut is the
        union of both bindings. This is the canonical case the
        whole arc was designed for — control-flow + value-flow
        both hold."""
        src = (
            "def handle(user):\n"
            "    if user.is_admin:\n"
            "        safe = html.escape(user.name)\n"
            "    else:\n"
            "        safe = html.escape(user.name)\n"
            "    render(safe)\n"
        )
        cfg = _cfg(src)
        sink = _node_with_call(cfg, "render")
        result = evaluate_finding(
            cfg, [cfg.entry_node], sink,
            cwe="CWE-79", language="python",
            source_symbols={"user"},
            sink_arg="safe",
        )
        assert result.verdict == VERDICT_SUPPRESS
        assert result.suppress is True
        # Both sanitizer nodes in the witness cut.
        assert len(result.cut_set) == 2


# ---------------------------------------------------------------------------
# Bypass — sanitizer not on every path
# ---------------------------------------------------------------------------


class TestBypass:
    """Findings where at least one path bypasses every sanitizer.
    Control-flow cut fails → ``no_suppress`` (not candidate_only —
    the cut itself didn't hold)."""

    def test_only_one_branch_sanitizes_no_suppress(self):
        src = (
            "def handle(user):\n"
            "    if user.is_admin:\n"
            "        safe = html.escape(user.name)\n"
            "    else:\n"
            "        safe = user.name\n"
            "    render(safe)\n"
        )
        cfg = _cfg(src)
        sink = _node_with_call(cfg, "render")
        result = evaluate_finding(
            cfg, [cfg.entry_node], sink,
            cwe="CWE-79", language="python",
            source_symbols={"user"},
            sink_arg="safe",
        )
        assert result.verdict == VERDICT_NO_SUPPRESS
        assert result.suppress is False


# ---------------------------------------------------------------------------
# Chained sanitizer — value binding broken by transformation
# ---------------------------------------------------------------------------


class TestChainedSanitizer:
    """``y = wrap(html.escape(x)); render(y)`` — html.escape's
    return flows into wrap, not y. Phase 3 makes the inner
    sanitizer's output_symbols empty. Phase 4's condition 3 fails
    (sink_arg=y not in html.escape's output_symbols). The control-
    flow cut still holds (html.escape on the only path), so
    verdict is candidate_only."""

    def test_chained_call_yields_candidate_only(self):
        src = (
            "def handle(x):\n"
            "    y = wrap(html.escape(x))\n"
            "    render(y)\n"
        )
        cfg = _cfg(src)
        sink = _node_with_call(cfg, "render")
        result = evaluate_finding(
            cfg, [cfg.entry_node], sink,
            cwe="CWE-79", language="python",
            source_symbols={"x"},
            sink_arg="y",
        )
        # Conservative: the cleaned value went through ``wrap``
        # which we don't model; can't prove sink reads the
        # sanitised value, so candidate_only.
        assert result.verdict == VERDICT_CANDIDATE_ONLY
        assert result.suppress is False


# ---------------------------------------------------------------------------
# Sanitized then rebound — sanitization overwritten
# ---------------------------------------------------------------------------


class TestSanitizationOverwritten:
    """``y = html.escape(x); y = x; render(y)`` — the sanitizer's
    def is killed by the rebinding. Condition 3 fails (binding.node
    not in rd.at(sink, y) because the rebind is now the live
    definer).

    Note: the control-flow cut still holds — the html.escape node
    is on every CFG path entry → … → render (every path crosses it
    structurally even though the cleaned value is overwritten on
    the next line). So this is a candidate_only case: structurally
    sanitized, value-wise not. Exactly the distinction Phase 4
    teases apart."""

    def test_rebound_after_sanitize_yields_candidate_only(self):
        src = (
            "def handle(x):\n"
            "    y = html.escape(x)\n"
            "    y = x\n"
            "    render(y)\n"
        )
        cfg = _cfg(src)
        sink = _node_with_call(cfg, "render")
        result = evaluate_finding(
            cfg, [cfg.entry_node], sink,
            cwe="CWE-79", language="python",
            source_symbols={"x"},
            sink_arg="y",
        )
        assert result.verdict == VERDICT_CANDIDATE_ONLY
        assert result.suppress is False


# ---------------------------------------------------------------------------
# Wrong-CWE / wrong-language gate predicates
# ---------------------------------------------------------------------------


class TestGatePreconditions:
    def test_wrong_cwe_still_no_suppress(self):
        src = (
            "def handle(x):\n"
            "    y = html.escape(x)\n"
            "    render(y)\n"
        )
        cfg = _cfg(src)
        sink = _node_with_call(cfg, "render")
        result = evaluate_finding(
            cfg, [cfg.entry_node], sink,
            cwe="CWE-89", language="python",  # SQLi catalog has no html.escape
            source_symbols={"x"},
            sink_arg="y",
        )
        assert result.verdict == VERDICT_NO_SUPPRESS

    def test_empty_source_symbols_falls_back_to_legacy_path(self):
        """``source_symbols=None`` is the legacy signal. An explicit
        empty frozenset means "no taint" — every binding's condition
        2 fails because input_symbols ∩ ∅ = ∅. With control-flow cut
        holding → candidate_only."""
        src = (
            "def handle(x):\n"
            "    y = html.escape(x)\n"
            "    render(y)\n"
        )
        cfg = _cfg(src)
        sink = _node_with_call(cfg, "render")
        result = evaluate_finding(
            cfg, [cfg.entry_node], sink,
            cwe="CWE-79", language="python",
            source_symbols=frozenset(),
            sink_arg="y",
        )
        # No taint → no value binding → candidate_only because
        # control-flow cut still holds.
        assert result.verdict == VERDICT_CANDIDATE_ONLY


# ---------------------------------------------------------------------------
# C/C++ call-graph auto-downgrade
# ---------------------------------------------------------------------------


class TestCallgraphAutoDowngrade:
    """Phase 3 made callgraph bindings carry empty input/output
    symbol sets — function granularity has no value layer. Phase 4
    must therefore auto-downgrade callgraph findings to
    ``candidate_only`` (when control-flow cut holds) when value
    context is provided. Without value context they take the
    legacy control-flow-only path and either suppress or
    no_suppress as before — back-compat preserved."""

    def test_callgraph_with_value_context_downgrades(self, tmp_path):
        binary = tmp_path / "fake.elf"
        binary.write_bytes(b"")
        edges = [
            ("main", "html.escape"),
            ("html.escape", "render"),
        ]
        with mock.patch(
            "core.inventory.binary_oracle_edges.extract_direct_call_edges",
            return_value=_stub_edge_index(binary, edges),
        ):
            graph = build_cpp_callgraph([binary], entry="main")
        sink = next(n for n in graph.nodes() if n.name == "render")
        sources = [next(n for n in graph.nodes() if n.name == "main")]
        result = evaluate_finding(
            graph, sources, sink,
            cwe="CWE-79", language="python",
            source_symbols={"x"},  # Anything truthy — callgraph
                                    # bindings have empty input_symbols
                                    # so condition 2 fails regardless.
            sink_arg="y",
        )
        # Control-flow cut over html.escape node holds; value-bound
        # subset is empty → candidate_only.
        assert result.verdict == VERDICT_CANDIDATE_ONLY

    def test_callgraph_without_value_context_legacy_suppresses(self, tmp_path):
        """Back-compat: existing Phase 7 callers calling this on a
        callgraph still get the control-flow-only behaviour."""
        binary = tmp_path / "fake.elf"
        binary.write_bytes(b"")
        edges = [
            ("main", "html.escape"),
            ("html.escape", "render"),
        ]
        with mock.patch(
            "core.inventory.binary_oracle_edges.extract_direct_call_edges",
            return_value=_stub_edge_index(binary, edges),
        ):
            graph = build_cpp_callgraph([binary], entry="main")
        sink = next(n for n in graph.nodes() if n.name == "render")
        sources = [next(n for n in graph.nodes() if n.name == "main")]
        result = evaluate_finding(
            graph, sources, sink,
            cwe="CWE-79", language="python",
        )
        assert result.verdict == VERDICT_SUPPRESS
        assert result.suppress is True


# ---------------------------------------------------------------------------
# Mid-function source (not the entry / param)
# ---------------------------------------------------------------------------


class TestNonEntrySource:
    """Source can be any node, not just the function entry. Useful
    when the taint origin is mid-function (e.g. ``user_input =
    request.body`` rather than a function parameter)."""

    def test_body_source_propagates_taint_to_sink(self):
        src = (
            "def handle(request):\n"
            "    user_input = request.body\n"
            "    y = html.escape(user_input)\n"
            "    render(y)\n"
        )
        cfg = _cfg(src)
        source = next(
            n for n in cfg.nodes()
            if isinstance(n, PyCFGNode) and "user_input" in n.defs
        )
        sink = _node_with_call(cfg, "render")
        result = evaluate_finding(
            cfg, [source], sink,
            cwe="CWE-79", language="python",
            source_symbols={"user_input"},
            sink_arg="y",
        )
        assert result.verdict == VERDICT_SUPPRESS
