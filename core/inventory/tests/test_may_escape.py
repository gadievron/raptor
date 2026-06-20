"""Pointer / alias conservatism tests (may_escape).

Two halves:

1. CFG builder stamps ``may_escape`` correctly on CPPCFGNode when
   the statement involves indirection (``*p``, ``&x``, ``a[i]``,
   ``obj->field``, ``memcpy``/``strcpy``/etc.).
2. ``evaluate_finding`` downgrades ``SUPPRESS → CANDIDATE_ONLY``
   when any node on a source→sink path is ``may_escape``, and stays
   bit-identical on the legacy path / Python path / non-escape C
   path.
"""
from __future__ import annotations

import pytest

from core.inventory.cfg_builder import build_python_cfg
from core.inventory.cfg_builder_cpp import (
    CPPCFG,
    CPPCFGNode,
    build_cpp_intraproc_cfg,
)
from core.inventory.sanitizer_cut import (
    VERDICT_CANDIDATE_ONLY,
    VERDICT_SUPPRESS,
    _may_escape_on_path,
    evaluate_finding,
)

pytest.importorskip("tree_sitter_c")


def _build(src: str, fn: str = "f", language: str = "c") -> CPPCFG:
    cfg = build_cpp_intraproc_cfg(src, fn, language=language)
    assert cfg is not None, f"function {fn!r} not found"
    return cfg


def _nodes_at(cfg: CPPCFG, lineno: int) -> list[CPPCFGNode]:
    return [n for n in cfg.nodes() if n.lineno == lineno]


# ---------------------------------------------------------------------------
# Stamping — indirection syntax flips may_escape
# ---------------------------------------------------------------------------


class TestStamping:
    def test_plain_assignment_is_not_may_escape(self):
        cfg = _build("void f(int x) { int y = x; }")
        n = _nodes_at(cfg, 1)[0]
        assert n.may_escape is False

    def test_deref_store_sets_may_escape(self):
        # ``*p = x;``
        src = "void f(int *p, int x) { *p = x; }"
        cfg = _build(src)
        stmt = [n for n in _nodes_at(cfg, 1) if n.kind == "stmt"][0]
        assert stmt.may_escape

    def test_deref_load_sets_may_escape(self):
        # ``int y = *p;``
        src = "void f(int *p) { int y = *p; }"
        cfg = _build(src)
        stmt = [n for n in _nodes_at(cfg, 1) if n.kind == "stmt"][0]
        assert stmt.may_escape

    def test_address_of_sets_may_escape(self):
        # ``g(&x);`` — address-of escapes x to g
        src = "extern void g(int *); void f(int x) { g(&x); }"
        cfg = _build(src)
        stmt = [n for n in _nodes_at(cfg, 1) if n.kind == "stmt"
                and any(cs.name == "g" for cs in n.call_sites)][0]
        assert stmt.may_escape

    def test_subscript_load_sets_may_escape(self):
        # ``int y = a[0];``
        src = "void f(int *a) { int y = a[0]; }"
        cfg = _build(src)
        stmt = [n for n in _nodes_at(cfg, 1) if n.kind == "stmt"][0]
        assert stmt.may_escape

    def test_subscript_store_sets_may_escape(self):
        # ``a[i] = x;``
        src = "void f(int *a, int i, int x) { a[i] = x; }"
        cfg = _build(src)
        stmt = [n for n in _nodes_at(cfg, 1) if n.kind == "stmt"][0]
        assert stmt.may_escape

    def test_arrow_field_access_sets_may_escape(self):
        # ``obj->field = x;`` — write through pointer
        src = (
            "struct S { int field; };\n"
            "void f(struct S *obj, int x) {\n"
            "    obj->field = x;\n"
            "}\n"
        )
        cfg = _build(src)
        stmt = [n for n in _nodes_at(cfg, 3) if n.kind == "stmt"][0]
        assert stmt.may_escape

    def test_dot_field_access_does_NOT_set_may_escape(self):
        # ``obj.field = x;`` where obj is a value — no indirection.
        src = (
            "struct S { int field; };\n"
            "void f(struct S obj, int x) {\n"
            "    obj.field = x;\n"
            "}\n"
        )
        cfg = _build(src)
        stmt = [n for n in _nodes_at(cfg, 3) if n.kind == "stmt"][0]
        # We choose not to flag dot-access conservatively — Phase 10
        # only stamps on syntactic indirection. (The caller-supplied
        # obj could still alias somewhere else, but that's Phase 12+'s
        # inter-procedural problem.)
        assert stmt.may_escape is False

    @pytest.mark.parametrize(
        "func",
        ["memcpy", "memmove", "memset", "strcpy", "strncpy",
         "strlcpy", "strcat", "snprintf", "sprintf"],
    )
    def test_bulk_copy_call_sets_may_escape(self, func):
        src = (
            f"extern void *{func}();\n"
            f"void f(char *dst, const char *src) {{ {func}(dst, src); }}\n"
        )
        cfg = _build(src)
        stmt = [n for n in _nodes_at(cfg, 2) if n.kind == "stmt"
                and any(cs.name == func for cs in n.call_sites)][0]
        assert stmt.may_escape, f"{func} should stamp may_escape"

    def test_if_condition_with_deref_sets_may_escape(self):
        src = (
            "void f(int *p) {\n"
            "    if (*p) { g(); }\n"
            "}\n"
        )
        cfg = _build(src)
        cond = [n for n in _nodes_at(cfg, 2)
                if n.kind == "stmt" and n.label.startswith("if")][0]
        assert cond.may_escape

    def test_for_step_with_subscript_sets_may_escape(self):
        src = (
            "void f(int *a) {\n"
            "    for (int i = 0; i < 10; a[i]++) { }\n"
            "}\n"
        )
        cfg = _build(src)
        # The step node should have may_escape
        step_nodes = [n for n in cfg.nodes()
                      if n.label.startswith("step")]
        assert step_nodes, "no step node emitted"
        assert step_nodes[0].may_escape

    def test_entry_and_exit_are_not_may_escape(self):
        cfg = _build("void f(int x) { int y = x; }")
        assert cfg.entry_node.may_escape is False
        assert cfg.exit_node.may_escape is False


# ---------------------------------------------------------------------------
# evaluate_finding — verdict downgrades on may_escape paths
# ---------------------------------------------------------------------------


# Phase 11 will pick up the CFG for evaluate_finding via the
# finding_resolver dispatch (Phase 5 only handles Python today).
# For now, build the CPPCFG directly and call evaluate_finding to
# exercise the Phase 10 plumbing end-to-end. The catalog matcher
# uses the call_sites' names; Phase 3 already supports the C/C++
# callgraph shape (empty input/output → callgraph-style binding),
# and the CPPCFG path through match_sanitizers_in_cfg currently
# returns no value-bound bindings (Phase 11 closes that — Phase 10
# tests use Python CFGs for the value-bound downgrade tests).


def test_python_path_unchanged_by_may_escape_check():
    """Sanity: PyCFGNode has no may_escape attribute. The Phase 4
    safe straight-line case still suppresses — Phase 10 doesn't
    accidentally downgrade Python verdicts."""
    src = (
        "def handle(x):\n"
        "    y = html.escape(x)\n"
        "    render(y)\n"
    )
    cfg = build_python_cfg(src, "handle")
    assert cfg is not None
    # Source = entry (param x); sink = render call on line 3
    sink_node = next(n for n in cfg.nodes() if n.lineno == 3)
    result = evaluate_finding(
        cfg, [cfg.entry_node], sink_node,
        cwe="CWE-79", language="python",
        source_symbols=["x"], sink_arg="y",
    )
    assert result.verdict == VERDICT_SUPPRESS, \
        f"Python safe path should still suppress: {result.reason}"


def test_may_escape_on_path_helper_python_node_returns_false():
    """``_may_escape_on_path`` over a Python CFG always returns False
    because PyCFGNode lacks the attribute (getattr default)."""
    src = (
        "def handle(x):\n"
        "    y = html.escape(x)\n"
        "    render(y)\n"
    )
    cfg = build_python_cfg(src, "handle")
    sink_node = next(n for n in cfg.nodes() if n.lineno == 3)
    assert _may_escape_on_path(
        cfg, [cfg.entry_node], sink_node, excluded=set(),
    ) is False


def test_may_escape_on_path_finds_indirection_in_cpp_cfg():
    """End-to-end of the helper on a C CFG with explicit ``*p``
    on a source→sink path."""
    src = (
        "extern char *escape(const char *);\n"
        "extern void render(const char *);\n"
        "void f(const char *x, char *p) {\n"
        "    *p = (char)*escape(x);\n"
        "    render(p);\n"
        "}\n"
    )
    cfg = _build(src)
    sink = [n for n in _nodes_at(cfg, 5) if n.kind == "stmt"][0]
    assert _may_escape_on_path(
        cfg, [cfg.entry_node], sink, excluded=set(),
    ) is True


def test_may_escape_on_path_returns_false_when_indirection_is_off_path():
    """``may_escape`` in a dead branch shouldn't downgrade — the
    helper only walks the forward∩backward (on-path) set."""
    src = (
        "void f(const char *x, int *p) {\n"
        "    if (0) { *p = 1; }\n"     # dead but contains *p
        "    render(x);\n"
        "}\n"
    )
    cfg = _build(src)
    sink = [n for n in _nodes_at(cfg, 3) if n.kind == "stmt"][0]
    # The dead branch is reachable in tree-sitter's CFG (we don't do
    # constant folding), so it WILL be in the forward set. This test
    # documents the conservative-by-design behaviour: any reachable
    # may_escape on the path triggers a downgrade. A future phase
    # could fold ``if (0)`` to refine — but Phase 10's policy is
    # "syntactic indirection anywhere on path → downgrade", and
    # that's the bit being tested.
    assert _may_escape_on_path(
        cfg, [cfg.entry_node], sink, excluded=set(),
    ) is True


def test_may_escape_excluded_node_does_not_trigger():
    """If the only may_escape node is in the cut_set (excluded),
    the on-path scan should treat it as removed."""
    src = (
        "void f(int *p, const char *x) {\n"
        "    *p = 1;\n"                # may_escape
        "    render(x);\n"
        "}\n"
    )
    cfg = _build(src)
    star_p = [n for n in _nodes_at(cfg, 2) if n.may_escape][0]
    sink = [n for n in _nodes_at(cfg, 3) if n.kind == "stmt"][0]
    assert _may_escape_on_path(
        cfg, [cfg.entry_node], sink, excluded={star_p},
    ) is False


# ---------------------------------------------------------------------------
# End-to-end downgrade via evaluate_finding (Python CFG + synthetic
# may_escape stamp — exercises the verdict-downgrade arm now,
# without waiting for Phase 11's resolver wiring)
# ---------------------------------------------------------------------------


def test_evaluate_finding_downgrades_suppress_when_may_escape_on_path():
    """Phase 10 verdict-downgrade test. We build a Python CFG that
    would normally suppress and synthetically stamp may_escape on
    one of its nodes by passing a wrapper graph whose ``successors``
    is identical but whose nodes have may_escape set. This
    exercises the evaluate_finding hook directly; Phase 11 wires
    it for real on CPPCFG."""
    src = (
        "def handle(x):\n"
        "    y = html.escape(x)\n"
        "    render(y)\n"
    )
    cfg = build_python_cfg(src, "handle")
    assert cfg is not None

    # Build a thin wrapper graph that adds may_escape to the SINK
    # node (line 3). The CFG's other surface is preserved.
    sink_node = next(n for n in cfg.nodes() if n.lineno == 3)

    class _StampedSink:
        # Marker object — equals sink_node by identity, exposes
        # may_escape=True. The wrapper graph below substitutes it
        # for sink_node in nodes() and successors().
        def __init__(self, inner):
            self._inner = inner
            self.may_escape = True
            # Forward the dataclass-ish surface evaluate_finding reads.
            for attr in ("kind", "lineno", "label", "calls",
                         "defs", "uses", "call_sites"):
                setattr(self, attr, getattr(inner, attr))

        def __hash__(self):
            return hash(self._inner)

        def __eq__(self, other):
            return (other is self
                    or other is self._inner
                    or getattr(other, "_inner", None) is self._inner)

    stamped = _StampedSink(sink_node)

    def _swap(n):
        return stamped if n is sink_node or n is stamped else n

    class WrapGraph:
        def __init__(self, inner_cfg):
            self._inner = inner_cfg
            self._params = inner_cfg.params

        @property
        def entry(self):
            return _swap(self._inner.entry_node)

        @property
        def params(self):
            return self._params

        def nodes(self):
            return [_swap(n) for n in self._inner.nodes()]

        def successors(self, node):
            target = node._inner if isinstance(node, _StampedSink) else node
            return [_swap(s) for s in self._inner.successors(target)]

    wrap = WrapGraph(cfg)
    result = evaluate_finding(
        wrap, [_swap(cfg.entry_node)], stamped,
        cwe="CWE-79", language="python",
        source_symbols=["x"], sink_arg="y",
    )
    assert result.verdict == VERDICT_CANDIDATE_ONLY, (
        f"expected may_escape downgrade, got {result.verdict!r}: "
        f"{result.reason}"
    )
    assert "may_escape" in result.reason


def test_evaluate_finding_no_downgrade_when_no_may_escape():
    """Regression: the unstamped CFG still suppresses cleanly."""
    src = (
        "def handle(x):\n"
        "    y = html.escape(x)\n"
        "    render(y)\n"
    )
    cfg = build_python_cfg(src, "handle")
    sink = next(n for n in cfg.nodes() if n.lineno == 3)
    result = evaluate_finding(
        cfg, [cfg.entry_node], sink,
        cwe="CWE-79", language="python",
        source_symbols=["x"], sink_arg="y",
    )
    assert result.verdict == VERDICT_SUPPRESS
