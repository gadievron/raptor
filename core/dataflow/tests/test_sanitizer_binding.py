"""Tests for ``SanitizerBinding`` + ``nodes_of`` — Phase 3 of the
value-binding arc.

Where ``test_sanitizer_catalog.py`` covers data integrity, CWE
normalization, and "which sanitizers are in this CFG?", this file
covers what Phase 3 adds: the *symbol* layer on top of those
matches.

A binding answers three questions per matched call:

* which symbols flowed IN — ``input_symbols``
* which symbols the return value flowed TO — ``output_symbols``
* where in the source it happened — ``lineno``

Phase 4's value-binding gate consumes these. The pinned properties:

* bare-call sanitizers (no LHS) have empty ``output_symbols`` —
  condition 3 of the gate will fail, no suppression.
* chained calls produce one binding per nested call, only the
  outermost carries ``output_symbols``.
* the call-graph fallback for C/C++ produces bindings with empty
  symbol sets — condition 2 will fail, Phase 4 downgrades to
  ``candidate_only``.
* ``nodes_of(bindings)`` is the lossy back-compat projection Phase
  7's vertex-cut consumer already uses.
"""
from __future__ import annotations

from unittest import mock

from core.dataflow.sanitizer_catalog import (
    SanitizerBinding,
    match_sanitizers_in_cfg,
    nodes_of,
)
from core.inventory.cfg_builder import (
    CallGraphNode,
    PyCFGNode,
    build_cpp_callgraph,
    build_python_cfg,
)


# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------


def _cfg(src: str, func: str = "handle"):
    return build_python_cfg(src, func)


def _bindings(src, cwe="CWE-79", language="python"):
    return match_sanitizers_in_cfg(_cfg(src), cwe, language)


def _single(bindings) -> SanitizerBinding:
    assert len(bindings) == 1, f"expected 1 binding, got {bindings}"
    return next(iter(bindings))


# ---------------------------------------------------------------------------
# Input / output symbol attribution
# ---------------------------------------------------------------------------


def test_bare_call_has_empty_output_symbols():
    """A sanitizer called for side-effect (no LHS) has empty
    ``output_symbols`` — Phase 4 condition 3 will fail because the
    cleaned value has nowhere to flow."""
    src = (
        "def handle(x):\n"
        "    html.escape(x)\n"
    )
    b = _single(_bindings(src))
    assert b.callable == "html.escape"
    assert b.input_symbols == frozenset({"x"})
    assert b.output_symbols == frozenset()


def test_top_level_assignment_captures_output_symbol():
    """``y = html.escape(x)`` — output flows to y."""
    src = (
        "def handle(x):\n"
        "    y = html.escape(x)\n"
    )
    b = _single(_bindings(src))
    assert b.input_symbols == frozenset({"x"})
    assert b.output_symbols == frozenset({"y"})


def test_chained_calls_only_outer_carries_output_symbols():
    """``y = wrap(html.escape(x))`` — html.escape's return flows
    into wrap, NOT into y. The inner sanitizer binding has empty
    output_symbols; the outer wrap (not a sanitizer here) would
    carry {y} as an unrelated call site.

    Phase 4 reads this: chaining a sanitizer through another
    transform breaks the value binding to the sink. Suppression
    only fires when output_symbols reaches the sink arg directly,
    and the inner sanitizer's output_symbols is empty here.
    """
    src = (
        "def handle(x):\n"
        "    y = wrap(html.escape(x))\n"
    )
    bindings = _bindings(src)
    assert len(bindings) == 1
    b = _single(bindings)
    assert b.callable == "html.escape"
    assert b.input_symbols == frozenset({"x"})
    # Inner call's return goes into wrap, not into y.
    assert b.output_symbols == frozenset()


def test_dotted_callable_name_resolution():
    """Multi-level attribute access resolves to the full dotted
    name. The catalog key for Django's XSS escaper."""
    src = (
        "def handle(x):\n"
        "    y = django.utils.html.escape(x)\n"
    )
    b = _single(_bindings(src))
    assert b.callable == "django.utils.html.escape"
    assert b.input_symbols == frozenset({"x"})
    assert b.output_symbols == frozenset({"y"})


def test_keyword_args_contribute_to_input_symbols():
    """``f(value=tainted)`` — keyword arg names count toward
    input_symbols just like positional args do."""
    src = (
        "def handle(tainted):\n"
        "    y = html.escape(value=tainted)\n"
    )
    b = _single(_bindings(src))
    assert b.input_symbols == frozenset({"tainted"})


def test_attribute_arg_records_base_name():
    """``html.escape(user.input)`` — base name ``user`` is what
    Phase 4's condition 2 will check against the taint front. The
    attribute ``input`` is not a bare symbol the gate can reason
    about."""
    src = (
        "def handle(user):\n"
        "    y = html.escape(user.input)\n"
    )
    b = _single(_bindings(src))
    assert b.input_symbols == frozenset({"user"})


def test_nested_call_arg_does_not_inject_inner_names():
    """``html.escape(transform(x))`` — outer sanitizer's
    input_symbols is empty because the arg is a Call expression,
    not a bare name. Phase 4 condition 2 then fails (no taint can
    intersect an empty set) and the gate refuses to suppress.

    This is the conservative under-count Phase 1 introduced to
    avoid over-suppression."""
    src = (
        "def handle(x):\n"
        "    y = html.escape(transform(x))\n"
    )
    b = _single(_bindings(src))
    assert b.input_symbols == frozenset()
    assert b.output_symbols == frozenset({"y"})


def test_lineno_carried_from_call_site():
    """The binding's lineno comes from the call itself, not the
    enclosing statement (matters for multi-line expressions)."""
    src = (
        "def handle(x):\n"
        "    y = html.escape(\n"
        "        x\n"
        "    )\n"
    )
    b = _single(_bindings(src))
    # The call's lineno is line 2 (where html.escape is mentioned)
    # — Python's AST records the start of the call expression.
    assert b.lineno == 2


# ---------------------------------------------------------------------------
# Multi-binding shapes
# ---------------------------------------------------------------------------


def test_multiple_matched_calls_same_node_produce_multiple_bindings():
    """A statement with two matched sanitizer calls (chained or
    paired) yields one binding per matched call site."""
    src = (
        "def handle(a, b):\n"
        "    out = html.escape(a) + html.escape(b)\n"
    )
    bindings = match_sanitizers_in_cfg(_cfg(src), "CWE-79", "python")
    assert len(bindings) == 2
    input_sets = sorted(tuple(sorted(b.input_symbols)) for b in bindings)
    assert input_sets == [("a",), ("b",)]


def test_bindings_for_distinct_cwes_are_independent():
    """Same function, two different sanitizer kinds — each CWE
    query produces its own binding set."""
    src = (
        "def handle(x, path):\n"
        "    y = html.escape(x)\n"
        "    p = werkzeug.security.safe_join(path)\n"
    )
    cfg = _cfg(src)
    xss = match_sanitizers_in_cfg(cfg, "CWE-79", "python")
    pathtrav = match_sanitizers_in_cfg(cfg, "CWE-22", "python")
    assert {b.callable for b in xss} == {"html.escape"}
    assert {b.callable for b in pathtrav} == {"werkzeug.security.safe_join"}


# ---------------------------------------------------------------------------
# Wrong-variable case — the pinned soundness witness
# ---------------------------------------------------------------------------


def test_wrong_variable_case_binding_shape_makes_gate_refuse():
    """The canonical wrong-variable false-suppression case. After
    Phase 3:

    * one binding for html.escape on line 2
    * input_symbols = {other}, output_symbols = {safe_other}
    * the sink at line 3 reads ``user`` — neither in input_symbols
      nor in output_symbols.

    Phase 4 will read this and:

    * condition 2: input_symbols ∩ tainted_at_node — fails iff
      ``other`` was the only tainted source AND it's still alive.
      Here it IS tainted; condition 2 passes.
    * condition 3: output_symbols reaches sink_arg via reaching-
      defs — ``safe_other`` doesn't reach ``user``, so this fails.
    * verdict: ``candidate_only`` (control-flow cut still holds —
      the html.escape node is on the only path — but value binding
      isn't proven).

    The whole point of the arc: refuse to suppress this without
    the LLM's review."""
    src = (
        "def handle(user, other):\n"
        "    safe_other = html.escape(other)\n"
        "    render(user.name)\n"
    )
    b = _single(_bindings(src))
    assert b.callable == "html.escape"
    assert b.input_symbols == frozenset({"other"})
    assert b.output_symbols == frozenset({"safe_other"})


# ---------------------------------------------------------------------------
# nodes_of projection
# ---------------------------------------------------------------------------


def test_nodes_of_collapses_bindings_to_node_set():
    """``nodes_of`` is the back-compat projection for Phase 7's
    vertex-cut consumer — drops symbols and lineno, keeps unique
    nodes."""
    src = (
        "def handle(a, b):\n"
        "    out = html.escape(a) + html.escape(b)\n"
    )
    cfg = _cfg(src)
    bindings = match_sanitizers_in_cfg(cfg, "CWE-79", "python")
    assert len(bindings) == 2
    nodes = nodes_of(bindings)
    # Two bindings collapse to one node — they're on the same stmt.
    assert len(nodes) == 1


def test_nodes_of_distinct_nodes_preserved():
    src = (
        "def handle(a, b):\n"
        "    x = html.escape(a)\n"
        "    y = html.escape(b)\n"
    )
    cfg = _cfg(src)
    bindings = match_sanitizers_in_cfg(cfg, "CWE-79", "python")
    nodes = nodes_of(bindings)
    assert len(nodes) == 2
    for n in nodes:
        assert isinstance(n, PyCFGNode)


def test_nodes_of_empty():
    assert nodes_of(frozenset()) == set()


# ---------------------------------------------------------------------------
# Call-graph fallback (C/C++ function granularity)
# ---------------------------------------------------------------------------


def _stub_edge_index(binary_path, edges):
    from core.inventory.binary_oracle_edges import (
        BinaryCallEdge, BinaryEdgeIndex,
    )
    return BinaryEdgeIndex(
        binary_path=str(binary_path),
        edges=[BinaryCallEdge(c, e, str(binary_path)) for c, e in edges],
        callees={e for _, e in edges},
    )


def test_callgraph_binding_has_empty_symbol_layer(tmp_path):
    """C/C++ callgraph nodes (CallGraphNode) carry no Phase-1
    CallSite records — function granularity. The recognizer falls
    back to ``node.name`` as both callable and matched id; symbols
    are empty.

    Phase 4 will read empty input_symbols and downgrade to
    ``candidate_only`` automatically — proper handling of "we don't
    have value-flow info at this granularity"."""
    binary = tmp_path / "fake.elf"
    binary.write_bytes(b"")
    edges = [
        ("main", "process"),
        ("process", "org.apache.commons.lang3.StringEscapeUtils.escapeHtml4"),
    ]
    with mock.patch(
        "core.inventory.binary_oracle_edges.extract_direct_call_edges",
        return_value=_stub_edge_index(binary, edges),
    ):
        graph = build_cpp_callgraph([binary], entry="main")
    bindings = match_sanitizers_in_cfg(graph, "CWE-79", "java")
    b = _single(bindings)
    assert isinstance(b.node, CallGraphNode)
    assert b.callable == (
        "org.apache.commons.lang3.StringEscapeUtils.escapeHtml4"
    )
    assert b.input_symbols == frozenset()
    assert b.output_symbols == frozenset()


# ---------------------------------------------------------------------------
# Hashability / set membership
# ---------------------------------------------------------------------------


def test_binding_is_hashable_and_set_membership_works():
    """``SanitizerBinding`` is frozen — bindings can live in
    frozensets, dict keys, etc. The recognizer returns a frozenset;
    Phase 4 will combine multiple-CWE results via set algebra."""
    src = (
        "def handle(x):\n"
        "    y = html.escape(x)\n"
    )
    bindings = match_sanitizers_in_cfg(_cfg(src), "CWE-79", "python")
    assert isinstance(bindings, frozenset)
    # Round-trip through dict.
    d = {b: True for b in bindings}
    assert all(d[b] for b in bindings)
