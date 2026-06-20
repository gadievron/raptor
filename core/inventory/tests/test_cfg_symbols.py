"""Tests for ``CallSite`` + symbol-aware ``PyCFGNode`` — Phase 1 of the
value-binding arc.

The shipped CFG builder records only ``calls`` per node — a frozenset
of callable names. Phase 1 adds:

* ``defs`` / ``uses`` — name-level data-flow facts the Phase 2
  reaching-defs pass will read.
* ``call_sites`` — per-call records with ``arg_names`` (what flows
  in) and ``assigned_names`` (what the return flows to).

The four-condition gate of Phase 4 will read these to close the
value-binding soundness hole (sanitizer node present on every path,
but the cleaned value never reaches the sink). These tests pin the
substrate; downstream phases reason from it.

Coverage focus areas:

* Assignment shapes — bare, augmented, annotated, tuple, walrus.
* Compound stmts respect the expr-roots discipline — bodies are
  attributed to their own nodes, not the header.
* Comprehension and lambda scopes don't leak their locals.
* CallSite attribution — only top-level RHS Calls carry
  ``assigned_names``; nested calls carry empty.
* Back-compat — the legacy ``calls`` frozenset still matches
  ``{cs.name for cs in call_sites}``.
"""
from __future__ import annotations

from core.inventory.cfg_builder import (
    CallSite,
    PyCFGNode,
    build_python_cfg,
)


# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------


def _stmt_nodes(cfg) -> list:
    return [n for n in cfg.nodes() if n.kind == "stmt"]


def _find_node(cfg, lineno: int) -> PyCFGNode:
    """Return the unique stmt node at ``lineno``. Useful when the test
    source has one statement per relevant line."""
    matches = [n for n in _stmt_nodes(cfg) if n.lineno == lineno]
    assert len(matches) == 1, (
        f"expected exactly one stmt at line {lineno}, got {matches}"
    )
    return matches[0]


def _site_by_name(node: PyCFGNode, name: str) -> CallSite:
    matches = [s for s in node.call_sites if s.name == name]
    assert len(matches) == 1, (
        f"expected exactly one CallSite named {name!r} on {node!r}, "
        f"got {matches}"
    )
    return matches[0]


# ---------------------------------------------------------------------------
# Defs / uses — assignment shapes
# ---------------------------------------------------------------------------


def test_bare_assign_defs_and_uses():
    src = (
        "def handle(x):\n"
        "    y = x + 1\n"
    )
    cfg = build_python_cfg(src, "handle")
    node = _find_node(cfg, 2)
    assert node.defs == frozenset({"y"})
    assert node.uses == frozenset({"x"})


def test_aug_assign_target_is_both_def_and_use():
    """``y += f(x)`` reads y before writing it back — the AST gives
    Store ctx but the read is implicit. The extractor must add it
    explicitly to uses."""
    src = (
        "def handle(x):\n"
        "    y = 0\n"
        "    y += compute(x)\n"
    )
    cfg = build_python_cfg(src, "handle")
    aug = _find_node(cfg, 3)
    assert "y" in aug.defs
    assert "y" in aug.uses
    assert "x" in aug.uses


def test_ann_assign_with_value():
    src = (
        "def handle(x):\n"
        "    y: int = x * 2\n"
    )
    cfg = build_python_cfg(src, "handle")
    node = _find_node(cfg, 2)
    assert "y" in node.defs
    assert "x" in node.uses


def test_tuple_unpack_assign():
    src = (
        "def handle(pair):\n"
        "    a, b = pair\n"
    )
    cfg = build_python_cfg(src, "handle")
    node = _find_node(cfg, 2)
    assert node.defs == frozenset({"a", "b"})
    assert node.uses == frozenset({"pair"})


def test_walrus_target_is_def():
    src = (
        "def handle(x):\n"
        "    if (y := compute(x)) > 0:\n"
        "        return y\n"
    )
    cfg = build_python_cfg(src, "handle")
    # walrus lives inside the If header; the If node carries the def
    if_node = _find_node(cfg, 2)
    assert "y" in if_node.defs
    assert "x" in if_node.uses


def test_subscript_lhs_records_base_as_def_and_use():
    """``arr[i] = x`` mutates arr through an index. The AST gives the
    inner Name "arr" Load ctx (because we're reading it to subscript)
    and "i" Load ctx. The shipped policy: we record arr as a use
    because it's syntactically loaded, x as a use, i as a use — and
    nothing as a def (the rebind happens through the subscript, not
    to the bare name)."""
    src = (
        "def handle(arr, i, x):\n"
        "    arr[i] = x\n"
    )
    cfg = build_python_cfg(src, "handle")
    node = _find_node(cfg, 2)
    # Soundness: we under-count defs (arr isn't rebound). Uses cover
    # the actually-referenced names so taint can still propagate.
    assert "x" in node.uses
    assert "i" in node.uses
    assert "arr" in node.uses


def test_attribute_lhs_records_base_as_use():
    """``self.x = value`` reads self, doesn't rebind it."""
    src = (
        "def handle(self, value):\n"
        "    self.x = value\n"
    )
    cfg = build_python_cfg(src, "handle")
    node = _find_node(cfg, 2)
    assert "value" in node.uses
    assert "self" in node.uses
    # self.x is an Attribute assignment — self isn't rebound.
    assert "self" not in node.defs


# ---------------------------------------------------------------------------
# Compound statements — expr-roots discipline
# ---------------------------------------------------------------------------


def test_if_header_only_attributes_test_uses():
    """The If statement's CFG node carries ONLY the test expression's
    symbols, not the body's. The body statements get their own
    nodes."""
    src = (
        "def handle(x):\n"
        "    if x > 0:\n"
        "        y = compute(x)\n"
        "        return y\n"
    )
    cfg = build_python_cfg(src, "handle")
    if_node = _find_node(cfg, 2)
    assign_node = _find_node(cfg, 3)
    assert if_node.uses == frozenset({"x"})
    # The If header MUST NOT inherit `y` from the body's assignment.
    assert "y" not in if_node.defs
    # The assignment carries its own facts.
    assert "y" in assign_node.defs
    assert "x" in assign_node.uses


def test_while_header_only_attributes_test_uses():
    src = (
        "def handle(n):\n"
        "    while n > 0:\n"
        "        n = n - 1\n"
    )
    cfg = build_python_cfg(src, "handle")
    while_node = _find_node(cfg, 2)
    body_node = _find_node(cfg, 3)
    assert while_node.uses == frozenset({"n"})
    assert "n" in body_node.defs
    assert "n" in body_node.uses


def test_for_header_attributes_target_def_and_iter_use():
    src = (
        "def handle(items):\n"
        "    for item in items:\n"
        "        process(item)\n"
    )
    cfg = build_python_cfg(src, "handle")
    for_node = _find_node(cfg, 2)
    body_node = _find_node(cfg, 3)
    assert "item" in for_node.defs
    assert "items" in for_node.uses
    # Body has its own use of item.
    assert "item" in body_node.uses


def test_with_items_record_ctx_use_and_var_def():
    src = (
        "def handle(path):\n"
        "    with open(path) as f:\n"
        "        data = f.read()\n"
    )
    cfg = build_python_cfg(src, "handle")
    with_node = _find_node(cfg, 2)
    body_node = _find_node(cfg, 3)
    assert "path" in with_node.uses
    assert "f" in with_node.defs
    # Body still its own node.
    assert "data" in body_node.defs


def test_try_header_has_no_statement_level_symbols():
    """``try:`` itself has no controlling expressions — only the body
    matters, and the body is its own CFG nodes."""
    src = (
        "def handle(x):\n"
        "    try:\n"
        "        y = compute(x)\n"
        "    except Exception:\n"
        "        y = 0\n"
        "    return y\n"
    )
    cfg = build_python_cfg(src, "handle")
    # The Try statement isn't represented as a single header in the
    # shipped builder — its body lines get their own nodes.
    body_node = _find_node(cfg, 3)
    assert "y" in body_node.defs
    assert "x" in body_node.uses


# ---------------------------------------------------------------------------
# Comprehensions and lambdas — local scope must not leak
# ---------------------------------------------------------------------------


def test_listcomp_target_does_not_leak_to_enclosing_function():
    """``[expr(i) for i in items]`` — i is comprehension-local. The
    enclosing statement must record items as a use but NOT i as a
    def."""
    src = (
        "def handle(items):\n"
        "    result = [expr(i) for i in items]\n"
    )
    cfg = build_python_cfg(src, "handle")
    node = _find_node(cfg, 2)
    assert "result" in node.defs
    assert "items" in node.uses
    assert "i" not in node.defs
    assert "i" not in node.uses


def test_dictcomp_key_value_scope():
    src = (
        "def handle(items):\n"
        "    out = {k: v for k, v in items}\n"
    )
    cfg = build_python_cfg(src, "handle")
    node = _find_node(cfg, 2)
    assert "out" in node.defs
    assert "items" in node.uses
    assert "k" not in node.defs
    assert "v" not in node.defs


def test_listcomp_first_iter_resolves_to_enclosing_scope():
    """The FIRST generator's ``iter`` is evaluated in the enclosing
    scope (Python semantic). So if it references an outer name,
    that name is a use of the enclosing function."""
    src = (
        "def handle(items, predicate):\n"
        "    out = [x for x in items if predicate(x)]\n"
    )
    cfg = build_python_cfg(src, "handle")
    node = _find_node(cfg, 2)
    # items is the outer iterable — must be a use.
    assert "items" in node.uses
    # predicate is referenced inside the ifs clause but it's not a
    # comp-local target, so it should be a use of the enclosing
    # scope.
    assert "predicate" in node.uses


def test_lambda_params_do_not_leak():
    src = (
        "def handle(values):\n"
        "    f = lambda v: v + 1\n"
        "    return list(map(f, values))\n"
    )
    cfg = build_python_cfg(src, "handle")
    assign = _find_node(cfg, 2)
    assert "f" in assign.defs
    # v is lambda-local; must NOT leak as a def or use.
    assert "v" not in assign.defs
    assert "v" not in assign.uses


# ---------------------------------------------------------------------------
# CallSite attribution
# ---------------------------------------------------------------------------


def test_bare_call_has_empty_assigned_names():
    src = (
        "def handle(x):\n"
        "    sink(x)\n"
    )
    cfg = build_python_cfg(src, "handle")
    node = _find_node(cfg, 2)
    site = _site_by_name(node, "sink")
    assert site.assigned_names == frozenset()
    assert site.arg_names == frozenset({"x"})


def test_top_level_call_assigned_names():
    src = (
        "def handle(x):\n"
        "    y = sanitize(x)\n"
    )
    cfg = build_python_cfg(src, "handle")
    node = _find_node(cfg, 2)
    site = _site_by_name(node, "sanitize")
    assert site.assigned_names == frozenset({"y"})
    assert site.arg_names == frozenset({"x"})


def test_chained_calls_only_outer_carries_assigned_names():
    """``y = wrap(sanitize(x))`` — sanitize's return flows into wrap,
    not into y. Only the outer wrap should carry assigned_names."""
    src = (
        "def handle(x):\n"
        "    y = wrap(sanitize(x))\n"
    )
    cfg = build_python_cfg(src, "handle")
    node = _find_node(cfg, 2)
    outer = _site_by_name(node, "wrap")
    inner = _site_by_name(node, "sanitize")
    assert outer.assigned_names == frozenset({"y"})
    assert inner.assigned_names == frozenset()


def test_dotted_callable_name_resolution():
    src = (
        "def handle(x):\n"
        "    y = django.utils.html.escape(x)\n"
    )
    cfg = build_python_cfg(src, "handle")
    node = _find_node(cfg, 2)
    site = _site_by_name(node, "django.utils.html.escape")
    assert site.assigned_names == frozenset({"y"})
    assert site.arg_names == frozenset({"x"})


def test_keyword_args_contribute_to_arg_names():
    src = (
        "def handle(value, key):\n"
        "    y = encode(value, k=key)\n"
    )
    cfg = build_python_cfg(src, "handle")
    node = _find_node(cfg, 2)
    site = _site_by_name(node, "encode")
    assert site.arg_names == frozenset({"value", "key"})
    assert site.assigned_names == frozenset({"y"})


def test_attribute_arg_records_base_name():
    """``foo(user.name)`` — base name ``user`` is the symbol that's
    actually flowing in at the bare-name level."""
    src = (
        "def handle(user):\n"
        "    render(user.name)\n"
    )
    cfg = build_python_cfg(src, "handle")
    node = _find_node(cfg, 2)
    site = _site_by_name(node, "render")
    assert site.arg_names == frozenset({"user"})


def test_nested_call_arg_does_not_inject_inner_names():
    """``foo(g(x))`` — the OUTER call's arg_names should NOT include
    ``x`` because ``x`` flows into ``g``, not directly into ``foo``.
    This is the conservative under-count that keeps the four-condition
    gate from over-suppressing."""
    src = (
        "def handle(x):\n"
        "    foo(g(x))\n"
    )
    cfg = build_python_cfg(src, "handle")
    node = _find_node(cfg, 2)
    outer = _site_by_name(node, "foo")
    inner = _site_by_name(node, "g")
    # The outer's bare-name arg list is empty (the arg is a Call).
    assert outer.arg_names == frozenset()
    # The inner's bare-name arg list has x.
    assert inner.arg_names == frozenset({"x"})


def test_aug_assign_call_records_target_as_assigned():
    """``acc += encode(x)`` — encode's return flows into acc."""
    src = (
        "def handle(x):\n"
        "    acc = 0\n"
        "    acc += encode(x)\n"
    )
    cfg = build_python_cfg(src, "handle")
    aug = _find_node(cfg, 3)
    site = _site_by_name(aug, "encode")
    assert site.assigned_names == frozenset({"acc"})


def test_multiple_calls_ordered_by_source_position():
    """``y = a(p); z = b(q)`` happen on separate lines so two nodes;
    on ONE line ``y, z = a(p), b(q)`` produces one node with two
    sites in source order."""
    src = (
        "def handle(p, q):\n"
        "    y, z = a(p), b(q)\n"
    )
    cfg = build_python_cfg(src, "handle")
    node = _find_node(cfg, 2)
    names_in_order = [s.name for s in node.call_sites]
    assert names_in_order == ["a", "b"]
    a_site = _site_by_name(node, "a")
    b_site = _site_by_name(node, "b")
    # Position-paired attribution: a → y, b → z.
    assert a_site.assigned_names == frozenset({"y"})
    assert b_site.assigned_names == frozenset({"z"})


def test_call_sites_in_compound_test_attributed_to_header():
    """``if check(x):`` — check is statement-level on the If header."""
    src = (
        "def handle(x):\n"
        "    if check(x):\n"
        "        return 0\n"
    )
    cfg = build_python_cfg(src, "handle")
    if_node = _find_node(cfg, 2)
    site = _site_by_name(if_node, "check")
    assert site.arg_names == frozenset({"x"})
    assert site.assigned_names == frozenset()


def test_call_sites_in_compound_body_are_separate():
    """Sanity check: the canonical wrong-variable case from the
    design doc has the right separation. The two calls live on two
    different lines, so they're attributed to two separate CFG
    nodes."""
    src = (
        "def handle(user, other):\n"
        "    safe_other = html.escape(other)\n"
        "    render(user.name)\n"
    )
    cfg = build_python_cfg(src, "handle")
    sanitize_node = _find_node(cfg, 2)
    sink_node = _find_node(cfg, 3)
    sanitize_site = _site_by_name(sanitize_node, "html.escape")
    sink_site = _site_by_name(sink_node, "render")
    # The sanitize binding: input is `other`, output is `safe_other`.
    assert sanitize_site.arg_names == frozenset({"other"})
    assert sanitize_site.assigned_names == frozenset({"safe_other"})
    # The sink binding: input is `user`, output is nowhere (unused
    # return).
    assert sink_site.arg_names == frozenset({"user"})
    assert sink_site.assigned_names == frozenset()
    # The Phase 4 gate will read these to conclude: sanitize cleans
    # `other`, sink reads `user` — value binding fails, do NOT
    # suppress. That's the whole point of Phase 1.


# ---------------------------------------------------------------------------
# Back-compat — legacy `calls` field stays in lockstep with new
# `call_sites`.
# ---------------------------------------------------------------------------


def test_calls_field_equals_call_sites_names():
    src = (
        "def handle(x, y):\n"
        "    a = sanitize(x)\n"
        "    b = encode(a)\n"
        "    if check(y):\n"
        "        return b\n"
    )
    cfg = build_python_cfg(src, "handle")
    for node in _stmt_nodes(cfg):
        derived = frozenset(s.name for s in node.call_sites)
        assert node.calls == derived, (
            f"calls / call_sites disagreement on {node!r}: "
            f"calls={node.calls}, derived={derived}"
        )


def test_empty_node_has_empty_symbol_sets():
    """A return-no-value statement carries nothing interesting."""
    src = (
        "def handle():\n"
        "    return\n"
    )
    cfg = build_python_cfg(src, "handle")
    node = _find_node(cfg, 2)
    assert node.defs == frozenset()
    assert node.uses == frozenset()
    assert node.call_sites == ()
    assert node.calls == frozenset()
