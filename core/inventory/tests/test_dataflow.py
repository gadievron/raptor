"""Tests for ``core.inventory.dataflow`` — Phase 2 of the value-binding arc.

Reaching-defs is a monotone-framework data-flow analysis with one
question: "at node N's entry, which earlier nodes' writes of symbol
s could still be the live definition?"

The fixture functions below cover the standard textbook cases the
design doc enumerates:

* straight-line def-then-use
* if/else merge (both branches' defs survive the join)
* while loop-carried def (initial def AND body def both reach the
  post-loop join, because the loop may have run 0 times)
* def-then-redef (later def kills the earlier)
* function parameters (treated as virtually defined at the entry)
* uninitialised symbol (empty reaching set)
* AugAssign (target is both def and use — prior def reaches the
  augassign's IN; only the augassign reaches subsequent IN-sets)
* nested loops with shadowed loop variables
* multiple symbols on the same node
* try / except / finally merge

These are the substrate Phase 4's gate reads, so a regression here
is a regression in the value-binding correctness proof.
"""
from __future__ import annotations

from core.inventory.cfg_builder import (
    PyCFGNode,
    PythonCFG,
    build_python_cfg,
)
from core.inventory.dataflow import (
    ReachingDefs,
    reaching_defs,
)


# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------


def _stmt_nodes(cfg: PythonCFG) -> list:
    return [n for n in cfg.nodes() if n.kind == "stmt"]


def _node_at(cfg: PythonCFG, lineno: int) -> PyCFGNode:
    matches = [n for n in _stmt_nodes(cfg) if n.lineno == lineno]
    assert len(matches) == 1, (
        f"expected exactly one stmt at line {lineno}, got {matches}"
    )
    return matches[0]


# ---------------------------------------------------------------------------
# Straight-line
# ---------------------------------------------------------------------------


def test_straight_line_def_then_use():
    """``y = x + 1; z = y * 2`` — the y-defining node reaches z's
    IN-set."""
    src = (
        "def handle(x):\n"
        "    y = x + 1\n"
        "    z = y * 2\n"
    )
    cfg = build_python_cfg(src, "handle")
    rd = reaching_defs(cfg)
    y_def = _node_at(cfg, 2)
    z_def = _node_at(cfg, 3)
    assert rd.at(z_def, "y") == frozenset({y_def})
    # x is a function parameter — reaches every body node via the entry.
    assert rd.at(y_def, "x") == frozenset({cfg.entry})


def test_uninitialised_symbol_has_empty_reaching_set():
    """``return y`` where y was never defined — the reaching set is
    empty, which Phase 4's gate reads as 'no value binding possible
    through this symbol.'"""
    src = (
        "def handle(x):\n"
        "    return y\n"
    )
    cfg = build_python_cfg(src, "handle")
    rd = reaching_defs(cfg)
    ret = _node_at(cfg, 2)
    assert rd.at(ret, "y") == frozenset()
    # And x still reaches from entry.
    assert rd.at(ret, "x") == frozenset({cfg.entry})


# ---------------------------------------------------------------------------
# Branches and joins
# ---------------------------------------------------------------------------


def test_if_else_both_branches_reach_join():
    """``if cond: y = a else: y = b; return y`` — both branch defs
    reach the return's IN-set. (Neither branch dominates the
    return; both are predecessors.)"""
    src = (
        "def handle(cond, a, b):\n"
        "    if cond:\n"
        "        y = a\n"
        "    else:\n"
        "        y = b\n"
        "    return y\n"
    )
    cfg = build_python_cfg(src, "handle")
    rd = reaching_defs(cfg)
    then_def = _node_at(cfg, 3)
    else_def = _node_at(cfg, 5)
    ret = _node_at(cfg, 6)
    assert rd.at(ret, "y") == frozenset({then_def, else_def})


def test_if_without_else_pre_def_still_reaches():
    """``y = 0; if cond: y = a; return y`` — the return sees y from
    the pre-If AND from the then-branch. The pre-If def is NOT
    killed because the else path skipped the redefinition."""
    src = (
        "def handle(cond, a):\n"
        "    y = 0\n"
        "    if cond:\n"
        "        y = a\n"
        "    return y\n"
    )
    cfg = build_python_cfg(src, "handle")
    rd = reaching_defs(cfg)
    pre = _node_at(cfg, 2)
    then_def = _node_at(cfg, 4)
    ret = _node_at(cfg, 5)
    assert rd.at(ret, "y") == frozenset({pre, then_def})


# ---------------------------------------------------------------------------
# Loops
# ---------------------------------------------------------------------------


def test_while_loop_carried_def_reaches_post():
    """The post-loop join sees both the initial def (loop ran 0
    times) and the loop-body def (loop ran ≥1 times)."""
    src = (
        "def handle(x):\n"
        "    y = x\n"
        "    while y > 0:\n"
        "        y = y - 1\n"
        "    return y\n"
    )
    cfg = build_python_cfg(src, "handle")
    rd = reaching_defs(cfg)
    init = _node_at(cfg, 2)
    body = _node_at(cfg, 4)
    ret = _node_at(cfg, 5)
    reaching = rd.at(ret, "y")
    assert init in reaching
    assert body in reaching


def test_for_loop_variable_defined_by_header():
    """``for item in items: process(item)`` — the loop variable
    ``item`` is defined by the For header. Inside the body its
    reaching def is the header."""
    src = (
        "def handle(items):\n"
        "    for item in items:\n"
        "        process(item)\n"
    )
    cfg = build_python_cfg(src, "handle")
    rd = reaching_defs(cfg)
    for_header = _node_at(cfg, 2)
    body = _node_at(cfg, 3)
    assert rd.at(body, "item") == frozenset({for_header})
    # items is a param — reaches via entry.
    assert rd.at(for_header, "items") == frozenset({cfg.entry})


def test_nested_loops_inner_redef_reaches_outer():
    """Initial def, inner-loop def, and (because the outer loop may
    run 0 times) the initial def again — all reach the return."""
    src = (
        "def handle(items):\n"
        "    y = 0\n"
        "    for outer in items:\n"
        "        for inner in outer:\n"
        "            y = inner\n"
        "    return y\n"
    )
    cfg = build_python_cfg(src, "handle")
    rd = reaching_defs(cfg)
    init = _node_at(cfg, 2)
    inner_def = _node_at(cfg, 5)
    ret = _node_at(cfg, 6)
    reaching = rd.at(ret, "y")
    assert init in reaching
    assert inner_def in reaching


# ---------------------------------------------------------------------------
# Def-then-redef
# ---------------------------------------------------------------------------


def test_redef_kills_earlier():
    """``y = 1; y = x; return y`` — only the second def reaches the
    return. The first is killed."""
    src = (
        "def handle(x):\n"
        "    y = 1\n"
        "    y = x\n"
        "    return y\n"
    )
    cfg = build_python_cfg(src, "handle")
    rd = reaching_defs(cfg)
    second = _node_at(cfg, 3)
    ret = _node_at(cfg, 4)
    assert rd.at(ret, "y") == frozenset({second})


def test_redef_only_on_one_branch_does_not_kill():
    """``y = 1; if c: y = 2; return y`` — both reach the return.
    The else path didn't kill the first."""
    src = (
        "def handle(c):\n"
        "    y = 1\n"
        "    if c:\n"
        "        y = 2\n"
        "    return y\n"
    )
    cfg = build_python_cfg(src, "handle")
    rd = reaching_defs(cfg)
    first = _node_at(cfg, 2)
    second = _node_at(cfg, 4)
    ret = _node_at(cfg, 5)
    assert rd.at(ret, "y") == frozenset({first, second})


# ---------------------------------------------------------------------------
# Function parameters
# ---------------------------------------------------------------------------


def test_function_params_reach_body_via_entry():
    """Every param is virtually defined at the entry. Body uses
    resolve to the entry as the reaching definer."""
    src = (
        "def handle(a, b, c):\n"
        "    return a + b + c\n"
    )
    cfg = build_python_cfg(src, "handle")
    rd = reaching_defs(cfg)
    ret = _node_at(cfg, 2)
    for name in ("a", "b", "c"):
        assert rd.at(ret, name) == frozenset({cfg.entry}), (
            f"param {name!r} should reach via entry"
        )


def test_keyword_only_and_vararg_params_reach():
    """``def handle(a, *args, b, **kw)`` — args, b, kw all reach
    the body via entry."""
    src = (
        "def handle(a, *args, b, **kw):\n"
        "    return a, args, b, kw\n"
    )
    cfg = build_python_cfg(src, "handle")
    rd = reaching_defs(cfg)
    ret = _node_at(cfg, 2)
    for name in ("a", "args", "b", "kw"):
        assert rd.at(ret, name) == frozenset({cfg.entry})


def test_no_params_function_still_works():
    """Degenerate case — function takes no args."""
    src = (
        "def handle():\n"
        "    y = 1\n"
        "    return y\n"
    )
    cfg = build_python_cfg(src, "handle")
    rd = reaching_defs(cfg)
    ret = _node_at(cfg, 3)
    assert rd.at(ret, "y") == frozenset({_node_at(cfg, 2)})


def test_param_redefined_in_body_replaces_entry():
    """``def handle(x): x = sanitize(x); return x`` — the body
    redef kills the entry's virtual def of x."""
    src = (
        "def handle(x):\n"
        "    x = sanitize(x)\n"
        "    return x\n"
    )
    cfg = build_python_cfg(src, "handle")
    rd = reaching_defs(cfg)
    redef = _node_at(cfg, 2)
    ret = _node_at(cfg, 3)
    # At the redef's IN, x still reaches from entry (read before
    # rewrite).
    assert rd.at(redef, "x") == frozenset({cfg.entry})
    # At return, only the redef reaches — entry was killed.
    assert rd.at(ret, "x") == frozenset({redef})


# ---------------------------------------------------------------------------
# AugAssign — both def and use on the same node
# ---------------------------------------------------------------------------


def test_aug_assign_reads_prior_then_kills():
    """``acc = 0; acc += x; return acc`` — at the aug node's IN,
    acc reaches from the initial def. At the return's IN, acc
    reaches only from the aug node."""
    src = (
        "def handle(x):\n"
        "    acc = 0\n"
        "    acc += x\n"
        "    return acc\n"
    )
    cfg = build_python_cfg(src, "handle")
    rd = reaching_defs(cfg)
    init = _node_at(cfg, 2)
    aug = _node_at(cfg, 3)
    ret = _node_at(cfg, 4)
    assert rd.at(aug, "acc") == frozenset({init})
    assert rd.at(ret, "acc") == frozenset({aug})


# ---------------------------------------------------------------------------
# Try / except / finally
# ---------------------------------------------------------------------------


def test_try_except_both_paths_reach_post():
    """``try: y = a except: y = b; return y`` — both defs reach the
    return, regardless of which exception model the builder uses.
    Soundness here: at least one of them must reach."""
    src = (
        "def handle(a, b):\n"
        "    try:\n"
        "        y = a\n"
        "    except Exception:\n"
        "        y = b\n"
        "    return y\n"
    )
    cfg = build_python_cfg(src, "handle")
    rd = reaching_defs(cfg)
    try_def = _node_at(cfg, 3)
    except_def = _node_at(cfg, 5)
    ret = _node_at(cfg, 6)
    reaching = rd.at(ret, "y")
    # Both should reach; the builder's conservative attachment
    # ensures the handler is reachable from the body.
    assert try_def in reaching
    assert except_def in reaching


# ---------------------------------------------------------------------------
# Multi-symbol & API surface
# ---------------------------------------------------------------------------


def test_multiple_symbols_independent_lifetimes():
    """``y = 1; z = 2; w = 3; return y, z, w`` — each symbol's
    reaching def is its own assignment, independent of the others."""
    src = (
        "def handle():\n"
        "    y = 1\n"
        "    z = 2\n"
        "    w = 3\n"
        "    return y, z, w\n"
    )
    cfg = build_python_cfg(src, "handle")
    rd = reaching_defs(cfg)
    y_def = _node_at(cfg, 2)
    z_def = _node_at(cfg, 3)
    w_def = _node_at(cfg, 4)
    ret = _node_at(cfg, 5)
    assert rd.at(ret, "y") == frozenset({y_def})
    assert rd.at(ret, "z") == frozenset({z_def})
    assert rd.at(ret, "w") == frozenset({w_def})


def test_all_at_returns_full_per_symbol_map():
    """``all_at`` is the diagnostic surface — full map of all
    reaching defs at a node, keyed by symbol."""
    src = (
        "def handle(x):\n"
        "    y = x\n"
        "    return y\n"
    )
    cfg = build_python_cfg(src, "handle")
    rd = reaching_defs(cfg)
    ret = _node_at(cfg, 3)
    full = rd.all_at(ret)
    assert full["x"] == frozenset({cfg.entry})
    assert full["y"] == frozenset({_node_at(cfg, 2)})


# ---------------------------------------------------------------------------
# The wrong-variable case — the whole point of Phase 2
# ---------------------------------------------------------------------------


def test_wrong_variable_case_reaching_defs_show_value_binding_gap():
    """``safe_other = html.escape(other); render(user.name)`` — at
    the sink node, ``user`` still reaches from the entry (never
    sanitised), and ``safe_other`` reaches from the sanitize node
    (but isn't read at the sink).

    Phase 4 will read this and refuse to suppress: the sanitizer's
    output never reaches the sink's input, so condition 3 of the
    gate fails."""
    src = (
        "def handle(user, other):\n"
        "    safe_other = html.escape(other)\n"
        "    render(user.name)\n"
    )
    cfg = build_python_cfg(src, "handle")
    rd = reaching_defs(cfg)
    sanitize_node = _node_at(cfg, 2)
    sink_node = _node_at(cfg, 3)
    # The sink reads user → still reaches from entry.
    assert rd.at(sink_node, "user") == frozenset({cfg.entry})
    # The sanitizer's output (safe_other) reaches the sink — but
    # the sink doesn't consume it.
    assert rd.at(sink_node, "safe_other") == frozenset({sanitize_node})
    # `other` (the sanitized input) also still reaches — its entry
    # def is alive at the sink because nobody rebound `other`.
    assert rd.at(sink_node, "other") == frozenset({cfg.entry})


# ---------------------------------------------------------------------------
# Degenerate inputs
# ---------------------------------------------------------------------------


def test_reaching_defs_object_is_immutable_facade():
    """ReachingDefs.at always returns frozenset — guards against
    callers mutating the underlying state."""
    src = (
        "def handle(x):\n"
        "    return x\n"
    )
    cfg = build_python_cfg(src, "handle")
    rd = reaching_defs(cfg)
    result = rd.at(_node_at(cfg, 2), "x")
    assert isinstance(result, frozenset)


def test_reaching_defs_on_call_graph_without_params_attr():
    """A graph without a ``params`` attribute (e.g. CppCallGraph)
    should still run — empty params is the correct default."""
    from core.inventory.cfg_builder import CallGraphNode

    class FakeCallGraph:
        def __init__(self):
            self.entry_node = CallGraphNode(name="main")
            self.other = CallGraphNode(name="other")
            self._adj = {self.entry_node: (self.other,)}

        @property
        def entry(self):
            return self.entry_node

        def nodes(self):
            return [self.entry_node, self.other]

        def successors(self, n):
            return self._adj.get(n, ())

    g = FakeCallGraph()
    rd = reaching_defs(g)
    # No defs anywhere, no params — every IN is empty.
    assert rd.at(g.entry, "anything") == frozenset()
    assert rd.at(g.other, "anything") == frozenset()


def test_empty_nodes_returns_empty_reaching_defs():
    """Degenerate edge — a graph with no nodes."""

    class EmptyGraph:
        entry = None

        def nodes(self):
            return []

        def successors(self, n):
            return ()

    rd = reaching_defs(EmptyGraph())
    assert isinstance(rd, ReachingDefs)
    assert rd.at(None, "x") == frozenset()
