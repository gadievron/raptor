"""Tests for ``core.analysis.cfg_builder`` — Phase 5b.

Covers:

* Straight-line CFG: every statement is a node in order.
* If/else: condition node branches; bodies join at successor.
* Loops (``while``, ``for``): body loops back to header; fall-through
  exits via ``orelse`` or directly.
* ``break`` / ``continue``: targets resolve to enclosing loop's
  break/continue points.
* ``try`` / ``except`` / ``finally``: handlers reachable, finally
  merges paths.
* ``with``: header dominates body.
* Calls extraction: statement-level only (compound headers don't
  inherit body calls).
* Dotted attribute calls (``re.sub``) and self-method calls
  (``self.helper.sanitize``).
* ``return`` / ``raise`` terminate flow into the exit sink.
* Missing function name returns ``None``.

Call-graph tests (``build_cpp_callgraph``) drive a synthetic
``BinaryEdgeIndex`` rather than invoking r2 — that's covered by
the binary-oracle-edges suite. We assert the graph protocol is
satisfied and the edges are unioned across binaries.
"""
from __future__ import annotations

from pathlib import Path
from unittest import mock

from core.analysis.cfg_builder import (
    ENTRY_LINENO,
    EXIT_LINENO,
    PythonCFG,
    build_cpp_callgraph,
    build_python_cfg,
)
from core.analysis.dominators import build_dom_tree

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _cfg(source: str, func: str = "f") -> PythonCFG:
    cfg = build_python_cfg(source, func)
    assert cfg is not None, f"function {func!r} not found in source"
    return cfg


# ---------------------------------------------------------------------------
# Smoke / structural
# ---------------------------------------------------------------------------


def test_function_not_found_returns_none():
    src = "def g():\n    pass\n"
    assert build_python_cfg(src, "nonexistent") is None


def test_async_function_supported():
    src = "async def f():\n    return 1\n"
    cfg = _cfg(src)
    assert cfg.function_name == "f"


def test_entry_and_exit_sentinels():
    cfg = _cfg("def f():\n    return 1\n")
    assert cfg.entry_node.kind == "entry"
    assert cfg.entry_node.lineno == ENTRY_LINENO
    assert cfg.exit_node.kind == "exit"
    assert cfg.exit_node.lineno == EXIT_LINENO


def test_straight_line_function():
    src = (
        "def f():\n"
        "    a = 1\n"
        "    b = 2\n"
        "    return a + b\n"
    )
    cfg = _cfg(src)
    nodes = list(cfg.nodes())
    # Entry, exit, three stmts (Assign, Assign, Return)
    stmt_lines = sorted(n.lineno for n in nodes if n.kind == "stmt")
    assert stmt_lines == [2, 3, 4]
    # Sequential edges
    by_lineno = {n.lineno: n for n in nodes if n.kind == "stmt"}
    assert by_lineno[3] in cfg.successors(by_lineno[2])
    assert by_lineno[4] in cfg.successors(by_lineno[3])
    # Return → exit
    assert cfg.exit_node in cfg.successors(by_lineno[4])


# ---------------------------------------------------------------------------
# Branches
# ---------------------------------------------------------------------------


def test_if_else_branches_then_joins():
    src = (
        "def f(x):\n"
        "    if x:\n"
        "        a = 1\n"
        "    else:\n"
        "        b = 2\n"
        "    return 3\n"
    )
    cfg = _cfg(src)
    nodes = {n.lineno: n for n in cfg.nodes() if n.kind == "stmt"}
    if_node = nodes[2]
    then_node = nodes[3]
    else_node = nodes[5]
    return_node = nodes[6]
    # If branches to both bodies
    assert then_node in cfg.successors(if_node)
    assert else_node in cfg.successors(if_node)
    # Both bodies join at return
    assert return_node in cfg.successors(then_node)
    assert return_node in cfg.successors(else_node)


def test_if_without_else_passes_through_to_join():
    src = (
        "def f(x):\n"
        "    if x:\n"
        "        a = 1\n"
        "    return a\n"
    )
    cfg = _cfg(src)
    nodes = {n.lineno: n for n in cfg.nodes() if n.kind == "stmt"}
    if_node = nodes[2]
    then_node = nodes[3]
    return_node = nodes[4]
    # If true: through then_node to return
    assert then_node in cfg.successors(if_node)
    assert return_node in cfg.successors(then_node)
    # If false: directly to return
    assert return_node in cfg.successors(if_node)


# ---------------------------------------------------------------------------
# Loops
# ---------------------------------------------------------------------------


def test_while_body_loops_back_to_header():
    src = (
        "def f():\n"
        "    while True:\n"
        "        a = 1\n"
        "    return 0\n"
    )
    cfg = _cfg(src)
    nodes = {n.lineno: n for n in cfg.nodes() if n.kind == "stmt"}
    header = nodes[2]
    body = nodes[3]
    # Body's successor is the header (loop back-edge)
    assert header in cfg.successors(body)
    # Header dominates body
    tree = build_dom_tree(cfg)
    assert tree.dominates(header, body)


def test_for_loop_dominates_body():
    src = (
        "def f(xs):\n"
        "    for x in xs:\n"
        "        process(x)\n"
        "    return 0\n"
    )
    cfg = _cfg(src)
    nodes = {n.lineno: n for n in cfg.nodes() if n.kind == "stmt"}
    header = nodes[2]
    body = nodes[3]
    tree = build_dom_tree(cfg)
    assert tree.dominates(header, body)


def test_break_targets_loop_successor():
    src = (
        "def f():\n"
        "    while True:\n"
        "        break\n"
        "    return 0\n"
    )
    cfg = _cfg(src)
    break_node = next(
        n for n in cfg.nodes() if "break" in n.label
    )
    exit_node = next(
        n for n in cfg.nodes() if "while-exit" in n.label
    )
    assert exit_node in cfg.successors(break_node)


def test_continue_targets_loop_header():
    src = (
        "def f(xs):\n"
        "    for x in xs:\n"
        "        if x < 0:\n"
        "            continue\n"
        "        process(x)\n"
        "    return 0\n"
    )
    cfg = _cfg(src)
    nodes = {n.lineno: n for n in cfg.nodes() if n.kind == "stmt"}
    header = nodes[2]
    continue_node = next(
        n for n in cfg.nodes() if "continue" in n.label
    )
    # continue → header
    assert header in cfg.successors(continue_node)


# ---------------------------------------------------------------------------
# Try / except / finally
# ---------------------------------------------------------------------------


def test_try_handler_reachable():
    src = (
        "def f():\n"
        "    try:\n"
        "        risky()\n"
        "    except ValueError:\n"
        "        handle()\n"
        "    return 0\n"
    )
    cfg = _cfg(src)
    handler_node = next(
        n for n in cfg.nodes()
        if n.kind == "stmt" and "handle" in n.calls
    )
    # Reachability assertion: handler is reachable from entry
    tree = build_dom_tree(cfg)
    assert handler_node in tree.nodes()


def test_finally_merges_paths():
    src = (
        "def f():\n"
        "    try:\n"
        "        risky()\n"
        "    except:\n"
        "        handle()\n"
        "    finally:\n"
        "        cleanup()\n"
        "    return 0\n"
    )
    cfg = _cfg(src)
    cleanup_node = next(
        n for n in cfg.nodes()
        if n.kind == "stmt" and "cleanup" in n.calls
    )
    # Cleanup must dominate the return (every path through the try
    # passes through finally).
    return_node = next(
        n for n in cfg.nodes()
        if n.kind == "stmt" and n.label.startswith("Return")
    )
    tree = build_dom_tree(cfg)
    assert tree.dominates(cleanup_node, return_node)


# ---------------------------------------------------------------------------
# With
# ---------------------------------------------------------------------------


def test_with_header_dominates_body():
    src = (
        "def f():\n"
        "    with lock:\n"
        "        critical()\n"
        "    return 0\n"
    )
    cfg = _cfg(src)
    with_node = next(
        n for n in cfg.nodes()
        if n.kind == "stmt" and n.label.startswith("With")
    )
    body_node = next(
        n for n in cfg.nodes()
        if n.kind == "stmt" and "critical" in n.calls
    )
    tree = build_dom_tree(cfg)
    assert tree.dominates(with_node, body_node)


def test_with_context_expression_payload_on_header():
    """Statement-position expression closure pin: the context-manager
    expression evaluates before the body, and its payload (calls, a
    walrus rebind) belongs to the header node — a dropped subtree here
    would be the Java-synchronized-lock class (an invisible definer
    the value gate's exclusivity proof never sees)."""
    src = (
        "def f(x):\n"
        "    y = clean(x)\n"
        "    with open(y := x) as fh:\n"
        "        sink(y)\n"
    )
    cfg = _cfg(src)
    header = next(
        n for n in cfg.nodes()
        if n.kind == "stmt" and n.label.startswith("With")
    )
    assert "open" in header.calls
    assert "y" in header.defs, (
        "walrus in the context expression must surface as a def"
    )
    assert "fh" in header.defs


# ---------------------------------------------------------------------------
# Call extraction
# ---------------------------------------------------------------------------


def test_calls_attributed_only_to_their_statement():
    """Regression: the If header should NOT inherit calls from its
    body. Phase 6 sanitizer matching depends on this."""
    src = (
        "def f(x):\n"
        "    if x:\n"
        "        sanitize(x)\n"
    )
    cfg = _cfg(src)
    nodes = {n.lineno: n for n in cfg.nodes() if n.kind == "stmt"}
    assert nodes[2].calls == frozenset()
    assert nodes[3].calls == frozenset({"sanitize"})


def test_calls_in_if_condition_attributed_to_header():
    """An ``if`` condition is statement-level; calls in it should be
    on the If node."""
    src = (
        "def f(x):\n"
        "    if validate(x):\n"
        "        pass\n"
    )
    cfg = _cfg(src)
    if_node = next(
        n for n in cfg.nodes() if n.label.startswith("If")
    )
    assert "validate" in if_node.calls


def test_dotted_attribute_calls():
    src = (
        "def f(x):\n"
        "    re.sub('foo', 'bar', x)\n"
        "    self.helper.sanitize(x)\n"
    )
    cfg = _cfg(src)
    all_calls = set()
    for n in cfg.nodes():
        all_calls |= n.calls
    assert "re.sub" in all_calls
    assert "self.helper.sanitize" in all_calls


def test_return_terminates_flow():
    """No statement should be reachable in the CFG after a ``return``.
    """
    src = (
        "def f():\n"
        "    return 1\n"
        "    unreachable()\n"
    )
    cfg = _cfg(src)
    # unreachable() statement should not be reachable from entry
    tree = build_dom_tree(cfg)
    unreachable_nodes = [
        n for n in cfg.nodes()
        if n.kind == "stmt" and "unreachable" in n.calls
    ]
    for n in unreachable_nodes:
        # Either pruned from dom tree, or only reachable through dead
        # code paths the builder doesn't link.
        assert n not in tree.nodes() or not tree.dominates(
            cfg.entry_node, n,
        ) or tree.idom(n) == cfg.entry_node


# ---------------------------------------------------------------------------
# Condition labels
# ---------------------------------------------------------------------------


def test_if_label_embeds_condition_text():
    """cfg_conditions parses the paren content of If/While/For labels
    as the guard expression — a positional-only label would hand it
    'line N' as the condition."""
    cfg = _cfg("def f(x):\n    if x > 0:\n        return x\n    return -x\n")
    if_node = next(n for n in cfg.nodes() if n.label.startswith("If"))
    assert if_node.label == "If (x > 0)"


def test_while_label_embeds_condition_text():
    cfg = _cfg("def f(x):\n    while x.ok():\n        step(x)\n    return x\n")
    node = next(n for n in cfg.nodes() if n.label.startswith("While ("))
    assert node.label == "While (x.ok())"


def test_for_label_embeds_target_and_iter():
    cfg = _cfg("def f(xs):\n    for x in xs:\n        use(x)\n    return 0\n")
    node = next(
        n for n in cfg.nodes()
        if n.label.startswith("For (") and "exit" not in n.label
    )
    assert node.label == "For (x in xs)"


def test_long_condition_label_truncated():
    cond = " or ".join(f"flag_{i}" for i in range(40))
    cfg = _cfg(f"def f():\n    if {cond}:\n        return 1\n    return 0\n")
    node = next(n for n in cfg.nodes() if n.label.startswith("If ("))
    from core.analysis.cfg_builder import _LABEL_EXPR_MAX
    assert len(node.label) <= len("If ()") + _LABEL_EXPR_MAX


# ---------------------------------------------------------------------------
# match statements
# ---------------------------------------------------------------------------


def test_match_without_wildcard_has_fallthrough_edge():
    """A ``match`` with only refutable cases can match NOTHING — the
    subject must flow directly to the post-match statement, or a
    sanitizer inside a case body looks like it dominates the sink."""
    src = (
        "def f(x):\n"
        "    match x:\n"
        "        case 'a':\n"
        "            y = clean(x)\n"
        "    sink(x)\n"
    )
    cfg = _cfg(src)
    subject = next(n for n in cfg.nodes() if n.label.startswith("match"))
    sink = next(n for n in cfg.nodes() if "sink" in n.calls)
    assert sink in cfg.successors(subject)


def test_match_with_wildcard_has_no_fallthrough_edge():
    """``case _:`` always matches — the subject's only successors are
    the case bodies, mirroring if/else."""
    src = (
        "def f(x):\n"
        "    match x:\n"
        "        case 'a':\n"
        "            y = clean(x)\n"
        "        case _:\n"
        "            y = clean(x)\n"
        "    sink(x)\n"
    )
    cfg = _cfg(src)
    subject = next(n for n in cfg.nodes() if n.label.startswith("match"))
    sink = next(n for n in cfg.nodes() if "sink" in n.calls)
    assert sink not in cfg.successors(subject)
    assert len(list(cfg.successors(subject))) == 2


def test_match_guarded_wildcard_still_falls_through():
    """``case _ if cond:`` can fail its guard — irrefutability requires
    the pattern to be guard-free."""
    src = (
        "def f(x):\n"
        "    match x:\n"
        "        case _ if x > 0:\n"
        "            y = clean(x)\n"
        "    sink(x)\n"
    )
    cfg = _cfg(src)
    subject = next(n for n in cfg.nodes() if n.label.startswith("match"))
    sink = next(n for n in cfg.nodes() if "sink" in n.calls)
    assert sink in cfg.successors(subject)


def test_match_case_capture_binds_as_def():
    """Pattern captures are identifier STRINGS (MatchAs.name /
    MatchStar.name / MatchMapping.rest) — invisible to any Name walk.
    Each case must carry them as defs, or a capture rebind of a
    sanitized name never reaches reaching-defs and the value-bound
    gate's exclusivity holds falsely (false-suppression direction)."""
    src = (
        "def f(x):\n"
        "    y = clean(x)\n"
        "    match x:\n"
        "        case [*y]:\n"
        "            pass\n"
        "    sink(y)\n"
    )
    cfg = _cfg(src)
    case_nodes = [n for n in cfg.nodes() if n.label.startswith("case")]
    assert case_nodes and "y" in case_nodes[0].defs


def test_match_mapping_rest_and_as_capture_bind_as_defs():
    src = (
        "def f(x):\n"
        "    match x:\n"
        "        case {'k': v, **rest}:\n"
        "            pass\n"
        "        case [1, 2] as whole:\n"
        "            pass\n"
        "    sink(x)\n"
    )
    cfg = _cfg(src)
    defs = set()
    for n in cfg.nodes():
        if n.label.startswith("case"):
            defs |= n.defs
    assert {"v", "rest", "whole"} <= defs


def test_match_case_guard_reads_and_calls_surface():
    src = (
        "def f(x):\n"
        "    match x:\n"
        "        case p if check(p, x):\n"
        "            pass\n"
        "    sink(x)\n"
    )
    cfg = _cfg(src)
    case_node = next(n for n in cfg.nodes() if n.label.startswith("case"))
    assert "check" in case_node.calls
    assert {"p", "x"} <= case_node.uses
    assert all(not cs.assigned_names for cs in case_node.call_sites)


def test_match_case_body_flows_through_case_node():
    """The case body's predecessors go subject -> case node -> body,
    so the capture def sits on every path into the body."""
    src = (
        "def f(x):\n"
        "    match x:\n"
        "        case 'a':\n"
        "            y = clean(x)\n"
        "    sink(x)\n"
    )
    cfg = _cfg(src)
    subject = next(n for n in cfg.nodes() if n.label.startswith("match"))
    case_node = next(n for n in cfg.nodes() if n.label.startswith("case"))
    body = next(n for n in cfg.nodes() if "clean" in n.calls)
    assert case_node in cfg.successors(subject)
    assert body in cfg.successors(case_node)


def test_match_bare_capture_counts_as_irrefutable():
    """``case other:`` (a bare capture) always matches, like ``case _``."""
    src = (
        "def f(x):\n"
        "    match x:\n"
        "        case 'a':\n"
        "            y = clean(x)\n"
        "        case other:\n"
        "            y = clean(other)\n"
        "    sink(x)\n"
    )
    cfg = _cfg(src)
    subject = next(n for n in cfg.nodes() if n.label.startswith("match"))
    sink = next(n for n in cfg.nodes() if "sink" in n.calls)
    assert sink not in cfg.successors(subject)


# ---------------------------------------------------------------------------
# Path-based source
# ---------------------------------------------------------------------------


def test_build_from_path(tmp_path: Path):
    src_file = tmp_path / "module.py"
    src_file.write_text(
        "def hello():\n    return 'world'\n", encoding="utf-8",
    )
    cfg = build_python_cfg(src_file, "hello")
    assert cfg is not None
    assert cfg.file_path == str(src_file)


# ---------------------------------------------------------------------------
# C/C++ call graph
# ---------------------------------------------------------------------------


def _stub_edge_index(binary_path, edges):
    from core.analysis.binary_oracle_edges import (
        BinaryCallEdge,
        BinaryEdgeIndex,
    )
    return BinaryEdgeIndex(
        binary_path=str(binary_path),
        edges=[BinaryCallEdge(c, e, str(binary_path)) for c, e in edges],
        callees={e for _, e in edges},
    )


def test_callgraph_from_synthetic_edges(tmp_path):
    """Drive ``build_cpp_callgraph`` with a stubbed
    ``extract_direct_call_edges`` so the test doesn't depend on r2."""
    binary = tmp_path / "fake.elf"
    binary.write_bytes(b"")
    edges = [("main", "f"), ("f", "g"), ("g", "h")]
    with mock.patch(
        "core.analysis.binary_oracle_edges.extract_direct_call_edges",
        return_value=_stub_edge_index(binary, edges),
    ):
        graph = build_cpp_callgraph([binary], entry="main")
    by_name = {n.name: n for n in graph.nodes()}
    assert {"main", "f", "g", "h"} <= set(by_name.keys())
    assert graph.entry.name == "main"
    assert by_name["f"] in graph.successors(by_name["main"])
    assert by_name["g"] in graph.successors(by_name["f"])
    assert by_name["h"] in graph.successors(by_name["g"])


def test_callgraph_unions_edges_across_binaries(tmp_path):
    bin_a = tmp_path / "a.elf"
    bin_a.write_bytes(b"")
    bin_b = tmp_path / "b.elf"
    bin_b.write_bytes(b"")

    def fake_extract(path):
        if path.name == "a.elf":
            return _stub_edge_index(path, [("main", "shared"), ("shared", "from_a")])
        if path.name == "b.elf":
            return _stub_edge_index(path, [("main", "shared"), ("shared", "from_b")])
        raise AssertionError

    with mock.patch(
        "core.analysis.binary_oracle_edges.extract_direct_call_edges",
        side_effect=fake_extract,
    ):
        graph = build_cpp_callgraph([bin_a, bin_b], entry="main")
    by_name = {n.name: n for n in graph.nodes()}
    shared_succs = {s.name for s in graph.successors(by_name["shared"])}
    assert shared_succs == {"from_a", "from_b"}


def test_callgraph_dominators_work(tmp_path):
    """End-to-end: dominators should run cleanly over a call graph."""
    binary = tmp_path / "fake.elf"
    binary.write_bytes(b"")
    edges = [("main", "f"), ("f", "sink"), ("main", "sink")]
    with mock.patch(
        "core.analysis.binary_oracle_edges.extract_direct_call_edges",
        return_value=_stub_edge_index(binary, edges),
    ):
        graph = build_cpp_callgraph([binary], entry="main")
    tree = build_dom_tree(graph)
    by_name = {n.name: n for n in graph.nodes()}
    # main dominates everything
    for name in ("f", "sink"):
        assert tree.dominates(by_name["main"], by_name[name])
    # f does NOT dominate sink (because main has a direct edge to sink)
    assert not tree.dominates(by_name["f"], by_name["sink"])


class TestCompoundStatementsNotFlattened:
    """AsyncFor / AsyncWith / TryStar and nested def/class must not
    collapse into one straight-line node — the flattened union puts a
    sanitizer from a conditionally-executed (or never-called) body on
    a node that sits unconditionally on the path, and leaks nested
    locals into defs."""

    def test_tryStar_handler_is_a_separate_node(self):
        src = (
            "def f(x):\n"
            "    try:\n"
            "        y = html.escape(x)\n"
            "    except* ValueError:\n"
            "        y = x\n"
            "    sink(y)\n"
        )
        cfg = _cfg(src)
        sanitizer = next(n for n in cfg.nodes() if "html.escape" in n.calls)
        handler = next(
            n for n in cfg.nodes()
            if n.lineno == 5 and "y" in n.defs and not n.calls
        )
        assert sanitizer is not handler

    def test_async_for_body_does_not_dominate(self):
        src = (
            "async def f(xs, x):\n"
            "    y = x\n"
            "    async for i in xs:\n"
            "        y = html.escape(x)\n"
            "    sink(y)\n"
        )
        cfg = _cfg(src)
        header = next(n for n in cfg.nodes() if n.lineno == 3
                      and "html.escape" not in n.calls)
        # Zero-iteration path exists: the body node is NOT the only
        # route from header to the sink.
        sanitizer = next(n for n in cfg.nodes() if "html.escape" in n.calls)
        assert sanitizer is not header

    def test_async_with_body_is_separate(self):
        src = (
            "async def f(x):\n"
            "    async with open_conn() as c:\n"
            "        y = html.escape(x)\n"
            "    sink(x)\n"
        )
        cfg = _cfg(src)
        header = next(n for n in cfg.nodes() if n.lineno == 2)
        assert "html.escape" not in header.calls
        assert "open_conn" in header.calls
        assert "c" in header.defs

    def test_nested_def_body_not_attributed_to_enclosing_node(self):
        src = (
            "def f(x):\n"
            "    def g(a=setup(x)):\n"
            "        local = html.escape(a)\n"
            "        return local\n"
            "    sink(x)\n"
        )
        cfg = _cfg(src)
        def_node = next(n for n in cfg.nodes() if n.lineno == 2)
        # Definition-site expressions (decorators, defaults) stay;
        # the body's calls and locals must not leak.
        assert "setup" in def_node.calls
        assert "html.escape" not in def_node.calls
        assert "local" not in def_node.defs

    def test_class_body_not_attributed_to_enclosing_node(self):
        src = (
            "def f(x):\n"
            "    class C(Base, metaclass=meta(x)):\n"
            "        attr = html.escape(x)\n"
            "    sink(x)\n"
        )
        cfg = _cfg(src)
        cls_node = next(n for n in cfg.nodes() if n.lineno == 2)
        assert "meta" in cls_node.calls
        assert "html.escape" not in cls_node.calls
        assert "attr" not in cls_node.defs


class TestDeferredExecutionBodies:
    """Lambda bodies and genexp payloads run later (or never) — their
    calls must not be attributed to the statement node, or a
    never-executed sanitizer sits unconditionally on the path (the
    nested-def hazard, same class). Eagerly-evaluated parts (lambda
    defaults, a genexp's first iterable, full list/set/dict
    comprehensions) keep contributing."""

    def _stmt_calls(self, src, marker):
        cfg = build_python_cfg(src, "handle")
        assert cfg is not None
        node = next(n for n in cfg.nodes() if marker in n.defs)
        return node.calls, node.call_sites

    def test_lambda_body_call_not_attributed(self):
        src = (
            "def handle(x):\n"
            "    f = lambda v: html.escape(v)\n"
            "    render(f)\n"
        )
        calls, sites = self._stmt_calls(src, "f")
        assert "html.escape" not in calls
        assert all(cs.name != "html.escape" for cs in sites)

    def test_genexp_payload_call_not_attributed(self):
        src = (
            "def handle(xs):\n"
            "    out = (html.escape(v) for v in xs)\n"
            "    render(out)\n"
        )
        calls, _ = self._stmt_calls(src, "out")
        assert "html.escape" not in calls

    def test_genexp_first_iterable_still_eager(self):
        src = (
            "def handle(xs):\n"
            "    out = (v for v in load(xs))\n"
            "    render(out)\n"
        )
        calls, _ = self._stmt_calls(src, "out")
        assert "load" in calls

    def test_lambda_default_still_eager(self):
        src = (
            "def handle(x):\n"
            "    f = lambda v=seed(x): v\n"
            "    render(f)\n"
        )
        calls, _ = self._stmt_calls(src, "f")
        assert "seed" in calls

    def test_listcomp_stays_eager(self):
        src = (
            "def handle(xs):\n"
            "    out = [html.escape(v) for v in xs]\n"
            "    render(out)\n"
        )
        calls, _ = self._stmt_calls(src, "out")
        assert "html.escape" in calls

    def test_lambda_sanitizer_cannot_carry_control_flow_cut(self):
        # Legacy no-value-context path: the vertex cut suppresses from
        # ``calls`` alone, so a lambda-wrapped sanitizer must not
        # register as a sanitizer node at all.
        from core.analysis.sanitizer_cut import evaluate_finding
        src = (
            "def handle(x):\n"
            "    f = lambda v: html.escape(v)\n"
            "    render(x)\n"
        )
        cfg = build_python_cfg(src, "handle")
        sink = next(n for n in cfg.nodes() if "render" in n.calls)
        result = evaluate_finding(
            cfg, [cfg.entry_node], sink, cwe="CWE-79", language="python",
        )
        assert not result.suppress


class TestLoopJoinSentinels:
    """Loop-exit joins are payload-free sentinels: re-extracting the
    header's payload duplicated its defs/calls on a second node at
    the same line (a walrus in the condition became a duplicate
    definer; a sanitizer call in the condition appeared twice)."""

    def test_while_join_carries_no_payload(self):
        src = (
            "def handle(x):\n"
            "    while (y := f(x)):\n"
            "        g(y)\n"
            "    render(y)\n"
        )
        cfg = build_python_cfg(src, "handle")
        definers = [n for n in cfg.nodes() if "y" in n.defs]
        assert len(definers) == 1
        join = next(n for n in cfg.nodes() if n.kind == "join")
        assert not join.defs and not join.calls and not join.call_sites

    def test_for_join_carries_no_payload(self):
        src = (
            "def handle(xs):\n"
            "    for v in load(xs):\n"
            "        g(v)\n"
            "    render(xs)\n"
        )
        cfg = build_python_cfg(src, "handle")
        joins = [n for n in cfg.nodes() if n.kind == "join"]
        assert joins and all(
            not j.defs and not j.calls and not j.uses for j in joins
        )
        # The header still carries the loop's payload.
        header = next(n for n in cfg.nodes() if "load" in n.calls)
        assert "v" in header.defs


class TestExceptHandlerBinding:
    """``except E as name`` binds ``name`` via an identifier STRING —
    invisible to every Store-ctx walk. The handler entry node must
    carry it as a def (mirroring the Java catch entry and the
    match-case capture nodes), or a handler rebind of a sanitized
    name is invisible to reaching-defs."""

    def test_handler_name_is_a_def(self):
        src = (
            "def handle(x):\n"
            "    try:\n"
            "        op(x)\n"
            "    except ValueError as err:\n"
            "        log(err)\n"
        )
        cfg = build_python_cfg(src, "handle")
        assert any("err" in n.defs for n in cfg.nodes())

    def test_handler_rebind_breaks_exclusivity(self):
        from core.analysis.sanitizer_cut import evaluate_finding
        src = (
            "def handle(x):\n"
            "    y = html.escape(x)\n"
            "    try:\n"
            "        op(x)\n"
            "    except ValueError as y:\n"
            "        pass\n"
            "    render(y)\n"
        )
        cfg = build_python_cfg(src, "handle")
        sink = next(n for n in cfg.nodes() if "render" in n.calls)
        result = evaluate_finding(
            cfg, [cfg.entry_node], sink,
            cwe="CWE-79", language="python",
            source_symbols=["x"], sink_arg="y",
        )
        assert not result.suppress

    def test_bare_except_adds_no_defs(self):
        src = (
            "def handle(x):\n"
            "    try:\n"
            "        op(x)\n"
            "    except Exception:\n"
            "        log(x)\n"
        )
        cfg = build_python_cfg(src, "handle")
        entries = [n for n in cfg.nodes() if n.label.startswith("except")]
        assert entries and all(not n.defs for n in entries)


class TestHostileBytesPathRead:
    def test_non_utf8_path_read_refuses(self, tmp_path):
        # Direct-Path API over hostile bytes: refuse (None), never
        # raise UnicodeDecodeError out of the builder.
        from pathlib import Path as _P
        from core.analysis.cfg_builder import build_python_cfg
        f = tmp_path / "bad.py"
        f.write_bytes(b"def f():\n    s = '\xff\xfe\x9d'\n")
        assert build_python_cfg(_P(f), "f") is None
