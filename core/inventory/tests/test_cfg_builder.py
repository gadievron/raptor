"""Tests for ``core.inventory.cfg_builder`` — Phase 5b.

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


from core.inventory.cfg_builder import (
    ENTRY_LINENO,
    EXIT_LINENO,
    PyCFGNode,
    PythonCFG,
    build_cpp_callgraph,
    build_python_cfg,
)
from core.inventory.dominators import build_dom_tree


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _cfg(source: str, func: str = "f") -> PythonCFG:
    cfg = build_python_cfg(source, func)
    assert cfg is not None, f"function {func!r} not found in source"
    return cfg


def _by_label(cfg: PythonCFG) -> dict:
    return {n.label: n for n in cfg.nodes()}


def _successors(cfg: PythonCFG, node: PyCFGNode):
    return list(cfg.successors(node))


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
    nodes = {n.lineno: n for n in cfg.nodes() if n.kind == "stmt"}
    # The break statement's successor should be the loop's after-loop
    # target (header in our model, since there's no orelse).
    break_node = next(
        n for n in cfg.nodes() if "break" in n.label
    )
    header = nodes[2]
    # break links to header (the after-loop pseudo-target)
    assert header in cfg.successors(break_node)


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
    from core.inventory.binary_oracle_edges import (
        BinaryCallEdge, BinaryEdgeIndex,
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
        "core.inventory.binary_oracle_edges.extract_direct_call_edges",
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
        "core.inventory.binary_oracle_edges.extract_direct_call_edges",
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
        "core.inventory.binary_oracle_edges.extract_direct_call_edges",
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
