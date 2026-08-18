"""Tests for core.audit.block_review."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, FrozenSet, Iterable, List, Tuple
from unittest.mock import patch

import pytest

from core.audit.block_review import (
    BlockReviewPlan,
    BlockTaintState,
    ComplexityProfile,
    CC_THRESHOLD,
    TAINT_BRANCH_THRESHOLD,
    analyze_complexity,
    build_block_review_plan,
    compute_cyclomatic_complexity,
    format_block_context,
    try_build_cfg,
    _count_paths_to_dangerous,
    _is_branch_node,
    _bfs_traversal,
)


# --- Minimal CFG stubs ---

@dataclass(frozen=True)
class _Node:
    kind: str = "stmt"
    lineno: int = 1
    label: str = ""
    calls: FrozenSet[str] = frozenset()
    defs: FrozenSet[str] = frozenset()
    uses: FrozenSet[str] = frozenset()
    call_sites: Tuple = ()


@dataclass
class _CFG:
    function_name: str = "test_fn"
    file_path: str = "test.py"
    entry_node: _Node = field(default_factory=lambda: _Node(kind="entry"))
    exit_node: _Node = field(default_factory=lambda: _Node(kind="exit"))
    _nodes: list = field(default_factory=list)
    _adj: Dict = field(default_factory=dict)
    params: Tuple[str, ...] = ()

    @property
    def entry(self):
        return self.entry_node

    def nodes(self) -> Iterable:
        return self._nodes or [self.entry_node, self.exit_node]

    def successors(self, node) -> Iterable:
        return self._adj.get(id(node), [])


def _linear_cfg(n_stmts=3):
    """Simple linear CFG: entry -> stmt1 -> stmt2 -> ... -> exit."""
    entry = _Node(kind="entry", lineno=1, label="entry")
    exit_n = _Node(kind="exit", lineno=n_stmts + 2, label="exit")
    stmts = [
        _Node(kind="stmt", lineno=i + 2, label=f"stmt{i}")
        for i in range(n_stmts)
    ]
    nodes = [entry] + stmts + [exit_n]
    adj = {}
    for i, node in enumerate(nodes[:-1]):
        adj[id(node)] = [nodes[i + 1]]
    adj[id(exit_n)] = []
    return _CFG(
        entry_node=entry, exit_node=exit_n,
        _nodes=nodes, _adj=adj,
    )


def _branching_cfg(n_branches=5):
    """CFG with n_branches if/else pairs off the main path."""
    entry = _Node(kind="entry", lineno=1, label="entry")
    exit_n = _Node(kind="exit", lineno=100, label="exit")
    nodes = [entry]
    adj = {}
    prev = entry

    for i in range(n_branches):
        cond = _Node(
            kind="stmt", lineno=10 + i * 10,
            label=f"If (x{i} > 0)",
            uses=frozenset({f"x{i}"}),
        )
        then_n = _Node(
            kind="stmt", lineno=11 + i * 10,
            label=f"then_{i}",
        )
        else_n = _Node(
            kind="stmt", lineno=12 + i * 10,
            label=f"else_{i}",
        )
        merge = _Node(
            kind="stmt", lineno=13 + i * 10,
            label=f"merge_{i}",
        )
        nodes.extend([cond, then_n, else_n, merge])
        adj[id(prev)] = [cond]
        adj[id(cond)] = [then_n, else_n]
        adj[id(then_n)] = [merge]
        adj[id(else_n)] = [merge]
        prev = merge

    nodes.append(exit_n)
    adj[id(prev)] = [exit_n]
    adj[id(exit_n)] = []

    return _CFG(
        entry_node=entry, exit_node=exit_n,
        _nodes=nodes, _adj=adj,
    )


def _loop_cfg():
    """CFG with a back-edge (cycle): entry -> cond -> body -> cond, cond -> exit."""
    entry = _Node(kind="entry", lineno=1, label="entry")
    cond = _Node(kind="stmt", lineno=5, label="while (i < n)",
                 uses=frozenset({"i", "n"}))
    body = _Node(kind="stmt", lineno=6, label="buf[i] = src[i]",
                 uses=frozenset({"i", "buf", "src"}),
                 defs=frozenset({"buf"}))
    exit_n = _Node(kind="exit", lineno=10, label="exit")
    nodes = [entry, cond, body, exit_n]
    adj = {
        id(entry): [cond],
        id(cond): [body, exit_n],
        id(body): [cond],
        id(exit_n): [],
    }
    return _CFG(
        entry_node=entry, exit_node=exit_n,
        _nodes=nodes, _adj=adj,
    )


class _FakeTaintApprox:
    def __init__(self, params=None, dangerous_flows=None):
        self.params = params or []
        self.dangerous_flows = dangerous_flows or {}


# ---- Cyclomatic complexity ----

class TestCyclomaticComplexity:
    def test_linear_cc_is_1(self):
        cfg = _linear_cfg(3)
        assert compute_cyclomatic_complexity(cfg) == 1

    def test_single_branch_cc_is_2(self):
        cfg = _branching_cfg(1)
        assert compute_cyclomatic_complexity(cfg) == 2

    def test_five_branches_cc_is_6(self):
        cfg = _branching_cfg(5)
        assert compute_cyclomatic_complexity(cfg) == 6

    def test_empty_cfg_returns_1(self):
        cfg = _CFG(_nodes=[], _adj={})
        assert compute_cyclomatic_complexity(cfg) == 1

    def test_loop_adds_complexity(self):
        cfg = _loop_cfg()
        cc = compute_cyclomatic_complexity(cfg)
        # entry->cond, cond->body, cond->exit, body->cond = 4 edges, 4 nodes
        assert cc == 2

    def test_single_node_cc_is_1(self):
        node = _Node(kind="entry")
        cfg = _CFG(_nodes=[node], _adj={id(node): []})
        assert compute_cyclomatic_complexity(cfg) == 1


# ---- Branch detection ----

class TestBranchDetection:
    def test_linear_node_not_branch(self):
        cfg = _linear_cfg(3)
        nodes = list(cfg.nodes())
        assert not _is_branch_node(cfg, nodes[0])

    def test_if_node_is_branch(self):
        cfg = _branching_cfg(1)
        nodes = list(cfg.nodes())
        cond = nodes[1]
        assert _is_branch_node(cfg, cond)

    def test_exit_not_branch(self):
        cfg = _linear_cfg(1)
        nodes = list(cfg.nodes())
        exit_n = nodes[-1]
        assert not _is_branch_node(cfg, exit_n)


# ---- BFS traversal ----

class TestBfsTraversal:
    def test_linear_preserves_order(self):
        cfg = _linear_cfg(3)
        nodes = list(cfg.nodes())
        order = _bfs_traversal(cfg, nodes)
        assert order[0].kind == "entry"
        assert order[-1].kind == "exit"
        assert len(order) == len(nodes)

    def test_cyclic_cfg_terminates(self):
        cfg = _loop_cfg()
        nodes = list(cfg.nodes())
        order = _bfs_traversal(cfg, nodes)
        assert len(order) == len(nodes)
        assert order[0].kind == "entry"

    def test_disconnected_nodes_included(self):
        entry = _Node(kind="entry", lineno=1)
        orphan = _Node(kind="stmt", lineno=5, label="orphan")
        exit_n = _Node(kind="exit", lineno=10)
        nodes = [entry, orphan, exit_n]
        adj = {id(entry): [exit_n], id(exit_n): [], id(orphan): []}
        cfg = _CFG(entry_node=entry, exit_node=exit_n,
                    _nodes=nodes, _adj=adj)
        order = _bfs_traversal(cfg, nodes)
        assert len(order) == 3
        assert orphan in order

    def test_no_entry_returns_nodes_as_is(self):
        n1 = _Node(kind="stmt", lineno=1)
        n2 = _Node(kind="stmt", lineno=2)
        nodes = [n1, n2]
        cfg = _CFG(_nodes=nodes, _adj={})
        cfg.entry_node = None
        order = _bfs_traversal(cfg, nodes)
        assert order == nodes


# ---- Path counting ----

class TestPathCounting:
    def test_no_sinks_returns_zero(self):
        cfg = _linear_cfg(3)
        nodes = list(cfg.nodes())
        count = _count_paths_to_dangerous(
            cfg, nodes, frozenset({"system"}), {"buf"},
        )
        assert count == 0

    def test_no_taint_returns_zero(self):
        entry = _Node(kind="entry", lineno=1)
        sink = _Node(kind="stmt", lineno=5,
                     calls=frozenset({"system"}))
        exit_n = _Node(kind="exit", lineno=10)
        nodes = [entry, sink, exit_n]
        adj = {id(entry): [sink], id(sink): [exit_n], id(exit_n): []}
        cfg = _CFG(entry_node=entry, exit_node=exit_n,
                    _nodes=nodes, _adj=adj)
        count = _count_paths_to_dangerous(
            cfg, nodes, frozenset({"system"}), set(),
        )
        assert count == 0

    def test_single_path_counted(self):
        entry = _Node(kind="entry", lineno=1)
        sink = _Node(kind="stmt", lineno=5,
                     calls=frozenset({"system"}),
                     uses=frozenset({"cmd"}))
        exit_n = _Node(kind="exit", lineno=10)
        nodes = [entry, sink, exit_n]
        adj = {id(entry): [sink], id(sink): [exit_n], id(exit_n): []}
        cfg = _CFG(entry_node=entry, exit_node=exit_n,
                    _nodes=nodes, _adj=adj)
        count = _count_paths_to_dangerous(
            cfg, nodes, frozenset({"system"}), {"cmd"},
        )
        assert count == 1

    def test_multiple_sinks_counted(self):
        entry = _Node(kind="entry", lineno=1)
        sink1 = _Node(kind="stmt", lineno=5,
                      calls=frozenset({"system"}),
                      uses=frozenset({"buf"}))
        sink2 = _Node(kind="stmt", lineno=8,
                      calls=frozenset({"exec"}),
                      uses=frozenset({"buf"}))
        exit_n = _Node(kind="exit", lineno=10)
        nodes = [entry, sink1, sink2, exit_n]
        adj = {
            id(entry): [sink1],
            id(sink1): [sink2],
            id(sink2): [exit_n],
            id(exit_n): [],
        }
        cfg = _CFG(entry_node=entry, exit_node=exit_n,
                    _nodes=nodes, _adj=adj)
        count = _count_paths_to_dangerous(
            cfg, nodes, frozenset({"system", "exec"}), {"buf"},
        )
        assert count == 2

    def test_dotted_sink_name_resolved(self):
        entry = _Node(kind="entry", lineno=1)
        sink = _Node(kind="stmt", lineno=5,
                     calls=frozenset({"os.system"}),
                     uses=frozenset({"cmd"}))
        exit_n = _Node(kind="exit", lineno=10)
        nodes = [entry, sink, exit_n]
        adj = {id(entry): [sink], id(sink): [exit_n], id(exit_n): []}
        cfg = _CFG(entry_node=entry, exit_node=exit_n,
                    _nodes=nodes, _adj=adj)
        count = _count_paths_to_dangerous(
            cfg, nodes, frozenset({"system"}), {"cmd"},
        )
        assert count == 1

    def test_taint_killed_by_redef_no_path(self):
        entry = _Node(kind="entry", lineno=1)
        redef = _Node(kind="stmt", lineno=3,
                      defs=frozenset({"cmd"}), uses=frozenset())
        sink = _Node(kind="stmt", lineno=5,
                     calls=frozenset({"system"}),
                     uses=frozenset({"cmd"}))
        exit_n = _Node(kind="exit", lineno=10)
        nodes = [entry, redef, sink, exit_n]
        adj = {
            id(entry): [redef],
            id(redef): [sink],
            id(sink): [exit_n],
            id(exit_n): [],
        }
        cfg = _CFG(entry_node=entry, exit_node=exit_n,
                    _nodes=nodes, _adj=adj)
        count = _count_paths_to_dangerous(
            cfg, nodes, frozenset({"system"}), {"cmd"},
        )
        assert count == 0

    def test_derived_var_reaches_sink(self):
        """y = f(x) where x is tainted, then system(y) should count."""
        entry = _Node(kind="entry", lineno=1)
        derive = _Node(kind="stmt", lineno=3,
                       defs=frozenset({"y"}), uses=frozenset({"x"}))
        sink = _Node(kind="stmt", lineno=5,
                     calls=frozenset({"system"}),
                     uses=frozenset({"y"}))
        exit_n = _Node(kind="exit", lineno=10)
        nodes = [entry, derive, sink, exit_n]
        adj = {
            id(entry): [derive],
            id(derive): [sink],
            id(sink): [exit_n],
            id(exit_n): [],
        }
        cfg = _CFG(entry_node=entry, exit_node=exit_n,
                    _nodes=nodes, _adj=adj)
        count = _count_paths_to_dangerous(
            cfg, nodes, frozenset({"system"}), {"x"},
        )
        assert count == 1

    def test_cap_limits_count(self):
        """Path count should not exceed the cap (20)."""
        entry = _Node(kind="entry", lineno=1)
        exit_n = _Node(kind="exit", lineno=100)
        sinks = [
            _Node(kind="stmt", lineno=10 + i,
                  calls=frozenset({"system"}),
                  uses=frozenset({"buf"}))
            for i in range(25)
        ]
        nodes = [entry] + sinks + [exit_n]
        adj = {id(entry): sinks}
        for s in sinks:
            adj[id(s)] = [exit_n]
        adj[id(exit_n)] = []
        cfg = _CFG(entry_node=entry, exit_node=exit_n,
                    _nodes=nodes, _adj=adj)
        count = _count_paths_to_dangerous(
            cfg, nodes, frozenset({"system"}), {"buf"},
        )
        assert count <= 20

    def test_cyclic_cfg_terminates(self):
        """Path counting on a loop CFG must terminate."""
        cfg = _loop_cfg()
        nodes = list(cfg.nodes())
        count = _count_paths_to_dangerous(
            cfg, nodes, frozenset({"memcpy"}), {"buf"},
        )
        assert count >= 0


# ---- Complexity profile ----

class TestComplexityProfile:
    def test_simple_function_no_block_review(self):
        cfg = _linear_cfg(3)
        profile = analyze_complexity(cfg)
        assert profile.cyclomatic_complexity == 1
        assert profile.needs_block_review is False

    def test_complex_with_tainted_branches_triggers(self):
        cfg = _branching_cfg(12)
        approx = _FakeTaintApprox(params=["x0", "x1", "x2", "x3"])
        profile = analyze_complexity(cfg, taint_approx=approx)
        assert profile.cyclomatic_complexity > CC_THRESHOLD
        assert profile.taint_relevant_branches > TAINT_BRANCH_THRESHOLD
        assert profile.needs_block_review is True

    def test_high_cc_but_no_taint_branches_no_trigger(self):
        cfg = _branching_cfg(12)
        profile = analyze_complexity(cfg)
        assert profile.cyclomatic_complexity > CC_THRESHOLD
        assert profile.taint_relevant_branches == 0
        assert profile.needs_block_review is False

    def test_many_paths_to_sink_triggers(self):
        entry = _Node(kind="entry", lineno=1, label="entry")
        exit_n = _Node(kind="exit", lineno=100, label="exit")
        cond = _Node(kind="stmt", lineno=10, label="branch",
                     uses=frozenset({"buf"}))
        sinks = [
            _Node(kind="stmt", lineno=20 + i * 10,
                  label=f"sink_{name}(buf)",
                  calls=frozenset({name}),
                  uses=frozenset({"buf"}))
            for i, name in enumerate(["system", "exec", "popen", "execve"])
        ]
        nodes = [entry, cond] + sinks + [exit_n]
        adj = {
            id(entry): [cond],
            id(cond): sinks,
            id(exit_n): [],
        }
        for s in sinks:
            adj[id(s)] = [exit_n]
        cfg = _CFG(entry_node=entry, exit_node=exit_n,
                    _nodes=nodes, _adj=adj)
        approx = _FakeTaintApprox(params=["buf"])
        profile = analyze_complexity(cfg, taint_approx=approx)
        assert profile.path_to_sink_count >= 4
        assert profile.needs_block_review is True

    def test_needs_block_review_thresholds(self):
        p = ComplexityProfile()
        assert p.needs_block_review is False

        p = ComplexityProfile(cyclomatic_complexity=11,
                              taint_relevant_branches=3)
        assert p.needs_block_review is True

        p = ComplexityProfile(cyclomatic_complexity=11,
                              taint_relevant_branches=2)
        assert p.needs_block_review is False

        p = ComplexityProfile(path_to_sink_count=4)
        assert p.needs_block_review is True

        p = ComplexityProfile(path_to_sink_count=3)
        assert p.needs_block_review is False

    def test_dangerous_calls_counted(self):
        entry = _Node(kind="entry", lineno=1)
        stmt = _Node(kind="stmt", lineno=5,
                     calls=frozenset({"memcpy", "strlen"}))
        exit_n = _Node(kind="exit", lineno=10)
        nodes = [entry, stmt, exit_n]
        adj = {id(entry): [stmt], id(stmt): [exit_n], id(exit_n): []}
        cfg = _CFG(entry_node=entry, exit_node=exit_n,
                    _nodes=nodes, _adj=adj)
        profile = analyze_complexity(cfg)
        assert profile.dangerous_calls >= 1

    def test_callee_names_not_in_taint(self):
        """Callee names from dangerous_flows are NOT taint sources."""
        entry = _Node(kind="entry", lineno=1)
        cond = _Node(kind="stmt", lineno=5,
                     uses=frozenset({"memcpy"}))
        then_n = _Node(kind="stmt", lineno=6)
        else_n = _Node(kind="stmt", lineno=7)
        exit_n = _Node(kind="exit", lineno=10)
        nodes = [entry, cond, then_n, else_n, exit_n]
        adj = {
            id(entry): [cond],
            id(cond): [then_n, else_n],
            id(then_n): [exit_n],
            id(else_n): [exit_n],
            id(exit_n): [],
        }
        cfg = _CFG(entry_node=entry, exit_node=exit_n,
                    _nodes=nodes, _adj=adj)
        approx = _FakeTaintApprox(
            params=[],
            dangerous_flows={0: [("memcpy", 1)]},
        )
        profile = analyze_complexity(cfg, taint_approx=approx)
        assert profile.taint_relevant_branches == 0

    def test_no_taint_approx(self):
        cfg = _branching_cfg(3)
        profile = analyze_complexity(cfg, taint_approx=None)
        assert profile.taint_relevant_branches == 0
        assert profile.path_to_sink_count == 0


# ---- Block review plan ----

class TestBuildBlockReviewPlan:
    def test_simple_function_returns_none(self):
        cfg = _linear_cfg(3)
        plan = build_block_review_plan(
            cfg, file_path="test.py", function_name="simple",
        )
        assert plan is None

    def test_complex_function_returns_plan(self):
        cfg = _branching_cfg(12)
        approx = _FakeTaintApprox(params=["x0", "x1", "x2", "x3"])
        plan = build_block_review_plan(
            cfg, file_path="test.py", function_name="complex",
            taint_approx=approx,
            source="line1\nline2\nline3\n" * 10,
        )
        assert plan is not None
        assert plan.function == "complex"
        assert plan.file == "test.py"
        assert plan.profile.needs_block_review is True
        assert len(plan.blocks) > 0

    def test_plan_includes_entry_and_exit(self):
        cfg = _branching_cfg(12)
        approx = _FakeTaintApprox(params=["x0", "x1", "x2"])
        plan = build_block_review_plan(
            cfg, file_path="test.py", function_name="f",
            taint_approx=approx,
        )
        assert plan is not None
        kinds = [b.label for b in plan.blocks]
        assert any("entry" in k.lower() for k in kinds) or plan.blocks[0].block_id == 0

    def test_tainted_branch_included(self):
        cfg = _branching_cfg(12)
        approx = _FakeTaintApprox(params=["x0", "x1", "x5"])
        plan = build_block_review_plan(
            cfg, file_path="t.c", function_name="f",
            taint_approx=approx,
        )
        assert plan is not None
        tainted_branches = [
            b for b in plan.blocks if b.branch_involves_tainted
        ]
        assert len(tainted_branches) >= 1

    def test_dangerous_call_block_included(self):
        """A block with a dangerous call should always be included."""
        entry = _Node(kind="entry", lineno=1, label="entry")
        exit_n = _Node(kind="exit", lineno=100, label="exit")
        nodes_list: List[_Node] = [entry]
        adj = {}
        prev = entry

        for i in range(12):
            cond = _Node(kind="stmt", lineno=10 + i * 10,
                         label=f"If (x{i} > 0)",
                         uses=frozenset({f"x{i}"}))
            then_n = _Node(kind="stmt", lineno=11 + i * 10,
                           label=f"then_{i}")
            else_n = _Node(kind="stmt", lineno=12 + i * 10,
                           label=f"else_{i}")
            merge = _Node(kind="stmt", lineno=13 + i * 10,
                          label=f"merge_{i}")
            nodes_list.extend([cond, then_n, else_n, merge])
            adj[id(prev)] = [cond]
            adj[id(cond)] = [then_n, else_n]
            adj[id(then_n)] = [merge]
            adj[id(else_n)] = [merge]
            prev = merge

        danger = _Node(kind="stmt", lineno=200, label="system(cmd)",
                       calls=frozenset({"system"}),
                       uses=frozenset({"cmd"}))
        nodes_list.extend([danger, exit_n])
        adj[id(prev)] = [danger]
        adj[id(danger)] = [exit_n]
        adj[id(exit_n)] = []

        cfg = _CFG(entry_node=entry, exit_node=exit_n,
                    _nodes=nodes_list, _adj=adj)
        approx = _FakeTaintApprox(params=["x0", "x1", "x2", "cmd"])
        plan = build_block_review_plan(
            cfg, file_path="t.c", function_name="f",
            taint_approx=approx,
        )
        assert plan is not None
        dangerous_blocks = [
            b for b in plan.blocks if b.calls_dangerous
        ]
        assert len(dangerous_blocks) >= 1
        assert "system" in dangerous_blocks[0].calls_dangerous

    def test_source_lines_populated(self):
        cfg = _branching_cfg(12)
        source = "\n".join(f"line {i}" for i in range(200))
        approx = _FakeTaintApprox(params=["x0", "x1", "x2"])
        plan = build_block_review_plan(
            cfg, file_path="t.c", function_name="f",
            taint_approx=approx,
            source=source,
        )
        assert plan is not None
        assert len(plan.source_lines) == 200

    def test_path_to_sink_triggers_without_high_cc(self):
        """PATH_TO_SINK_THRESHOLD alone should trigger block review."""
        entry = _Node(kind="entry", lineno=1, label="entry")
        exit_n = _Node(kind="exit", lineno=50, label="exit")
        sinks = [
            _Node(kind="stmt", lineno=10 + i,
                  calls=frozenset({"system"}),
                  uses=frozenset({"buf"}))
            for i in range(5)
        ]
        nodes = [entry] + sinks + [exit_n]
        adj = {id(entry): sinks}
        for s in sinks:
            adj[id(s)] = [exit_n]
        adj[id(exit_n)] = []
        cfg = _CFG(entry_node=entry, exit_node=exit_n,
                    _nodes=nodes, _adj=adj)
        approx = _FakeTaintApprox(params=["buf"])
        plan = build_block_review_plan(
            cfg, file_path="t.c", function_name="f",
            taint_approx=approx,
        )
        assert plan is not None


# ---- Taint propagation through blocks ----

class TestTaintPropagation:
    def _build_plan_for_cfg(self, nodes, adj, entry, exit_n, taint_params):
        """Helper: force needs_block_review=True via mock, build plan."""
        cfg = _CFG(entry_node=entry, exit_node=exit_n,
                    _nodes=nodes, _adj=adj)
        approx = _FakeTaintApprox(params=taint_params)
        with patch(
            "core.audit.block_review.analyze_complexity",
            return_value=ComplexityProfile(
                cyclomatic_complexity=20,
                taint_relevant_branches=5,
            ),
        ):
            plan = build_block_review_plan(
                cfg, file_path="t.c", function_name="f",
                taint_approx=approx,
            )
        return plan

    def test_taint_flows_through_linear(self):
        entry = _Node(kind="entry", lineno=1, label="entry")
        mid = _Node(kind="stmt", lineno=5, label="mid",
                    uses=frozenset({"buf"}))
        exit_n = _Node(kind="exit", lineno=10, label="exit")
        nodes = [entry, mid, exit_n]
        adj = {
            id(entry): [mid], id(mid): [exit_n], id(exit_n): [],
        }
        plan = self._build_plan_for_cfg(
            nodes, adj, entry, exit_n, ["buf"],
        )
        assert plan is not None
        exit_block = [b for b in plan.blocks if "exit" in b.label.lower()]
        assert exit_block
        assert "buf" in exit_block[0].tainted_at_entry

    def test_redef_kills_taint(self):
        entry = _Node(kind="entry", lineno=1, label="entry")
        redef = _Node(kind="stmt", lineno=5, label="buf = safe()",
                      defs=frozenset({"buf"}), uses=frozenset())
        exit_n = _Node(kind="exit", lineno=10, label="exit")
        nodes = [entry, redef, exit_n]
        adj = {
            id(entry): [redef], id(redef): [exit_n], id(exit_n): [],
        }
        plan = self._build_plan_for_cfg(
            nodes, adj, entry, exit_n, ["buf"],
        )
        assert plan is not None
        exit_block = [b for b in plan.blocks if "exit" in b.label.lower()]
        assert exit_block
        assert "buf" not in exit_block[0].tainted_at_entry

    def test_tainted_redef_preserves_taint(self):
        """x = x + 1 keeps x tainted."""
        entry = _Node(kind="entry", lineno=1, label="entry")
        redef = _Node(kind="stmt", lineno=5, label="x = x + 1",
                      defs=frozenset({"x"}), uses=frozenset({"x"}))
        exit_n = _Node(kind="exit", lineno=10, label="exit")
        nodes = [entry, redef, exit_n]
        adj = {
            id(entry): [redef], id(redef): [exit_n], id(exit_n): [],
        }
        plan = self._build_plan_for_cfg(
            nodes, adj, entry, exit_n, ["x"],
        )
        assert plan is not None
        exit_block = [b for b in plan.blocks if "exit" in b.label.lower()]
        assert exit_block
        assert "x" in exit_block[0].tainted_at_entry

    def test_derived_var_becomes_tainted(self):
        """y = f(x) where x is tainted should make y tainted too."""
        entry = _Node(kind="entry", lineno=1, label="entry")
        derive = _Node(kind="stmt", lineno=5, label="y = f(x)",
                       defs=frozenset({"y"}), uses=frozenset({"x", "f"}))
        exit_n = _Node(kind="exit", lineno=10, label="exit")
        nodes = [entry, derive, exit_n]
        adj = {
            id(entry): [derive], id(derive): [exit_n], id(exit_n): [],
        }
        plan = self._build_plan_for_cfg(
            nodes, adj, entry, exit_n, ["x"],
        )
        assert plan is not None
        exit_block = [b for b in plan.blocks if "exit" in b.label.lower()]
        assert exit_block
        assert "x" in exit_block[0].tainted_at_entry
        assert "y" in exit_block[0].tainted_at_entry

    def test_branch_merges_taint(self):
        """At a merge point after a branch, taint from both paths should be present."""
        entry = _Node(kind="entry", lineno=1, label="entry")
        cond = _Node(kind="stmt", lineno=5, label="If",
                     uses=frozenset({"x"}))
        then_n = _Node(kind="stmt", lineno=6, label="then",
                       defs=frozenset({"y"}), uses=frozenset({"x"}))
        else_n = _Node(kind="stmt", lineno=7, label="else")
        exit_n = _Node(kind="exit", lineno=10, label="exit")
        nodes = [entry, cond, then_n, else_n, exit_n]
        adj = {
            id(entry): [cond],
            id(cond): [then_n, else_n],
            id(then_n): [exit_n],
            id(else_n): [exit_n],
            id(exit_n): [],
        }
        plan = self._build_plan_for_cfg(
            nodes, adj, entry, exit_n, ["x"],
        )
        assert plan is not None
        exit_block = [b for b in plan.blocks if "exit" in b.label.lower()]
        assert exit_block
        assert "x" in exit_block[0].tainted_at_entry


# ---- Format block context ----

class TestFormatBlockContext:
    def test_renders_blocks(self):
        plan = BlockReviewPlan(
            function="handle_request",
            file="handler.c",
            profile=ComplexityProfile(
                cyclomatic_complexity=15,
                taint_relevant_branches=4,
                path_to_sink_count=3,
            ),
            blocks=[
                BlockTaintState(
                    block_id=0, lineno=10, label="entry",
                    tainted_at_entry=["buf", "len"],
                ),
                BlockTaintState(
                    block_id=3, lineno=25, label="If (len > 1024)",
                    tainted_at_entry=["buf", "len"],
                    is_branch=True,
                    branch_involves_tainted=True,
                ),
                BlockTaintState(
                    block_id=5, lineno=30, label="memcpy(dest, buf, len)",
                    tainted_at_entry=["buf", "len"],
                    calls_dangerous=["memcpy"],
                ),
            ],
            source_lines=[],
        )
        text = format_block_context(plan)
        assert "Block-level analysis" in text
        assert "CC=15" in text
        assert "DANGEROUS CALLS" in text
        assert "memcpy" in text
        assert "BRANCH on tainted variable" in text
        assert "`buf`" in text

    def test_sanitizer_rendered(self):
        plan = BlockReviewPlan(
            function="f", file="a.c",
            profile=ComplexityProfile(cyclomatic_complexity=15),
            blocks=[
                BlockTaintState(
                    block_id=0, lineno=10, label="escape(input)",
                    calls_sanitizer=["html_escape"],
                ),
            ],
        )
        text = format_block_context(plan)
        assert "Sanitizer calls" in text
        assert "html_escape" in text

    def test_source_snippet_included(self):
        source = [f"line {i}" for i in range(50)]
        plan = BlockReviewPlan(
            function="f", file="a.c",
            profile=ComplexityProfile(cyclomatic_complexity=15),
            blocks=[
                BlockTaintState(block_id=0, lineno=10, label="stmt"),
            ],
            source_lines=source,
        )
        text = format_block_context(plan)
        assert "line 9" in text
        assert "line 10" in text

    def test_non_taint_branch_noted(self):
        plan = BlockReviewPlan(
            function="f", file="a.c",
            profile=ComplexityProfile(cyclomatic_complexity=15),
            blocks=[
                BlockTaintState(
                    block_id=0, lineno=10, label="If (flag)",
                    is_branch=True,
                    branch_involves_tainted=False,
                ),
            ],
        )
        text = format_block_context(plan)
        assert "not taint-dependent" in text

    def test_empty_blocks_still_renders_header(self):
        plan = BlockReviewPlan(
            function="f", file="a.c",
            profile=ComplexityProfile(
                cyclomatic_complexity=12,
                taint_relevant_branches=3,
                path_to_sink_count=1,
            ),
            blocks=[],
        )
        text = format_block_context(plan)
        assert "Block-level analysis" in text
        assert "CC=12" in text

    def test_header_includes_cfg_size(self):
        plan = BlockReviewPlan(
            function="f", file="a.c",
            profile=ComplexityProfile(
                cyclomatic_complexity=12,
                taint_relevant_branches=3,
                path_to_sink_count=1,
                total_nodes=42,
                branch_nodes=7,
            ),
            blocks=[],
        )
        text = format_block_context(plan)
        assert "42 CFG nodes / 7 branches" in text


# ---- try_build_cfg ----

class TestTryBuildCfg:
    def test_python_file(self, tmp_path: Path):
        src = tmp_path / "test.py"
        src.write_text("def hello(name):\n    print(name)\n")
        cfg = try_build_cfg("test.py", "hello", tmp_path)
        assert cfg is not None

    def test_c_file(self, tmp_path: Path):
        src = tmp_path / "test.c"
        src.write_text("void hello(int x) { return; }\n")
        cfg = try_build_cfg("test.c", "hello", tmp_path)
        # May be None if tree-sitter C grammar not installed
        # but should not raise
        assert cfg is None or cfg is not None

    def test_unsupported_extension_returns_none(self, tmp_path: Path):
        src = tmp_path / "test.rb"
        src.write_text("def hello\n  puts 'hi'\nend\n")
        cfg = try_build_cfg("test.rb", "hello", tmp_path)
        assert cfg is None

    def test_missing_function_returns_none(self, tmp_path: Path):
        src = tmp_path / "test.py"
        src.write_text("def hello():\n    pass\n")
        cfg = try_build_cfg("test.py", "nonexistent", tmp_path)
        assert cfg is None

    def test_missing_file_returns_none(self, tmp_path: Path):
        cfg = try_build_cfg("missing.py", "f", tmp_path)
        assert cfg is None

    def test_source_override(self, tmp_path: Path):
        (tmp_path / "test.py").write_text("")
        cfg = try_build_cfg(
            "test.py", "greet", tmp_path,
            source="def greet(x):\n    return x\n",
        )
        assert cfg is not None


# ---- E2E: real CFG from eval target ----

class TestE2ERealTarget:
    """End-to-end test against eval/audit-synthetic/target."""

    @pytest.fixture
    def target_path(self):
        p = Path(__file__).resolve().parents[3] / "eval" / "audit-synthetic" / "target"
        if not p.exists():
            pytest.skip("eval/audit-synthetic/target not available")
        return p

    def test_reqparse_parse_headers_triggers_block_review(self, target_path):
        """parse_headers is known-complex (CC=11, 4 taint branches)."""
        cfg = try_build_cfg("reqparse.c", "parse_headers", target_path)
        if cfg is None:
            pytest.skip("C tree-sitter grammar not available")

        from core.analysis.taint_approx import extract_taint_approx_c
        source = (target_path / "reqparse.c").read_text()
        approx_map = extract_taint_approx_c(source)
        approx = approx_map.get("parse_headers")

        profile = analyze_complexity(cfg, taint_approx=approx)
        assert profile.cyclomatic_complexity > CC_THRESHOLD
        assert profile.taint_relevant_branches > 0
        assert profile.needs_block_review is True

        plan = build_block_review_plan(
            cfg,
            file_path="reqparse.c",
            function_name="parse_headers",
            taint_approx=approx,
            source=source,
        )
        assert plan is not None
        assert len(plan.blocks) >= 5

        ctx = format_block_context(plan)
        assert "Block-level analysis" in ctx
        assert "taint-relevant branches" in ctx

    def test_simple_function_no_trigger(self, target_path):
        """to_lowercase should NOT trigger block review."""
        cfg = try_build_cfg("reqparse.c", "to_lowercase", target_path)
        if cfg is None:
            pytest.skip("C tree-sitter grammar not available")
        profile = analyze_complexity(cfg)
        assert profile.needs_block_review is False

    def test_evidence_index_populates_sink_narrowing(self, target_path):
        """Sink-unreachable functions get narrowed classes."""
        from core.inventory.sink_discovery import discover_sinks_for_target
        from core.evidence import build_evidence_index

        sinks = discover_sinks_for_target(target_path)

        from core.inventory.sink_discovery import (
            _get_call_graph_extractors,
            _iter_source_files,
        )
        from core.inventory.languages import detect_language

        call_graphs = {}
        extractors = _get_call_graph_extractors()
        for source_file in _iter_source_files(target_path):
            rel = str(source_file.relative_to(target_path))
            lang = detect_language(rel)
            ext_fn = extractors.get(lang)
            if ext_fn:
                content = source_file.read_text(errors="replace")
                call_graphs[rel] = ext_fn(content)

        checklist = {"files": []}
        for filepath, graph in call_graphs.items():
            seen = set()
            items = []
            for call in graph.calls:
                c = call.caller or "<module>"
                if c not in seen:
                    seen.add(c)
                    items.append({"name": c, "kind": "function"})
            if items:
                checklist["files"].append({"path": filepath, "items": items})

        index = build_evidence_index(
            checklist=checklist,
            sink_results=sinks,
        )

        unreachable = [
            k for k, r in index.items() if r.sink_unreachable
        ]
        assert len(unreachable) > 0

        for key in unreachable:
            rec = index[key]
            assert len(rec.sink_narrowed_classes) > 0
            assert "CWE-78" in rec.sink_narrowed_classes

        reachable = [
            k for k, r in index.items() if not r.sink_unreachable
        ]
        for key in reachable:
            rec = index[key]
            assert rec.sink_narrowed_classes == []

    def test_full_context_render_with_block_analysis(self, target_path):
        """Verify context rendering includes block analysis for complex fns."""
        from core.audit.context import format_context_for_prompt

        cfg = try_build_cfg("reqparse.c", "parse_headers", target_path)
        if cfg is None:
            pytest.skip("C tree-sitter grammar not available")

        from core.analysis.taint_approx import extract_taint_approx_c
        source = (target_path / "reqparse.c").read_text()
        approx_map = extract_taint_approx_c(source)
        approx = approx_map.get("parse_headers")

        plan = build_block_review_plan(
            cfg,
            file_path="reqparse.c",
            function_name="parse_headers",
            taint_approx=approx,
            source=source,
        )
        assert plan is not None
        block_ctx = format_block_context(plan)

        ctx = {
            "file": "reqparse.c",
            "function": "parse_headers",
            "line_start": 1,
            "source": source[:500],
            "metadata": {},
            "callers": [],
            "callees": [],
            "sinks": [],
            "existing_annotation": None,
            "block_analysis": block_ctx,
        }
        result = format_context_for_prompt(ctx)
        assert "Block-level analysis" in result
        assert "DANGEROUS CALLS" in result or "taint-relevant" in result
