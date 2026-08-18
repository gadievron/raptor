"""Tests for core.audit.task_graph.TaskGraph."""

from __future__ import annotations

from typing import Any

from core.audit.task_graph import TaskGraph, _break_cycles, _relax_bottlenecks


def _gap(file: str, name: str, priority: float = 0.5, line_start: int = 0) -> dict[str, Any]:
    return {"file": file, "name": name, "priority_score": priority, "line_start": line_start}


def _edge(
    caller_file: str, caller: str,
    callee_file: str, callee: str,
) -> dict[str, Any]:
    return {
        "caller_file": caller_file, "caller": caller,
        "callee_file": callee_file, "callee": callee,
    }


class TestFromWorkqueue:
    def test_empty(self) -> None:
        g = TaskGraph.from_workqueue([], [])
        assert len(g) == 0
        assert g.pending == 0

    def test_no_edges_all_ready(self) -> None:
        wq = [_gap("a.py", "f1"), _gap("a.py", "f2")]
        g = TaskGraph.from_workqueue(wq, [])
        ready = g.pop_ready(10)
        assert len(ready) == 2

    def test_edge_creates_dependency(self) -> None:
        wq = [_gap("a.py", "caller", 0.9), _gap("a.py", "callee", 0.5)]
        edges = [_edge("a.py", "caller", "a.py", "callee")]
        g = TaskGraph.from_workqueue(wq, edges)

        ready = g.pop_ready(10)
        assert len(ready) == 1
        assert ready[0].key == "a.py:callee:0"

    def test_self_edge_ignored(self) -> None:
        wq = [_gap("a.py", "recurse")]
        edges = [_edge("a.py", "recurse", "a.py", "recurse")]
        g = TaskGraph.from_workqueue(wq, edges)
        ready = g.pop_ready(1)
        assert len(ready) == 1

    def test_edge_to_non_workqueue_ignored(self) -> None:
        wq = [_gap("a.py", "caller")]
        edges = [_edge("a.py", "caller", "b.py", "external")]
        g = TaskGraph.from_workqueue(wq, edges)
        ready = g.pop_ready(1)
        assert len(ready) == 1


class TestMarkComplete:
    def test_unlocks_dependent(self) -> None:
        wq = [_gap("a.py", "caller"), _gap("a.py", "callee")]
        edges = [_edge("a.py", "caller", "a.py", "callee")]
        g = TaskGraph.from_workqueue(wq, edges)

        ready = g.pop_ready(1)
        assert ready[0].key == "a.py:callee:0"

        newly_ready = g.mark_complete("a.py:callee:0")
        assert "a.py:caller:0" in newly_ready

        ready2 = g.pop_ready(1)
        assert ready2[0].key == "a.py:caller:0"

    def test_multiple_deps_both_needed(self) -> None:
        wq = [
            _gap("a.py", "caller"),
            _gap("a.py", "dep1"),
            _gap("a.py", "dep2"),
        ]
        edges = [
            _edge("a.py", "caller", "a.py", "dep1"),
            _edge("a.py", "caller", "a.py", "dep2"),
        ]
        g = TaskGraph.from_workqueue(wq, edges)

        g.mark_complete("a.py:dep1:0")
        ready = g.pop_ready(10)
        keys = {t.key for t in ready}
        assert "a.py:caller:0" not in keys

        g.mark_complete("a.py:dep2:0")
        ready = g.pop_ready(10)
        keys = {t.key for t in ready}
        assert "a.py:caller:0" in keys

    def test_pending_decrements(self) -> None:
        wq = [_gap("a.py", "f1"), _gap("a.py", "f2")]
        g = TaskGraph.from_workqueue(wq, [])
        assert g.pending == 2
        g.pop_ready(1)
        g.mark_complete("a.py:f1:0")
        assert g.pending == 1


class TestPopReady:
    def test_priority_ordering(self) -> None:
        wq = [
            _gap("a.py", "low", 0.1),
            _gap("a.py", "high", 0.9),
            _gap("a.py", "mid", 0.5),
        ]
        g = TaskGraph.from_workqueue(wq, [])
        ready = g.pop_ready(3)
        keys = [t.key for t in ready]
        assert keys[0] == "a.py:high:0"
        assert keys[-1] == "a.py:low:0"

    def test_pop_respects_n(self) -> None:
        wq = [_gap("a.py", f"f{i}") for i in range(5)]
        g = TaskGraph.from_workqueue(wq, [])
        ready = g.pop_ready(2)
        assert len(ready) == 2


class TestSerialOrder:
    def test_matches_topo_order(self) -> None:
        wq = [
            _gap("a.py", "root", 0.9),
            _gap("a.py", "mid", 0.5),
            _gap("a.py", "leaf", 0.1),
        ]
        edges = [
            _edge("a.py", "root", "a.py", "mid"),
            _edge("a.py", "mid", "a.py", "leaf"),
        ]
        g = TaskGraph.from_workqueue(wq, edges)
        order = g.serial_order()
        keys = [t.key for t in order]
        assert keys == ["a.py:leaf:0", "a.py:mid:0", "a.py:root:0"]

    def test_independent_tasks_by_priority(self) -> None:
        wq = [
            _gap("a.py", "low", 0.1),
            _gap("a.py", "high", 0.9),
        ]
        g = TaskGraph.from_workqueue(wq, [])
        order = g.serial_order()
        keys = [t.key for t in order]
        assert keys[0] == "a.py:high:0"

    def test_diamond_dependency(self) -> None:
        wq = [
            _gap("a.py", "top", 0.9),
            _gap("a.py", "left", 0.6),
            _gap("a.py", "right", 0.4),
            _gap("a.py", "bottom", 0.1),
        ]
        edges = [
            _edge("a.py", "top", "a.py", "left"),
            _edge("a.py", "top", "a.py", "right"),
            _edge("a.py", "left", "a.py", "bottom"),
            _edge("a.py", "right", "a.py", "bottom"),
        ]
        g = TaskGraph.from_workqueue(wq, edges)
        order = g.serial_order()
        keys = [t.key for t in order]
        assert keys[0] == "a.py:bottom:0"
        assert keys[-1] == "a.py:top:0"
        assert keys.index("a.py:left:0") < keys.index("a.py:top:0")
        assert keys.index("a.py:right:0") < keys.index("a.py:top:0")


class TestCycleBreaking:
    def test_simple_cycle_all_complete(self) -> None:
        """A→B→A cycle: both functions must eventually complete."""
        wq = [_gap("a.py", "A", 0.9), _gap("a.py", "B", 0.5)]
        edges = [
            _edge("a.py", "A", "a.py", "B"),
            _edge("a.py", "B", "a.py", "A"),
        ]
        g = TaskGraph.from_workqueue(wq, edges)
        order = g.serial_order()
        assert len(order) == 2

    def test_three_member_cycle_all_complete(self) -> None:
        """A→B→C→A cycle: all three must complete."""
        wq = [
            _gap("a.py", "A", 0.9),
            _gap("a.py", "B", 0.5),
            _gap("a.py", "C", 0.1),
        ]
        edges = [
            _edge("a.py", "A", "a.py", "B"),
            _edge("a.py", "B", "a.py", "C"),
            _edge("a.py", "C", "a.py", "A"),
        ]
        g = TaskGraph.from_workqueue(wq, edges)
        order = g.serial_order()
        assert len(order) == 3

    def test_cycle_root_is_lowest_priority(self) -> None:
        """The spanning tree root should be the lowest-priority member."""
        adj = {
            "a.py:high": {"a.py:low"},
            "a.py:low": {"a.py:high"},
        }
        scores = {"a.py:high": 0.9, "a.py:low": 0.1}
        dropped = _break_cycles(adj, scores)
        assert len(dropped) == 1
        _caller, callee = next(iter(dropped))
        assert callee == "a.py:low"

    def test_cycle_preserves_tree_edges(self) -> None:
        """In A→B→C→A, only 1 back-edge is dropped, 2 tree edges kept."""
        adj = {
            "a.py:A": {"a.py:B"},
            "a.py:B": {"a.py:C"},
            "a.py:C": {"a.py:A"},
        }
        scores = {"a.py:A": 0.9, "a.py:B": 0.5, "a.py:C": 0.1}
        dropped = _break_cycles(adj, scores)
        assert len(dropped) == 1

    def test_transitive_dependents_unblocked(self) -> None:
        """Functions depending on cycle members must also complete."""
        wq = [
            _gap("a.py", "top", 0.9),
            _gap("a.py", "A", 0.5),
            _gap("a.py", "B", 0.3),
        ]
        edges = [
            _edge("a.py", "top", "a.py", "A"),
            _edge("a.py", "A", "a.py", "B"),
            _edge("a.py", "B", "a.py", "A"),
        ]
        g = TaskGraph.from_workqueue(wq, edges)
        order = g.serial_order()
        assert len(order) == 3
        keys = [t.key for t in order]
        assert keys.index("a.py:A:0") < keys.index("a.py:top:0")

    def test_no_cycle_no_edges_dropped(self) -> None:
        """DAG with no cycles drops nothing."""
        adj = {
            "a.py:caller": {"a.py:callee"},
        }
        dropped = _break_cycles(adj, {})
        assert len(dropped) == 0

    def test_pop_ready_drains_cycle(self) -> None:
        """Cycle members can be fully drained via pop_ready + mark_complete."""
        wq = [
            _gap("a.py", "A", 0.9),
            _gap("a.py", "B", 0.5),
            _gap("a.py", "C", 0.1),
        ]
        edges = [
            _edge("a.py", "A", "a.py", "B"),
            _edge("a.py", "B", "a.py", "C"),
            _edge("a.py", "C", "a.py", "A"),
        ]
        g = TaskGraph.from_workqueue(wq, edges)

        completed = []
        while g.pending > 0:
            ready = g.pop_ready(10)
            if not ready:
                break
            for task in ready:
                g.mark_complete(task.key)
                completed.append(task.key)

        assert g.pending == 0
        assert len(completed) == 3


class TestRepass:
    def test_cycle_repass_returns_affected_callers(self) -> None:
        wq = [
            _gap("a.py", "A", 0.9),
            _gap("a.py", "B", 0.5),
            _gap("a.py", "C", 0.1),
        ]
        edges = [
            _edge("a.py", "A", "a.py", "B"),
            _edge("a.py", "B", "a.py", "C"),
            _edge("a.py", "C", "a.py", "A"),
        ]
        g = TaskGraph.from_workqueue(wq, edges)
        repass = g.repass_tasks()
        assert len(repass) >= 1
        keys = {t.key for t in repass}
        assert keys <= {"a.py:A:0", "a.py:B:0", "a.py:C:0"}

    def test_repass_empty_for_dag(self) -> None:
        wq = [_gap("a.py", "caller"), _gap("a.py", "callee")]
        edges = [_edge("a.py", "caller", "a.py", "callee")]
        g = TaskGraph.from_workqueue(wq, edges)
        assert g.repass_tasks() == []

    def test_repass_sorted_by_priority(self) -> None:
        wq = [
            _gap("a.py", "high", 0.9),
            _gap("a.py", "low", 0.1),
        ]
        edges = [
            _edge("a.py", "high", "a.py", "low"),
            _edge("a.py", "low", "a.py", "high"),
        ]
        g = TaskGraph.from_workqueue(wq, edges)
        repass = g.repass_tasks()
        if len(repass) > 1:
            assert repass[0].priority >= repass[1].priority


class TestBottleneckRelaxation:
    def _non_leaf_bottleneck(self, n_callers, n_workers=2):
        """Build graph where bottleneck is NOT a leaf (has its own dep)."""
        wq = [_gap("a.py", f"c{i}", 0.5) for i in range(n_callers)]
        wq.append(_gap("a.py", "bottleneck", 0.5))
        wq.append(_gap("a.py", "deep_dep", 0.5))
        edges = [_edge("a.py", f"c{i}", "a.py", "bottleneck") for i in range(n_callers)]
        edges.append(_edge("a.py", "bottleneck", "a.py", "deep_dep"))
        return wq, edges

    def test_no_relaxation_serial(self) -> None:
        """max_workers=1 skips bottleneck relaxation."""
        wq, edges = self._non_leaf_bottleneck(10)
        g = TaskGraph.from_workqueue(wq, edges, max_workers=1)
        ready = g.pop_ready(100)
        assert len(ready) == 1
        assert ready[0].key == "a.py:deep_dep:0"

    def test_relaxation_widens_wavefront(self) -> None:
        """With max_workers=2, callers beyond 2 proceed immediately."""
        wq, edges = self._non_leaf_bottleneck(6, n_workers=2)
        g = TaskGraph.from_workqueue(wq, edges, max_workers=2)
        ready = g.pop_ready(100)
        # deep_dep + relaxed callers should be ready
        assert len(ready) > 1

    def test_relaxed_callers_in_repass(self) -> None:
        """Relaxed callers appear in repass_tasks()."""
        wq, edges = self._non_leaf_bottleneck(6, n_workers=2)
        g = TaskGraph.from_workqueue(wq, edges, max_workers=2)
        repass = g.repass_tasks()
        # 6-2=4 relaxable, but repass_cap=max(8//20, 2)=2 limits it
        assert len(repass) == 2

    def test_relax_bottlenecks_direct(self) -> None:
        """_relax_bottlenecks drops edges from non-leaf excess callers."""
        adj = {f"c{i}": {"mid"} for i in range(5)}
        adj["mid"] = {"leaf"}
        scores = {f"c{i}": float(i) / 10 for i in range(5)}
        dropped = _relax_bottlenecks(adj, scores, max_workers=2, max_repass=10)
        assert len(dropped) == 3
        dropped_callers = {c for c, _ in dropped}
        assert "c0" in dropped_callers
        assert "c1" in dropped_callers
        assert "c2" in dropped_callers

    def test_leaf_bottleneck_skipped(self) -> None:
        """Leaf nodes (no callees) are not treated as bottlenecks."""
        adj = {f"c{i}": {"leaf"} for i in range(5)}
        scores = {}
        dropped = _relax_bottlenecks(adj, scores, max_workers=2, max_repass=10)
        assert len(dropped) == 0

    def test_repass_cap_limits_edges(self) -> None:
        """max_repass caps the total number of relaxed edges."""
        adj = {f"c{i}": {"mid"} for i in range(20)}
        adj["mid"] = {"leaf"}
        scores = {f"c{i}": float(i) / 100 for i in range(20)}
        dropped = _relax_bottlenecks(adj, scores, max_workers=2, max_repass=5)
        assert len(dropped) == 5

    def test_all_drain_with_relaxation(self) -> None:
        """All tasks complete even with bottleneck relaxation."""
        wq, edges = self._non_leaf_bottleneck(20, n_workers=4)
        g = TaskGraph.from_workqueue(wq, edges, max_workers=4)
        completed = 0
        while g.pending > 0:
            ready = g.pop_ready(100)
            if not ready:
                break
            for t in ready:
                g.mark_complete(t.key)
                completed += 1
        assert g.pending == 0
        assert completed == 22  # 20 callers + bottleneck + deep_dep


class TestUnblockingPriority:
    def test_high_dependent_count_promoted(self) -> None:
        """A callee with many dependents is scheduled before one with fewer."""
        wq = [
            _gap("a.py", "popular", 0.5),
            _gap("a.py", "lonely", 0.5),
        ]
        # popular is called by 5 callers (not in workqueue, but edges create dependents)
        for i in range(5):
            wq.append(_gap("a.py", f"caller{i}", 0.5))
        edges = [_edge("a.py", f"caller{i}", "a.py", "popular") for i in range(5)]
        # lonely has just 1 dependent
        wq.append(_gap("a.py", "solo_caller", 0.5))
        edges.append(_edge("a.py", "solo_caller", "a.py", "lonely"))

        g = TaskGraph.from_workqueue(wq, edges)
        ready = g.pop_ready(2)
        # popular should come first (higher effective priority due to dependents)
        keys = [t.key for t in ready]
        assert keys[0] == "a.py:popular:0"

    def test_security_priority_still_wins(self) -> None:
        """A high-security-priority task beats a high-dependent one."""
        wq = [
            _gap("a.py", "secure", 0.9),
            _gap("a.py", "popular", 0.1),
        ]
        for i in range(10):
            wq.append(_gap("a.py", f"dep{i}", 0.5))
        edges = [_edge("a.py", f"dep{i}", "a.py", "popular") for i in range(10)]

        g = TaskGraph.from_workqueue(wq, edges)
        ready = g.pop_ready(2)
        keys = [t.key for t in ready]
        assert keys[0] == "a.py:secure:0"


class TestGraphStats:
    def test_stats_empty_graph(self) -> None:
        g = TaskGraph.from_workqueue([], [])
        assert g.stats.total_tasks == 0
        assert g.stats.total_edges == 0

    def test_stats_dag(self) -> None:
        wq = [_gap("a.py", "caller"), _gap("a.py", "callee")]
        edges = [_edge("a.py", "caller", "a.py", "callee")]
        g = TaskGraph.from_workqueue(wq, edges)
        assert g.stats.total_tasks == 2
        assert g.stats.total_edges == 1
        assert g.stats.cycle_back_edges_dropped == 0
        assert g.stats.initial_ready == 1
        assert g.stats.max_fan_out == 1

    def test_stats_cycle(self) -> None:
        wq = [_gap("a.py", "A", 0.3), _gap("a.py", "B", 0.5)]
        edges = [
            _edge("a.py", "A", "a.py", "B"),
            _edge("a.py", "B", "a.py", "A"),
        ]
        g = TaskGraph.from_workqueue(wq, edges)
        assert g.stats.cycle_back_edges_dropped >= 1
        assert g.stats.repass_tasks >= 1

    def test_stats_bottleneck(self) -> None:
        wq = [_gap("a.py", f"c{i}") for i in range(10)]
        wq.append(_gap("a.py", "mid"))
        wq.append(_gap("a.py", "deep"))
        edges = [_edge("a.py", f"c{i}", "a.py", "mid") for i in range(10)]
        edges.append(_edge("a.py", "mid", "a.py", "deep"))
        g = TaskGraph.from_workqueue(wq, edges, max_workers=4)
        assert g.stats.bottleneck_edges_dropped > 0
        assert g.stats.repass_tasks > 0

    def test_stats_to_dict(self) -> None:
        g = TaskGraph.from_workqueue([_gap("a.py", "f")], [])
        d = g.stats.to_dict()
        assert isinstance(d, dict)
        assert d["total_tasks"] == 1
        assert "cycle_back_edges_dropped" in d
        assert "initial_ready" in d


class TestInjectTask:
    def test_inject_new_task(self) -> None:
        """inject_task adds a brand-new task to the ready heap."""
        g = TaskGraph.from_workqueue([_gap("a.py", "f1")], [])
        assert len(g) == 1
        added = g.inject_task(
            "b.py:f2:0", _gap("b.py", "f2", 0.9), 0.9,
        )
        assert added is True
        assert len(g) == 2
        assert g.pending == 2

    def test_inject_completed_returns_false(self) -> None:
        """Injecting a completed task returns False and doesn't re-add."""
        wq = [_gap("a.py", "f1")]
        g = TaskGraph.from_workqueue(wq, [])
        g.pop_ready(1)
        g.mark_complete("a.py:f1:0")
        result = g.inject_task("a.py:f1:0", _gap("a.py", "f1"), 1.0)
        assert result is False
        assert g.pending == 0

    def test_inject_reprioritises_existing(self) -> None:
        """Injecting an existing task at higher priority reprioritises it."""
        wq = [
            _gap("a.py", "low", 0.1),
            _gap("a.py", "high", 0.9),
        ]
        g = TaskGraph.from_workqueue(wq, [])
        g.inject_task("a.py:low:0", _gap("a.py", "low"), 2.0)
        ready = g.pop_ready(2)
        assert ready[0].key == "a.py:low:0"

    def test_inject_lower_priority_no_change(self) -> None:
        """Injecting at lower priority than existing doesn't demote."""
        wq = [_gap("a.py", "high", 0.9)]
        g = TaskGraph.from_workqueue(wq, [])
        g.inject_task("a.py:high:0", _gap("a.py", "high"), 0.1)
        ready = g.pop_ready(1)
        assert ready[0].key == "a.py:high:0"

    def test_injected_count(self) -> None:
        """injected_count tracks tasks added after construction."""
        g = TaskGraph.from_workqueue([_gap("a.py", "f1")], [])
        assert g.injected_count == 0
        g.inject_task("b.py:f2:0", _gap("b.py", "f2"), 0.5)
        assert g.injected_count == 1
        g.inject_task("c.py:f3:0", _gap("c.py", "f3"), 0.5)
        assert g.injected_count == 2

    def test_inject_interleaves_with_pop(self) -> None:
        """Injected tasks appear in pop_ready based on priority."""
        wq = [_gap("a.py", "first", 0.5)]
        g = TaskGraph.from_workqueue(wq, [])
        g.pop_ready(1)
        g.inject_task("a.py:urgent:0", _gap("a.py", "urgent", 2.0), 2.0)
        ready = g.pop_ready(1)
        assert ready[0].key == "a.py:urgent:0"

    def test_drain_with_injected_tasks(self) -> None:
        """All tasks (original + injected) drain correctly."""
        g = TaskGraph.from_workqueue([_gap("a.py", "f1")], [])
        g.inject_task("b.py:f2:0", _gap("b.py", "f2"), 0.5)
        completed = []
        while g.pending > 0:
            ready = g.pop_ready(10)
            if not ready:
                break
            for t in ready:
                g.mark_complete(t.key)
                completed.append(t.key)
        assert g.pending == 0
        assert len(completed) == 2

    def test_requeue_completed_task(self) -> None:
        """requeue=True moves a completed task back to the ready queue."""
        g = TaskGraph.from_workqueue([_gap("a.py", "f1")], [])
        g.pop_ready(1)
        g.mark_complete("a.py:f1:0")
        assert g.pending == 0
        result = g.inject_task(
            "a.py:f1:0", _gap("a.py", "f1"), 5.0, requeue=True,
        )
        assert result is True
        assert g.pending == 1
        ready = g.pop_ready(1)
        assert ready[0].key == "a.py:f1:0"

    def test_requeue_only_once(self) -> None:
        """A task can only be requeued once to prevent infinite loops."""
        g = TaskGraph.from_workqueue([_gap("a.py", "f1")], [])
        g.pop_ready(1)
        g.mark_complete("a.py:f1:0")
        g.inject_task("a.py:f1:0", _gap("a.py", "f1"), 5.0, requeue=True)
        g.pop_ready(1)
        g.mark_complete("a.py:f1:0")
        result = g.inject_task(
            "a.py:f1:0", _gap("a.py", "f1"), 5.0, requeue=True,
        )
        assert result is False
        assert g.pending == 0

    def test_requeue_false_default(self) -> None:
        """Without requeue=True, completed tasks are not re-added."""
        g = TaskGraph.from_workqueue([_gap("a.py", "f1")], [])
        g.pop_ready(1)
        g.mark_complete("a.py:f1:0")
        result = g.inject_task("a.py:f1:0", _gap("a.py", "f1"), 5.0)
        assert result is False

    def test_requeue_updates_gap(self) -> None:
        """Requeued task picks up the new gap dict."""
        g = TaskGraph.from_workqueue([_gap("a.py", "f1")], [])
        g.pop_ready(1)
        g.mark_complete("a.py:f1:0")
        new_gap = _gap("a.py", "f1")
        new_gap["force_review"] = True
        g.inject_task("a.py:f1:0", new_gap, 5.0, requeue=True)
        ready = g.pop_ready(1)
        assert ready[0].gap.get("force_review") is True

    def test_reprioritise_merges_force_review(self) -> None:
        """Reprioritising a pending task merges force_review into its gap."""
        wq = [_gap("a.py", "f1", 0.1)]
        g = TaskGraph.from_workqueue(wq, [])
        new_gap = _gap("a.py", "f1")
        new_gap["force_review"] = True
        g.inject_task("a.py:f1:0", new_gap, 5.0)
        ready = g.pop_ready(1)
        assert ready[0].gap.get("force_review") is True


class TestSameBareCrossEdge:
    def test_same_bare_key_edge_skipped(self) -> None:
        """Edge where caller and callee have the same bare key (e.g. Go
        receiver methods Rows.Scan and NullString.Scan) must not create
        false cross-dependencies between line-disambiguated variants."""
        wq = [
            _gap("sql.go", "Scan", 0.5, line_start=3232),
            _gap("sql.go", "Scan", 0.5, line_start=4500),
            _gap("sql.go", "helper", 0.5, line_start=100),
        ]
        edges = [_edge("sql.go", "Scan", "sql.go", "Scan")]
        g = TaskGraph.from_workqueue(wq, edges)
        ready = g.pop_ready(10)
        assert len(ready) == 3

    def test_same_bare_different_callee_still_creates_dep(self) -> None:
        """Same-named functions calling a different function should
        still create dependency edges for both variants."""
        wq = [
            _gap("sql.go", "Scan", 0.5, line_start=3232),
            _gap("sql.go", "Scan", 0.5, line_start=4500),
            _gap("sql.go", "helper", 0.5, line_start=100),
        ]
        edges = [_edge("sql.go", "Scan", "sql.go", "helper")]
        g = TaskGraph.from_workqueue(wq, edges)
        ready = g.pop_ready(10)
        assert len(ready) == 1
        assert ready[0].key == "sql.go:helper:100"


class TestCostSchedule:
    """LPT ordering: with schedule="cost", the ready set pops the
    longest-predicted review first; priority breaks duration ties;
    priority mode (the default) is untouched."""

    @staticmethod
    def _hints(**by_name):
        return {f"a.py:{n}:0": v for n, v in by_name.items()}

    def test_longest_first_within_ready_set(self) -> None:
        wq = [
            _gap("a.py", "small", priority=0.9),
            _gap("a.py", "big", priority=0.1),
            _gap("a.py", "medium", priority=0.5),
        ]
        g = TaskGraph.from_workqueue(
            wq, [],
            duration_hints=self._hints(small=100, big=50000, medium=6000),
            schedule="cost",
        )
        order = [t.gap["name"] for t in g.pop_ready(3)]
        assert order == ["big", "medium", "small"]

    def test_priority_breaks_duration_ties(self) -> None:
        wq = [
            _gap("a.py", "low", priority=0.1),
            _gap("a.py", "high", priority=0.9),
        ]
        g = TaskGraph.from_workqueue(
            wq, [],
            duration_hints=self._hints(low=6000, high=6000),
            schedule="cost",
        )
        order = [t.gap["name"] for t in g.pop_ready(2)]
        assert order == ["high", "low"]

    def test_missing_hint_sorts_last(self) -> None:
        wq = [_gap("a.py", "hinted"), _gap("a.py", "unhinted")]
        g = TaskGraph.from_workqueue(
            wq, [],
            duration_hints=self._hints(hinted=500),
            schedule="cost",
        )
        order = [t.gap["name"] for t in g.pop_ready(2)]
        assert order == ["hinted", "unhinted"]

    def test_default_schedule_is_priority(self) -> None:
        wq = [
            _gap("a.py", "small", priority=0.9),
            _gap("a.py", "big", priority=0.1),
        ]
        g = TaskGraph.from_workqueue(
            wq, [],
            duration_hints=self._hints(small=100, big=50000),
        )
        order = [t.gap["name"] for t in g.pop_ready(2)]
        assert order == ["small", "big"], (
            "without schedule='cost', duration hints must not reorder"
        )

    def test_unknown_schedule_falls_back_to_priority(self) -> None:
        wq = [
            _gap("a.py", "small", priority=0.9),
            _gap("a.py", "big", priority=0.1),
        ]
        g = TaskGraph.from_workqueue(
            wq, [],
            duration_hints=self._hints(small=100, big=50000),
            schedule="bogus",
        )
        order = [t.gap["name"] for t in g.pop_ready(2)]
        assert order == ["small", "big"]

    def test_newly_ready_respects_cost_order(self) -> None:
        # caller_big and caller_small unlock together when leaf
        # completes — big must pop first under cost scheduling.
        wq = [
            _gap("a.py", "leaf"),
            _gap("a.py", "caller_small", priority=0.9),
            _gap("a.py", "caller_big", priority=0.1),
        ]
        edges = [
            _edge("a.py", "caller_small", "a.py", "leaf"),
            _edge("a.py", "caller_big", "a.py", "leaf"),
        ]
        g = TaskGraph.from_workqueue(
            wq, edges,
            duration_hints=self._hints(
                leaf=100, caller_small=500, caller_big=50000,
            ),
            schedule="cost",
        )
        first = g.pop_ready(1)[0]
        assert first.gap["name"] == "leaf"
        g.mark_complete(first.key)
        order = [t.gap["name"] for t in g.pop_ready(2)]
        assert order == ["caller_big", "caller_small"]

    def test_injected_task_jumps_cost_queue(self) -> None:
        wq = [_gap("a.py", "big"), _gap("a.py", "medium")]
        g = TaskGraph.from_workqueue(
            wq, [],
            duration_hints=self._hints(big=50000, medium=6000),
            schedule="cost",
        )
        g.inject_task("a.py:chain:0", _gap("a.py", "chain"), 5.0)
        order = [t.gap["name"] for t in g.pop_ready(3)]
        assert order[0] == "chain", (
            "chain-followed tasks stay urgent under cost scheduling"
        )


class TestDurationHints:
    def test_orchestrator_hint_derivation(self) -> None:
        from core.audit.orchestrator import _review_duration_hints

        class _TR:
            def __init__(self, budget):
                self.token_budget = budget

        wq = [
            {"file": "a.py", "name": "deep", "line_start": 1,
             "line_end": 200, "sloc": 200},
            {"file": "a.py", "name": "glance", "line_start": 300,
             "line_end": 305, "sloc": 6},
            {"file": "a.py", "name": "untriaged", "line_start": 400,
             "line_end": 449},
        ]
        triage = {
            "a.py:deep:1": _TR(50000),
            "a.py:glance:300": _TR(500),
        }
        hints = _review_duration_hints(wq, triage)
        assert hints["a.py:deep:1"] == 50200.0
        assert hints["a.py:glance:300"] == 506.0
        # no triage entry: SLOC derived from the span
        assert hints["a.py:untriaged:400"] == 50.0
        assert hints["a.py:deep:1"] > hints["a.py:glance:300"]

    def test_bare_key_fallback(self) -> None:
        from core.audit.orchestrator import _review_duration_hints

        class _TR:
            token_budget = 6000

        wq = [{"file": "a.py", "name": "f", "line_start": 1, "sloc": 10}]
        hints = _review_duration_hints(wq, {"a.py:f": _TR()})
        assert hints["a.py:f:1"] == 6010.0
