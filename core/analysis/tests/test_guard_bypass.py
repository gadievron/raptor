"""Tests for core.analysis.guard_bypass — the guard-bypass query (PR3)."""

from __future__ import annotations

from core.analysis.guard_bypass import (
    Guard,
    GuardBypassResult,
    check_guard_coverage,
    query,
)
from core.analysis.cfg_conditions import ControlCondition


class _FakeNode:
    def __init__(self, lineno, label):
        self.lineno = lineno
        self.label = label


class _FakeCFG:
    def __init__(self, nodes, adjacency):
        self._nodes = nodes
        self._adjacency = adjacency
        self.entry = nodes[0] if nodes else None

    def nodes(self):
        return self._nodes

    def successors(self, node):
        return self._adjacency.get(id(node), [])


class TestQueryNoGuards:
    """Source -> sink with no constraining guards on the variable."""

    def test_all_paths_bypassable(self):
        # entry -> source(2) -> sink(4)
        n_entry = _FakeNode(1, "entry")
        n_src = _FakeNode(2, "x = input()")
        n_sink = _FakeNode(4, "eval(x)")
        cfg = _FakeCFG(
            [n_entry, n_src, n_sink],
            {id(n_entry): [n_src], id(n_src): [n_sink]},
        )
        result = query(cfg, "x", 2, 4)
        assert result.is_bypassed()
        assert len(result.constraining_guards) == 0
        assert len(result.must_visit_guards) == 0
        assert result.confidence == "structural"


class TestQueryWithGuardNoBypass:
    """Source -> guard -> sink, no bypass path."""

    def test_no_bypass(self):
        # entry -> source(2) -> If(x > 0) -> sink(5) / exit(6)
        n_entry = _FakeNode(1, "entry")
        n_src = _FakeNode(2, "x = input()")
        n_guard = _FakeNode(3, "If (x > 0)")
        n_sink = _FakeNode(5, "eval(x)")
        n_exit = _FakeNode(6, "exit")
        cfg = _FakeCFG(
            [n_entry, n_src, n_guard, n_sink, n_exit],
            {
                id(n_entry): [n_src],
                id(n_src): [n_guard],
                id(n_guard): [n_sink, n_exit],
            },
        )
        result = query(cfg, "x", 2, 5)
        assert not result.is_bypassed()
        assert len(result.constraining_guards) == 1
        assert result.constraining_guards[0].condition.text == "x > 0"
        assert len(result.must_visit_guards) == 1

    def test_guard_on_different_var_not_constraining(self):
        n_entry = _FakeNode(1, "entry")
        n_src = _FakeNode(2, "x = input()")
        n_guard = _FakeNode(3, "If (y > 0)")
        n_sink = _FakeNode(5, "eval(x)")
        n_exit = _FakeNode(6, "exit")
        cfg = _FakeCFG(
            [n_entry, n_src, n_guard, n_sink, n_exit],
            {
                id(n_entry): [n_src],
                id(n_src): [n_guard],
                id(n_guard): [n_sink, n_exit],
            },
        )
        result = query(cfg, "x", 2, 5)
        assert result.is_bypassed()
        assert len(result.constraining_guards) == 0


class TestQueryWithBypass:
    """Source -> (guard | bypass) -> sink."""

    def test_bypass_path_found(self):
        #         source(2)
        #        /        \
        #  If(x>0)(3)   bypass(4)
        #     |             |
        #   sink(5)    sink(5)
        n_entry = _FakeNode(1, "entry")
        n_src = _FakeNode(2, "x = input()")
        n_guard = _FakeNode(3, "If (x > 0)")
        n_bypass = _FakeNode(4, "log(x)")
        n_sink = _FakeNode(5, "eval(x)")
        n_exit = _FakeNode(6, "exit")
        cfg = _FakeCFG(
            [n_entry, n_src, n_guard, n_bypass, n_sink, n_exit],
            {
                id(n_entry): [n_src],
                id(n_src): [n_guard, n_bypass],
                id(n_guard): [n_sink, n_exit],
                id(n_bypass): [n_sink],
            },
        )
        result = query(cfg, "x", 2, 5)
        assert result.is_bypassed()
        assert len(result.bypassable_paths) >= 1
        assert len(result.constraining_guards) == 1
        assert len(result.must_visit_guards) == 0


class TestQueryMustVisit:
    """Guard present on ALL paths to sink."""

    def test_must_visit_when_guard_dominates(self):
        # entry -> source(2) -> If(x>0)(3) -> then(4) -> sink(6)
        #                                   -> else(5) -> sink(6)
        n_entry = _FakeNode(1, "entry")
        n_src = _FakeNode(2, "x = input()")
        n_guard = _FakeNode(3, "If (x > 0)")
        n_then = _FakeNode(4, "y = x + 1")
        n_else = _FakeNode(5, "y = x - 1")
        n_sink = _FakeNode(6, "eval(y)")
        cfg = _FakeCFG(
            [n_entry, n_src, n_guard, n_then, n_else, n_sink],
            {
                id(n_entry): [n_src],
                id(n_src): [n_guard],
                id(n_guard): [n_then, n_else],
                id(n_then): [n_sink],
                id(n_else): [n_sink],
            },
        )
        result = query(cfg, "x", 2, 6)
        assert not result.is_bypassed()
        assert len(result.must_visit_guards) == 1
        assert result.must_visit_guards[0].node_line == 3


class TestQueryCustomClassifier:
    """Custom guard_classifier predicate."""

    def test_custom_classifier(self):
        n_entry = _FakeNode(1, "entry")
        n_src = _FakeNode(2, "x = input()")
        n_guard = _FakeNode(3, "If (is_safe(x))")
        n_sink = _FakeNode(5, "eval(x)")
        n_exit = _FakeNode(6, "exit")
        cfg = _FakeCFG(
            [n_entry, n_src, n_guard, n_sink, n_exit],
            {
                id(n_entry): [n_src],
                id(n_src): [n_guard],
                id(n_guard): [n_sink, n_exit],
            },
        )

        def safe_classifier(cond, var):
            return "is_safe" in cond.text and var in cond.text

        result = query(cfg, "x", 2, 5, guard_classifier=safe_classifier)
        assert not result.is_bypassed()
        assert len(result.constraining_guards) == 1


class TestQueryIncomplete:
    """Confidence degrades when no CFG nodes exist."""

    def test_empty_cfg(self):
        cfg = _FakeCFG([], {})
        result = query(cfg, "x", 1, 5)
        assert result.confidence == "incomplete"

    def test_single_node_no_path(self):
        n = _FakeNode(10, "entry")
        cfg = _FakeCFG([n], {})
        result = query(cfg, "x", 10, 10)
        assert not result.is_bypassed() or result.confidence == "structural"


class TestCheckGuardCoverage:
    """Lifecycle-oriented simplified query."""

    def test_guard_on_all_paths(self):
        n_entry = _FakeNode(1, "entry")
        n_guard = _FakeNode(3, "If (task->mm != NULL)")
        n_body = _FakeNode(5, "dumpable = get_dumpable(task)")
        n_exit = _FakeNode(7, "exit")
        cfg = _FakeCFG(
            [n_entry, n_guard, n_body, n_exit],
            {
                id(n_entry): [n_guard],
                id(n_guard): [n_body, n_exit],
                id(n_body): [n_exit],
            },
        )
        assert check_guard_coverage(cfg, 5, "task->mm != NULL")

    def test_guard_missing_on_one_path(self):
        n_entry = _FakeNode(1, "entry")
        n_guard = _FakeNode(3, "If (task->mm != NULL)")
        n_guarded = _FakeNode(4, "guarded path")
        n_bypass = _FakeNode(5, "bypass path")
        n_read = _FakeNode(6, "dumpable = get_dumpable(task)")
        n_exit = _FakeNode(7, "exit")
        cfg = _FakeCFG(
            [n_entry, n_guard, n_guarded, n_bypass, n_read, n_exit],
            {
                id(n_entry): [n_guard, n_bypass],
                id(n_guard): [n_guarded, n_exit],
                id(n_guarded): [n_read],
                id(n_bypass): [n_read],
                id(n_read): [n_exit],
            },
        )
        assert not check_guard_coverage(cfg, 6, "task->mm != NULL")

    def test_guard_text_not_found(self):
        n_entry = _FakeNode(1, "entry")
        n_read = _FakeNode(2, "use")
        cfg = _FakeCFG(
            [n_entry, n_read],
            {id(n_entry): [n_read]},
        )
        assert not check_guard_coverage(cfg, 2, "nonexistent_guard")


class TestGuardBypassResult:
    def test_to_dict(self):
        cc = ControlCondition(text="x > 0", references=frozenset({"x"}))
        g = Guard(condition=cc, node_line=5)
        r = GuardBypassResult(
            bypassable_paths=[[1, 3, 5]],
            constraining_guards=[g],
            must_visit_guards=[g],
            confidence="structural",
        )
        d = r.to_dict()
        assert d["bypassable_paths"] == [[1, 3, 5]]
        assert len(d["constraining_guards"]) == 1
        assert d["confidence"] == "structural"

    def test_empty_result(self):
        r = GuardBypassResult()
        assert not r.is_bypassed()
        assert r.confidence == "structural"
