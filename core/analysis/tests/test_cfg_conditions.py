"""Tests for core.analysis.cfg_conditions — ControlCondition and edge extraction."""

from __future__ import annotations

from core.analysis.cfg_conditions import (
    ConditionEdge,
    ControlCondition,
    extract_conditions_from_cfg,
    extract_references,
)


class TestControlCondition:
    def test_round_trip(self):
        cc = ControlCondition(
            text="x > 0",
            references=frozenset({"x"}),
            smt_parseable=True,
            polarity=True,
        )
        d = cc.to_dict()
        assert d["text"] == "x > 0"
        assert d["references"] == ["x"]
        assert d["smt_parseable"] is True
        assert "polarity" not in d  # True is default, omitted

        restored = ControlCondition.from_dict(d)
        assert restored == cc

    def test_negated_preserves_text_flips_polarity(self):
        cc = ControlCondition(
            text="buf != NULL",
            references=frozenset({"buf"}),
            polarity=True,
        )
        neg = cc.negated()
        assert neg.text == "buf != NULL"
        assert neg.polarity is False
        assert neg.references == cc.references

    def test_false_polarity_serialized(self):
        cc = ControlCondition(
            text="x", references=frozenset({"x"}), polarity=False,
        )
        d = cc.to_dict()
        assert d["polarity"] is False
        assert ControlCondition.from_dict(d).polarity is False


class TestExtractReferences:
    def test_simple_comparison(self):
        refs = extract_references("x > 0")
        assert "x" in refs

    def test_field_access(self):
        refs = extract_references("task->mm != NULL")
        assert "task->mm" in refs

    def test_dot_access(self):
        refs = extract_references("self.is_admin == True")
        assert "self.is_admin" in refs

    def test_keywords_excluded(self):
        refs = extract_references("not x and y or None")
        assert "x" in refs
        assert "y" in refs
        assert "not" not in refs
        assert "and" not in refs
        assert "None" not in refs

    def test_multiple_refs(self):
        refs = extract_references("a > b + c")
        assert refs == frozenset({"a", "b", "c"})


class TestConditionEdge:
    def test_to_dict_no_condition(self):
        e = ConditionEdge(src_line=10, dst_line=20)
        d = e.to_dict()
        assert d == {"src_line": 10, "dst_line": 20}

    def test_to_dict_with_condition(self):
        cc = ControlCondition(
            text="x > 0", references=frozenset({"x"}),
        )
        e = ConditionEdge(src_line=10, dst_line=20, condition=cc)
        d = e.to_dict()
        assert "condition" in d
        assert d["condition"]["text"] == "x > 0"


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


class TestExtractConditions:
    def test_if_branch_produces_true_and_false_edges(self):
        n_if = _FakeNode(5, "If (x > 0)")
        n_true = _FakeNode(6, "y = x")
        n_false = _FakeNode(8, "y = -x")
        cfg = _FakeCFG(
            [n_if, n_true, n_false],
            {id(n_if): [n_true, n_false]},
        )
        edges = extract_conditions_from_cfg(cfg)
        cond_edges = [e for e in edges if e.condition is not None]
        assert len(cond_edges) == 2

        true_edge = next(e for e in cond_edges if e.condition.polarity is True)
        false_edge = next(e for e in cond_edges if e.condition.polarity is False)
        assert true_edge.condition.text == "x > 0"
        assert false_edge.condition.text == "x > 0"
        assert "x" in true_edge.condition.references

    def test_non_conditional_edge(self):
        n1 = _FakeNode(1, "a = 1")
        n2 = _FakeNode(2, "b = 2")
        cfg = _FakeCFG([n1, n2], {id(n1): [n2]})
        edges = extract_conditions_from_cfg(cfg)
        assert len(edges) == 1
        assert edges[0].condition is None

    def test_while_loop(self):
        n_while = _FakeNode(3, "While (i < n)")
        n_body = _FakeNode(4, "i += 1")
        n_after = _FakeNode(5, "return i")
        cfg = _FakeCFG(
            [n_while, n_body, n_after],
            {id(n_while): [n_body, n_after], id(n_body): [n_while]},
        )
        edges = extract_conditions_from_cfg(cfg)
        cond_edges = [e for e in edges if e.condition is not None]
        assert len(cond_edges) == 2
        assert cond_edges[0].condition.text == "i < n"

    def test_smt_parseable_flag(self):
        n_if = _FakeNode(1, "If (x > 0)")
        n_t = _FakeNode(2, "pass")
        n_f = _FakeNode(3, "pass")
        cfg = _FakeCFG([n_if, n_t, n_f], {id(n_if): [n_t, n_f]})
        edges = extract_conditions_from_cfg(cfg)
        cond_edges = [e for e in edges if e.condition is not None]
        assert all(e.condition.smt_parseable for e in cond_edges)

    def test_non_smt_parseable(self):
        n_if = _FakeNode(1, "If (buf)")
        n_t = _FakeNode(2, "use(buf)")
        n_f = _FakeNode(3, "return")
        cfg = _FakeCFG([n_if, n_t, n_f], {id(n_if): [n_t, n_f]})
        edges = extract_conditions_from_cfg(cfg)
        cond_edges = [e for e in edges if e.condition is not None]
        assert not any(e.condition.smt_parseable for e in cond_edges)
