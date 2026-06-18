"""Tests for ``core.inventory.sanitizer_cut`` — Phase 7.

Coverage:

* **Canonical sibling-branch case** — sanitizer in BOTH ``if`` and
  ``else`` branches. The existing lexical dominance check at
  ``core/dataflow/smt_barrier.py:1189`` (``line < sink_line``)
  cannot decide this correctly because neither sanitizer call
  lexically precedes the sink uniformly. The vertex-cut suppresses
  it. This is the motivating test for the whole project.
* Bypass case — sanitizer present on one branch only; the other
  branch bypasses. Must NOT suppress.
* Loop body sanitizer — must NOT suppress when the loop can exit
  without entering the body.
* Multi-source — vertex cut generalizes; suppress iff sink is
  unreachable from every source.
* Wrong CWE / wrong language — no candidate sanitizers, no
  suppression.
* No sanitizer calls in the graph — no suppression.
* JSONL integration — the suppression record lands in
  ``out_dir/suppressions.jsonl`` with the agreed schema.
"""
from __future__ import annotations

import json
from pathlib import Path


from core.inventory.cfg_builder import (
    PyCFGNode,
    build_python_cfg,
)
from core.inventory.dominators import AdjacencyGraph
from core.inventory.sanitizer_cut import (
    VERDICT_SANITIZER_DOMINATED,
    SanitizerCutResult,
    evaluate_finding,
    record_sanitizer_cut_suppression,
    sanitizer_cuts_source_to_sink,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _cfg(src, func="handle"):
    cfg = build_python_cfg(src, func)
    assert cfg is not None
    return cfg


def _node_with_call(cfg, call_name):
    return next(
        n for n in cfg.nodes()
        if isinstance(n, PyCFGNode) and call_name in n.calls
    )


# ---------------------------------------------------------------------------
# Pure vertex-cut algorithm
# ---------------------------------------------------------------------------


class TestPureVertexCut:
    def test_empty_cut_set_does_not_disconnect_reachable_sink(self):
        g = AdjacencyGraph(entry="A", adjacency={"A": ["B"], "B": ["C"]})
        assert not sanitizer_cuts_source_to_sink(g, ["A"], "C", set())

    def test_cut_set_disconnects_single_path(self):
        g = AdjacencyGraph(entry="A", adjacency={"A": ["B"], "B": ["C"]})
        assert sanitizer_cuts_source_to_sink(g, ["A"], "C", {"B"})

    def test_cut_set_of_one_does_not_cut_parallel_paths(self):
        """A → {B, X} → C. Cutting only {B} leaves the A→X→C path,
        sink still reachable."""
        g = AdjacencyGraph(entry="A", adjacency={
            "A": ["B", "X"], "B": ["C"], "X": ["C"],
        })
        assert not sanitizer_cuts_source_to_sink(g, ["A"], "C", {"B"})

    def test_cut_set_of_two_cuts_parallel_paths(self):
        """Same graph; cutting {B, X} kills both paths."""
        g = AdjacencyGraph(entry="A", adjacency={
            "A": ["B", "X"], "B": ["C"], "X": ["C"],
        })
        assert sanitizer_cuts_source_to_sink(g, ["A"], "C", {"B", "X"})

    def test_multi_source_requires_all_disconnected(self):
        """Sources {A, A2}; A→B→C, A2→C directly. Cutting {B} only
        kills A's path; A2→C still goes direct."""
        g = AdjacencyGraph(entry="A", adjacency={
            "A": ["B"], "B": ["C"], "A2": ["C"],
        })
        assert not sanitizer_cuts_source_to_sink(g, ["A", "A2"], "C", {"B"})

    def test_sink_in_cut_set_returns_true(self):
        """Defensive: if the sink itself is a sanitizer it trivially
        "cuts" — removing the sink disconnects it from itself."""
        g = AdjacencyGraph(entry="A", adjacency={"A": ["B"]})
        assert sanitizer_cuts_source_to_sink(g, ["A"], "B", {"B"})


# ---------------------------------------------------------------------------
# evaluate_finding — Python CFG canonical cases
# ---------------------------------------------------------------------------


class TestCanonicalSiblingBranch:
    """The motivating case the design doc highlighted."""

    def test_both_branches_sanitize_suppresses(self):
        src = (
            "def handle(user):\n"
            "    if user.is_admin:\n"
            "        x = html.escape(user.name)\n"
            "    else:\n"
            "        x = html.escape(user.name)\n"
            "    render(x)\n"
        )
        cfg = _cfg(src)
        sink = _node_with_call(cfg, "render")
        result = evaluate_finding(
            cfg, [cfg.entry_node], sink,
            cwe="CWE-79", language="python",
        )
        assert result.suppress is True
        assert "vertex-cut" in result.reason
        # The cut set contains BOTH sanitizer nodes (one per branch).
        assert len(result.cut_set) == 2

    def test_only_one_branch_sanitizes_does_not_suppress(self):
        src = (
            "def handle(user):\n"
            "    if user.is_admin:\n"
            "        x = html.escape(user.name)\n"
            "    else:\n"
            "        x = user.name\n"
            "    render(x)\n"
        )
        cfg = _cfg(src)
        sink = _node_with_call(cfg, "render")
        result = evaluate_finding(
            cfg, [cfg.entry_node], sink,
            cwe="CWE-79", language="python",
        )
        assert result.suppress is False
        # cut_set is empty because the cut FAILED — bypass exists
        assert result.cut_set == frozenset()
        # The candidate callables are still recorded for the audit
        assert "html.escape" in result.candidate_callables


class TestStraightLineSanitize:
    """A linear function with a single sanitizer call should
    suppress — every path crosses it."""

    def test_linear_sanitize_then_sink_suppresses(self):
        src = (
            "def handle(x):\n"
            "    y = html.escape(x)\n"
            "    render(y)\n"
        )
        cfg = _cfg(src)
        sink = _node_with_call(cfg, "render")
        result = evaluate_finding(
            cfg, [cfg.entry_node], sink,
            cwe="CWE-79", language="python",
        )
        assert result.suppress is True

    def test_sink_then_sanitize_does_not_suppress(self):
        """Sanitizer AFTER the sink — bypass; current model treats
        this as 'not on every path to sink' which is correct."""
        src = (
            "def handle(x):\n"
            "    render(x)\n"
            "    y = html.escape(x)\n"
            "    return y\n"
        )
        cfg = _cfg(src)
        sink = _node_with_call(cfg, "render")
        result = evaluate_finding(
            cfg, [cfg.entry_node], sink,
            cwe="CWE-79", language="python",
        )
        assert result.suppress is False


class TestLoops:
    def test_sanitizer_only_in_loop_body_does_not_suppress(self):
        """A ``for`` with a sanitizer inside doesn't help — the loop
        may execute zero iterations, leaving the post-loop sink
        reachable without crossing the sanitizer."""
        src = (
            "def handle(items):\n"
            "    for x in items:\n"
            "        y = html.escape(x)\n"
            "    render(items)\n"
        )
        cfg = _cfg(src)
        sink = _node_with_call(cfg, "render")
        result = evaluate_finding(
            cfg, [cfg.entry_node], sink,
            cwe="CWE-79", language="python",
        )
        assert result.suppress is False


# ---------------------------------------------------------------------------
# Negative cases
# ---------------------------------------------------------------------------


class TestNoSuppression:
    def test_wrong_cwe_does_not_suppress(self):
        src = (
            "def handle(x):\n"
            "    y = html.escape(x)\n"
            "    render(y)\n"
        )
        cfg = _cfg(src)
        sink = _node_with_call(cfg, "render")
        # CWE-89 (SQLi) has no python sanitizers matching html.escape
        result = evaluate_finding(
            cfg, [cfg.entry_node], sink,
            cwe="CWE-89", language="python",
        )
        assert result.suppress is False
        assert "no sanitizer" in result.reason.lower() or \
               "no catalog" in result.reason.lower()

    def test_wrong_language_does_not_suppress(self):
        src = (
            "def handle(x):\n"
            "    y = html.escape(x)\n"
            "    render(y)\n"
        )
        cfg = _cfg(src)
        sink = _node_with_call(cfg, "render")
        result = evaluate_finding(
            cfg, [cfg.entry_node], sink,
            cwe="CWE-79", language="haskell",
        )
        assert result.suppress is False
        # Reason indicates the catalog lookup found nothing
        assert "no catalog" in result.reason.lower()

    def test_unknown_cwe_does_not_suppress(self):
        src = (
            "def handle(x):\n"
            "    y = html.escape(x)\n"
            "    render(y)\n"
        )
        cfg = _cfg(src)
        sink = _node_with_call(cfg, "render")
        result = evaluate_finding(
            cfg, [cfg.entry_node], sink,
            cwe="CWE-99999", language="python",
        )
        assert result.suppress is False

    def test_no_sanitizer_calls_in_graph_does_not_suppress(self):
        src = (
            "def handle(x):\n"
            "    render(x)\n"
        )
        cfg = _cfg(src)
        sink = _node_with_call(cfg, "render")
        result = evaluate_finding(
            cfg, [cfg.entry_node], sink,
            cwe="CWE-79", language="python",
        )
        assert result.suppress is False
        assert "no sanitizer calls" in result.reason

    def test_no_sources_does_not_suppress(self):
        src = (
            "def handle(x):\n"
            "    y = html.escape(x)\n"
            "    render(y)\n"
        )
        cfg = _cfg(src)
        sink = _node_with_call(cfg, "render")
        result = evaluate_finding(
            cfg, [], sink, cwe="CWE-79", language="python",
        )
        assert result.suppress is False
        assert "no sources" in result.reason

    def test_no_sink_does_not_suppress(self):
        src = (
            "def handle(x):\n"
            "    y = html.escape(x)\n"
            "    return y\n"
        )
        cfg = _cfg(src)
        result = evaluate_finding(
            cfg, [cfg.entry_node], None,
            cwe="CWE-79", language="python",
        )
        assert result.suppress is False
        assert "no sink" in result.reason


# ---------------------------------------------------------------------------
# Phase 7b — JSONL integration
# ---------------------------------------------------------------------------


class TestSuppressionRecord:
    def test_writes_jsonl_on_suppression(self, tmp_path: Path):
        src = (
            "def handle(x):\n"
            "    y = html.escape(x)\n"
            "    render(y)\n"
        )
        cfg = _cfg(src)
        sink = _node_with_call(cfg, "render")
        result = evaluate_finding(
            cfg, [cfg.entry_node], sink,
            cwe="CWE-79", language="python",
        )
        assert result.suppress is True
        finding = {
            "finding_id": "F1",
            "rule_id": "py/xss",
            "file_path": "src/handler.py",
            "line": 3,
            "function": "handle",
        }
        record_sanitizer_cut_suppression(tmp_path, finding, result)
        jsonl = tmp_path / "suppressions.jsonl"
        assert jsonl.is_file()
        lines = jsonl.read_text().strip().split("\n")
        assert len(lines) == 1
        record = json.loads(lines[0])
        assert record["finding_id"] == "F1"
        assert record["rule_id"] == "py/xss"
        assert record["verdict"] == VERDICT_SANITIZER_DOMINATED
        assert "vertex-cut" in record["reason"]

    def test_does_not_write_when_suppress_is_false(self, tmp_path: Path):
        """No-op for non-suppressed findings — the chokepoint records
        dropped findings, not surviving ones."""
        result = SanitizerCutResult(
            suppress=False, reason="bypass",
            cut_set=frozenset(), candidate_callables=frozenset(),
        )
        record_sanitizer_cut_suppression(
            tmp_path, {"finding_id": "F1"}, result,
        )
        assert not (tmp_path / "suppressions.jsonl").exists()

    def test_appends_alongside_other_suppressions(self, tmp_path: Path):
        """Multiple suppressions append to the same file."""
        existing = tmp_path / "suppressions.jsonl"
        existing.write_text(
            '{"finding_id": "F0", "verdict": "binary_oracle_absent"}\n',
            encoding="utf-8",
        )
        src = (
            "def handle(x):\n"
            "    y = html.escape(x)\n"
            "    render(y)\n"
        )
        cfg = _cfg(src)
        sink = _node_with_call(cfg, "render")
        result = evaluate_finding(
            cfg, [cfg.entry_node], sink,
            cwe="CWE-79", language="python",
        )
        record_sanitizer_cut_suppression(
            tmp_path, {"finding_id": "F1"}, result,
        )
        lines = existing.read_text().strip().split("\n")
        assert len(lines) == 2
        verdicts = [json.loads(line)["verdict"] for line in lines]
        assert "binary_oracle_absent" in verdicts
        assert VERDICT_SANITIZER_DOMINATED in verdicts


# ---------------------------------------------------------------------------
# Cut-set shape
# ---------------------------------------------------------------------------


def test_cut_set_contains_actual_cfg_nodes():
    src = (
        "def handle(x):\n"
        "    y = html.escape(x)\n"
        "    render(y)\n"
    )
    cfg = _cfg(src)
    sink = _node_with_call(cfg, "render")
    result = evaluate_finding(
        cfg, [cfg.entry_node], sink,
        cwe="CWE-79", language="python",
    )
    # Every node in cut_set should be a PyCFGNode from the actual CFG
    for n in result.cut_set:
        assert isinstance(n, PyCFGNode)
        assert n in set(cfg.nodes())
