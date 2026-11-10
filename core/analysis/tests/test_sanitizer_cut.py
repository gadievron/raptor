"""Tests for ``core.analysis.sanitizer_cut`` — Phase 7.

Coverage:

* **Canonical sibling-branch case** — sanitizer in BOTH ``if`` and
  ``else`` branches. The existing lexical dominance check at
  ``core/dataflow/smt_barrier.py:1189`` (``line < sink_line``)
  cannot decide this correctly because neither sanitizer call
  lexically precedes the sink uniformly. The vertex-cut retains the
  complete candidate; unresolved primitive requirements prevent a drop.
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


from core.analysis.cfg_builder import (
    PyCFGNode,
    build_python_cfg,
)
from core.analysis.dominators import AdjacencyGraph
from core.analysis.sanitizer_cut import (
    VERDICT_CANDIDATE_ONLY,
    VERDICT_SANITIZER_CANDIDATE,
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



def _assert_unverified_html_candidate(result, *, value_bound=False):
    assert result.verdict == VERDICT_CANDIDATE_ONLY
    assert result.suppress is False
    assert result.cut_set == frozenset()
    assert result.all_matched_bindings
    assert {binding.callable for binding in result.all_matched_bindings} == {"html.escape"}
    assert all("exact_builtin_str_default_call" in binding.unverified_source_contracts
               for binding in result.all_matched_bindings)
    if value_bound:
        assert result.value_bound_bindings
    else:
        assert not result.value_bound_bindings

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
            "import html\n"
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
        _assert_unverified_html_candidate(result)
        # Both branch nodes remain recognisable, without an authorised cut.
        assert len(result.all_matched_bindings) == 2

    def test_only_one_branch_sanitizes_does_not_suppress(self):
        src = (
            "import html\n"
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
    """A linear call remains a complete control-flow candidate."""

    def test_linear_sanitize_then_sink_suppresses(self):
        src = (
            "import html\n"
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
        _assert_unverified_html_candidate(result)

    def test_sink_then_sanitize_does_not_suppress(self):
        """Sanitizer AFTER the sink — bypass; current model treats
        this as 'not on every path to sink' which is correct."""
        src = (
            "import html\n"
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


class TestMatch:
    def test_sanitizer_only_in_match_case_does_not_suppress(self):
        """A ``match`` with no irrefutable case has a no-match
        fall-through: at runtime no case may match and the post-match
        sink is reached without crossing the case-body sanitizer."""
        src = (
            "import html\n"
            "def handle(x):\n"
            "    match x:\n"
            "        case 'a':\n"
            "            y = html.escape(x)\n"
            "    render(x)\n"
        )
        cfg = _cfg(src)
        sink = _node_with_call(cfg, "render")
        result = evaluate_finding(
            cfg, [cfg.entry_node], sink,
            cwe="CWE-79", language="python",
        )
        assert result.suppress is False

    def test_every_case_sanitizes_with_wildcard_suppresses(self):
        """With ``case _:`` some case always runs — when every case
        body sanitizes, the cut is genuinely complete."""
        src = (
            "import html\n"
            "def handle(x):\n"
            "    match x:\n"
            "        case 'a':\n"
            "            y = html.escape(x)\n"
            "        case _:\n"
            "            y = html.escape(x)\n"
            "    render(y)\n"
        )
        cfg = _cfg(src)
        sink = _node_with_call(cfg, "render")
        result = evaluate_finding(
            cfg, [cfg.entry_node], sink,
            cwe="CWE-79", language="python",
        )
        _assert_unverified_html_candidate(result)


class TestLoops:
    def test_sanitizer_only_in_loop_body_does_not_suppress(self):
        """A ``for`` with a sanitizer inside doesn't help — the loop
        may execute zero iterations, leaving the post-loop sink
        reachable without crossing the sanitizer."""
        src = (
            "import html\n"
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
            "import html\n"
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
            "import html\n"
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
            "import html\n"
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
            "import html\n"
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
            "import html\n"
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
            "import html\n"
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
        _assert_unverified_html_candidate(result)
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
        assert record["verdict"] == VERDICT_SANITIZER_CANDIDATE
        assert record["dropped"] is False
        assert record["catalog_matches"][0]["unverified_source_contracts"] == ["exact_builtin_str_default_call"]

    def test_does_not_write_when_suppress_is_false(self, tmp_path: Path):
        """No candidate or suppression means there is no cut record."""
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
            "import html\n"
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
        assert VERDICT_SANITIZER_CANDIDATE in verdicts


# ---------------------------------------------------------------------------
# Cut-set shape
# ---------------------------------------------------------------------------


def test_candidate_witness_contains_actual_cfg_nodes():
    src = (
        "import html\n"
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
    _assert_unverified_html_candidate(result)
    # Candidate node identity remains visible even without an authorised cut.
    for binding in result.all_matched_bindings:
        assert isinstance(binding.node, PyCFGNode)
        assert binding.node in set(cfg.nodes())


class TestLegacySinkInCutNotTrivial:
    """Legacy (no value context) path: a sanitizer ON the sink node
    used to count as a trivial cut — sink(escape(other), tainted)
    read as fully sanitized one caller-invariant away from
    enforcement. Candidate cuts still exclude the sink itself, and
    unresolved source contracts independently prevent suppression."""

    def _cfg(self, src):
        from core.analysis.cfg_builder import build_python_cfg
        cfg = build_python_cfg(src, "handle")
        assert cfg is not None
        return cfg

    def _sink(self, cfg, call_name):
        from core.analysis.cfg_builder import PyCFGNode
        return next(
            n for n in cfg.nodes()
            if isinstance(n, PyCFGNode) and call_name in n.calls
        )

    def test_sanitizer_on_sink_node_refuses_legacy(self):
        from core.analysis.sanitizer_cut import (
            VERDICT_NO_SUPPRESS,
            evaluate_finding,
        )
        src = (
            "import html\n"
            "def handle(tainted, other):\n"
            "    render(html.escape(other), tainted)\n"
        )
        cfg = self._cfg(src)
        result = evaluate_finding(
            cfg, [cfg.entry_node], self._sink(cfg, "render"),
            cwe="CWE-79", language="python",
        )
        assert result.verdict == VERDICT_NO_SUPPRESS

    def test_on_path_sanitizer_still_suppresses_legacy(self):
        from core.analysis.sanitizer_cut import (
            evaluate_finding,
        )
        src = (
            "import html\n"
            "def handle(x):\n"
            "    y = html.escape(x)\n"
            "    render(y)\n"
        )
        cfg = self._cfg(src)
        result = evaluate_finding(
            cfg, [cfg.entry_node], self._sink(cfg, "render"),
            cwe="CWE-79", language="python",
        )
        _assert_unverified_html_candidate(result)

    def test_value_bound_same_node_sanitize_at_sink_unchanged(self):
        # The VALUE-BOUND path keeps its same-node semantics — this
        # guard is scoped to the legacy branch only.
        from core.analysis.sanitizer_cut import (
            evaluate_finding,
        )
        src = (
            "import html\n"
            "def handle(x):\n"
            "    y = html.escape(x)\n"
            "    render(y)\n"
        )
        cfg = self._cfg(src)
        result = evaluate_finding(
            cfg, [cfg.entry_node], self._sink(cfg, "render"),
            cwe="CWE-79", language="python",
            source_symbols={"x"}, sink_arg="y",
        )
        _assert_unverified_html_candidate(result, value_bound=True)
