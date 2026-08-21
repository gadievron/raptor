"""Tests for mid-loop chain-following helpers.

Covers _collect_chain_findings, _inject_chain_targets, and the
chain_findings prompt rendering in context.py.
"""

from __future__ import annotations

from typing import Any, Dict

from core.audit.orchestrator import ReviewOutcome, _collect_chain_findings, _inject_chain_targets
from core.audit.task_graph import TaskGraph


def _outcome(
    file: str,
    function: str,
    status: str = "finding",
    hypothesis: str = "",
    body: str = "",
) -> ReviewOutcome:
    return ReviewOutcome(
        file=file, function=function, status=status,
        body=body, hypothesis=hypothesis,
    )


def _edge(
    caller_file: str, caller: str,
    callee_file: str, callee: str,
) -> Dict[str, str]:
    return {
        "caller_file": caller_file, "caller": caller,
        "callee_file": callee_file, "callee": callee,
    }


def _gap(file: str, name: str, priority: float = 0.5, line_start: int = 0) -> Dict[str, Any]:
    return {"file": file, "name": name, "priority_score": priority, "line_start": line_start}


def _checklist(*items: Dict[str, Any]) -> Dict[str, Any]:
    """Build a minimal checklist from gap dicts."""
    by_file: Dict[str, list] = {}
    for g in items:
        by_file.setdefault(g["file"], []).append({
            "name": g["name"],
            "line_start": g.get("line_start", 0),
        })
    return {"files": [{"path": f, "items": fns} for f, fns in by_file.items()]}


# ── _collect_chain_findings ──────────────────────────────────────────────


class TestEdgeIndex:
    def test_collect_uses_index(self) -> None:
        """_collect_chain_findings with edge index only examines relevant edges."""
        edges = [
            _edge("a.py", "f", "b.py", "g"),
            _edge("x.py", "unrelated", "y.py", "other"),
        ]
        index = {"a.py:f": [edges[0]], "b.py:g": [edges[0]]}
        outcomes = {"b.py:g": _outcome("b.py", "g", "finding")}
        chain = _collect_chain_findings("a.py:f", edges, outcomes, call_edge_index=index)
        assert len(chain) == 1
        assert chain[0]["function"] == "b.py:g"

    def test_inject_uses_index(self) -> None:
        """_inject_chain_targets with indexes avoids full scans."""
        outcome = _outcome("a.py", "vulnerable")
        edges = [
            _edge("a.py", "caller", "a.py", "vulnerable"),
            _edge("x.py", "unrelated", "y.py", "other"),
        ]
        edge_idx = {"a.py:vulnerable": [edges[0]], "a.py:caller": [edges[0]]}
        cl_idx = {("a.py", "caller"): {"file": "a.py", "name": "caller", "line_start": 0, "line_end": None}}
        gaps = [_gap("a.py", "caller"), _gap("a.py", "vulnerable")]
        checklist = _checklist(*gaps)
        graph = TaskGraph.from_workqueue(gaps, [])
        count = _inject_chain_targets(
            outcome, graph, edges, checklist,
            finding_priority=10.0,
            call_edge_index=edge_idx,
            checklist_index=cl_idx,
        )
        assert count == 1


class TestCollectChainFindings:
    def test_callee_finding_collected(self) -> None:
        edges = [_edge("a.py", "caller", "a.py", "callee")]
        outcomes = {"a.py:callee": _outcome("a.py", "callee", "finding", hypothesis="BOF")}
        chain = _collect_chain_findings("a.py:caller", edges, outcomes)
        assert len(chain) == 1
        assert chain[0]["direction"] == "callee"
        assert chain[0]["status"] == "finding"
        assert chain[0]["hypothesis"] == "BOF"

    def test_caller_finding_collected(self) -> None:
        edges = [_edge("a.py", "caller", "a.py", "callee")]
        outcomes = {"a.py:caller": _outcome("a.py", "caller", "suspicious", body="risky")}
        chain = _collect_chain_findings("a.py:callee", edges, outcomes)
        assert len(chain) == 1
        assert chain[0]["direction"] == "caller"
        assert chain[0]["status"] == "suspicious"

    def test_evidence_tool_included(self) -> None:
        edges = [_edge("a.py", "caller", "a.py", "callee")]
        o = _outcome("a.py", "callee", "finding", hypothesis="BOF")
        o.evidence_tool = "semgrep:buffer-overflow"
        outcomes = {"a.py:callee": o}
        chain = _collect_chain_findings("a.py:caller", edges, outcomes)
        assert len(chain) == 1
        assert chain[0]["evidence_tool"] == "semgrep:buffer-overflow"

    def test_clean_neighbour_excluded(self) -> None:
        edges = [_edge("a.py", "caller", "a.py", "callee")]
        outcomes = {"a.py:callee": _outcome("a.py", "callee", "clean")}
        chain = _collect_chain_findings("a.py:caller", edges, outcomes)
        assert chain == []

    def test_unreviewed_neighbour_excluded(self) -> None:
        edges = [_edge("a.py", "caller", "a.py", "callee")]
        chain = _collect_chain_findings("a.py:caller", edges, {})
        assert chain == []

    def test_no_edges_returns_empty(self) -> None:
        outcomes = {"a.py:f": _outcome("a.py", "f", "finding")}
        assert _collect_chain_findings("a.py:f", [], outcomes) == []

    def test_deduplication(self) -> None:
        edges = [
            _edge("a.py", "f", "b.py", "g"),
            _edge("a.py", "f", "b.py", "g"),
        ]
        outcomes = {"b.py:g": _outcome("b.py", "g", "finding")}
        chain = _collect_chain_findings("a.py:f", edges, outcomes)
        assert len(chain) == 1

    def test_max_items_cap(self) -> None:
        edges = [_edge("a.py", "f", "b.py", f"g{i}") for i in range(20)]
        outcomes = {
            f"b.py:g{i}": _outcome("b.py", f"g{i}", "finding")
            for i in range(20)
        }
        chain = _collect_chain_findings("a.py:f", edges, outcomes)
        assert len(chain) == 5  # _MAX_CHAIN_CONTEXT_ITEMS

    def test_body_truncated(self) -> None:
        edges = [_edge("a.py", "f", "b.py", "g")]
        outcomes = {"b.py:g": _outcome("b.py", "g", "finding", body="X" * 500)}
        chain = _collect_chain_findings("a.py:f", edges, outcomes)
        assert len(chain[0]["body"]) == 300

    def test_callee_file_fallback(self) -> None:
        edge = {"caller_file": "a.py", "caller": "f", "callee": "g"}
        outcomes = {"a.py:g": _outcome("a.py", "g", "finding")}
        chain = _collect_chain_findings("a.py:f", [edge], outcomes)
        assert len(chain) == 1

    def test_unrelated_edge_ignored(self) -> None:
        edges = [_edge("x.py", "a", "y.py", "b")]
        outcomes = {"y.py:b": _outcome("y.py", "b", "finding")}
        chain = _collect_chain_findings("z.py:c", edges, outcomes)
        assert chain == []


# ── _inject_chain_targets ────────────────────────────────────────────────


class TestInjectChainTargets:
    def test_injects_caller_of_finding(self) -> None:
        outcome = _outcome("a.py", "vulnerable")
        edges = [_edge("a.py", "caller", "a.py", "vulnerable")]
        checklist = _checklist(_gap("a.py", "caller"), _gap("a.py", "vulnerable"))
        graph = TaskGraph.from_workqueue(
            [_gap("a.py", "caller"), _gap("a.py", "vulnerable")], [],
        )
        # The finding's own review completes while the (pending,
        # not-yet-dispatched) caller waits in the ready queue.
        graph.mark_complete("a.py:vulnerable:0")
        count = _inject_chain_targets(outcome, graph, edges, checklist, finding_priority=10.0)
        assert count == 1
        ready = graph.pop_ready(1)
        assert ready[0].key == "a.py:caller:0"

    def test_in_flight_caller_not_double_dispatched(self) -> None:
        """A caller already handed to a worker must not be re-issued
        by chain injection — the elevated priority still counts as an
        injection, but pop_ready hands the task out once."""
        outcome = _outcome("a.py", "vulnerable")
        edges = [_edge("a.py", "caller", "a.py", "vulnerable")]
        checklist = _checklist(_gap("a.py", "caller"), _gap("a.py", "vulnerable"))
        graph = TaskGraph.from_workqueue(
            [_gap("a.py", "caller"), _gap("a.py", "vulnerable")], [],
        )
        graph.pop_ready(10)  # both tasks now held by workers
        graph.mark_complete("a.py:vulnerable:0")
        count = _inject_chain_targets(
            outcome, graph, edges, checklist, finding_priority=10.0,
        )
        assert count == 1
        assert graph.pop_ready(1) == []  # caller is already in flight

    def test_injects_callee_of_finding(self) -> None:
        outcome = _outcome("a.py", "vulnerable")
        edges = [_edge("a.py", "vulnerable", "b.py", "consumer")]
        checklist = _checklist(_gap("a.py", "vulnerable"), _gap("b.py", "consumer"))
        graph = TaskGraph.from_workqueue(
            [_gap("a.py", "vulnerable"), _gap("b.py", "consumer")], [],
        )
        count = _inject_chain_targets(outcome, graph, edges, checklist, finding_priority=10.0)
        assert count == 1

    def test_skips_already_finding(self) -> None:
        outcome = _outcome("a.py", "vulnerable")
        edges = [_edge("a.py", "caller", "a.py", "vulnerable")]
        checklist = _checklist(_gap("a.py", "caller"))
        graph = TaskGraph.from_workqueue([_gap("a.py", "caller")], [])
        reviewed = {"a.py:caller": _outcome("a.py", "caller", "finding")}
        count = _inject_chain_targets(
            outcome, graph, edges, checklist,
            reviewed_outcomes=reviewed, finding_priority=10.0,
        )
        assert count == 0

    def test_no_graph_returns_zero(self) -> None:
        outcome = _outcome("a.py", "f")
        count = _inject_chain_targets(outcome, None, [_edge("a.py", "f", "b.py", "g")], {})
        assert count == 0

    def test_no_edges_returns_zero(self) -> None:
        outcome = _outcome("a.py", "f")
        graph = TaskGraph.from_workqueue([_gap("a.py", "f")], [])
        count = _inject_chain_targets(outcome, graph, [], {})
        assert count == 0

    def test_not_in_checklist_skipped(self) -> None:
        outcome = _outcome("a.py", "vulnerable")
        edges = [_edge("a.py", "caller", "a.py", "vulnerable")]
        checklist = _checklist()  # empty
        graph = TaskGraph.from_workqueue([_gap("a.py", "vulnerable")], [])
        count = _inject_chain_targets(outcome, graph, edges, checklist, finding_priority=10.0)
        assert count == 0

    def test_max_injections_cap(self) -> None:
        outcome = _outcome("a.py", "vulnerable")
        edges = [_edge("a.py", f"c{i}", "a.py", "vulnerable") for i in range(20)]
        gaps = [_gap("a.py", f"c{i}") for i in range(20)]
        gaps.append(_gap("a.py", "vulnerable"))
        checklist = _checklist(*gaps)
        graph = TaskGraph.from_workqueue(gaps, [])
        count = _inject_chain_targets(outcome, graph, edges, checklist, finding_priority=10.0)
        assert count == 10  # _MAX_CHAIN_INJECTIONS_PER_FINDING

    def test_reprioritises_existing_task(self) -> None:
        outcome = _outcome("a.py", "vulnerable")
        edges = [_edge("a.py", "low", "a.py", "vulnerable")]
        gaps = [_gap("a.py", "low", 0.1), _gap("a.py", "vulnerable", 0.5)]
        checklist = _checklist(*gaps)
        graph = TaskGraph.from_workqueue(gaps, [])
        count = _inject_chain_targets(outcome, graph, edges, checklist, finding_priority=10.0)
        assert count == 1
        assert graph.injected_count == 0  # existing task, not new

    def test_requeues_completed_neighbour(self) -> None:
        outcome = _outcome("a.py", "vulnerable")
        edges = [_edge("a.py", "caller", "a.py", "vulnerable")]
        gaps = [_gap("a.py", "caller"), _gap("a.py", "vulnerable")]
        checklist = _checklist(*gaps)
        graph = TaskGraph.from_workqueue(gaps, [])
        graph.pop_ready(10)
        graph.mark_complete("a.py:caller:0")
        graph.mark_complete("a.py:vulnerable:0")
        assert graph.pending == 0
        count = _inject_chain_targets(outcome, graph, edges, checklist, finding_priority=10.0)
        assert count == 1
        assert graph.pending == 1
        ready = graph.pop_ready(1)
        assert ready[0].gap.get("force_review") is True

    def test_requeue_only_once_per_function(self) -> None:
        outcome1 = _outcome("a.py", "vuln1")
        outcome2 = _outcome("a.py", "vuln2")
        edges = [
            _edge("a.py", "target", "a.py", "vuln1"),
            _edge("a.py", "target", "a.py", "vuln2"),
        ]
        gaps = [_gap("a.py", "target"), _gap("a.py", "vuln1"), _gap("a.py", "vuln2")]
        checklist = _checklist(*gaps)
        graph = TaskGraph.from_workqueue(gaps, [])
        graph.pop_ready(10)
        graph.mark_complete("a.py:target:0")
        graph.mark_complete("a.py:vuln1:0")
        graph.mark_complete("a.py:vuln2:0")
        _inject_chain_targets(outcome1, graph, edges, checklist, finding_priority=10.0)
        graph.pop_ready(1)
        graph.mark_complete("a.py:target:0")
        count = _inject_chain_targets(outcome2, graph, edges, checklist, finding_priority=10.0)
        assert count == 0


# ── chain_findings prompt rendering ──────────────────────────────────────


class TestChainFindingsPrompt:
    def test_chain_findings_rendered(self) -> None:
        from core.audit.context import format_context_for_prompt
        ctx = {
            "file": "a.py",
            "function": "f",
            "line_start": 1,
            "line_end": 1,
            "source": "def f(): pass",
            "chain_findings": [
                {
                    "function": "a.py:caller",
                    "status": "finding",
                    "direction": "caller",
                    "hypothesis": "buffer overflow",
                    "body": "unbounded memcpy",
                },
            ],
        }
        prompt = format_context_for_prompt(ctx)
        assert "Connected findings" in prompt
        assert "a.py:caller" in prompt
        assert "buffer overflow" in prompt
        assert "unbounded memcpy" in prompt

    def test_direction_split_rendering(self) -> None:
        from core.audit.context import format_context_for_prompt
        ctx = {
            "file": "a.py",
            "function": "f",
            "line_start": 1,
            "line_end": 1,
            "source": "def f(): pass",
            "chain_findings": [
                {
                    "function": "a.py:upstream",
                    "status": "finding",
                    "direction": "caller",
                    "hypothesis": "SQL injection",
                    "body": "unsanitised query",
                },
                {
                    "function": "a.py:downstream",
                    "status": "suspicious",
                    "direction": "callee",
                    "hypothesis": "buffer overflow",
                    "body": "unbounded copy",
                },
            ],
        }
        prompt = format_context_for_prompt(ctx)
        assert "CALLED BY" in prompt
        assert "CALLERS of" in prompt
        assert "a.py:downstream" in prompt
        assert "a.py:upstream" in prompt
        callee_pos = prompt.index("CALLED BY")
        caller_pos = prompt.index("CALLERS of")
        downstream_pos = prompt.index("a.py:downstream")
        upstream_pos = prompt.index("a.py:upstream")
        assert callee_pos < downstream_pos < caller_pos < upstream_pos

    def test_no_chain_findings_no_section(self) -> None:
        from core.audit.context import format_context_for_prompt
        ctx = {"file": "a.py", "function": "f", "line_start": 1, "line_end": 1, "source": "def f(): pass"}
        prompt = format_context_for_prompt(ctx)
        assert "Connected findings" not in prompt
