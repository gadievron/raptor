"""Owned chain scheduling metadata; no tool-grounding claim."""
import pytest

from core.audit.orchestrator import ReviewOutcome, _inject_chain_targets
from core.audit.shared_state import SharedState
from core.audit.task_graph import TaskGraph
from core.audit.tests.test_shared_state import _prep_kwargs
from core.orchestration.context_map_callgraph import enrich_with_call_edges


@pytest.mark.parametrize("ambiguous", [True, False], ids=["ambiguous", "unique"])
def test_bare_chain_injection_does_not_choose_a_duplicate_occurrence(ambiguous):
    items = [{"name": "f", "line_start": 4}, {"name": "g", "line_start": 6}]
    if ambiguous:
        items.insert(0, {"name": "f", "line_start": 2})
    checklist = {"files": [{"path": "unit.c", "items": items,
                           "call_graph": {"calls": [{"caller": "g", "chain": ["f"]}]}}]}
    context_map = {}
    assert enrich_with_call_edges(context_map, checklist=checklist) == 1
    kwargs = _prep_kwargs()
    kwargs.update(checklist=checklist, context_map=context_map, call_edges=context_map["call_edges"])
    shared = SharedState.from_prep(**kwargs)
    gap = {"file": "unit.c", "name": "g", "line_start": 6, "priority_score": 1.0}
    graph = TaskGraph.from_workqueue([gap], [])
    assert graph.pop_ready(1)[0].key == "unit.c:g:6"
    graph.mark_complete("unit.c:g:6")
    # This is an owned declared finding producer for the scheduling helper,
    # not a native checker result or a public-pipeline evidence proof.
    outcome = ReviewOutcome("unit.c", "g", "finding", "Owned scheduling trigger", line=6)
    injected = _inject_chain_targets(outcome, graph, shared.call_edges, checklist,
        reviewed_outcomes={}, finding_priority=3.0, call_edge_index=shared.call_edge_index,
        checklist_index=shared.checklist_index, occurrences=shared.chain_occurrences)
    ready = graph.pop_ready(10)
    assert [task.key for task in ready] == ([] if ambiguous else ["unit.c:f:4"])
    assert injected == (0 if ambiguous else 1)


@pytest.mark.parametrize("scenario", ["duplicate_current", "unknown_current", "wrong_current_line",
    "bool_current", "unknown_target", "changed_target_name", "changed_target_file",
    "changed_target_line", "bool_target", "healthy"])
def test_strict_injection_preserves_original_endpoint_identity(scenario):
    items = [{"name": "f", "line_start": 4}, {"name": "g", "line_start": 6}]
    if scenario == "duplicate_current":
        items.append({"name": "g", "line_start": 8})
    elif scenario == "unknown_current":
        items.pop()
    elif scenario == "unknown_target":
        items.pop(0)
    checklist = {"files": [{"path": "unit.c", "items": items}]}
    edge = {"caller_file": "unit.c", "caller": "g", "callee_file": "unit.c", "callee": "f"}
    kwargs = _prep_kwargs()
    kwargs.update(checklist=checklist, call_edges=[edge])
    shared = SharedState.from_prep(**kwargs)
    change = {"changed_target_name": ("name", "other"), "changed_target_file": ("file", "other.c"),
              "changed_target_line": ("line_start", 99), "bool_target": ("line_start", True)}.get(scenario)
    if change:
        shared.checklist_index["unit.c", "f"][change[0]] = change[1]
    outcome = ReviewOutcome("unit.c", "g", "finding", "Owned scheduling trigger",
                           line=True if scenario == "bool_current" else 8 if scenario == "wrong_current_line" else 6)
    graph = TaskGraph.from_workqueue([], [])
    injected = _inject_chain_targets(outcome, graph, [edge], checklist,
        call_edge_index=shared.call_edge_index, checklist_index=shared.checklist_index,
        occurrences=shared.chain_occurrences, finding_priority=3.0)
    assert injected == (1 if scenario == "healthy" else 0)
    assert [task.key for task in graph.pop_ready(10)] == (["unit.c:f:4"] if scenario == "healthy" else [])
    assert all("force_review" not in item for item in shared.checklist_index.values())


def test_actual_post_ack_caller_supplies_the_owned_occurrence_snapshot():
    # The strict helper's compatibility default is intentionally permissive;
    # pin the production ownership handoff so it cannot silently use legacy mode.
    import ast
    import inspect

    from core.audit import orchestrator

    body = ast.parse(inspect.getsource(orchestrator._review_one_function_impl))
    calls = [node for node in ast.walk(body) if isinstance(node, ast.Call)
             and isinstance(node.func, ast.Name) and node.func.id == "_inject_chain_targets"]
    assert len(calls) == 1
    owned = next(keyword.value for keyword in calls[0].keywords if keyword.arg == "occurrences")
    assert isinstance(owned, ast.Attribute) and owned.attr == "chain_occurrences"
    assert isinstance(owned.value, ast.Name) and owned.value.id == "shared"
