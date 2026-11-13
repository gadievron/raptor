"""Bare call edges cannot attribute a finding to an ambiguous source occurrence."""
import json

import pytest

from core.audit import orchestrator as orch
from core.audit.collector import Collector, append_journal_for_outcome
from core.audit.knowledge_runtime import AuditKnowledgeRuntime
from core.audit.llm_review import make_review_fn
from core.audit.shared_state import SharedState
from core.audit.tests.test_study_claim_retention import _owned_review_caches as _owned_review_caches
from core.coverage.journal import load_entries
from core.llm.providers import StructuredResponse
from core.orchestration.context_map_callgraph import enrich_with_call_edges
from core.testing.audit_shutdown import isolated_audit_shutdown
from core.testing.module_views import module_function_view


@pytest.mark.parametrize("ambiguous", [True, False], ids=["ambiguous", "unique"])
def test_bare_neighbour_requires_unique_occurrence_in_actual_review_prompt(tmp_path, monkeypatch, ambiguous):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    target, out = tmp_path / "target", tmp_path / "out"
    target.mkdir()
    out.mkdir()
    (target / "unit.c").write_text("#ifdef FIRST\nunsigned f(unsigned n) { return n; }\n#else\nunsigned f(unsigned n) { return n + 1; }\n#endif\nunsigned g(unsigned n) { return f(n); }\n")
    gaps = [{"file": "unit.c", "name": name, "kind": "function", "line_start": line,
             "line_end": line, "pinned": True} for name, line in (("f", 2), ("f", 4), ("g", 6))]
    if not ambiguous:
        (target / "unit.c").write_text("\n\n\nunsigned f(unsigned n) { return n + 1; }\n\nunsigned g(unsigned n) { return f(n); }\n")
        gaps = gaps[1:]
    selected = next(gap for gap in gaps if gap["name"] == "g")
    neighbour = next(gap for gap in gaps if gap["name"] == "f" and gap["line_start"] == 4)
    checklist = {"files": [{"path": "unit.c", "items": [dict(gap) for gap in gaps],
                           "call_graph": {"calls": [{"caller": "g", "chain": ["f"]}]}}]}
    (out / "checklist.json").write_text(json.dumps(checklist))
    context_map = {}
    assert enrich_with_call_edges(context_map, checklist=checklist) == 1
    edges = context_map["call_edges"]
    assert edges == [{"caller_file": "unit.c", "caller": "g", "callee": "f", "callee_file": "unit.c"}]
    config = orch.OrchestratorConfig(target_path=target, out_dir=out, prefilter=False,
        validate=False, max_refinements=0, immediate_verify=False, sweep_validate_findings=False,
        sage_recall=False, propagate_constraints=False, deepen_suspicious=False,
        open_discovery=False, iris=False, joern_overrides={"enabled": False},
        no_binary_oracle=True, enable_session_context=False)
    sentinel = "OWNED_UNRESOLVED_FOURTH_LINE_CONCERN"
    prior = orch.ReviewOutcome("unit.c", "f", "suspicious", sentinel, line=4, cost_usd=.2)
    result = orch.OrchestratorResult()
    orch._tally_outcome(result, prior)
    assert append_journal_for_outcome(out_dir=out, target_path=target, run_id=out.name,
                                     outcome=prior, gap=neighbour) is not None
    reviewed = orch._LockedOutcomes()
    reviewed["unit.c:f"] = prior
    calls = []

    class Client:
        _attempt_admission_protocol = 1
        _call_cost_history = None

        def is_budget_exhausted(self):
            return False

        def generate_structured(self, prompt, schema, **kwargs):
            assert kwargs.pop("accounting_attempt_admission")() is True
            calls.append(prompt)
            return StructuredResponse(result={"status": "suspicious", "body": "Independent g assessment",
                "reading_list": [], "language_reference_requests": []}, raw="", cost=.125, model="scripted")

    client = Client()
    config.llm_budget_client = client
    private = module_function_view(orch, bindings={
        "_correlated_mech_detector_tool": lambda *a, **k: None,
        "_gather_library_candidates": lambda *a, **k: [],
        "_get_llm_client": lambda *a, **k: None,
        "_proactive_validate": lambda outcome, *a, **k: outcome,
    })
    runtime = AuditKnowledgeRuntime(target, orch.StudyQueue(), deadline=float("inf"), window=0)
    try:
        with isolated_audit_shutdown(private):
            fresh = runtime.wrap_unit(private.review_one_function)(selected,
                SharedState(checklist=checklist, call_edges=edges), config,
                make_review_fn(client, escalate_clean=False), result, reviewed_outcomes=reviewed,
                collector=Collector(out_dir=out, target_path=target, run_id=out.name), knowledge_runtime=runtime)
        assert len(calls) == sum(runtime._calls.values()) == 1
        assert fresh.function == "g" and fresh.line == 6
        assert len(result.outcomes) == result.reviewed == result.suspicious == 2
        assert any(item is prior for item in result.outcomes)
        assert len(load_entries(out, fresh=True)) == 2
        assert (sentinel in calls[0]) is (not ambiguous)
    finally:
        runtime.close("test_complete")


@pytest.mark.parametrize("scenario", ["duplicate_current", "duplicate_neighbour", "wrong_alias_line",
                                     "invalid_line", "unknown_neighbour", "malformed", "healthy"])
def test_indexed_chain_selection_refuses_unresolved_occurrences(scenario):
    items = [{"name": "g", "line_start": 6}, {"name": "f", "line_start": 4}]
    checklist = {"files": [{"path": "unit.c", "items": items}]}
    if scenario == "duplicate_current":
        items.append({"name": "g", "line_start": 8})
    elif scenario == "duplicate_neighbour":
        items.append({"name": "f", "line_start": 2})
    elif scenario == "invalid_line":
        items[1]["line_start"] = True
    elif scenario == "unknown_neighbour":
        items.pop()
    elif scenario == "malformed":
        items.append(None)
    shared = SharedState(checklist=checklist)
    edge = {"caller_file": "unit.c", "caller": "g", "callee_file": "unit.c", "callee": "f"}
    prior = orch.ReviewOutcome("unit.c", "f", "suspicious", "Owned concern",
                              line=2 if scenario == "wrong_alias_line" else 4)
    reviewed = orch._LockedOutcomes()
    reviewed["unit.c:f"] = prior
    chain = orch._collect_chain_findings("unit.c:g", [edge], reviewed,
        call_edge_index={"unit.c:g": [edge]}, occurrence=("unit.c", "g", 6),
        occurrences=shared.chain_occurrences)
    assert bool(chain) is (scenario == "healthy")


def test_occurrence_snapshot_is_owned_immutable_and_built_once():
    items = [{"name": "g", "line_start": 6}, {"name": "f", "line_start": 4}]
    checklist = {"files": [{"path": "unit.c", "items": items}]}
    shared = SharedState(checklist=checklist)
    items[1]["line_start"] = 99
    items.append({"name": "f", "line_start": 2})
    assert dict(shared.chain_occurrences) == {("unit.c", "g"): 6, ("unit.c", "f"): 4}
    with pytest.raises(TypeError):
        shared.chain_occurrences["unit.c", "f"] = 2
    class NoInventoryRead(dict):
        def get(self, *args):
            raise AssertionError("review lookup scanned the inventory again")
    shared.checklist = NoInventoryRead(checklist)
    prior = orch.ReviewOutcome("unit.c", "f", "suspicious", "Owned concern", line=4)
    edge = {"caller_file": "unit.c", "caller": "g", "callee_file": "unit.c", "callee": "f"}
    for _ in range(3):
        assert orch._collect_chain_findings("unit.c:g", [], {"unit.c:f": prior},
            call_edge_index={"unit.c:g": [edge]}, occurrence=("unit.c", "g", 6),
            occurrences=shared.chain_occurrences)[0]["body"] == "Owned concern"


def test_from_prep_derives_ambiguity_without_borrowing_last_write_index():
    from core.audit.tests.test_shared_state import _prep_kwargs

    kwargs = _prep_kwargs()
    kwargs["checklist"] = {"files": [{"path": "unit.c", "items": [
        {"name": "f", "line_start": 2}, {"name": "f", "line_start": 4},
        {"name": "g", "line_start": 6}]}]}
    shared = SharedState.from_prep(**kwargs)
    assert shared.checklist_index["unit.c", "f"]["line_start"] == 4
    assert shared.chain_occurrences["unit.c", "f"] is None
    assert shared.chain_occurrences["unit.c", "g"] == 6
    with pytest.raises(TypeError):
        SharedState(checklist=kwargs["checklist"], chain_occurrences={("unit.c", "f"): 4})
