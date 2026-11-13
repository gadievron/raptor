"""A pre-dispatch refusal must retain the prior forced-review assessment.

Owned source, Runtime, formatter and journal exercise consumer restoration;
no provider attempt, billing, native tool or atomic-publication proof is made.
"""
import json
from types import SimpleNamespace

import pytest

from core.audit import orchestrator as orch
from core.audit.collector import Collector, append_journal_for_outcome
from core.audit.knowledge_calls import KnowledgeCallRefused
from core.audit.knowledge_runtime import AuditKnowledgeRuntime
from core.audit.llm_review import make_review_fn
from core.audit.shared_state import SharedState
from core.audit.tests.test_study_claim_retention import _owned_review_caches as _owned_review_caches
from core.coverage.journal import load_entries
from core.llm.providers import StructuredResponse
from core.testing.audit_shutdown import isolated_audit_shutdown
from core.testing.module_views import module_function_view


def _initial_case(tmp_path, monkeypatch, reused=False):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    target, out = tmp_path / "target", tmp_path / "out"
    target.mkdir()
    out.mkdir()
    (target / "unit.c").write_text("unsigned f(unsigned n) { return n + 1; }\n")
    gap = {"file": "unit.c", "name": "f", "kind": "function", "line_start": 1,
           "line_end": 1, "pinned": True, "force_review": True}
    checklist = {"files": [{"path": "unit.c", "items": [dict(gap)]}]}
    (out / "checklist.json").write_text(json.dumps(checklist))
    config = orch.OrchestratorConfig(target_path=target, out_dir=out, prefilter=False,
        validate=False, max_refinements=0, immediate_verify=False, sweep_validate_findings=False,
        sage_recall=False, propagate_constraints=False, deepen_suspicious=False,
        open_discovery=False, iris=False, joern_overrides={"enabled": False},
        no_binary_oracle=True, enable_session_context=False)
    prior = orch.ReviewOutcome(file="unit.c", function="f", line=1, status="suspicious",
        body="Prior concern remains unresolved", hypothesis="An earlier independent concern", cost_usd=.2,
        reused=reused)
    assert append_journal_for_outcome(out_dir=out, target_path=target, run_id=out.name,
        outcome=prior, gap=gap) is not None
    result = orch.OrchestratorResult()
    orch._tally_outcome(result, prior, reused=reused)
    reviewed = orch._LockedOutcomes()
    reviewed["unit.c:f"] = prior
    calls = []

    class Client:
        _attempt_admission_protocol = 1
        _call_cost_history = None

        def is_budget_exhausted(self):
            return False

        def generate_structured(self, prompt, schema, **kwargs):
            # Entry itself is observed, before the compatible callback. A
            # refusal here would be too late to satisfy the zero-entry claim.
            calls.append(prompt)
            assert kwargs.pop("accounting_attempt_admission")() is True
            return StructuredResponse(result={"status": "suspicious", "body": "Unreached proposal",
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
    return locals()


@pytest.mark.parametrize("reused", [False, True])
def test_closed_runtime_forced_review_retains_prior_before_dispatch(tmp_path, monkeypatch, reused):
    case = _initial_case(tmp_path, monkeypatch, reused)
    runtime = case["runtime"]
    private = case["private"]
    gap = case["gap"]
    checklist = case["checklist"]
    config = case["config"]
    client = case["client"]
    result = case["result"]
    reviewed = case["reviewed"]
    out = case["out"]
    target = case["target"]
    calls = case["calls"]
    prior = case["prior"]
    runtime.close("owned_before_forced_review")
    try:
        with isolated_audit_shutdown(private):
            with pytest.raises(KnowledgeCallRefused, match="unit_validity") as caught:
                runtime.wrap_unit(private.review_one_function)(gap,
                    SharedState(checklist=checklist), config, make_review_fn(client, escalate_clean=False), result,
                    reviewed_outcomes=reviewed,
                    collector=Collector(out_dir=out, target_path=target, run_id=out.name),
                    knowledge_runtime=runtime)
        assert caught.value.reason == "unit_validity"
        assert not calls and sum(runtime._calls.values()) == 0
        assert not runtime._busy and not runtime._active and not runtime._active_units
        entries = load_entries(out, fresh=True)
        assert len(entries) == 1 and entries[0].verdict == "suspicious"
        assert result.total_cost_usd == pytest.approx(.2)
        assert result.suspicious == 1 and result.clean == result.errors == 0
        assert result.reviewed == (0 if reused else 1)
        assert result.reused_from_prior == (1 if reused else 0)
        assert len(result.outcomes) == 1 and result.outcomes[0] is prior
        assert reviewed["unit.c:f"] is prior
    finally:
        runtime.close("test_complete")


@pytest.mark.parametrize("scenario", ["current", "promoted", "newer", "ambiguous", "other_alias", "restored"])
def test_abort_uses_actual_selected_prior_and_preserves_newer_current(scenario):
    # Owned outcome-producer controls exercise the real wrapper and selector;
    # they do not establish checker, source-freshness or billing authority.
    prior = orch.ReviewOutcome("unit.c", "f", "clean" if scenario == "promoted" else "suspicious",
                              "Original assessment", line=1, cost_usd=.2)
    result = orch.OrchestratorResult()
    orch._tally_outcome(result, prior)
    reviewed = orch._LockedOutcomes()
    reviewed["unit.c:f"] = prior
    extra = None
    if scenario in {"ambiguous", "other_alias"}:
        extra = orch.ReviewOutcome("unit.c", "f", "suspicious", "Independent concern",
                                   line=1 if scenario == "ambiguous" else 3, cost_usd=.2)
        orch._tally_outcome(result, extra)
        if scenario == "other_alias":
            reviewed["unit.c:f"] = extra
    primary = RuntimeError("owned review abort")
    replacements = []

    def body(gap, shared, config, review_fn, actual_result, **kwargs):
        assert actual_result is result
        if scenario == "promoted":
            current = orch.ReviewOutcome("unit.c", "f", "suspicious", "Replacement concern", line=1,
                                         cost_usd=.2, reused=True)
            with result._lock:
                result.outcomes.remove(prior)
                orch._untally_outcome_unlocked(result, prior)
                orch._tally_outcome_unlocked(result, current, reused=True, book_cost=False)
            replacements.append(current)
        selected = private._supersede_prior_outcome(result, reviewed, "unit.c:f",
                                                    occurrence=("unit.c", "f", 1))
        if scenario == "ambiguous":
            assert selected is None
        else:
            assert selected is (replacements[0] if replacements else prior)
        if scenario == "newer":
            current = orch.ReviewOutcome("unit.c", "f", "suspicious", "New current concern", line=1,
                                         cost_usd=.2)
            with result._lock:
                orch._tally_outcome_unlocked(result, current, book_cost=False)
            reviewed["unit.c:f"] = current
            replacements.append(current)
        elif scenario == "restored":
            with result._lock:
                orch._tally_outcome_unlocked(result, prior, book_cost=False)
        raise primary

    private = module_function_view(orch, bindings={"_review_one_function_impl": body})
    with pytest.raises(RuntimeError) as caught:
        private.review_one_function({"file": "unit.c", "name": "f", "line_start": 1, "force_review": True},
            None, SimpleNamespace(target_path=None), None, result, reviewed_outcomes=reviewed)
    assert caught.value is primary
    assert orch._initial_review_replacement.get() is None
    assert result.total_cost_usd == pytest.approx(.4 if extra is not None else .2)
    assert result.clean == result.errors == 0
    if scenario in {"promoted", "newer"}:
        assert len(result.outcomes) == 1 and result.outcomes[0] is replacements[0]
        assert reviewed["unit.c:f"] is replacements[0]
    else:
        assert any(outcome is prior for outcome in result.outcomes)
        if extra is not None:
            assert any(outcome is extra for outcome in result.outcomes)
        assert reviewed["unit.c:f"] is (extra if scenario == "other_alias" else prior)
    assert result.suspicious == (2 if extra is not None else 1)
    assert result.reviewed == (0 if scenario == "promoted" else 2 if extra is not None else 1)
    assert result.reused_from_prior == (1 if scenario == "promoted" else 0)


def test_interrupt_and_optional_alias_failure_keep_original_exception():
    prior = orch.ReviewOutcome("unit.c", "f", "suspicious", "Original concern", line=1, cost_usd=.2)
    result = orch.OrchestratorResult()
    orch._tally_outcome(result, prior)

    class FaultyAlias(orch._LockedOutcomes):
        fail_writes = False

        def __setitem__(self, key, value):
            if self.fail_writes:
                raise OSError("owned alias write failure")
            super().__setitem__(key, value)

    reviewed = FaultyAlias()
    reviewed["unit.c:f"] = prior
    primary = KeyboardInterrupt("owned after-selection interruption")

    def body(gap, shared, config, review_fn, actual_result, **kwargs):
        assert private._supersede_prior_outcome(result, reviewed, "unit.c:f",
            occurrence=("unit.c", "f", 1)) is prior
        reviewed.fail_writes = True
        raise primary

    private = module_function_view(orch, bindings={"_review_one_function_impl": body})
    with pytest.raises(KeyboardInterrupt) as caught:
        private.review_one_function({"file": "unit.c", "name": "f", "line_start": 1, "force_review": True},
            None, SimpleNamespace(target_path=None), None, result, reviewed_outcomes=reviewed)
    assert caught.value is primary
    assert primary.__notes__ == ["Prior assessment restoration also failed: OSError"]
    assert result.outcomes == [prior] and result.outcomes[0] is prior
    assert result.reviewed == result.suspicious == 1
    assert result.total_cost_usd == pytest.approx(.2)
    assert orch._initial_review_replacement.get() is None


def test_private_module_view_owns_body_delegate_without_changing_shared_binding():
    shared_body = orch._review_one_function_impl
    sentinel = object()
    calls = []

    def body(*args, **kwargs):
        calls.append((args, kwargs))
        return sentinel

    private = module_function_view(orch, bindings={"_review_one_function_impl": body})
    result = orch.OrchestratorResult()
    assert private.review_one_function({"file": "unit.c", "name": "f", "line_start": 1},
        None, None, None, result) is sentinel
    assert len(calls) == 1 and orch._review_one_function_impl is shared_body
    assert orch._initial_review_replacement.get() is None


@pytest.mark.parametrize("phase", ["current", "changed", "tallied"])
def test_real_ack_before_tally_abort_keeps_one_consistent_current_assessment(tmp_path, monkeypatch, phase):
    import builtins
    from types import ModuleType
    from core.analysis import summaries

    case = _initial_case(tmp_path, monkeypatch)
    runtime, result, reviewed = case["runtime"], case["result"], case["reviewed"]
    primary = RuntimeError("owned abort after initial alias publication")
    published = []

    def fail_summary(*args, **kwargs):
        if phase == "tallied":
            return None
        fresh = reviewed["unit.c:f"]
        assert fresh is not case["prior"]
        assert not result.outcomes
        assert len(load_entries(case["out"], fresh=True)) == 2
        published.append(fresh)
        if phase == "changed":
            path = case["target"] / "unit.c"
            path.write_text(path.read_text() + "/* owned source change after ACK */\n")
        raise primary

    private_summaries = ModuleType(summaries.__name__)
    vars(private_summaries).update(vars(summaries))
    private_summaries.summary_from_review_result = fail_summary

    def import_local(name, globals=None, locals=None, fromlist=(), level=0):
        if level == 0 and name == "core.analysis.summaries":
            return private_summaries
        return builtins.__import__(name, globals, locals, fromlist, level)

    def abort_after_tally(actual_result, outcome, **kwargs):
        orch._tally_outcome(actual_result, outcome, **kwargs)
        published.append(outcome)
        raise primary

    names = ("_correlated_mech_detector_tool", "_gather_library_candidates", "_get_llm_client", "_proactive_validate")
    bindings = {name: getattr(case["private"], name) for name in names}
    if phase == "tallied":
        bindings["_tally_outcome"] = abort_after_tally
    private = module_function_view(orch, bindings=bindings, import_hook=import_local)
    try:
        shared = SharedState(checklist=case["checklist"], taint_summary_results={})
        with isolated_audit_shutdown(private), pytest.raises(RuntimeError) as caught:
            runtime.wrap_unit(private.review_one_function)(case["gap"], shared, case["config"],
                make_review_fn(case["client"], escalate_clean=False), result, reviewed_outcomes=reviewed,
                collector=Collector(out_dir=case["out"], target_path=case["target"], run_id=case["out"].name),
                knowledge_runtime=runtime)
        assert caught.value is primary and len(published) == 1
        assert len(case["calls"]) == sum(runtime._calls.values()) == 1
        assert len(load_entries(case["out"], fresh=True)) == 2
        expected = case["prior"] if phase == "changed" else published[0]
        assert len(result.outcomes) == 1 and result.outcomes[0] is expected
        assert reviewed["unit.c:f"] is expected
        assert result.total_cost_usd == pytest.approx(.325)
        assert result.reviewed == result.suspicious == 1
    finally:
        runtime.close("test_complete")
