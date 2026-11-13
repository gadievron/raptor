"""Initial source publication uses the original live binding after real ACK.

Pure scripted-client consumer control; no provider or atomic filesystem proof.
"""
import json

import pytest

from core.audit import collector as collector_mod, orchestrator as orch
from core.audit.knowledge_runtime import AuditKnowledgeRuntime
from core.audit.llm_review import make_review_fn
from core.audit.refutation_source import capture_source_identity
from core.audit.review_input_scope import ReviewInputScope
from core.audit.shared_state import SharedState
from core.audit.tests.test_study_claim_retention import _owned_review_caches as _owned_review_caches
from core.coverage.journal import load_entries
from core.llm.providers import StructuredResponse
from core.testing.audit_shutdown import isolated_audit_shutdown
from core.testing.module_views import module_function_view


@pytest.mark.parametrize("use_collector", [False, True], ids=["standalone", "collector"])
@pytest.mark.parametrize("change", ["none", "revision", "rewrite_restore"])
def test_initial_source_replacement_rechecks_original_scope_after_ack(
    tmp_path, monkeypatch, change, use_collector,
):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    target, out = tmp_path / "target", tmp_path / "out"
    target.mkdir()
    out.mkdir()
    path = target / "unit.c"
    source = "unsigned short f(unsigned value) { return value; }\n"
    path.write_text(source)
    original_identity = capture_source_identity(target, "unit.c")
    gap = {"file": "unit.c", "name": "f", "kind": "function", "line_start": 1,
           "line_end": 1, "pinned": True, "force_review": True}
    checklist = {"files": [{"path": "unit.c", "items": [dict(gap)]}]}
    (out / "checklist.json").write_text(json.dumps(checklist))
    calls = []

    class Client:
        _attempt_admission_protocol = 1
        _call_cost_history = None

        def is_budget_exhausted(self):
            return False

        def generate_structured(self, prompt, schema, **kwargs):
            assert kwargs.pop("accounting_attempt_admission")() is True
            calls.append(prompt)
            return StructuredResponse(result={"status": "clean", "body": "Fresh proposal",
                "reading_list": [], "language_reference_requests": []}, raw="",
                cost=.125, model="scripted")

    client = Client()
    config = orch.OrchestratorConfig(target_path=target, out_dir=out, prefilter=False,
        validate=False, max_refinements=0, immediate_verify=False,
        sweep_validate_findings=False, sage_recall=False, propagate_constraints=False,
        deepen_suspicious=False, open_discovery=False, iris=False,
        joern_overrides={"enabled": False}, no_binary_oracle=True,
        enable_session_context=False, llm_budget_client=client)
    prior = orch.ReviewOutcome(file="unit.c", function="f", line=1, status="suspicious",
        body="Prior concern", cost_usd=.2)
    prior_ack = collector_mod.append_journal_for_outcome(out_dir=out, target_path=target,
        run_id=out.name, outcome=prior, gap=gap)
    assert prior_ack is not None
    result = orch.OrchestratorResult()
    orch._tally_outcome(result, prior)
    reviewed = {"unit.c:f": prior}
    acknowledgements, proposed = [], []

    def append_then_change(append, outcome, actual_gap):
        scope = outcome.review_input_scope
        assert isinstance(scope, ReviewInputScope)
        assert scope.origin.source_identity == original_identity
        assert scope.current(target)
        rows = outcome.review_result["language_reference_delivery"]
        assert rows and all(row["delivered"] is True for row in rows)
        acknowledgement = append(outcome, actual_gap)
        assert acknowledgement is not None
        acknowledgements.append(acknowledgement)
        proposed.append(outcome)
        if change != "none":
            path.write_text(source + "/* owned revision after ACK */\n")
            if change == "rewrite_restore":
                path.write_text(source)
        return acknowledgement

    class OwnedCollector(collector_mod.Collector):
        def _append_journal_entry(self, outcome, actual_gap):
            return append_then_change(super()._append_journal_entry, outcome, actual_gap)

    collector = OwnedCollector(out_dir=out, target_path=target, run_id=out.name) if use_collector else None
    private = module_function_view(orch, bindings={
        "_correlated_mech_detector_tool": lambda *a, **k: None,
        "_gather_library_candidates": lambda *a, **k: [],
        "_get_llm_client": lambda *a, **k: None,
        "_proactive_validate": lambda outcome, *a, **k: outcome,
    })
    original_commit = private._commit_outcome

    def commit_then_change(cfg, outcome, actual_gap):
        return append_then_change(lambda value, item: original_commit(cfg, value, item), outcome, actual_gap)

    private._commit_outcome = commit_then_change
    runtime = AuditKnowledgeRuntime(target, orch.StudyQueue(), deadline=float("inf"), window=0)
    try:
        with isolated_audit_shutdown(private):
            final = runtime.wrap_unit(private.review_one_function)(gap,
                SharedState(checklist=checklist), config,
                make_review_fn(client, escalate_clean=False), result,
                reviewed_outcomes=reviewed, collector=collector, knowledge_runtime=runtime)
        if collector is not None:
            collector.flush()
        assert len(calls) == len(acknowledgements) == len(proposed) == 1
        assert "c.integer-promotion v1:" in calls[0]
        assert result.total_cost_usd == pytest.approx(.325)
        assert result.reviewed == 1
        assert [entry.verdict for entry in load_entries(out, fresh=True)] == ["suspicious", "clean"]
        current = capture_source_identity(target, "unit.c")
        if change == "none":
            assert current == original_identity
            assert proposed[0].review_input_scope.current(target)
            assert final is proposed[0] and result.outcomes == [final]
            assert reviewed["unit.c:f"] is final
            assert result.clean == 1 and result.suspicious == 0
            assert not result.publication_failures
        else:
            assert current != original_identity
            assert not proposed[0].review_input_scope.current(target)
            if change == "rewrite_restore":
                assert current.sha256 == original_identity.sha256
                assert current.version != original_identity.version
            assert final.status == "error" and final.error_class == "publication"
            assert result.outcomes == [prior] and reviewed["unit.c:f"] is prior
            assert result.suspicious == 1 and result.clean == 0
            assert len(result.publication_failures) == 1
    finally:
        runtime.close("test_complete")


@pytest.mark.parametrize("change", ["none", "incomplete", "replace_scope", "remove_scope",
                                    "change_history", "unbound", "wrong_root"])
def test_initial_ack_retains_original_scope_and_history(tmp_path, change):
    from copy import deepcopy
    from dataclasses import replace

    from core.audit.review_claims import begin_review
    from core.audit.tests.test_review_input_scope import _scope

    scope, manifest, target, study = _scope(tmp_path, complete=change != "incomplete")
    out = tmp_path / "out"
    out.mkdir()
    history = begin_review(scope.origin, "owned-attempt")
    history["source_inputs"] = manifest
    outcome = orch.ReviewOutcome(file="unit.c", function="f", line=1,
        status="suspicious", body="Owned assessment", review_result={"review_claims": history},
        review_input_scope=scope)
    gap = {"file": "unit.c", "name": "f", "line_start": 1, "line_end": 1}
    acknowledgement = collector_mod.append_journal_for_outcome(out_dir=out, target_path=target,
        run_id=out.name, outcome=outcome, gap=gap, source_roots=scope.roots())
    assert acknowledgement is not None
    assert scope.current(target)
    original = scope
    if change == "replace_scope":
        outcome.review_input_scope = replace(scope)
    elif change == "remove_scope":
        outcome.review_input_scope = None
    elif change == "change_history":
        changed = deepcopy(history)
        changed["source_inputs"]["complete"] = not manifest["complete"]
        outcome.review_result["review_claims"] = changed
    elif change == "unbound":
        outcome.review_input_scope = None
        original = None
    admitted = orch._initial_publication_acknowledged(acknowledgement, outcome, gap,
        target_path=study if change == "wrong_root" else target, source_scope=original)
    assert admitted is (change in {"none", "incomplete"})
    assert len(load_entries(out, fresh=True)) == 1
