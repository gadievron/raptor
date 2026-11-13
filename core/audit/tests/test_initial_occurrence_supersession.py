"""Forced re-review may replace only the scheduled source occurrence."""
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
from core.testing.audit_shutdown import isolated_audit_shutdown
from core.testing.module_views import module_function_view


@pytest.mark.parametrize("tracking", ["other", "current", "stale", "absent"])
@pytest.mark.parametrize("journal_failure", [False, True], ids=["ack", "refused"])
def test_forced_review_preserves_another_same_named_occurrence(
    tmp_path, monkeypatch, tracking, journal_failure,
):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    target, out = tmp_path / "target", tmp_path / "out"
    target.mkdir()
    out.mkdir()
    (target / "unit.c").write_text("#ifdef FIRST\nunsigned f(unsigned n) { return n; }\n#else\nunsigned f(unsigned n) { return n + 1; }\n#endif\n")
    gaps = [{"file": "unit.c", "name": "f", "kind": "function", "line_start": line,
             "line_end": line, "pinned": True} for line in (2, 4)]
    checklist = {"files": [{"path": "unit.c", "items": [dict(gap) for gap in gaps]}]}
    (out / "checklist.json").write_text(json.dumps(checklist))
    config = orch.OrchestratorConfig(target_path=target, out_dir=out, prefilter=False,
        validate=False, max_refinements=0, immediate_verify=False, sweep_validate_findings=False,
        sage_recall=False, propagate_constraints=False, deepen_suspicious=False,
        open_discovery=False, iris=False, joern_overrides={"enabled": False},
        no_binary_oracle=True, enable_session_context=False)
    priors = [orch.ReviewOutcome(file="unit.c", function="f", line=line, status="suspicious",
              body="Independent concern at line " + str(line), cost_usd=.2) for line in (2, 4)]
    result = orch.OrchestratorResult()
    for prior, gap in zip(priors, gaps):
        assert append_journal_for_outcome(out_dir=out, target_path=target, run_id=out.name,
            outcome=prior, gap=gap) is not None
        orch._tally_outcome(result, prior)
    # The compatibility map contains the most recently reviewed same-name site.
    from dataclasses import replace

    reviewed = orch._LockedOutcomes()
    if tracking != "absent":
        tracked = (priors[1] if tracking == "other" else
                   replace(priors[0], status="clean", body="Older same-site assessment")
                   if tracking == "stale" else priors[0])
        reviewed["unit.c:f"] = tracked
    calls = []

    class Client:
        _attempt_admission_protocol = 1
        _call_cost_history = None

        def is_budget_exhausted(self):
            return False

        def generate_structured(self, prompt, schema, **kwargs):
            assert kwargs.pop("accounting_attempt_admission")() is True
            calls.append(prompt)
            return StructuredResponse(result={"status": "suspicious", "body": "Updated first concern",
                "reading_list": [], "language_reference_requests": []}, raw="", cost=.125, model="scripted")

    client = Client()
    config.llm_budget_client = client
    private = module_function_view(orch, bindings={
        "_correlated_mech_detector_tool": lambda *a, **k: None,
        "_gather_library_candidates": lambda *a, **k: [],
        "_get_llm_client": lambda *a, **k: None,
        "_proactive_validate": lambda outcome, *a, **k: outcome,
    })
    class OwnedCollector(Collector):
        def _append_journal_entry(self, outcome, actual_gap):
            return None if journal_failure else super()._append_journal_entry(outcome, actual_gap)

    runtime = AuditKnowledgeRuntime(target, orch.StudyQueue(), deadline=float("inf"), window=0)
    try:
        with isolated_audit_shutdown(private):
            fresh = runtime.wrap_unit(private.review_one_function)({**gaps[0], "force_review": True},
                SharedState(checklist=checklist), config, make_review_fn(client, escalate_clean=False), result,
                reviewed_outcomes=reviewed, collector=OwnedCollector(out_dir=out, target_path=target, run_id=out.name),
                knowledge_runtime=runtime)
        assert len(calls) == sum(runtime._calls.values()) == 1
        assert fresh.line == 2
        assert result.total_cost_usd == pytest.approx(.525)
        assert result.reviewed == result.suspicious == 2 and result.clean == 0
        assert len(load_entries(out, fresh=True)) == (2 if journal_failure else 3)
        assert any(outcome is priors[1] for outcome in result.outcomes)
        assert sorted(outcome.line for outcome in result.outcomes) == [2, 4]
        if journal_failure:
            assert fresh.status == "error" and fresh.error_class == "publication"
            assert any(outcome is priors[0] for outcome in result.outcomes)
            assert reviewed["unit.c:f"] is priors[0]
        else:
            assert fresh.status == "suspicious"
            assert not any(outcome is priors[0] for outcome in result.outcomes)
            assert fresh in result.outcomes and reviewed["unit.c:f"] is fresh
    finally:
        runtime.close("test_complete")


@pytest.mark.parametrize("selection", ["missing", "ambiguous"])
def test_unselectable_occurrence_does_not_remove_or_untally_another_site(selection):
    first = orch.ReviewOutcome("unit.c", "f", "suspicious", "First concern", line=2, cost_usd=.2)
    other = orch.ReviewOutcome("unit.c", "f", "suspicious", "Independent concern", line=4, cost_usd=.2)
    result = orch.OrchestratorResult()
    for outcome in (first, other):
        orch._tally_outcome(result, outcome)
    if selection == "ambiguous":
        duplicate = orch.ReviewOutcome("unit.c", "f", "suspicious", "Competing first record", line=2, cost_usd=.2)
        orch._tally_outcome(result, duplicate)
    before = tuple(result.outcomes), result.reviewed, result.suspicious, result.total_cost_usd
    removed = orch._supersede_prior_outcome(result, {"unit.c:f": other}, "unit.c:f",
        occurrence=("unit.c", "f", 6 if selection == "missing" else 2))
    assert removed is None
    assert (tuple(result.outcomes), result.reviewed, result.suspicious, result.total_cost_usd) == before
