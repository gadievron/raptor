"""A returned failed assessment is not a new canonical review judgment."""
from dataclasses import replace

import pytest

from core.audit import llm_review, orchestrator as orch
from core.audit.knowledge_runtime import AuditKnowledgeRuntime
from core.audit.layer_resolution import Disagreement, DisagreementKind, LayerClaim, LayerVerdict
from core.audit.llm_review import make_review_fn
from core.llm.providers import StructuredResponse

SOURCE = "def reviewed(value):\n    return value\n"


@pytest.mark.parametrize("stage", ["callee", "deepen", "disagreement"])
def test_returned_failure_preserves_prior_and_failed_round(stage, tmp_path, monkeypatch):
    (tmp_path / "unit.py").write_text(SOURCE)
    cfg = orch.OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path / "out",
        enable_session_context=False, propagate_constraints=False,
        immediate_verify=False, sweep_validate_findings=False)
    cfg.out_dir.mkdir()
    runtime = AuditKnowledgeRuntime(tmp_path, orch.StudyQueue(), deadline=float("inf"))
    calls = []
    class Client:
        def generate_structured(self, prompt, schema, **kwargs):
            calls.append(prompt)
            return StructuredResponse(result={"status": "suspicious", "body": "Fresh raw concern",
                "hypothesis": "Raw concern retained for investigation"}, raw="", cost=.25, model="scripted")
    rendered = make_review_fn(Client(), escalate_clean=False)
    def failed_assessment(ctx, config):
        outcome = rendered(ctx, config)
        return replace(outcome, status="error", body="Assessment adapter could not produce a judgment")
    failed_assessment._knowledge_observed_client_contract = True
    prior = orch.ReviewOutcome("unit.py", "reviewed", "suspicious" if stage == "deepen" else "clean",
        "Prior independent judgment", line=1, context_reduced=stage == "deepen",
        review_result={"body": "Prior independent judgment",
                       "relies_on": [{"callee": "callee", "assumption": "checks the argument"}]})
    result = orch.OrchestratorResult(outcomes=[prior],
        clean=int(prior.status == "clean"), suspicious=int(prior.status == "suspicious"))
    checklist = {"files": [{"path": "unit.py", "items": [
        {"name": "reviewed", "line_start": 1, "line_end": 2}]}]}
    monkeypatch.setattr(llm_review, "_prompt_budget", lambda *a: 0)
    monkeypatch.setattr(orch, "_build_context", lambda *a, **k: {
        "file": "unit.py", "function": "reviewed", "line_start": 1, "line_end": 2,
        "source": SOURCE, "language": "python"})
    monkeypatch.setattr(orch, "_make_dispatch_gate", lambda *a, **k: None)
    monkeypatch.setattr(orch, "_check_budget", lambda *a: False)
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    if stage == "callee":
        result.outcomes.append(orch.ReviewOutcome("callee.py", "callee", "suspicious", "Prior callee concern", line=1))
        result.suspicious += 1
        orch._callee_contract_requeue(result, cfg, failed_assessment, checklist=checklist,
            context_map=None, fuzz_coverage=None, evidence_index={}, knowledge_runtime=runtime)
    elif stage == "deepen":
        orch._deepen_suspicious(result, cfg, failed_assessment, checklist, None, None,
            [], None, set(), 0, None, {}, knowledge_runtime=runtime)
    else:
        disagreement = Disagreement(file="unit.py", function="reviewed",
            kind=DisagreementKind.MECHANICAL_VS_LLM,
            mechanical_claim=LayerClaim(LayerVerdict.MECHANICAL, reachable=True),
            resolution="Controlled advisory signal", winner=LayerVerdict.MECHANICAL)
        orch._re_review_disagreements([disagreement], result, cfg, failed_assessment,
            checklist, None, {}, 0, None, knowledge_runtime=runtime)
    assert len(calls) == 1
    assert result.outcomes[0] is prior
    assert result.total_cost_usd == .25
    assert not runtime._active
    assert not any(event["event"] == "continuation_completed" for event in runtime.events())
    assert any(event["event"] == "continuation_failed" for event in runtime.events())
    # Retain the failed invocation and proposed concern without upgrading it.
    assessment, = [event for event in runtime.events() if event["event"] == "review_assessment"]
    assert assessment["status"] == "error"
    assert assessment["hypothesis"] == "Raw concern retained for investigation"
