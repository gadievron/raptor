"""Returned transport/error states cannot replace an owned assessment."""

import pytest

from core.audit import orchestrator as orch
from core.audit.tests.test_study_claim_retention import _knowledge_reassess


@pytest.mark.parametrize("status", ["error", "deferred"])
def test_owned_study_rejects_failed_assessment_and_retains_observation_and_spend(
    tmp_path, status,
):
    target, out = tmp_path / "target", tmp_path / "out"
    target.mkdir()
    out.mkdir()
    (target / "owned.c").write_text("unsigned f(unsigned value) { return value + 1; }\n")
    config = orch.OrchestratorConfig(target_path=target, out_dir=out,
        sweep_validate_findings=False, enable_session_context=False,
        joern_overrides={"enabled": False})
    prior = orch.ReviewOutcome("owned.c", "f", "clean", "Prior canonical assessment", line=1)
    result = orch.OrchestratorResult(outcomes=[prior], reviewed=1, clean=1, total_cost_usd=.5)
    checklist = {"files": [{"path": "owned.c", "items": [
        {"name": "f", "line_start": 1, "line_end": 1}]}]}
    case = {"config": config, "prior": prior, "result": result, "checklist": checklist, "calls": []}
    candidate = orch.ReviewOutcome("owned.c", "f", status,
        "Unpublished raw concern", line=1, cost_usd=.25, error_class="api_error")
    runtime = _knowledge_reassess(case, candidate)
    assert result.outcomes == [prior] and result.outcomes[0] is prior
    assert result.reviewed == result.clean == 1
    assert result.total_cost_usd == pytest.approx(.75)
    assert any(event.get("reason") == "study_assessment_failed" for event in runtime.events())
    observations = [event for event in runtime.events() if event.get("event") == "review_assessment"]
    assert any(event.get("body") == "Unpublished raw concern" for event in observations)
    assert not any(event.get("event") == "continuation_completed" for event in runtime.events())
    runtime.close("test_complete")
