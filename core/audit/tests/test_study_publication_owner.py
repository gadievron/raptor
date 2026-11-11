"""Missing continuation ownership cannot fall through to journal publication."""

import pytest

from core.audit import collector, orchestrator as orch
from core.audit.knowledge_runtime import AuditKnowledgeRuntime


@pytest.mark.parametrize("runtime_present", [False, True])
def test_missing_study_publication_owner_retains_prior_without_journal(
    tmp_path, monkeypatch, runtime_present,
):
    config = orch.OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path)
    runtime = AuditKnowledgeRuntime(tmp_path, orch.StudyQueue(), deadline=float("inf")) if runtime_present else None
    prior = orch.ReviewOutcome(file="unit.py", function="unit", line=1,
        status="suspicious", body="Prior canonical assessment", cost_usd=.2)
    candidate = orch.ReviewOutcome(file="unit.py", function="unit", line=1,
        status="clean", body="Unacknowledged proposal", cost_usd=.125)
    result = orch.OrchestratorResult()
    orch._tally_outcome(result, prior)
    before = (result.reviewed, result.suspicious, result.clean, result.total_cost_usd)

    def forbidden(*args, **kwargs):
        pytest.fail("missing publication ownership reached journal append")

    monkeypatch.setattr(collector, "append_journal_for_outcome", forbidden)
    disposition = orch._publish_study_outcome(config, result, runtime, None,
        prior, candidate, {"file": "unit.py", "name": "unit", "line_start": 1, "line_end": 2})
    assert disposition == "study_publication_owner_unavailable"
    assert result.outcomes == [prior]
    assert (result.reviewed, result.suspicious, result.clean, result.total_cost_usd) == before
    if runtime is not None:
        assert not runtime.events()
        runtime.close("test_complete")
