"""A failed review cannot escape run ownership through the legacy retry pass."""

from time import monotonic

import pytest

from core.audit import orchestrator as orch
from core.audit.knowledge_runtime import AuditKnowledgeRuntime


@pytest.mark.parametrize("journal_failure", [False, True])
@pytest.mark.parametrize("closed", [False, True])
@pytest.mark.parametrize("error_class", ["json_parse", "truncation", "api_error", "timeout"])
def test_owned_failed_review_is_retained_without_unbound_recovery(
    tmp_path, monkeypatch, closed, error_class, journal_failure,
):
    source = tmp_path / "unit.py"
    source.write_text("def unit():\n    return 1\n")
    runtime = AuditKnowledgeRuntime(tmp_path, orch.StudyQueue(), deadline=float("inf"))
    context = {
        "file": "unit.py", "function": "unit", "line_start": 1,
        "line_end": 2, "source": source.read_text(), "language": "python",
    }

    def fail_initial(ctx, config):
        raise TimeoutError("scripted initial failure")

    config = orch.OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path / "out")
    config.out_dir.mkdir()
    with pytest.raises(TimeoutError):
        runtime.wrap_review(fail_initial)(context, config)
    if closed:
        runtime.close("review_context_complete")
    events_before = runtime.events()
    assert any(event.get("event") == "review_failed" for event in events_before)

    # Current bytes cannot retroactively bind the failed attempt's inputs.
    source.write_text("def unit():\n    return 2\n")
    prior = orch.ReviewOutcome(
        file="unit.py", function="unit", line=1, status="error",
        body="Original failure", error_class=error_class,
        review_result={"retained_detail": "original"}, cost_usd=0.125,
    )
    result = orch.OrchestratorResult()
    orch._tally_outcome(result, prior)
    result.cost_tracker.record_call("review", cost_usd=0.125)
    counts_before = dict(result.error_counts)
    cost_before = result.cost_tracker.to_dict()

    def forbidden(*args, **kwargs):
        pytest.fail("unbound recovery must stop before context rebuild or dispatch")

    if journal_failure:
        def failed_journal(*args, **kwargs):
            raise OSError("scripted decision journal failure")
        monkeypatch.setattr(orch, "append_audit_log", failed_journal)
    monkeypatch.setattr(orch, "_build_context", forbidden)
    monkeypatch.setattr(orch, "_make_dispatch_gate", forbidden)
    returned = orch._retry_error_outcomes(
        result, config, forbidden, {}, None, None, monotonic(), None,
        knowledge_runtime=runtime,
    )
    assert returned is result
    assert result.outcomes == [prior]
    assert prior.status == "error" and prior.body == "Original failure"
    assert prior.review_result == {
        "retained_detail": "original",
        "review_recovery": {
            "status": "deferred", "reason": "original_failed_input_scope_unavailable",
        },
    }
    assert result.errors == 1 and result.error_counts == counts_before
    assert result.error_retries == result.error_retry_recovered == 0
    assert result.cost_tracker.to_dict() == cost_before
    assert runtime.events() == events_before
    if not journal_failure:
        from core.audit.record import load_verified_audit_log
        decisions = load_verified_audit_log(config.out_dir)
        assert len(decisions) == 1
        assert decisions[0]["action"] == "error_recovery_deferred"
        assert decisions[0]["adjudication"] == "unverified"
        assert decisions[0]["line_start"] == 1
    runtime.close("test_complete")


@pytest.mark.slow
def test_actual_pipeline_does_not_retry_outside_closed_owner(tmp_path, monkeypatch):
    from core.audit.tests.test_live_sink_pipeline import execute, setup_pipeline

    config = setup_pipeline(tmp_path, monkeypatch)
    calls = []

    class Client:
        def is_budget_exhausted(self):
            return False

    def failed_review(ctx, cfg):
        calls.append((ctx["file"], ctx["function"]))
        raise ConnectionError("scripted initial failure")

    result = execute(config, Client(), monkeypatch, failed_review)
    assert calls == [("unit.py", "caller")]
    assert result.errors == 1 and result.error_retries == 0
    assert result.outcomes[0].error_class == "api_error"
    assert result.outcomes[0].review_result["review_recovery"] == {
        "status": "deferred", "reason": "original_failed_input_scope_unavailable",
    }
