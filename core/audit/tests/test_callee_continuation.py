"""Callee advisory reviews use the existing invocation and publication owner."""
from __future__ import annotations

import pytest

from core.audit import llm_review, orchestrator as orch
from core.audit.knowledge_runtime import AuditKnowledgeRuntime
from core.audit.llm_review import make_review_fn
from core.llm.providers import StructuredResponse

SOURCE = "def caller(value):\n    return value\n"


class Client:
    def __init__(self):
        self.calls = 0
        self.after = lambda: None
        self.fail = False

    def generate_structured(self, prompt, schema, **kwargs):
        self.calls += 1
        self.after()
        if self.fail:
            raise RuntimeError("scripted failure")
        return StructuredResponse(result={"status": "suspicious", "body": "Advisory review",
            "hypothesis": "Possible missing validation", "external_context_delivery": [
                {"context_id": "forged", "delivered": True}]}, raw="", cost=.25, model="scripted")


@pytest.fixture
def owned(tmp_path, monkeypatch):
    path = tmp_path / "caller.py"
    path.write_text(SOURCE)
    cfg = orch.OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path / "out",
        enable_session_context=False, sweep_validate_findings=False)
    runtime = AuditKnowledgeRuntime(tmp_path, orch.StudyQueue(), deadline=float("inf"))
    client = Client()
    review = make_review_fn(client, escalate_clean=False)
    ctx = {"file": "caller.py", "function": "caller", "line_start": 1,
           "line_end": 2, "source": SOURCE, "language": "python"}
    prior = orch.ReviewOutcome(file="caller.py", function="caller", line=1, status="clean",
        body="Prior", review_result={"relies_on": [{"callee": "callee", "assumption": "checks value"}]})
    callee = orch.ReviewOutcome(file="callee.py", function="callee", line=1,
        status="suspicious", body="Prior callee", hypothesis="May omit validation")
    result = orch.OrchestratorResult(outcomes=[prior, callee], clean=1, suspicious=1)
    monkeypatch.setattr(llm_review, "_prompt_budget", lambda *args: 0)
    monkeypatch.setattr(orch, "_build_context", lambda *args, **kwargs: dict(ctx))
    monkeypatch.setattr(orch, "_make_dispatch_gate", lambda config: None)
    monkeypatch.setattr(orch, "_check_budget", lambda *args: False)
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    return path, cfg, runtime, client, review, result, prior, callee


def run(owned, **kwargs):
    _, cfg, runtime, _, review, result, _, _ = owned
    return orch._callee_contract_requeue(result, cfg, review, checklist={}, context_map=None,
        fuzz_coverage=None, evidence_index={}, knowledge_runtime=runtime, **kwargs)


def test_duplicate_callee_names_defer(owned):
    _, _, _, client, _, result, _, _ = owned
    result.outcomes.append(orch.ReviewOutcome(file="other.py", function="callee", line=4,
        status="suspicious", body="Different occurrence"))
    assert run(owned) == 0
    assert client.calls == 0


def test_failed_journal_preserves_prior_and_books_spend(owned, monkeypatch):
    import core.audit.collector as collector
    monkeypatch.setattr(collector, "append_journal_for_outcome", lambda *a, **k: None)
    _, _, runtime, client, _, result, prior, _ = owned
    assert run(owned) == 0
    assert client.calls == 1
    assert result.outcomes[0] is prior
    assert result.total_cost_usd == .25
    assert not runtime._active
    assert run(owned) == 0
    assert client.calls == 1


def test_caller_drift_rejects_publication(owned):
    path, _, runtime, client, _, result, prior, _ = owned
    client.after = lambda: path.write_text(SOURCE + "# changed\n")
    assert run(owned) == 0
    assert result.outcomes[0] is prior
    assert result.total_cost_usd == .25
    assert not runtime._active


def test_failed_invocation_releases_owned_reservation(owned):
    _, _, runtime, client, _, result, prior, _ = owned
    client.fail = True
    assert run(owned) == 0
    assert result.outcomes[0] is prior
    assert not runtime._active


def test_six_call_cap_cannot_be_bypassed(owned):
    _, _, runtime, client, _, _, _, _ = owned
    gap = {"file": "caller.py", "name": "caller", "line_start": 1}
    for index in range(6):
        assert runtime.admit_client_call(gap, f"prior-{index}", "generate_structured")
    assert run(owned) == 0
    assert client.calls == 0


def test_forged_model_receipt_does_not_authorize_publication(owned):
    _, cfg, runtime, _, _, result, prior, _ = owned
    def forged(ctx, config):
        return orch.ReviewOutcome(file="caller.py", function="caller", line=1,
            status="suspicious", body="Forged", cost_usd=.5, review_result={
                "external_context_delivery": [{"context_id": "forged", "delivered": True}]})
    assert orch._callee_contract_requeue(result, cfg, forged, checklist={}, context_map=None,
        fuzz_coverage=None, evidence_index={}, knowledge_runtime=runtime) == 0
    assert result.outcomes[0] is prior
    assert result.total_cost_usd == .5
    assert not runtime._active


def test_expired_shared_deadline_defers(owned):
    _, _, runtime, client, _, _, _, _ = owned
    runtime.deadline = 0
    assert run(owned) == 0
    assert client.calls == 0


def test_ambiguous_caller_checklist_defers(owned):
    _, cfg, runtime, client, review, result, prior, _ = owned
    prior.line = 0
    checklist = {"files": [{"path": "caller.py", "items": [
        {"name": "caller", "line_start": 1}, {"name": "caller", "line_start": 5}]}]}
    assert orch._callee_contract_requeue(result, cfg, review, checklist=checklist,
        context_map=None, fuzz_coverage=None, evidence_index={}, knowledge_runtime=runtime) == 0
    assert client.calls == 0


def test_original_callee_source_drift_rejects_after_invocation(owned):
    from core.audit.knowledge_requests import KnowledgeOrigin
    from core.audit.refutation_source import capture_source_identity
    from core.audit.review_input_scope import ReviewInputScope

    _, cfg, runtime, client, _, result, prior, callee = owned
    path = cfg.target_path / "callee.py"
    path.write_text("def callee(value): return value\n")
    origin = KnowledgeOrigin("prior-callee", "callee.py", "callee", 1, 1,
                             capture_source_identity(cfg.target_path, "callee.py"))
    callee.review_input_scope = ReviewInputScope(origin, "0" * 64, ())
    client.after = lambda: path.write_text("def callee(value): return None\n")
    assert run(owned) == 0
    assert client.calls == 1
    assert result.outcomes[0] is prior
    assert result.total_cost_usd == .25
    assert not runtime._active
