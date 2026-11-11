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


def test_knowledge_and_callee_share_two_continuation_rounds(owned):
    from core.concepts.subject_study import SubjectExplanation, SubjectMaterial, SubjectPacket

    _, cfg, runtime, _, _, result, prior, callee = owned
    ctx = {"file": "caller.py", "function": "caller", "line_start": 1,
           "line_end": 2, "source": SOURCE, "language": "python"}
    calls = []

    class KnowledgeClient:
        def generate_structured(self, prompt, schema, **kwargs):
            calls.append(prompt)
            response = {"status": "clean", "body": "Still provisional",
                        "relies_on": [{"callee": "callee", "assumption": "checks value"}]}
            if len(calls) == 1:
                response["reading_list"] = [{"subject": "caller", "resolution": "identifier",
                                             "context": "role of this supplied function"}]
            return StructuredResponse(result=response, raw="", cost=.25, model="scripted")

    review = make_review_fn(KnowledgeClient(), escalate_clean=False)
    owned_review = runtime.wrap_review(review)
    initial = owned_review(dict(ctx), cfg)
    initial.line = 1
    result.outcomes[0] = initial
    request, = runtime.requests()
    packet = runtime.bindings.bind(SubjectPacket((), (
        SubjectMaterial("caller-material", "caller.py", 1, "caller", SOURCE.rstrip(), False),)))
    assert len(packet.materials) == 1
    answer = SubjectExplanation(request.request_id, "partial", "Returns the supplied value.",
                                "Caller validation is not established.",
                                packet.materials, packet.materials)
    runtime.record_source_answers((answer,))
    first, = runtime.ready_continuations(admission=lambda: True)
    assert first.packet.explanations == (answer,)
    enriched = dict(ctx)
    assert runtime.enrich_context(enriched, first)
    owned_review(enriched, cfg)
    assert runtime.complete(first, enriched, published_status="clean")
    assert answer.explanation in calls[1]

    # A real callee helper dispatch is the second shared continuation. A clean
    # result preserves eligibility, allowing the third attempt to test the cap
    # rather than merely finding no clean caller to revisit.
    def callee_pass():
        return orch._callee_contract_requeue(result, cfg, review, checklist={}, context_map=None,
            fuzz_coverage=None, evidence_index={}, knowledge_runtime=runtime)

    assert callee_pass() == 0
    assert len(calls) == 3
    assert "Advisory prior callee assessment" in calls[2]
    assert result.outcomes[0].status == "clean"
    assert not runtime._active
    callee.hypothesis = "A distinct advisory assessment requiring another look"
    assert callee_pass() == 0
    assert len(calls) == 3
    events = runtime.events()
    assert len([e for e in events if e["event"] == "continuation_reserved"]) == 2
    offered = [e for e in events if e["event"] == "context_delta_offered"]
    assert len(offered) == 2 and offered[0]["context_id"] != offered[1]["context_id"]
    assert not runtime._active
    assert prior is not result.outcomes[0]


def test_valid_callee_review_publishes_after_durable_acknowledgement(owned):
    from core.coverage.journal import load_entries

    _, cfg, runtime, client, review, result, prior, _ = owned
    cfg.out_dir.mkdir()
    checklist = {"files": [{"path": "caller.py", "items": [
        {"name": "caller", "line_start": 1, "line_end": 2}]}]}
    assert orch._callee_contract_requeue(result, cfg, review, checklist=checklist,
        context_map=None, fuzz_coverage=None, evidence_index={}, knowledge_runtime=runtime) == 1
    assert client.calls == 1
    assert result.outcomes[0] is not prior
    assert result.outcomes[0].status == "suspicious"
    assert result.clean == 0 and result.suspicious == 2
    assert result.total_cost_usd == .25
    entry, = load_entries(cfg.out_dir)
    assert (entry.file, entry.function, entry.line_start, entry.verdict) == (
        "caller.py", "caller", 1, "suspicious")
    completed = [e for e in runtime.events() if e["event"] == "continuation_completed"]
    assert len(completed) == 1 and completed[0]["published_status"] == "suspicious"
    assert completed[0]["delivered_request_ids"]
    assert not runtime._active
