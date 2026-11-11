"""Actual deepen dispatch retains the shared invocation/publication owner."""
from __future__ import annotations

import pytest

from core.audit import llm_review, orchestrator as orch
from core.audit.knowledge_runtime import AuditKnowledgeRuntime
from core.audit.llm_review import make_review_fn
from core.llm.providers import StructuredResponse

SOURCE = "def caller(value):\n    return value\n"


@pytest.fixture
def actual(tmp_path, monkeypatch):
    (tmp_path / "caller.py").write_text(SOURCE)
    cfg = orch.OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path / "out",
        enable_session_context=False, immediate_verify=False, sweep_validate_findings=False)
    cfg.out_dir.mkdir()
    runtime = AuditKnowledgeRuntime(tmp_path, orch.StudyQueue(), deadline=float("inf"))
    calls = []
    class Client:
        def generate_structured(self, prompt, schema, **kwargs):
            calls.append(prompt)
            return StructuredResponse(result={"status": "suspicious", "body": "Unresolved concern",
                "hypothesis": "Validation needs inspection"}, raw="", cost=.25, model="scripted")
    review = make_review_fn(Client(), escalate_clean=False)
    prior = orch.ReviewOutcome(file="caller.py", function="caller", line=1, status="suspicious",
        body="Prior concern", hypothesis="Validation needs inspection", context_reduced=True,
        review_result={"body": "Prior concern"})
    result = orch.OrchestratorResult(outcomes=[prior], suspicious=1)
    checklist = {"files": [{"path": "caller.py", "items": [
        {"name": "caller", "line_start": 1, "line_end": 2}]}]}
    monkeypatch.setattr(orch, "_build_context", lambda *a, **k: {
        "file": "caller.py", "function": "caller", "line_start": 1, "line_end": 2,
        "source": SOURCE, "language": "python"})
    monkeypatch.setattr(llm_review, "_prompt_budget", lambda *a: 0)
    monkeypatch.setattr(orch, "_make_dispatch_gate", lambda *a, **k: None)
    monkeypatch.setattr(orch, "_check_budget", lambda *a: False)
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    def run():
        return orch._deepen_suspicious(result, cfg, review, checklist, None, None,
            [], None, set(), 0, None, {}, knowledge_runtime=runtime)
    return cfg, runtime, result, prior, calls, run


def test_actual_deepen_publishes_with_shared_owner(actual):
    cfg, runtime, result, prior, calls, run = actual
    assert run() is result
    assert len(calls) == 1
    assert result.outcomes[0] is not prior
    assert result.suspicious == 1 and result.total_cost_usd == .25
    assert not runtime._active
    assert any(e["event"] == "continuation_completed" for e in runtime.events())


def test_actual_deepen_journal_failure_preserves_prior(actual, monkeypatch):
    import core.audit.collector as collector
    monkeypatch.setattr(collector, "append_journal_for_outcome", lambda *a, **k: None)
    _, runtime, result, prior, calls, run = actual
    run()
    assert len(calls) == 1
    assert result.outcomes[0] is prior
    assert result.suspicious == 1 and result.total_cost_usd == .25
    assert not runtime._active


def test_fresh_deepen_does_not_inherit_prior_claim_receipt(actual):
    _, _, result, prior, _, run = actual
    prior.evidence_tool = "semgrep"
    prior.hypothesis = "A different earlier concern"
    run()
    assert result.outcomes[0] is not prior
    assert result.outcomes[0].hypothesis != prior.hypothesis
    assert not result.outcomes[0].evidence_tool


@pytest.mark.slow
def test_actual_pipeline_keeps_runtime_open_through_deepen(tmp_path, monkeypatch):
    import json
    from core.audit import capabilities
    from core.testing.audit_shutdown import isolated_audit_shutdown
    from core.testing.wallclock import wall_deadline

    target, out = tmp_path / "target", tmp_path / "out"
    target.mkdir()
    out.mkdir()
    source = "def reviewed(value):\n" + "    value += 1\n" * 28 + "    return value\n"
    (target / "unit.py").write_text(source)
    checklist = {"files": [{"path": "unit.py", "items": [
        {"name": "reviewed", "kind": "function", "line_start": 1, "line_end": 30}]}]}
    (out / "checklist.json").write_text(json.dumps(checklist))
    monkeypatch.setattr(orch, "_run_mechanical_detectors", lambda *a, **k: ({}, set()))
    monkeypatch.setattr(orch, "_proactive_validate", lambda outcome, *a, **k: outcome)
    monkeypatch.setattr(capabilities, "probe_capabilities", lambda *a, **k: capabilities.AuditCapabilities())
    prompts = []
    class Client:
        def is_budget_exhausted(self):
            return False
        def generate_structured(self, prompt, schema, **kwargs):
            prompts.append(prompt)
            return StructuredResponse(result={"status": "suspicious", "body": "Unresolved concern",
                "hypothesis": "Validation needs inspection"}, raw="", cost=0, model="scripted")
    client = Client()
    monkeypatch.setattr(orch, "_run_llm_client", lambda cfg: client)
    config = orch.OrchestratorConfig(target_path=target, out_dir=out, inventory=checklist,
        max_workers=1, batch_sloc_threshold=0, resume=False, prefilter=False, validate=False,
        immediate_verify=False, sweep_validate_findings=False, max_refinements=0,
        deepen_suspicious=True, open_discovery=False, sage_recall=False, iris=False,
        adversarial=False, joern_overrides={"enabled": False}, llm_budget_client=client)
    with isolated_audit_shutdown(orch), wall_deadline(30, code_bound_s=float("inf"), what="owned deepen pipeline"):
        result = orch.run_orchestrator(config, make_review_fn(client, escalate_clean=False))
    assert len(prompts) == 2
    assert "Selection policy: deepen-quality-v1" in prompts[1]
    assert len(result.outcomes) == 1
    trace = json.loads((out / "knowledge-results.json").read_text())
    completed = [event for event in trace["events"] if event["event"] == "continuation_completed"]
    assert len(completed) == 1 and completed[0]["delivered_request_ids"]
    assert trace["units"][0]["all_model_calls"] == 2
