"""Callee-contract and graph propagation consume one canonical input union."""
from __future__ import annotations

import pytest

from core.audit import llm_review, orchestrator as orch
from core.audit.knowledge_runtime import AuditKnowledgeRuntime
from core.audit.llm_review import make_review_fn
from core.llm.providers import StructuredResponse

SOURCE = "def caller(value):\n    return value\n"


@pytest.fixture
def related(tmp_path, monkeypatch):
    (tmp_path / "caller.py").write_text(SOURCE)
    cfg = orch.OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path / "out",
        propagate_constraints=True, enable_session_context=False,
        immediate_verify=False, sweep_validate_findings=False)
    cfg.out_dir.mkdir()
    runtime = AuditKnowledgeRuntime(tmp_path, orch.StudyQueue(), deadline=float("inf"))
    relies = [{"callee": "a", "assumption": "checks the first input"},
              {"callee": "b", "assumption": "checks the second input"}]
    caller = orch.ReviewOutcome("caller.py", "caller", "clean", "Prior caller", line=1,
                               review_result={"relies_on": relies})
    a = orch.ReviewOutcome("a.py", "a", "suspicious", "Prior A", line=1, hypothesis="Concern A")
    b = orch.ReviewOutcome("b.py", "b", "suspicious", "Prior B", line=1, hypothesis="Concern B")
    result = orch.OrchestratorResult(outcomes=[caller, a, b], clean=1, suspicious=2)
    checklist = {"files": [{"path": "caller.py", "items": [
        {"name": "caller", "line_start": 1, "line_end": 2}]}]}
    context_map = {"call_edges": [
        {"caller_file": "caller.py", "caller": "caller", "callee_file": "a.py", "callee": "a"},
        {"caller_file": "caller.py", "caller": "caller", "callee_file": "b.py", "callee": "b"}]}
    class CapturedPrompts(list):
        def after(self):
            pass
    prompts = CapturedPrompts()
    class Client:
        def generate_structured(self, prompt, schema, **kwargs):
            prompts.append(prompt)
            prompts.after()
            return StructuredResponse(result={"status": "clean", "body": "Independent caller judgment",
                "relies_on": relies}, raw="", cost=.25, model="scripted")
    review = make_review_fn(Client(), escalate_clean=False)
    monkeypatch.setattr(llm_review, "_prompt_budget", lambda *a: 0)
    monkeypatch.setattr(orch, "_build_context", lambda *a, **k: {
        "file": "caller.py", "function": "caller", "line_start": 1, "line_end": 2,
        "source": SOURCE, "language": "python"})
    monkeypatch.setattr(orch, "_make_dispatch_gate", lambda *a, **k: None)
    monkeypatch.setattr(orch, "_check_budget", lambda *a: False)
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    def callee():
        return orch._callee_contract_requeue(result, cfg, review, checklist=checklist,
            context_map=context_map, fuzz_coverage=None, evidence_index={}, knowledge_runtime=runtime)
    def iterative():
        return orch._iterative_re_review(result, cfg, review, checklist, context_map,
            None, set(), [], None, None, 0, None, {}, knowledge_runtime=runtime)
    return cfg, runtime, result, caller, a, b, prompts, callee, iterative


def test_two_ready_callees_share_one_pass_across_stages(related):
    _, runtime, result, _, _, _, prompts, callee, iterative = related
    callee()
    assert len(prompts) == 1
    assert "Concern A" in prompts[0] and "Concern B" in prompts[0]
    assert iterative() is result
    assert len(prompts) == 1
    assert len([e for e in runtime.events() if e["event"] == "continuation_reserved"]) == 1
    assert not runtime._active


def test_new_assessment_revision_is_eligible_but_round_limit_stays_shared(related):
    _, runtime, _, _, a, b, prompts, callee, iterative = related
    callee()
    b.hypothesis = "A genuinely revised concern B"
    iterative()
    assert len(prompts) == 2 and b.hypothesis in prompts[1]
    a.hypothesis = "A further revised concern A"
    iterative()
    assert len(prompts) == 2
    assert len([e for e in runtime.events() if e["event"] == "continuation_reserved"]) == 2
    assert not runtime._active


def test_failed_publication_cannot_buy_same_information_under_iterative_name(related, monkeypatch):
    import core.audit.collector as collector
    monkeypatch.setattr(collector, "append_journal_for_outcome", lambda *a, **k: None)
    _, runtime, result, caller, _, _, prompts, callee, iterative = related
    callee()
    iterative()
    assert len(prompts) == 1
    assert result.outcomes[0] is caller
    assert result.total_cost_usd == .25
    assert not runtime._active


def _original_scope(cfg, outcome):
    from core.audit.knowledge_requests import KnowledgeOrigin
    from core.audit.refutation_source import capture_source_identity
    from core.audit.review_context_inputs import context_inputs_from_sources, context_inputs_record_digest
    from core.audit.review_input_scope import CapturedReviewInput, ReviewInputScope

    path = cfg.target_path / outcome.file
    path.write_text(f"def {outcome.function}(value):\n    return value\n")
    identity = capture_source_identity(cfg.target_path, outcome.file)
    origin = KnowledgeOrigin("original-assessment", outcome.file, outcome.function, 1, 2, identity)
    manifest = context_inputs_from_sources([("target", outcome.file, identity.sha256)], complete=True)
    outcome.review_input_scope = ReviewInputScope(origin, context_inputs_record_digest(manifest), (
        CapturedReviewInput("target", cfg.target_path.resolve(), outcome.file, identity),))
    return path


def test_stale_contributor_does_not_block_fresh_advisory_sibling(related):
    cfg, runtime, _, _, a, b, prompts, callee, _ = related
    _original_scope(cfg, a)
    path = _original_scope(cfg, b)
    path.write_text("def b(value):\n    return None\n")
    callee()
    assert len(prompts) == 1
    assert "Concern A" in prompts[0] and "Concern B" not in prompts[0]
    assert not runtime._active


def test_any_delivered_contributor_source_drift_blocks_publication(related):
    cfg, runtime, result, caller, a, b, prompts, callee, _ = related
    _original_scope(cfg, a)
    path = _original_scope(cfg, b)
    prompts.after = lambda: path.write_text("def b(value):\n    return None\n")
    callee()
    assert len(prompts) == 1
    assert "Concern A" in prompts[0] and "Concern B" in prompts[0]
    assert result.outcomes[0] is caller
    assert result.total_cost_usd == .25
    assert not runtime._active
