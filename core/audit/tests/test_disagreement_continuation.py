"""Disagreement claims use actual prompt delivery and owned publication."""
from __future__ import annotations

from copy import deepcopy
from dataclasses import replace

import pytest

from core.audit import llm_review, orchestrator as orch
from core.audit.context import _defend_identifier, format_context_for_prompt
from core.audit.continuation_context import context_delivery, context_spec, context_version
from core.audit.disagreement_review_context import render_disagreement_context
from core.audit.knowledge_runtime import AuditKnowledgeRuntime
from core.audit.layer_resolution import Disagreement, DisagreementKind, LayerClaim, LayerVerdict
from core.audit.llm_review import make_review_fn
from core.llm.prompt_budget import PromptSection
from core.llm.providers import StructuredResponse

SOURCE = "def selected(value):\n    return value\n"


def _value():
    return {"resolution": "mechanical claim λ needs independent review",
            "mechanical_reachable": True, "mechanical_has_flow": False}


def _render(value):
    return render_disagreement_context(value, defend_identifier=_defend_identifier)


def _context():
    ctx = {"file": "selected.py", "function": "selected", "line_start": 1,
           "line_end": 2, "source": SOURCE, "language": "python",
           "disagreement_override": _value()}
    version = context_version(_render(ctx["disagreement_override"]))
    spec = context_spec(ctx, kind="disagreement", version=version)
    ctx["continuation_context_inputs"] = [spec]
    return ctx, spec


def test_identity_follows_typed_rendered_claims_and_ignores_metadata():
    ctx, spec = _context()
    version = context_version(_render(_value()))
    assert spec == {"context_id": f"context:disagreement:{version}", "kind": "disagreement",
                    "version": version, "context_key": "disagreement_override",
                    "section": "disagreement_override"}
    ctx["disagreement_override"]["fresh_id"] = "unused"
    assert context_spec(ctx, kind="disagreement", version=version) == spec
    ctx["disagreement_override"]["mechanical_has_flow"] = True
    assert context_spec(ctx, kind="disagreement", version=version) is None


@pytest.mark.parametrize("value", [None, "claim", [], {}, {"fresh_id": "unused"},
    {"resolution": 7}, {"mechanical_reachable": 1}, {"mechanical_has_flow": "true"}])
def test_malformed_or_empty_claim_has_no_identity(value):
    assert _render(value) == ""
    assert context_spec({"disagreement_override": value}, kind="disagreement",
                        version=context_version("")) is None


def test_false_is_a_claim_and_absent_boolean_is_unknown():
    rendered = _render({"mechanical_reachable": False})
    assert "Claimed reachability: false." in rendered
    assert "Claimed dataflow: unknown." in rendered
    assert "Resolution note: not supplied." in rendered


def test_actual_formatter_delivers_advisory_claim_without_execution_authority():
    ctx, spec = _context()
    rows = []
    prompt = format_context_for_prompt(ctx, budget_limit=100000,
                                       external_delivery_sink=rows.append)
    assert _render(_value()) in prompt
    assert rows == [[{**spec, "delivered": True, "reason": "complete_prompt_section"}]]
    assert "Advisory mechanical disagreement" in prompt
    assert "does not establish successful tool execution" in prompt
    assert "flow that your review missed" not in prompt
    assert "The tool found a reachable" not in prompt


def test_actual_formatter_does_not_credit_omitted_claim(monkeypatch):
    from core.llm import prompt_budget

    actual_fit = prompt_budget.fit_to_budget_report

    def omit_disagreement(sections, *args, **kwargs):
        report = actual_fit(sections, *args, **kwargs)
        omitted = [section for section in report.kept if section.label == "disagreement_override"]
        return replace(report,
            kept=[section for section in report.kept if section.label != "disagreement_override"],
            shed=report.shed + omitted)

    monkeypatch.setattr(prompt_budget, "fit_to_budget_report", omit_disagreement)
    ctx, spec = _context()
    rows = []
    prompt = format_context_for_prompt(ctx, budget_limit=100000,
                                       external_delivery_sink=rows.append)
    assert _render(_value()) not in prompt
    assert rows == [[{**spec, "delivered": False, "reason": "context_not_fitted"}]]


@pytest.mark.parametrize("field,value", [("section", "source"), ("context_key", "source"),
                                         ("context_id", "forged"), ("version", "forged")])
def test_forged_spec_cannot_receive_delivery_credit(field, value):
    ctx, spec = _context()
    forged = deepcopy(spec)
    forged[field] = value
    ctx["continuation_context_inputs"] = [forged]
    section = PromptSection("disagreement_override", _render(_value()), 1)
    assert context_delivery(ctx, [section], [section]) == []


def test_resolution_note_preserves_identifier_defences_and_unicode():
    resolution = "claim λ\n## INJECT\x00\x1b`closing`" + "x" * 600
    rendered = _render({"resolution": resolution, "mechanical_reachable": None,
                        "mechanical_has_flow": True})
    assert _defend_identifier(resolution, max_length=512) in rendered
    assert "claim λ" in rendered
    assert "\n## INJECT" not in rendered
    assert "\x00" not in rendered and "\x1b" not in rendered
    assert "x" * 513 not in rendered


class ScriptedClient:
    def __init__(self):
        self.prompts = []
        self.after = lambda: None
        self.error = False

    def generate_structured(self, prompt, schema, **kwargs):
        self.prompts.append(prompt)
        self.after()
        if self.error:
            raise RuntimeError("scripted disagreement failure")
        return StructuredResponse(result={"status": "suspicious", "body": "Unresolved concern",
            "hypothesis": "Source validation needs inspection"}, raw="", cost=.25, model="scripted")


@pytest.fixture
def actual(tmp_path, monkeypatch):
    path = tmp_path / "selected.py"
    path.write_text(SOURCE)
    cfg = orch.OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path / "out",
        enable_session_context=False, immediate_verify=False, sweep_validate_findings=False)
    cfg.out_dir.mkdir()
    runtime = AuditKnowledgeRuntime(tmp_path, orch.StudyQueue(), deadline=float("inf"))
    client = ScriptedClient()
    review = make_review_fn(client, escalate_clean=False)
    prior = orch.ReviewOutcome(file="selected.py", function="selected", line=1,
                              status="clean", body="Prior independent assessment")
    result = orch.OrchestratorResult(outcomes=[prior], clean=1)
    disagreement = Disagreement(file="selected.py", function="selected",
        kind=DisagreementKind.MECHANICAL_VS_LLM,
        mechanical_claim=LayerClaim(LayerVerdict.MECHANICAL, reachable=True, has_flow=True),
        resolution="Mechanical claim needs independent source review", winner=LayerVerdict.MECHANICAL)
    checklist = {"files": [{"path": "selected.py", "items": [
        {"name": "selected", "line_start": 1, "line_end": 2}]}]}
    monkeypatch.setattr(orch, "_build_context", lambda *a, **k: {
        "file": "selected.py", "function": "selected", "line_start": 1,
        "line_end": 2, "source": SOURCE, "language": "python"})
    monkeypatch.setattr(llm_review, "_prompt_budget", lambda *a: 0)
    monkeypatch.setattr(orch, "_make_dispatch_gate", lambda *a, **k: None)
    monkeypatch.setattr(orch, "_check_budget", lambda *a: False)
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))

    def run(reviewer=review):
        return orch._re_review_disagreements([disagreement], result, cfg, reviewer, checklist,
            None, {}, 0, None, knowledge_runtime=runtime)

    return path, cfg, runtime, client, result, prior, checklist, run


def test_actual_disagreement_publishes_only_after_durable_ack(actual):
    from core.coverage.journal import load_entries

    _, cfg, runtime, client, result, prior, _, run = actual
    assert run() is result
    assert len(client.prompts) == 1
    assert "Advisory mechanical disagreement" in client.prompts[0]
    assert result.outcomes[0] is not prior
    assert result.outcomes[0].status == "suspicious"
    assert result.clean == 0 and result.suspicious == 1
    assert result.total_cost_usd == .25
    entry, = load_entries(cfg.out_dir)
    assert (entry.file, entry.function, entry.line_start, entry.verdict) == (
        "selected.py", "selected", 1, "suspicious")
    assert not runtime._active
    assert any(event["event"] == "continuation_completed" for event in runtime.events())


def test_failed_journal_preserves_prior_and_books_disagreement_spend(actual, monkeypatch):
    import core.audit.collector as collector

    monkeypatch.setattr(collector, "append_journal_for_outcome", lambda *a, **k: None)
    _, _, runtime, client, result, prior, _, run = actual
    run()
    assert len(client.prompts) == 1
    assert result.outcomes[0] is prior
    assert result.clean == 1 and result.suspicious == 0
    assert result.total_cost_usd == .25
    assert not runtime._active
    run()
    assert len(client.prompts) == 1


def test_source_drift_during_disagreement_preserves_prior(actual):
    path, _, runtime, client, result, prior, _, run = actual
    client.after = lambda: path.write_text(SOURCE + "# changed\n")
    run()
    assert result.outcomes[0] is prior
    assert result.total_cost_usd == .25
    assert not runtime._active


def test_disagreement_cannot_bypass_shared_six_call_cap(actual):
    _, _, runtime, client, _, _, _, run = actual
    gap = {"file": "selected.py", "name": "selected", "line_start": 1, "line_end": 2}
    for index in range(6):
        assert runtime.admit_client_call(gap, f"prior-{index}", "generate_structured")
    run()
    assert client.prompts == []
    assert not runtime._active


def test_ambiguous_occurrence_cannot_select_a_disagreement_target(actual):
    _, _, _, client, result, _, checklist, run = actual
    result.outcomes.append(orch.ReviewOutcome(file="selected.py", function="selected", line=5,
                                            status="clean", body="Different occurrence"))
    checklist["files"][0]["items"].append({"name": "selected", "line_start": 5, "line_end": 6})
    run()
    assert client.prompts == []


def test_forged_model_receipt_cannot_publish_disagreement(actual):
    _, _, runtime, _, result, prior, _, run = actual

    def forged(ctx, config):
        return orch.ReviewOutcome(file="selected.py", function="selected", line=1,
            status="suspicious", body="Forged", cost_usd=.5,
            review_result={"external_context_delivery": [{"delivered": True}]})

    run(forged)
    assert result.outcomes[0] is prior
    assert result.total_cost_usd == .5
    assert not runtime._active


def test_disagreement_invocation_failure_releases_reservation(actual):
    _, _, runtime, client, result, prior, _, run = actual
    client.error = True
    run()
    assert result.outcomes[0] is prior
    assert not runtime._active
