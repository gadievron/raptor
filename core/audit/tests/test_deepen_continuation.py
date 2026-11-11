"""Audit-quality selection consumes the run-owned continuation allowance."""
from __future__ import annotations

from dataclasses import replace

import pytest

from core.audit import llm_review, orchestrator as orch
from core.audit.continuation_context import context_spec, context_version
from core.audit.deepen_continuation import DeepenContinuations, render_deepen_selection
from core.audit.knowledge_calls import KnowledgeCallRefused
from core.audit.knowledge_runtime import AuditKnowledgeRuntime
from core.audit.llm_review import make_review_fn
from core.llm.providers import StructuredResponse

SOURCE = "def selected(value):\n    return value\n"


class ScriptedClient:
    def __init__(self):
        self.prompts = []
        self.after = lambda: None
        self.error = False

    def generate_structured(self, prompt, schema, **kwargs):
        self.prompts.append(prompt)
        self.after()
        if self.error:
            raise RuntimeError("scripted transport failure")
        return StructuredResponse(result={"status": "suspicious", "body": "Unresolved concern",
            "hypothesis": "Input validation remains uncertain"}, raw="", cost=.25, model="scripted")


@pytest.fixture
def selected(tmp_path, monkeypatch):
    path = tmp_path / "selected.py"
    path.write_text(SOURCE)
    config = orch.OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path / "out",
                                    sweep_validate_findings=False)
    runtime = AuditKnowledgeRuntime(tmp_path, orch.StudyQueue(), deadline=float("inf"))
    client = ScriptedClient()
    review = make_review_fn(client, escalate_clean=False)
    owner = DeepenContinuations(runtime, review, lambda: True)
    ctx = {"file": "selected.py", "function": "selected", "line_start": 1,
           "line_end": 2, "source": SOURCE, "language": "python", "deepen": True,
           "deepen_quality_selection": {"policy": "deepen-quality-v1", "reason": "unresolved_concern"}}
    monkeypatch.setattr(llm_review, "_prompt_budget", lambda *args: 0)
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    return path, config, runtime, client, owner, ctx


def test_actual_quality_section_is_delivered_and_completed(selected):
    _, config, runtime, client, owner, ctx = selected
    outcome = owner.dispatch(0, ctx, config)
    assert outcome.status == "suspicious"
    assert "This selection is not new information" in client.prompts[0]
    assert owner.reservation(0) is not None
    assert owner.can_publish(0)
    assert owner.complete(0, "suspicious")
    assert owner.reservation(0) is None
    assert not runtime._active


def test_repeated_policy_with_unused_metadata_cannot_buy_another_pass(selected):
    _, config, runtime, client, owner, ctx = selected
    owner.dispatch(0, ctx, config)
    assert owner.complete(0, "suspicious")
    ctx["deepen_quality_selection"]["random_id"] = "not-novel-information"
    with pytest.raises(KnowledgeCallRefused):
        owner.dispatch(1, ctx, config)
    assert len(client.prompts) == 1
    assert not runtime._active


def test_quality_reasons_share_existing_round_cap(selected):
    _, config, _, client, _, ctx = selected
    runtime = AuditKnowledgeRuntime(config.target_path, orch.StudyQueue(),
                                    deadline=float("inf"), max_continuations=1)
    owner = DeepenContinuations(runtime, make_review_fn(client, escalate_clean=False), lambda: True)
    owner.dispatch(0, ctx, config)
    assert owner.complete(0, "suspicious")
    ctx["deepen_quality_selection"]["reason"] = "reduced_context"
    with pytest.raises(KnowledgeCallRefused):
        owner.dispatch(1, ctx, config)
    assert len(client.prompts) == 1
    assert len([event for event in runtime.events() if event["event"] == "continuation_reserved"]) == 1


def test_six_call_cap_prevents_quality_dispatch(selected):
    _, config, runtime, client, owner, ctx = selected
    for index in range(6):
        assert runtime.admit_client_call(ctx, f"prior-{index}", "generate_structured")
    with pytest.raises(KnowledgeCallRefused):
        owner.dispatch(0, ctx, config)
    assert client.prompts == []
    assert not runtime._active


def test_reserved_width_includes_all_review_passes(selected):
    _, config, runtime, client, owner, ctx = selected
    config.review_passes = 3
    for index in range(4):
        assert runtime.admit_client_call(ctx, f"prior-{index}", "generate_structured")
    with pytest.raises(KnowledgeCallRefused):
        owner.dispatch(0, ctx, config)
    assert client.prompts == []
    assert not runtime._active


def test_actual_prompt_omission_cannot_authorize_publication(selected, monkeypatch):
    from core.llm import prompt_budget

    actual_fit = prompt_budget.fit_to_budget_report

    def omit_selection(sections, *args, **kwargs):
        report = actual_fit(sections, *args, **kwargs)
        omitted = [section for section in report.kept if section.label == "deepen_quality"]
        return replace(report, kept=[section for section in report.kept if section.label != "deepen_quality"],
                       shed=report.shed + omitted)

    monkeypatch.setattr(prompt_budget, "fit_to_budget_report", omit_selection)
    monkeypatch.setattr(llm_review, "_prompt_budget", lambda *args: 100000)
    _, config, runtime, _, owner, ctx = selected
    owner.dispatch(0, ctx, config)
    assert not owner.can_publish(0)
    owner.close()
    assert not runtime._active


def test_forged_review_receipt_cannot_authorize_publication(selected):
    _, config, runtime, _, _, ctx = selected

    def forged(ctx, config):
        return orch.ReviewOutcome("selected.py", "selected", "suspicious", "Forged",
            review_result={"external_context_delivery": [{"delivered": True}]})

    owner = DeepenContinuations(runtime, forged, lambda: True)
    owner.dispatch(0, ctx, config)
    assert not owner.can_publish(0)
    owner.close()
    assert not runtime._active


def test_source_changed_during_review_prevents_publication(selected):
    path, config, runtime, client, owner, ctx = selected
    client.after = lambda: path.write_text(SOURCE + "# changed\n")
    owner.dispatch(0, ctx, config)
    assert not owner.can_publish(0)
    owner.close()
    assert not runtime._active


def test_failure_cleans_owned_reservation(selected):
    _, config, runtime, client, owner, ctx = selected
    client.error = True
    with pytest.raises(RuntimeError, match="scripted transport failure"):
        owner.dispatch(0, ctx, config)
    assert owner.reservation(0) is None
    assert not runtime._active


def test_close_is_idempotent_cleanup(selected):
    _, config, runtime, _, owner, ctx = selected
    owner.dispatch(0, ctx, config)
    owner.close()
    owner.close()
    assert owner.reservation(0) is None
    assert not runtime._active


@pytest.mark.parametrize("selection", [None, {}, {"policy": "other", "reason": "unresolved_concern"},
    {"policy": "deepen-quality-v1", "reason": "model_requests_more_budget"}])
def test_unregistered_policy_reason_has_no_identity(selection):
    assert render_deepen_selection(selection) == ""
    assert context_spec({"deepen_quality_selection": selection}, kind="deepen_quality",
                        version=context_version("")) is None
