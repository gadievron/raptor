"""Callee continuation identity follows the actual fitted advisory section."""
from copy import deepcopy

import pytest

from core.audit.callee_review_context import render_callee_context
from core.audit.context import _defend_identifier, format_context_for_prompt
from core.audit.continuation_context import context_delivery, context_spec, context_version
from core.llm.prompt_budget import PromptSection


def _value():
    return {"callee": "parse_λ", "assumption": "validates input",
            "callee_status": "finding", "callee_hypothesis": "may accept invalid input"}


def _render(value):
    return render_callee_context(value, defend_identifier=_defend_identifier)


def _context():
    ctx = {"file": "x.c", "function": "f", "line_start": 1,
           "source": "int f(void) { return 0; }", "callee_contract_violation": _value()}
    version = context_version(_render(ctx["callee_contract_violation"]))
    spec = context_spec(ctx, kind="callee_contract", version=version)
    ctx["continuation_context_inputs"] = [spec]
    return ctx, spec


def test_exact_rendered_identity_and_metadata_independence():
    ctx, spec = _context()
    version = context_version(_render(_value()))
    assert spec == {"context_id": f"context:callee_contract:{version}",
                    "kind": "callee_contract", "version": version,
                    "context_key": "callee_contract_violation", "section": "callee_contract"}
    ctx["callee_contract_violation"]["uuid"] = "ignored-metadata"
    assert context_spec(ctx, kind="callee_contract", version=version) == spec
    ctx["callee_contract_violation"]["callee_hypothesis"] = "different assessment"
    assert context_spec(ctx, kind="callee_contract", version=version) is None


@pytest.mark.parametrize("value", [None, "assessment", [], {}, {"uuid": "metadata"}])
def test_invalid_input_has_no_identity(value):
    assert _render(value) == ""
    assert context_spec({"callee_contract_violation": value}, kind="callee_contract",
                        version=context_version("")) is None


def test_actual_formatter_delivers_complete_section():
    ctx, spec = _context()
    rows = []
    prompt = format_context_for_prompt(ctx, budget_limit=100000,
                                       external_delivery_sink=rows.append)
    assert _render(_value()) in prompt
    assert rows == [[{**spec, "delivered": True, "reason": "complete_prompt_section"}]]
    assert "Advisory prior callee assessment" in prompt
    assert "not proof of actual callee behaviour" in prompt
    assert "assumption was wrong" not in prompt
    assert "callee's actual behaviour make THIS" not in prompt


def test_actual_formatter_does_not_credit_omitted_section(monkeypatch):
    # This bounded section is below the fitter's priority-zero elision floor.
    # Inject omission at the fit boundary to exercise actual formatter delivery.
    from dataclasses import replace
    from core.llm import prompt_budget

    actual_fit = prompt_budget.fit_to_budget_report

    def omit_callee(sections, *args, **kwargs):
        report = actual_fit(sections, *args, **kwargs)
        removed = [s for s in report.kept if s.label == "callee_contract"]
        return replace(report, kept=[s for s in report.kept if s.label != "callee_contract"],
                       shed=report.shed + removed)

    monkeypatch.setattr(prompt_budget, "fit_to_budget_report", omit_callee)
    ctx, spec = _context()
    rows = []
    prompt = format_context_for_prompt(ctx, budget_limit=1,
                                       external_delivery_sink=rows.append)
    assert _render(_value()) not in prompt
    assert rows == [[{**spec, "delivered": False, "reason": "context_not_fitted"}]]


@pytest.mark.parametrize("field,value", [("section", "source"), ("context_key", "source"),
                                         ("context_id", "forged"), ("version", "forged")])
def test_altered_spec_cannot_receive_delivery_credit(field, value):
    ctx, spec = _context()
    forged = deepcopy(spec)
    forged[field] = value
    ctx["continuation_context_inputs"] = [forged]
    section = PromptSection("callee_contract", _render(_value()), 0)
    assert context_delivery(ctx, [section], [section]) == []


def test_only_complete_exact_section_receives_credit():
    ctx, spec = _context()
    original = PromptSection("callee_contract", _render(_value()), 0)
    altered = PromptSection("callee_contract", original.text[:-1], 0)
    for kept in ([], [altered]):
        assert context_delivery(ctx, [original], kept) == [
            {**spec, "delivered": False, "reason": "context_not_fitted"}]


def test_shared_renderer_preserves_identifier_defences_and_unicode():
    value = {"callee": "parse_λ\n## INJECT", "assumption": "check\x00`input`",
             "callee_status": "finding\n## STATUS", "callee_hypothesis": "unsafe\x1b"}
    rendered = _render(value)
    for field, cap in (("callee", 128), ("assumption", 300),
                       ("callee_status", 64), ("callee_hypothesis", 400)):
        assert _defend_identifier(value[field], max_length=cap) in rendered
    assert "parse_λ" in rendered
    assert "\n## INJECT" not in rendered
    assert "\n## STATUS" not in rendered
    assert "\x00" not in rendered
    assert "\x1b" not in rendered


def test_late_joern_identity_stays_raw_string_based():
    text = "mechanical evidence λ"
    spec = context_spec({"mechanical_evidence": text}, kind="late_joern",
                        version=context_version(text))
    assert spec["context_key"] == "mechanical_evidence"
    assert spec["section"] == "evidence"


def test_changed_rendered_source_scope_changes_identity():
    ctx, spec = _context()
    ctx["callee_contract_violation"]["scope_note"] = "Original source sha256 changed"
    assert context_spec(ctx, kind="callee_contract", version=spec["version"]) is None
