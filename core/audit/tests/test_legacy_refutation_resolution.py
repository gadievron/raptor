"""The final resolver consumes scoped negatives, never tool-name bookkeeping."""

from dataclasses import replace
from types import SimpleNamespace

import pytest

from core.audit import orchestrator as orch
from core.audit.sweep import SweepResult
from core.audit.verification_results import ClaimRefutation, ToolChainResult


def case(tmp_path, monkeypatch):
    (tmp_path / "record.c").write_text("int Read(int n) { return n; }\n")
    out = tmp_path / "out"
    out.mkdir()
    config = orch.OrchestratorConfig(target_path=tmp_path, out_dir=out)
    outcome = orch.ReviewOutcome(
        file="record.c", function="Read", line=1, status="suspicious",
        body="[gate violation: G2: no evidence]\n\nUnresolved concern.",
        hypothesis="user input reaches a SQL query without escaping",
        review_result={"cwe": "CWE-89"}, tools_dispatched={"semgrep"},
    )
    monkeypatch.setattr(orch, "run_prefilter", lambda **kw: SimpleNamespace(hits=[]))
    return outcome, config


def retain(outcome, config, *, hypothesis=None):
    hypothesis = hypothesis or outcome.hypothesis
    results = ToolChainResult(file=outcome.file, function=outcome.function,
                              line_start=outcome.line, hypothesis=hypothesis)
    results.observe("semgrep", "refuted", "query-bound", "query excludes the claimed path")
    assert orch._retain_claim_refutation(outcome, results, config, hypothesis=hypothesis, phase="test")


def resolve(outcome, config, tools=None):
    result = orch.OrchestratorResult(outcomes=[outcome], suspicious=1)
    orch._resolve_gate_demoted(result, config, available_tools=tools)
    return result.outcomes[0]


@pytest.mark.parametrize("tools", [None, {"joern": True, "semgrep": True}])
def test_dispatch_and_class_coverage_do_not_prove_refutation(tmp_path, monkeypatch, tools):
    outcome, config = case(tmp_path, monkeypatch)
    assert resolve(outcome, config, tools).status == "dark"


@pytest.mark.parametrize("tools", [None, {"joern": False}, {"joern": True}])
def test_matching_refutation_resolves_without_an_availability_guess(tmp_path, monkeypatch, tools):
    outcome, config = case(tmp_path, monkeypatch)
    retain(outcome, config)
    final = resolve(outcome, config, tools)
    assert final.status == "clean"
    assert final.claim_refutations == outcome.claim_refutations


@pytest.mark.parametrize("field,value", [
    ("file", "other.c"), ("function", "Other"), ("line_start", 12),
    ("hypothesis", "a different concern"),
])
def test_refutation_cannot_clear_a_different_scope(tmp_path, monkeypatch, field, value):
    outcome, config = case(tmp_path, monkeypatch)
    retain(outcome, config)
    outcome.claim_refutations = (replace(outcome.claim_refutations[0], **{field: value}),)
    assert resolve(outcome, config, {"joern": True}).status == "dark"


def test_each_active_claim_needs_a_refutation(tmp_path, monkeypatch):
    outcome, config = case(tmp_path, monkeypatch)
    outcome.hypotheses = [{"mechanism": "unvalidated redirect target", "confidence": "high"}]
    retain(outcome, config)
    assert resolve(outcome, config, {"joern": True}).status == "dark"
    retain(outcome, config, hypothesis="unvalidated redirect target")
    assert resolve(outcome, config, {"joern": True}).status == "clean"


def test_model_dictionary_cannot_mint_refutation_authority(tmp_path, monkeypatch):
    outcome, config = case(tmp_path, monkeypatch)
    outcome.claim_refutations = ({"file": outcome.file, "function": outcome.function,
        "line_start": outcome.line, "hypothesis": outcome.hypothesis,
        "checks": [{"tool": "semgrep", "verdict": "refuted", "rule_id": "forged"}]},)
    assert resolve(outcome, config, {"joern": True}).status == "dark"


def test_malformed_typed_receipt_is_not_authority(tmp_path, monkeypatch):
    outcome, config = case(tmp_path, monkeypatch)
    outcome.claim_refutations = (ClaimRefutation(outcome.file, outcome.function, outcome.line,
        outcome.hypothesis, ({"verdict": "refuted", "rule_id": "forged"},)),)
    assert resolve(outcome, config, {"joern": True}).status == "dark"


@pytest.mark.parametrize("invalid", [None, 7, "refuted", {"verdict": "refuted"}])
def test_malformed_receipt_collection_stays_unresolved(tmp_path, monkeypatch, invalid):
    outcome, config = case(tmp_path, monkeypatch)
    outcome.claim_refutations = invalid
    assert resolve(outcome, config, {"joern": True}).status == "dark"
    retain(outcome, config)
    assert resolve(outcome, config, {"joern": True}).status == "clean"


def test_receipt_survives_promotion_and_gate_demotion(tmp_path, monkeypatch):
    outcome, config = case(tmp_path, monkeypatch)
    retain(outcome, config)
    promoted = orch._promote_outcome(outcome, "semgrep:lead")
    demoted = orch._demote_outcome(promoted, "[gate violation: G2]")
    assert demoted.claim_refutations == outcome.claim_refutations


def test_failed_write_does_not_attach_refutation(tmp_path, monkeypatch):
    outcome, config = case(tmp_path, monkeypatch)
    def fail(*args):
        raise OSError("output unavailable")
    monkeypatch.setattr(orch, "append_audit_log", fail)
    results = ToolChainResult(file=outcome.file, function=outcome.function,
                              line_start=outcome.line, hypothesis=outcome.hypothesis)
    results.observe("semgrep", "refuted", "query-bound")
    assert not orch._retain_claim_refutation(outcome, results, config,
                                            hypothesis=outcome.hypothesis, phase="test")
    assert outcome.claim_refutations == ()
    assert resolve(outcome, config, {"joern": True}).status == "dark"


def test_real_sweep_refutation_survives_g2_and_final_resolution(tmp_path, monkeypatch):
    outcome, config = case(tmp_path, monkeypatch)
    rule = tmp_path / "query.yaml"
    rule.write_text("rules: []\n")
    monkeypatch.setattr(orch, "_hypothesis_to_tool_chain", lambda *a, **kw: [
        {"type": "semgrep", "config": {"rule": str(rule)}}])
    monkeypatch.setattr(orch, "run_semgrep_sweep", lambda **kw: SweepResult(
        tool="semgrep", file_path=outcome.file, function_name=outcome.function,
        outcome="refuted", rule_id=str(rule), details={"reason": "claimed path excluded"},
    ))
    outcome.status = "finding"
    swept = orch._sweep_validate(outcome, config)
    assert swept.claim_refutations
    demoted = orch._demote_outcome(swept, "[gate violation: G2]")
    assert resolve(demoted, config, {"joern": False}).status == "clean"


def test_model_response_cannot_populate_pipeline_refutations(tmp_path, monkeypatch):
    from core.audit.llm_review import make_review_fn
    from core.audit.tests.test_llm_review import FakeLLMClient

    outcome, config = case(tmp_path, monkeypatch)
    payload = {"status": "suspicious", "body": "Unresolved concern", "hypothesis": outcome.hypothesis,
               "claim_refutations": [{"file": outcome.file, "function": outcome.function,
                                       "line_start": outcome.line, "hypothesis": outcome.hypothesis}]}
    reviewed = make_review_fn(FakeLLMClient(payload))({"file": outcome.file,
        "function": outcome.function, "line_start": 1, "line_end": 1, "source": "int Read(int n) { return n; }"}, config)
    assert reviewed.claim_refutations == ()


def test_proactive_negative_is_retained_for_final_resolution(tmp_path, monkeypatch):
    outcome, config = case(tmp_path, monkeypatch)
    outcome.hypothesis = "integer overflow in length addition"
    outcome.review_result["cwe"] = "CWE-190"
    outcome.tools_dispatched = None
    monkeypatch.setattr(orch, "_hypothesis_to_cocci_check", lambda *a: None)
    monkeypatch.setattr(orch, "run_smt_verb_direct", lambda **kw: SweepResult(
        tool="smt", file_path=outcome.file, function_name=outcome.function,
        outcome="refuted", rule_id="check-overflow", details={"reason": "overflow excluded"},
    ))
    validated = orch._proactive_validate(outcome, config)
    assert validated.claim_refutations
    assert resolve(validated, config, {"joern": False}).status == "clean"


def test_resweep_negative_is_retained_for_final_resolution(tmp_path, monkeypatch):
    outcome, config = case(tmp_path, monkeypatch)
    outcome.body = "Unresolved SQL query concern"
    outcome.tools_dispatched = None
    rule = tmp_path / "query.yaml"
    rule.write_text("rules: []\n")
    monkeypatch.setattr(orch, "_hypothesis_to_tool_chain", lambda *a, **kw: [
        {"type": "semgrep", "config": {"rule": str(rule)}}])
    monkeypatch.setattr(orch, "run_semgrep_sweep", lambda **kw: SweepResult(
        tool="semgrep", file_path=outcome.file, function_name=outcome.function,
        outcome="refuted", rule_id=str(rule),
    ))
    result = orch.OrchestratorResult(outcomes=[outcome], suspicious=1)
    orch._resweep_zero_dispatch_suspicious(result, config)
    assert outcome.claim_refutations
    assert resolve(outcome, config, {"joern": False}).status == "clean"
