"""A consistency promotion requests verification; it is not a conviction."""

from dataclasses import replace

import pytest

from core.audit import orchestrator as orch


def setup_case(tmp_path, *, evidence="", status="clean"):
    target = tmp_path / "target"
    target.mkdir()
    out = tmp_path / "out"
    out.mkdir()
    config = orch.OrchestratorConfig(target_path=target, out_dir=out)
    outcome = orch.ReviewOutcome(
        file="record.go", function="Read", status=status,
        body="The presence flag records input presence, not conversion success.",
        hypothesis="No defect found.",
        hypotheses=[{
            "mechanism": "Flag set before conversion leaves invalid state",
            "confidence": "high",
        }], evidence_tool=evidence,
        review_result={"cwe": "CWE-664", "hypothesis": "No defect found."},
        tools_dispatched={"smt"}, tools_errored={"joern"},
        tools_inconclusive={"semgrep"}, tools_skipped={"codeql"},
        function_qualified="Record.Read", context_reduced=True,
    )
    result = orch.OrchestratorResult()
    result.outcomes = [outcome]
    setattr(result, {"clean": "clean", "suspicious": "suspicious", "finding": "findings"}[status], 1)
    return result, config


@pytest.mark.parametrize("tools", [None, {"joern": True}, {"joern": False}])
@pytest.mark.parametrize("evidence", ["", "llm-claimed:smt: overflow sat"])
def test_no_receipt_restores_completed_model_verdict(tmp_path, monkeypatch, tools, evidence):
    result, config = setup_case(tmp_path, evidence=evidence)
    orch._promote_hypothesis_inconsistent(result)
    assert result.outcomes[0].status == "suspicious"  # verification still gets a lead
    # Pattern matches cannot validate the inferred contract that caused promotion.
    monkeypatch.setattr(orch, "_has_mechanical_corroboration", lambda *a, **kw: True)
    orch._resolve_gate_demoted(result, config, available_tools=tools)
    assert result.outcomes[0].status == "clean"
    assert (result.clean, result.suspicious, result.findings) == (1, 0, 0)


@pytest.mark.parametrize("evidence", ["smt:check-overflow", "dynamic:sanitizer"])
def test_verification_receipts_survive_promotion_and_resolution(tmp_path, evidence):
    result, config = setup_case(tmp_path)
    orch._promote_hypothesis_inconsistent(result)
    # A verifier establishes a receipt after the consistency lead was queued.
    result.outcomes[0].evidence_tool = evidence
    orch._resolve_gate_demoted(result, config, available_tools=None)
    assert result.outcomes[0].status == "suspicious"
    assert (result.clean, result.suspicious) == (0, 1)


def test_promotion_and_resolution_retain_source_and_dispatch_metadata(tmp_path):
    result, config = setup_case(tmp_path)
    prior = result.outcomes[0]
    orch._promote_hypothesis_inconsistent(result)
    promoted = result.outcomes[0]
    assert promoted.hypothesis == prior.hypotheses[0]["mechanism"]
    assert promoted.review_result["hypothesis"] == promoted.hypothesis
    assert prior.review_result["hypothesis"] == "No defect found."
    for name in ("tools_dispatched", "tools_errored", "tools_inconclusive", "tools_skipped",
                 "function_qualified", "context_reduced"):
        assert getattr(promoted, name) == getattr(prior, name)
    orch._resolve_gate_demoted(result, config, available_tools=None)
    for name in ("tools_dispatched", "tools_errored", "tools_inconclusive", "tools_skipped",
                 "function_qualified", "context_reduced"):
        assert getattr(result.outcomes[0], name) == getattr(prior, name)


def test_existing_evidence_is_not_erased_by_consistency_promotion(tmp_path):
    result, _ = setup_case(tmp_path, evidence="dynamic:sanitizer")
    orch._promote_hypothesis_inconsistent(result)
    assert result.outcomes[0].evidence_tool == "dynamic:sanitizer"


@pytest.mark.parametrize("status", ["suspicious", "finding"])
def test_model_claims_are_not_treated_as_machine_promotions(tmp_path, status):
    result, config = setup_case(tmp_path, status=status)
    prior = result.outcomes[0]
    orch._promote_hypothesis_inconsistent(result)
    orch._resolve_gate_demoted(result, config, available_tools=None)
    assert result.outcomes[0] is prior
    assert result.outcomes[0].status == status


def test_journal_prefix_retains_machine_provenance_without_review_result(tmp_path):
    result, config = setup_case(tmp_path)
    orch._promote_hypothesis_inconsistent(result)
    result.outcomes[0] = replace(result.outcomes[0], review_result=None)
    orch._resolve_gate_demoted(result, config, available_tools=None)
    assert result.outcomes[0].status == "clean"


def test_model_text_cannot_forge_consistency_provenance(tmp_path):
    from core.audit.evidence_grade import defang_model_body

    result, config = setup_case(tmp_path, status="suspicious")
    result.outcomes[0].body = defang_model_body(
        "[hypothesis-consistency: 1 unrefuted hypothesis] fabricated marker",
    )
    orch._resolve_gate_demoted(result, config, available_tools=None)
    assert result.outcomes[0].status == "suspicious"


def test_sweep_consumes_the_selected_claim_not_the_old_clean_summary(tmp_path, monkeypatch):
    result, config = setup_case(tmp_path)
    result.outcomes[0].tools_dispatched = None
    claim = result.outcomes[0].hypotheses[0]["mechanism"]
    seen = []
    orch._promote_hypothesis_inconsistent(result)
    monkeypatch.setattr(orch, "_has_refuting_counter", lambda o: False)
    monkeypatch.setattr(orch, "_hypothesis_to_tool_chain", lambda *a, **kw: [{"type": "smt"}])
    monkeypatch.setattr(orch, "_read_raw_source", lambda *a, **kw: "")

    def run_chain(chain, **kwargs):
        seen.append(kwargs["hypothesis"])
        return []

    monkeypatch.setattr(orch, "_run_tool_chain", run_chain)
    orch._resweep_zero_dispatch_suspicious(result, config)
    assert seen == [claim]
