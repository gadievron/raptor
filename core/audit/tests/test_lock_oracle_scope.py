"""Lexical lock observations must not decide source-level defect verdicts."""

from dataclasses import asdict

import pytest

from core.audit import condition_smt, evidence_grade as grade, orchestrator as orch, sweep
from core.audit.refutation_source import SourceIdentity
from core.audit.verification_results import ClaimRefutation, ProbeOutcome, ToolChainResult


# Both paths are balanced: the early return occurs only without acquiring.
BALANCED = """int Read(int enabled) {
    if (enabled) {
        mutex_lock(&guard);
    }
    if (!enabled) {
        return 0;
    }
    mutex_unlock(&guard);
    return 1;
}
"""


@pytest.mark.parametrize("fallback", [False, True])
@pytest.mark.parametrize("suffix", ["", ":witness", ":model"])
def test_lock_observation_cannot_promote_with_or_without_classifier(monkeypatch, fallback, suffix):
    receipt = "smt:check-lock-discipline" + suffix
    assert sweep.is_detection_rule_id(receipt)
    if fallback:
        monkeypatch.setattr(grade, "_channel_detection_classifier", lambda namespace: None)
    assert not grade.is_tool_evidence(receipt)
    assert not grade.is_verification_evidence(receipt)
    assert not orch._promotion_grade_receipt(receipt)
    assert grade.is_verification_evidence(receipt + "+lifecycle")
    assert grade.is_verification_evidence("smt:check-overflow")


@pytest.mark.parametrize("numeric", [False, True])
def test_balanced_conditional_acquisition_is_only_a_lead(monkeypatch, numeric):
    pytest.importorskip("z3")
    source = BALANCED.replace("if (enabled)", "if (enabled > 0)").replace("if (!enabled)", "if (enabled <= 0)") if numeric else BALANCED
    # Use the real guard checker without a nested subprocess. Its unmodeled
    # negation fallback reports feasibility, without proving lock ownership.
    monkeypatch.setattr(condition_smt, "_try_z3_lock_discipline", lambda guard, lock, line, bypassed:
                        condition_smt._z3_lock_discipline_check(guard, lock, line))
    observation = condition_smt.check_lock_discipline(source)
    assert observation.violation_found
    if numeric:
        assert observation.witness["enabled"] <= 0
    result = sweep._run_smt_verb_inner(file_path="record.c", function_name="Read",
                                       verb="check-lock-discipline", source=source, hypothesis="claim")
    assert result.outcome == "confirmed"
    assert result.details["oracle_scope"] == "lexical-lock-discipline"
    assert result.details["violation_found"]
    assert not grade.is_verification_evidence(result.rule_id)


@pytest.mark.parametrize("applicable", [False, True])
def test_detector_silence_is_not_a_claim_refutation(monkeypatch, applicable):
    monkeypatch.setattr(condition_smt, "check_lock_discipline", lambda *args:
                        condition_smt.LockDisciplineResult(applicable=applicable, reasoning="no candidate"))
    result = sweep._run_smt_verb_inner(file_path="record.c", function_name="Read",
                                       verb="check-lock-discipline", source=BALANCED, hypothesis="claim")
    assert result.outcome == "inconclusive"
    assert result.details["reasoning"] == "no candidate"
    assert result.details["oracle_scope"] == "lexical-lock-discipline"


@pytest.mark.parametrize("verdict", ["confirmed", "refuted", "inconclusive"])
def test_parent_normalizes_old_lock_worker_results(monkeypatch, verdict):
    old = sweep.SweepResult(tool="smt", file_path="record.c", function_name="Read",
                            outcome=verdict, rule_id="smt:check-overflow:witness",
                            details={"witness": {"enabled": 0}})
    monkeypatch.setattr("core.audit.subproc_json.run_json_child", lambda *a, **kw: asdict(old))
    result = sweep._smt_verb_in_subprocess(file_path="record.c", function_name="Read",
                                          verb="check-lock-discipline", source=BALANCED, hypothesis="claim")
    assert result.outcome == "inconclusive"
    assert result.rule_id == "smt:check-lock-discipline"
    assert result.details["witness"] == {"enabled": 0}
    assert result.details["oracle_scope"] == "lexical-lock-discipline"
    assert not grade.is_verification_evidence(result.rule_id)


@pytest.mark.parametrize("rule", ["check-lock-discipline", "smt:check-lock-discipline",
                                   "check-lock-discipline:witness", "smt:check-lock-discipline:witness"])
def test_legacy_negative_receipt_cannot_clear_a_claim(rule):
    identity = SourceIdentity("current", (1, 2, 3))
    scope = dict(file="record.c", function="Read", line_start=1, hypothesis="claim")
    receipt = ClaimRefutation(**scope, source_identity=identity,
                              checks=(ProbeOutcome("smt", "refuted", rule),))
    assert not receipt.matches(**scope, source_identity=identity)
    chain = ToolChainResult(**scope, source_identity=identity)
    chain.observe("smt", "refuted", rule)
    assert not chain.refutations(**scope)
    assert chain.refutation_record(**scope) is None


@pytest.mark.parametrize("found", [False, True])
def test_dispatcher_retains_observation_without_verdict_authority(tmp_path, monkeypatch, found):
    (tmp_path / "record.c").write_text(BALANCED)
    monkeypatch.setattr(condition_smt, "check_lock_discipline", lambda *a:
                        condition_smt.LockDisciplineResult(violation_found=found, witness={"enabled": 0}))
    monkeypatch.setattr(sweep, "_smt_verb_in_subprocess", sweep._run_smt_verb_inner)
    config = orch.OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path / "out")
    result = orch._run_tool_chain([{"type": "smt", "config": {"verb": "check-lock-discipline"}}],
                                  config=config, file_path="record.c", function_name="Read",
                                  source=BALANCED, hypothesis="claim", line_start=1)
    assert not any(grade.is_verification_evidence(receipt) for receipt in result)
    assert not result.refutations(file="record.c", function="Read", line_start=1, hypothesis="claim")
    assert result.outcomes[0].verdict == ("confirmed" if found else "inconclusive")


def test_pre_loop_still_queues_lock_leads_for_review(tmp_path, monkeypatch):
    monkeypatch.setattr(orch, "_read_raw_source", lambda *a, **kw: BALANCED)
    monkeypatch.setattr(condition_smt, "check_lock_discipline", lambda *a:
                        condition_smt.LockDisciplineResult(violation_found=True, witness={"enabled": 0}))
    gap = {"file": "record.c", "name": "Read", "line_start": 1}
    config = orch.OrchestratorConfig(target_path=tmp_path, out_dir=None)
    result = orch.OrchestratorResult()
    kept = orch._pre_loop_smt_screen([gap], config, result)
    assert kept == [gap]
    assert gap["_smt_pre_evidence"] == "smt:check-lock-discipline:witness"
    assert not grade.is_verification_evidence(gap["_smt_pre_evidence"])
    assert not result.outcomes


def test_clean_review_escalates_to_review_without_verified_evidence(tmp_path, monkeypatch):
    monkeypatch.setattr(orch, "_read_raw_source", lambda *a, **kw: BALANCED)
    monkeypatch.setattr(condition_smt, "check_lock_discipline", lambda *a:
                        condition_smt.LockDisciplineResult(violation_found=True, witness={"enabled": 0}))
    outcome = orch.ReviewOutcome(file="record.c", function="Read", line=1,
                                 status="clean", body="review", hypothesis="claim")
    result = orch.OrchestratorResult(outcomes=[outcome], clean=1)
    config = orch.OrchestratorConfig(target_path=tmp_path, out_dir=None)
    orch._promote_smt_clean(result, config)
    assert result.outcomes[0].status == "suspicious"
    assert not grade.is_verification_evidence(result.outcomes[0].evidence_tool)
    assert result.suspicious == 1
    assert result.findings == 0
