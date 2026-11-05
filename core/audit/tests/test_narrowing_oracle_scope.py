"""Type-width models are diagnostic even when their input extraction improves."""

from dataclasses import asdict

import pytest

from core.audit import (
    condition_smt,
    evidence_grade as grade,
    orchestrator as orch,
    sweep,
)
from core.audit.refutation_source import SourceIdentity
from core.audit.verification_results import (
    ClaimRefutation,
    ProbeOutcome,
    ToolChainResult,
)


@pytest.mark.parametrize("suffix", ["", ":witness", ":model"])
@pytest.mark.parametrize("fallback", [False, True])
def test_width_receipts_cannot_verify_a_defect(monkeypatch, suffix, fallback):
    stamp = "smt:check-integer-narrowing" + suffix
    if fallback:
        monkeypatch.setattr(
            grade, "_channel_detection_classifier", lambda namespace: None
        )
    assert sweep.is_detection_rule_id(stamp)
    assert not grade.is_verification_evidence(stamp)
    assert not grade.is_tool_evidence(stamp)
    assert not orch._promotion_grade_receipt(stamp)
    assert grade.is_verification_evidence(stamp + "+lifecycle")
    assert grade.is_verification_evidence("smt:check-overflow")


@pytest.mark.parametrize("found", [False, True])
def test_width_worker_preserves_observations_without_negative_authority(
    monkeypatch, found
):
    monkeypatch.setattr(
        condition_smt,
        "check_integer_narrowing",
        lambda *a, **kw: condition_smt.IntegerNarrowingResult(
            narrowing_found=found, witness={"count": 1}
        ),
    )
    result = sweep._run_smt_verb_inner(
        file_path="record.c",
        function_name="Read",
        verb="check-integer-narrowing",
        source="int Read(void) { return 0; }",
        hypothesis="claim",
    )
    assert result.outcome == ("confirmed" if found else "inconclusive")
    assert result.details["oracle_scope"] == "type-width-only"
    assert result.details["witness"] == {"count": 1}


@pytest.mark.parametrize("verdict", ["confirmed", "refuted", "inconclusive"])
def test_stale_worker_cannot_restore_width_authority(monkeypatch, verdict):
    old = sweep.SweepResult(
        tool="smt",
        file_path="record.c",
        function_name="Read",
        outcome=verdict,
        rule_id="smt:check-overflow:witness",
        details={"witness": {"count": 1}},
    )
    monkeypatch.setattr(
        "core.audit.subproc_json.run_json_child", lambda *a, **kw: asdict(old)
    )
    result = sweep._smt_verb_in_subprocess(
        file_path="record.c",
        function_name="Read",
        verb="check-integer-narrowing",
        source="int Read(void) { return 0; }",
        hypothesis="claim",
    )
    assert result.outcome == ("confirmed" if verdict == "confirmed" else "inconclusive")
    assert result.rule_id == "smt:check-integer-narrowing"
    assert result.details["oracle_scope"] == "type-width-only"
    assert not grade.is_verification_evidence(result.rule_id)


@pytest.mark.parametrize(
    "rule",
    [
        "check-integer-narrowing",
        "smt:check-integer-narrowing",
        "check-integer-narrowing:witness",
        "smt:check-integer-narrowing:witness",
    ],
)
def test_legacy_width_negative_cannot_refute_a_source_claim(rule):
    scope = dict(file="record.c", function="Read", line_start=1, hypothesis="claim")
    identity = SourceIdentity("current", (1, 2, 3))
    receipt = ClaimRefutation(
        **scope,
        source_identity=identity,
        checks=(ProbeOutcome("smt", "refuted", rule),),
    )
    assert not receipt.matches(**scope, source_identity=identity)
    chain = ToolChainResult(**scope, source_identity=identity)
    chain.observe("smt", "refuted", rule)
    assert not chain.refutations(**scope)
    assert chain.refutation_record(**scope) is None


@pytest.mark.parametrize("protected", [False, True])
def test_actual_guarded_candidate_reaches_dispatch_without_verdict_authority(
    tmp_path, monkeypatch, protected
):
    prefix = (
        "if (wide > INT_MAX) return 0;"
        if protected
        else "if (wide > INT_MAX) log_value(wide);"
    )
    source = f"int Read(size_t wide) {{\n{prefix}\nint small = wide;\nreturn small;\n}}"
    (tmp_path / "record.c").write_text(source)
    monkeypatch.setattr(condition_smt, "_try_z3_integer_narrowing", lambda *a, **kw: None)
    monkeypatch.setattr(orch, "run_smt_verb_direct", sweep._run_smt_verb_inner)
    config = orch.OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path / "out")
    result = orch._run_tool_chain(
        [{"type": "smt", "config": {"verb": "check-integer-narrowing"}}],
        config=config,
        file_path="record.c",
        function_name="Read",
        line_start=1,
        source=source,
        hypothesis="claim",
    )
    assert not any(grade.is_verification_evidence(receipt) for receipt in result)
    assert not result.refutations(
        file="record.c", function="Read", line_start=1, hypothesis="claim"
    )
    assert result.outcomes[0].verdict == ("inconclusive" if protected else "confirmed")
