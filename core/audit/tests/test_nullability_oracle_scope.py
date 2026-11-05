"""Pointer nullability is a mathematical lead, not a source dereference proof."""

from dataclasses import asdict

import pytest

from core.audit import evidence_grade as grade, orchestrator as orch, sweep
from core.audit.refutation_source import SourceIdentity
from core.audit.verification_results import ClaimRefutation, ProbeOutcome, ToolChainResult


@pytest.mark.parametrize("source", ["", "int Read(void) { return 0; }"])
def test_free_pointer_sat_does_not_verify_even_without_a_dereference(source):
    pytest.importorskip("z3")
    result = sweep._run_smt_verb_inner(
        file_path="record.c", function_name="Read", verb="check-null-deref",
        source=source, hypothesis="p is null",
    )
    assert result.outcome == "confirmed"
    assert result.details["feasible"] is True
    assert result.details["oracle_scope"] == "pointer-nullability-only"
    assert not grade.is_verification_evidence(result.rule_id)


@pytest.mark.parametrize("suffix", ["", ":witness", ":model"])
@pytest.mark.parametrize("fallback", [False, True])
def test_nullability_receipts_cannot_promote_or_hold_verification(monkeypatch, suffix, fallback):
    receipt = f"smt:check-null-deref{suffix}"
    if fallback:
        monkeypatch.setattr(grade, "_channel_detection_classifier", lambda namespace: None)
    assert sweep.is_detection_rule_id(receipt)
    assert not grade.is_tool_evidence(receipt)
    assert not grade.is_verification_evidence(receipt)
    assert not orch._promotion_grade_receipt(receipt)
    assert grade.is_verification_evidence(receipt + "+lifecycle")
    assert grade.is_verification_evidence("smt:check-overflow")


@pytest.mark.parametrize("suffix", ["", ":witness", ":model"])
def test_source_identity_cannot_authorize_a_nullability_refutation(suffix):
    identity = SourceIdentity("current-source", (1, 2, 3))
    scope = dict(file="record.c", function="Read", line_start=1, hypothesis="p is null")
    rule = f"smt:check-null-deref{suffix}"
    receipt = ClaimRefutation(**scope, source_identity=identity,
                              checks=(ProbeOutcome("smt", "refuted", rule),))
    assert not receipt.matches(**scope, source_identity=identity)
    chain = ToolChainResult(**scope, source_identity=identity)
    chain.observe("smt", "refuted", rule)
    assert not chain.refutations(**scope)
    assert chain.refutation_record(**scope) is None
    control = ClaimRefutation(**scope, source_identity=identity,
                              checks=(ProbeOutcome("smt", "refuted", "check-overflow"),))
    assert control.matches(**scope, source_identity=identity)


@pytest.mark.parametrize("verdict", ["confirmed", "refuted", "inconclusive"])
def test_parent_caps_old_worker_nullability_results(monkeypatch, verdict):
    old = sweep.SweepResult(tool="smt", file_path="record.c", function_name="Read",
                            outcome=verdict, rule_id="smt:check-null-deref:witness",
                            matches=[{"model": {"p": 0}}])
    monkeypatch.setattr("core.audit.subproc_json.run_json_child", lambda *a, **kw: asdict(old))
    result = sweep._smt_verb_in_subprocess(
        file_path="record.c", function_name="Read", verb="check-null-deref",
        source="int Read(void) { return 0; }", hypothesis="p is null",
    )
    assert result.rule_id == "smt:check-null-deref"
    assert result.outcome == ("confirmed" if verdict == "confirmed" else "inconclusive")
    assert result.details["oracle_scope"] == "pointer-nullability-only"
    if verdict != "confirmed":
        assert not result.matches


@pytest.mark.parametrize("guards,expected", [([], True), (["p != 0"], False)])
def test_explicit_math_api_retains_nullability_results(guards, expected):
    pytest.importorskip("z3")
    from packages.exploit_feasibility.smt_verbs import check_null_deref

    assert check_null_deref("p", guards=guards)["feasible"] is expected


@pytest.mark.parametrize("feasible", [True, False, None])
def test_tool_chain_cannot_turn_nullability_into_source_verdict(tmp_path, monkeypatch, feasible):
    from packages.exploit_feasibility import smt_verbs

    source = "int Read(void) { return 0; }"
    (tmp_path / "record.c").write_text(source)
    monkeypatch.setattr(smt_verbs, "check_null_deref", lambda *a, **kw: {"feasible": feasible})
    monkeypatch.setattr(orch, "run_smt_verb_direct", sweep._run_smt_verb_inner)
    config = orch.OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path / "out")
    scope = dict(file_path="record.c", function_name="Read", line_start=1, hypothesis="p is null")
    result = orch._run_tool_chain(
        [{"type": "smt", "config": {"verb": "check-null-deref"}}],
        config=config, source=source, **scope,
    )
    assert not any(grade.is_verification_evidence(receipt) for receipt in result)
    assert not result.refutations(file="record.c", function="Read", line_start=1, hypothesis="p is null")


@pytest.mark.parametrize("feasible", [True, False, None])
def test_cli_adapter_caps_nullability_math(monkeypatch, feasible):
    import json
    from types import SimpleNamespace

    monkeypatch.setattr(sweep.Path, "exists", lambda self: True)
    monkeypatch.setattr(sweep.subprocess, "run", lambda *a, **kw: SimpleNamespace(
        returncode=0, stdout=json.dumps({"feasible": feasible}), stderr=""))
    result = sweep.run_smt_sweep(
        file_path="record.c", function_name="Read", verb="check-null-deref",
        smt_args={"ptr": "p", "guard": ["p != 0"]},
    )
    assert result.outcome == ("confirmed" if feasible is True else "inconclusive")
    assert result.details["oracle_scope"] == "pointer-nullability-only"
    if feasible is not True:
        assert not result.matches
