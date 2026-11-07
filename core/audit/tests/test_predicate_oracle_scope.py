"""A solver model of supplied predicates is not a source-level defect oracle."""

from dataclasses import asdict

import pytest

from core.audit import evidence_grade as grade
from core.audit import orchestrator as orch
from core.audit import sweep
from core.audit.refutation_source import SourceIdentity
from core.audit.smt_evidence import scope_smt_feasibility
from core.audit.verification_results import ClaimRefutation, ProbeOutcome, ToolChainResult


ALIASES = ("validate-path", "path-feasible", "path_feasibility", "path-feasibility")
SOURCE = "int Read(int count) { return count; }"


@pytest.mark.parametrize("alias", ALIASES)
@pytest.mark.parametrize("suffix", ["", ":witness"])
@pytest.mark.parametrize("fallback", [False, True])
def test_predicate_receipts_never_promote_even_with_a_solver_witness(monkeypatch, alias, suffix, fallback):
    receipt = f"smt:{alias}{suffix}"
    assert sweep.is_detection_rule_id(receipt)
    if fallback:
        monkeypatch.setattr(grade, "_channel_detection_classifier", lambda namespace: None)
    assert not grade.is_tool_evidence(receipt)
    assert not grade.is_verification_evidence(receipt)
    assert not orch._promotion_grade_receipt(receipt)
    assert grade.is_verification_evidence(receipt + "+lifecycle")


@pytest.mark.parametrize("conditions,feasible", [
    ("`count > 0` and `count < 3`", True),
    ("`count > 5` and `count < 2`", False),
])
def test_real_solver_preserves_math_without_source_claim_authority(conditions, feasible):
    pytest.importorskip("z3")
    result = sweep._run_smt_verb_inner(
        file_path="record.c", function_name="Read", verb="validate-path",
        source=SOURCE, hypothesis=conditions,
    )
    assert not result.errors
    assert result.details["oracle_scope"] == "supplied-predicates"
    assert result.details["feasible"] is feasible
    assert result.outcome == ("confirmed" if feasible else "inconclusive")
    assert not grade.is_verification_evidence(result.rule_id)


@pytest.mark.parametrize("verdict,feasible", [("confirmed", True), ("refuted", False), ("inconclusive", None)])
def test_old_worker_cannot_restore_source_unbound_authority(monkeypatch, verdict, feasible):
    old = sweep.SweepResult(tool="smt", file_path="record.c", function_name="Read",
                            outcome=verdict, rule_id="smt:check-overflow", matches=[{"line": 1}])
    monkeypatch.setattr("core.audit.subproc_json.run_json_child", lambda *a, **k: asdict(old))
    result = sweep._smt_verb_in_subprocess(
        file_path="record.c", function_name="Read", verb="validate-path",
        source=SOURCE, hypothesis="count > 0",
    )
    assert result.rule_id == "smt:validate-path"
    assert result.outcome == ("confirmed" if feasible is True else "inconclusive")
    assert result.details["feasible"] is feasible
    if feasible is not True:
        assert not result.matches


@pytest.mark.parametrize("feasible", [True, False, None])
def test_scoped_results_survive_repeated_worker_admission(feasible):
    original = "confirmed" if feasible else "inconclusive"
    details = {"oracle_scope": "supplied-predicates", "feasible": feasible}
    once = scope_smt_feasibility("validate-path", original, details)
    assert scope_smt_feasibility("validate-path", *once) == once
    assert once[1]["feasible"] is feasible


@pytest.mark.parametrize("alias", ALIASES)
@pytest.mark.parametrize("suffix", ["", ":witness"])
def test_source_identity_does_not_license_legacy_predicate_refutations(alias, suffix):
    identity = SourceIdentity("current-source", (1, 2, 3))
    scope = dict(file="record.c", function="Read", line_start=1, hypothesis="claim")
    receipt = ClaimRefutation(**scope, source_identity=identity,
                              checks=(ProbeOutcome("smt", "refuted", f"smt:{alias}{suffix}"),))
    assert not receipt.matches(**scope, source_identity=identity)
    legacy_chain = ToolChainResult(**scope, source_identity=identity)
    legacy_chain.observe("smt", "refuted", f"smt:{alias}{suffix}")
    assert not legacy_chain.refutations(**scope)
    assert legacy_chain.refutation_record(**scope) is None
    control = ClaimRefutation(**scope, source_identity=identity,
                              checks=(ProbeOutcome("smt", "refuted", "check-overflow"),))
    assert control.matches(**scope, source_identity=identity)


@pytest.mark.parametrize("conditions", ["`count > 0` and `count < 3`", "`count > 5` and `count < 2`"])
def test_tool_chain_does_not_turn_math_into_verification_or_refutation(tmp_path, monkeypatch, conditions):
    pytest.importorskip("z3")
    (tmp_path / "record.c").write_text(SOURCE)
    monkeypatch.setattr(orch, "run_smt_verb_direct", sweep._run_smt_verb_inner)
    config = orch.OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path / "out")
    scope = dict(file_path="record.c", function_name="Read", line_start=1, hypothesis=conditions)
    result = orch._run_tool_chain(
        [{"type": "smt", "config": {"verb": "validate-path"}}],
        config=config, source=SOURCE, **scope,
    )
    assert not any(grade.is_verification_evidence(receipt) for receipt in result)
    assert not result.refutations(file="record.c", function="Read", line_start=1, hypothesis=conditions)


def test_alternative_flow_predicates_cannot_demote_a_finding(tmp_path, monkeypatch):
    from core.audit import path_feasibility
    from core.analysis import lifecycle_audit_integration

    (tmp_path / "record.c").write_text(SOURCE)
    calls = []
    def forbidden_combination(*args, **kwargs):
        calls.append((args, kwargs))
        raise AssertionError("alternative traces are not one conjunction")
    monkeypatch.setattr(path_feasibility, "check_path_feasibility", forbidden_combination)
    monkeypatch.setattr(lifecycle_audit_integration, "check_lifecycle_at_function", lambda **kw: [])
    outcome = orch.ReviewOutcome(file="record.c", function="Read", line=1,
                                 status="finding", body="claim", hypothesis="claim")
    outcome.review_result = {"cwe_class": "CWE-190"}
    config = orch.OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path / "out")
    result = orch._proactive_validate(
        outcome, config, dispatched_tools={"smt", "joern", "semgrep", "codeql", "cross_function"},
        flow_traces=[{"file": "record.c", "path_conditions": ["count > 0"]},
                     {"file": "record.c", "path_conditions": ["count <= 0"]}],
    )
    assert not calls
    assert result.status == "finding"
    assert not grade.is_verification_evidence(result.evidence_tool or "")


def test_partial_sat_predicates_do_not_confirm_an_audit_observation(monkeypatch):
    pytest.importorskip("z3")
    monkeypatch.setattr(sweep, "_extract_path_conditions", lambda *args: [
        "count == 0", "count / 2 == 1",
    ])
    result = sweep._run_smt_verb_inner(
        file_path="record.c", function_name="Read", verb="validate-path",
        source=SOURCE, hypothesis="partial predicate set",
    )
    assert not result.errors
    assert result.outcome == "inconclusive"
    assert result.details["feasible"] is None
    assert result.details["model"]["count"] == 0
    assert result.details["unknown"] == ["count / 2 == 1"]
    assert not result.matches
