"""A predicate model cannot verify or refute the source bug behind an outlier."""

from types import SimpleNamespace

import pytest

from core.audit.condition_smt import PathFeasibilityResult
from core.audit.consistency_verify import guard_predicate_verdict, guard_presence_verdict
from core.audit.consistency_dimensions import detect_guard_presence_deviations
from core.audit.tests.test_guard_predicate_verdict import _deviation
from core.audit.tests.test_consistency_guard_presence import _null_fixture
from core.audit.gaps import _reuse_block_class, _reuse_ineligibility
from core.audit.tests.test_verdict_reuse import _entry, _write_target


@pytest.mark.parametrize("feasible", [True, False, None])
@pytest.mark.parametrize("dimension", ["presence", "predicate"])
def test_integer_models_keep_diagnostics_without_verdict_authority(feasible, dimension):
    if dimension == "presence":
        pytest.importorskip("tree_sitter_c")
        deviation = detect_guard_presence_deviations(_null_fixture(deviant=True, conforming=9))[0]
        verifier = guard_presence_verdict
    else:
        deviation = _deviation()
        verifier = guard_predicate_verdict
    model = PathFeasibilityResult(feasible=feasible, reasoning="integer model only", witness={"Value": 8})
    result = verifier(deviation, smt_check=lambda _: model)
    assert result.outcome == "confirmed"  # only the statistical deviation
    assert result.rule_id.endswith("-majority")
    assert result.contract is None
    assert result.peer_evidence.contract_source == "majority"
    assert result.corroboration[0]["smt_model"]["modeled_feasible"] is feasible
    assert result.corroboration[0]["smt_model"]["witness"] == {"Value": 8}


@pytest.mark.parametrize("feasible", [True, False])
def test_signed_comparison_models_do_not_establish_a_source_violation(feasible):
    model = SimpleNamespace(feasible=feasible, witness={"Value": -1}, reasoning="comparison only",
                            oracle_scope="signed-comparison-model")
    result = guard_predicate_verdict(_deviation(), smt_check=lambda _: model)
    assert result.rule_id.endswith("-majority") and result.contract is None
    assert result.outcome != "refuted"


@pytest.mark.parametrize("receipt", ["consistency:guard-presence", "consistency:guard-predicate",
                                     "clean-refuted:consistency:guard-presence",
                                     "joern:flow+consistency:guard-predicate-majority"])
def test_old_clean_predicate_receipts_need_source_revalidation(tmp_path, receipt):
    target = _write_target(tmp_path)
    entry = _entry(target, evidence_tools=[receipt], body="old predicate result", clean_basis="verdict")
    reason = _reuse_ineligibility(entry, "auth.c:check_pw", current_strategies_fn=None, current_model=None)
    assert reason == "predicate consistency receipt requires source revalidation"
    assert _reuse_block_class(reason) == "predicate_consistency"


@pytest.mark.parametrize("fallback", [False, True])
@pytest.mark.parametrize("receipt", ["consistency:guard-presence", "consistency:guard-predicate",
                                     "consistency:guard-presence:witness", "consistency:guard-predicate-majority:witness"])
def test_old_and_suffixed_guard_receipts_do_not_grant_verification(monkeypatch, fallback, receipt):
    from core.audit import evidence_grade as grade
    if fallback:
        monkeypatch.setattr(grade, "_channel_detection_classifier", lambda _: None)
    assert not grade.is_verification_evidence(receipt)
    assert not grade.is_tool_evidence(receipt)


def test_other_consistency_producers_keep_their_reuse_policy(tmp_path):
    target = _write_target(tmp_path)
    entry = _entry(target, evidence_tools=["consistency:return-check"], body="independent contract", clean_basis="verdict")
    assert _reuse_ineligibility(entry, "auth.c:check_pw", current_strategies_fn=None, current_model=None) is None


def test_diagnostic_guard_models_do_not_erase_independent_verification():
    from core.audit.evidence_grade import is_verification_evidence
    assert is_verification_evidence("consistency:guard-presence+smt:check-array-bounds")
