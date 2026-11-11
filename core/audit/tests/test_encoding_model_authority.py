"""A supplied byte-transfer model cannot refute a source claim."""

import pytest

from core.audit import evidence_grade
from core.audit.refutation_source import SourceIdentity
from core.audit.smt_evidence import is_diagnostic_smt_rule, is_non_refuting_smt_rule, scope_smt_observation
from core.audit.verification_results import ClaimRefutation, ProbeOutcome, ToolChainResult

VERB = "check-encoding-residual"


def test_supplied_transfer_unsat_cannot_mint_a_source_refutation():
    scope = dict(file="unit.c", function="Encode", line_start=1, hypothesis="source encoding is incomplete")
    identity = SourceIdentity("source", (1, 2, 3))
    receipt = ClaimRefutation(**scope, source_identity=identity,
                             checks=(ProbeOutcome("smt", "refuted", "smt:" + VERB),))
    assert not receipt.matches(**scope, source_identity=identity)


@pytest.mark.parametrize("feasible", [True, False, None])
def test_transfer_observation_preserves_math_without_source_refutation(feasible):
    original = {"feasible": feasible, "model": {"byte": 1} if feasible is True else {}}
    outcome = "confirmed" if feasible is True else "refuted" if feasible is False else "inconclusive"
    verdict, details = scope_smt_observation(VERB, outcome, original)
    assert verdict == ("confirmed" if feasible is True else "inconclusive")
    assert details["feasible"] is feasible
    assert details["oracle_scope"] == "supplied-byte-transfer"
    assert details is not original and "oracle_scope" not in original


@pytest.mark.parametrize("suffix", ["", ":witness", ":model", ":legacy"])
def test_encoding_model_namespace_is_diagnostic_and_non_refuting(suffix):
    rule = "smt:" + VERB + suffix
    assert is_diagnostic_smt_rule(rule) and is_non_refuting_smt_rule(rule)
    assert not evidence_grade.is_verification_evidence(rule)


@pytest.mark.parametrize("tool,prefix", [("smt", "smt:"), ("smt", ""), ("legacy-channel", "smt:")])
@pytest.mark.parametrize("suffix", ["", ":witness"])
def test_historical_encoding_refutations_cannot_reenter_through_aliases(tool, prefix, suffix):
    scope = dict(file="unit.c", function="Encode", line_start=1, hypothesis="source encoding is incomplete")
    identity = SourceIdentity("source", (1, 2, 3))
    rule = prefix + VERB + suffix
    receipt = ClaimRefutation(**scope, source_identity=identity,
                             checks=(ProbeOutcome(tool, "refuted", rule),))
    assert not receipt.matches(**scope, source_identity=identity)
    chain = ToolChainResult(**scope, source_identity=identity)
    chain.observe(tool, "refuted", rule)
    assert chain.refutation_record(**scope) is None


def test_real_transfer_model_unsat_remains_mathematical_observation_only():
    pytest.importorskip("z3")
    from packages.exploit_feasibility.smt_encoding import check_encoding_residual

    result = check_encoding_residual({"escaped": ["x"]}, forbidden=["x"])
    assert result["feasible"] is False
    outcome, details = scope_smt_observation(VERB, "refuted", result)
    assert outcome == "inconclusive"
    assert details["feasible"] is False and details["oracle_scope"] == "supplied-byte-transfer"
