"""An integer witness must establish the requested positive source goal."""

import pytest

from core.audit import evidence_grade, sweep
from core.audit.integer_goal import COMPARISON_GOALS, DIVISION_GOALS, parse_integer_goal


def test_negated_division_goal_cannot_receive_a_verification_receipt():
    source = "int Read(int Value,int Count){return Value/Count;}"
    claim = "no division by zero in `Value / Count`"
    result = sweep._run_smt_verb_inner(file_path="unit.c", function_name="Read", verb="check-integer-division",
                                      source=source, hypothesis=claim, integer_abi="lp64")
    assert result.outcome == "inconclusive", {
        "outcome": result.outcome,
        "matches": result.matches,
        "verification_role": sweep.get_smt_verb_role("check-integer-division"),
        "verification_rule": evidence_grade.is_verification_evidence(result.rule_id),
        "source_scope": result.details.get("source_scope"),
    }
    assert result.matches == []


@pytest.mark.parametrize('claim', [
    'division by zero in `Value / Count`',
    'Potential zero divisor in `Value / Count`.',
    'CWE-369: Possible division by zero at `Value / Count`.',
    '`Value / Count` division by zero',
    'Potential `Value / Count` division by zero.',
])
def test_complete_positive_goal_labels(claim):
    assert parse_integer_goal(claim, DIVISION_GOALS) == 'zero-divisor'


@pytest.mark.parametrize('claim', [
    'no division by zero in `Value / Count`',
    'division by zero in `Value / Count` only when Count is positive',
    'division by zero unless validated in `Value / Count`',
    'division by zero in `Value / Count` and `Other / Count`',
    'division by zero',
    'x' * 8193,
])
def test_unknown_or_qualified_goal_is_not_rewritten(claim):
    assert parse_integer_goal(claim, DIVISION_GOALS) is None


@pytest.mark.parametrize('truth', ['true', 'false'])
def test_comparison_polarity_is_part_of_the_goal(truth):
    assert parse_integer_goal(f'comparison is always {truth}: `Value < 0`', COMPARISON_GOALS) == truth


@pytest.mark.parametrize('verb,source,claim', [
    ('check-integer-division', 'int Read(int Value,int Count){return Value/Count;}',
     'division by zero in `Value / Count` only if Count is positive'),
    ('check-shift-count', 'int Read(int Value,int Count){return Value<<Count;}',
     'no invalid shift count in `Value << Count`'),
    ('check-integer-comparison', 'int Read(unsigned Value){return Value<0;}',
     'no comparison is always false: `Value < 0`'),
    ('check-array-bounds', 'int Read(int Index){int Data[4]={0};return Data[Index];}',
     'no out-of-bounds read at `Data[Index]`'),
])
def test_worker_does_not_confirm_an_unadmitted_goal(verb, source, claim):
    result = sweep._run_smt_verb_inner(file_path='unit.c', function_name='Read', verb=verb,
                                      source=source, hypothesis=claim, integer_abi='lp64')
    assert result.outcome == 'inconclusive'
    assert result.matches == []


@pytest.mark.slow
def test_confined_worker_cannot_promote_a_negated_division_goal():
    result = sweep.run_smt_verb_direct(
        file_path='unit.c', function_name='Read', verb='check-integer-division',
        source='int Read(int Value,int Count){return Value/Count;}',
        hypothesis='no division by zero in `Value / Count`', integer_abi='lp64')
    assert result.outcome == 'inconclusive', result.errors
    assert result.errors == []
    assert result.matches == []
    assert result.details['source_scope']['query_contract'] == 'source-integer-division-v3'
