"""Overflow receipts must establish the requested mathematical objective."""

import pytest

from core.audit.arithmetic_claim import parse_arithmetic_claim, parse_overflow_claim
from core.audit.condition_smt import disprove_integer_overflow
from core.audit.literal_call import check_literal_calls, literal_call_witness_valid
from core.audit import sweep


def test_negated_overflow_goal_cannot_receive_a_verification_receipt():
    source = ('unsigned Read(unsigned Value,unsigned Count){'
              'if(Value<=65536 && Count<=65536)return Value*Count;return 0;}')
    result = sweep._run_smt_verb_inner(
        file_path='unit.c', function_name='Read', verb='check-overflow', source=source,
        hypothesis='no integer overflow in `Value * Count`', integer_abi='ilp32')
    assert result.outcome == 'inconclusive', {'outcome': result.outcome, 'details': result.details}
    assert result.matches == []


@pytest.mark.parametrize('expression', [
    '`Value * Count`', '`Value` * `Count`', 'Value * Count',
    '`Value` times `Count`', 'Value times Count', '`((Value) * (Count))`',
])
def test_positive_overflow_goal_preserves_supported_expression_forms(expression):
    claim = f'CWE-190: Potential integer overflow in {expression}.'
    parsed = parse_overflow_claim(claim)
    assert parsed == parse_arithmetic_claim(claim)
    assert parsed is not None and parsed.operands == ('Value', 'Count') and parsed.operator == '*'


@pytest.mark.parametrize('goal', [
    'no integer overflow in `Value * Count`',
    'integer overflow in `Value * Count` only if Count is zero',
    'integer overflow in `Value * Count` unless the caller checks Count',
    'integer overflow in `Value * Count` and `Count * Value`',
])
def test_unknown_goal_cannot_authorise_either_overflow_direction(goal):
    source = ('unsigned Read(unsigned Value,unsigned Count){'
              'if(Value<=65536 && Count<=65536)return Value*Count;return 0;}')
    assert parse_arithmetic_claim(goal) is not None
    assert parse_overflow_claim(goal) is None
    direct = sweep._run_smt_verb_inner(
        file_path='unit.c', function_name='Read', verb='check-overflow', source=source,
        hypothesis=goal, integer_abi='ilp32')
    assert direct.outcome == 'inconclusive' and direct.matches == []
    auxiliary = disprove_integer_overflow(goal, source, file_path='unit.c', function_name='Read', integer_abi='ilp32')
    assert not auxiliary.disproved and not auxiliary.error


def test_literal_overflow_tuple_cannot_be_relabelled_as_a_negated_goal():
    source = ('unsigned Read(unsigned Value,unsigned Count){return Value*Count;}\n'
              'unsigned Drive(void){return Read(65536,65536);}\n')
    positive = 'integer overflow in `Value * Count`'
    negative = 'no integer overflow in `Value * Count`'
    reply = check_literal_calls(source, 'Read', 'check-overflow', positive, 'ilp32', [2])
    call = reply['calls'][0]
    assert call['verdict'] == 'violation'
    assert literal_call_witness_valid(reply, call, 'check-overflow', positive, 'ilp32')
    assert not literal_call_witness_valid(reply, call, 'check-overflow', negative, 'ilp32')
    declined = check_literal_calls(source, 'Read', 'check-overflow', negative, 'ilp32', [2])
    assert declined['calls'] == []


@pytest.mark.slow
def test_confined_overflow_worker_preserves_a_positive_closed_goal():
    source = ('unsigned Read(unsigned Value,unsigned Count){'
              'if(Value<=65536 && Count<=65536)return Value*Count;return 0;}')
    result = sweep.run_smt_verb_direct(
        file_path='unit.c', function_name='Read', verb='check-overflow', source=source,
        hypothesis='integer overflow in `Value` times `Count`', integer_abi='ilp32')
    assert result.outcome == 'confirmed', result.errors
    assert result.matches and not result.errors
    assert result.details['source_scope']['goal_contract'] == 'closed-overflow-objective-v1'
