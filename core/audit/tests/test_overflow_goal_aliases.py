"""Dispatched arithmetic aliases must retain their exact source operation."""

import pytest

from core.audit.arithmetic_claim import parse_overflow_claim
from core.audit.condition_smt import disprove_integer_overflow
from core.audit.literal_call import check_literal_calls, literal_call_witness_valid
from core.audit import sweep
from core.audit.hypothesis_mapping import hypothesis_to_smt_verb

SOURCE = ('int Read(int Value,int Count){'
          'if(Value>0 && Count>0)return Value*Count;return 0;}')


def test_dispatched_multiplication_goal_retains_the_native_product_proof():
    canonical = 'integer overflow in `Value * Count`'
    alias = 'multiplication overflow in `Value * Count`'
    assert hypothesis_to_smt_verb(alias) == 'check-overflow'
    common = dict(file_path='unit.c', function_name='Read', verb='check-overflow',
                  source=SOURCE, integer_abi='lp64')
    assert sweep._run_smt_verb_inner(**common, hypothesis=canonical).outcome == 'confirmed'
    result = sweep._run_smt_verb_inner(**common, hypothesis=alias)
    assert result.outcome == 'confirmed', result.details


@pytest.mark.parametrize('label,operator', [
    ('addition overflow', '+'), ('multiplication overflow', '*'),
    ('arithmetic overflow', '+'), ('arithmetic overflow', '*'),
])
def test_dispatched_positive_alias_confirms_only_a_bound_operation(label, operator):
    source = SOURCE.replace('Value*Count', 'Value' + operator + 'Count')
    goal = f'CWE-190: Possible {label} in `Value {operator} Count`.'
    assert hypothesis_to_smt_verb(goal) == 'check-overflow'
    claim = parse_overflow_claim(goal)
    assert claim is not None and claim.operator == operator
    result = sweep._run_smt_verb_inner(
        file_path='unit.c', function_name='Read', verb='check-overflow', source=source,
        hypothesis=goal, integer_abi='lp64')
    assert result.outcome == 'confirmed', result.details
    assert result.details['witness_validated']


@pytest.mark.parametrize('label,operator', [
    ('addition overflow', '*'), ('multiplication overflow', '+'),
    ('no addition overflow', '+'), ('no multiplication overflow', '*'),
    ('addition overflow unless validated', '+'),
    ('multiplication overflow only for positive Count', '*'),
    ('truncation overflow', '+'),
])
def test_other_objectives_cannot_borrow_an_existing_arithmetic_witness(label, operator):
    source = SOURCE.replace('Value*Count', 'Value' + operator + 'Count')
    goal = f'{label} in `Value {operator} Count`'
    assert parse_overflow_claim(goal) is None
    result = sweep._run_smt_verb_inner(
        file_path='unit.c', function_name='Read', verb='check-overflow', source=source,
        hypothesis=goal, integer_abi='lp64')
    assert result.outcome == 'inconclusive' and result.matches == []


@pytest.mark.usefixtures('overflow_disproof_unit_worker')
def test_auxiliary_disproof_accepts_the_same_closed_alias():
    safe = SOURCE.replace('Value>0 && Count>0', 'Value>0 && Value<=100 && Count>0 && Count<=100')
    result = disprove_integer_overflow(
        'multiplication overflow in `Value * Count`', safe,
        file_path='unit.c', function_name='Read', integer_abi='lp64')
    assert result.disproved and not result.error, result.reasoning


def test_literal_alias_tuple_requires_the_correct_operator_label():
    source = ('unsigned Read(unsigned Value,unsigned Count){return Value*Count;}\n'
              'unsigned Drive(void){return Read(65536,65536);}\n')
    goal = 'multiplication overflow in `Value * Count`'
    reply = check_literal_calls(source, 'Read', 'check-overflow', goal, 'lp64', [2])
    call = reply['calls'][0]
    assert call['verdict'] == 'violation'
    assert literal_call_witness_valid(reply, call, 'check-overflow', goal, 'lp64')
    assert not literal_call_witness_valid(reply, call, 'check-overflow',
                                          'addition overflow in `Value * Count`', 'lp64')


@pytest.mark.slow
def test_confined_worker_preserves_the_operation_specific_alias_contract():
    result = sweep.run_smt_verb_direct(
        file_path='unit.c', function_name='Read', verb='check-overflow', source=SOURCE,
        hypothesis='multiplication overflow in `Value * Count`', integer_abi='lp64')
    assert result.outcome == 'confirmed', result.errors
    assert result.details['witness_validated'] and not result.errors
    assert result.details['source_scope']['goal_contract'] == 'closed-overflow-objective-v2'
