"""Literal caller tuples must establish the stated positive array goal."""

import pytest

from core.audit.literal_call import check_literal_calls, literal_call_witness_valid

SOURCE = ('int Read(int Index){int Data[4]={0};return Data[Index];}\n'
          'int Drive(void){return Read(4);}\n')


def test_negated_array_goal_cannot_be_confirmed_by_a_literal_tuple():
    goal = 'no out-of-bounds read at `Data[Index]`'
    reply = check_literal_calls(SOURCE, 'Read', 'check-array-bounds', goal, 'lp64', [2])
    violations = [call for call in reply['calls'] if call['verdict'] == 'violation']
    accepted = [call for call in violations
                if literal_call_witness_valid(reply, call, 'check-array-bounds', goal, 'lp64')]
    assert accepted == [], reply


@pytest.mark.parametrize('goal', [
    'out-of-bounds read at `Data[Index]`', 'Data[Index]',
    'Potential out-of-bounds read at `Data[Index]`.',
    'CWE-125: possible out-of-bounds read at `Data[Index]`.',
])
def test_positive_literal_goal_retains_a_validated_tuple(goal):
    reply = check_literal_calls(SOURCE, 'Read', 'check-array-bounds', goal, 'lp64', [2])
    assert reply['status'] == 'checked'
    assert reply['binding']['query_contract'] == 'common-width-literal-frame-v13'
    assert len(reply['calls']) == 1
    call = reply['calls'][0]
    assert call['verdict'] == 'violation' and call['arguments'] == {'Index': 4}
    assert literal_call_witness_valid(reply, call, 'check-array-bounds', goal, 'lp64')


@pytest.mark.parametrize('goal', [
    'no out-of-bounds read at `Data[Index]`',
    'out-of-bounds read at `Data[Index]` only if Index is negative',
    'safe read at `Data[Index]`',
])
def test_positive_worker_tuple_cannot_be_relabelled_with_another_goal(goal):
    positive = 'out-of-bounds read at `Data[Index]`'
    reply = check_literal_calls(SOURCE, 'Read', 'check-array-bounds', positive, 'lp64', [2])
    call = reply['calls'][0]
    assert literal_call_witness_valid(reply, call, 'check-array-bounds', positive, 'lp64')
    assert not literal_call_witness_valid(reply, call, 'check-array-bounds', goal, 'lp64')


@pytest.mark.slow
def test_confined_literal_gate_holds_a_negated_read_goal():
    from core.audit.literal_call_gate import evaluate_literal_caller_gate

    decision = evaluate_literal_caller_gate(
        'unit.c', 'Read', 'check-array-bounds', 'no out-of-bounds read at `Data[Index]`',
        defining_source=SOURCE, source=SOURCE.splitlines()[0], integer_abi='lp64')
    assert decision is not None
    assert decision.action == 'hold' and decision.channel_outcome == 'inconclusive'
    assert decision.citation == ''
