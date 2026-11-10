"""QUALITY should discover range-fault leads its source oracle can establish."""

import pytest

from core.audit.hypothesis_mapping import hypothesis_to_smt_verb
from core.audit import sweep
from core.audit.arithmetic_seeds import seed_arithmetic_hypotheses


def test_quality_discovers_a_source_product_with_an_existing_native_witness():
    source = ('int Read(int Value,int Count){'
              'if(Value>0 && Count>0)return Value*Count;return 0;}')
    hypothesis = 'Potential integer overflow in `Value * Count`.'
    result = sweep._run_smt_verb_inner(
        file_path='unit.c', function_name='Read', verb='check-overflow',
        source=source, hypothesis=hypothesis, integer_abi='lp64')
    assert result.outcome == 'confirmed', result.details
    gap = {'file': 'unit.c', 'name': 'Read', 'line_start': 1, 'line_end': 1}
    seeded = seed_arithmetic_hypotheses([gap], {'unit.c': source}, mode='quality', integer_abi='lp64')
    assert seeded == 1, gap
    assert gap['injected_hypotheses'][0]['mechanism'] == hypothesis
    assert gap['injected_hypotheses'][0]['confidence'] == 'low'


def discover(source, *, abi='lp64', extension='c', mode='quality'):
    gap = {'file': 'unit.' + extension, 'name': 'Read', 'line_start': 1, 'line_end': 1}
    seed_arithmetic_hypotheses([gap], {gap['file']: source}, mode=mode, integer_abi=abi)
    return gap.get('injected_hypotheses', [])


@pytest.mark.parametrize('operator,types,guard', [
    ('+', 'int', 'Value>0 && Count>0'),
    ('-', 'unsigned', 'Value<Count'),
    ('*', 'int', 'Value>0 && Count>0'),
])
@pytest.mark.parametrize('extension', ['c', 'cpp'])
def test_new_range_fault_leads_reach_the_existing_source_oracle(operator, types, guard, extension):
    source = (f'{types} Read({types} Value,{types} Count){{'
              f'if({guard})return Value{operator}Count;return 0;}}')
    rows = discover(source, extension=extension)
    assert len(rows) == 1
    row = rows[0]
    assert row['arithmetic_site']['claim_kind'] == 'integer-wrap'
    assert row['arithmetic_site']['operator'] == operator
    assert row['confidence'] == 'low' and 'verdict' not in row and 'confirmed' not in row
    assert hypothesis_to_smt_verb(row['mechanism']) == 'check-overflow'
    result = sweep._run_smt_verb_inner(
        file_path='unit.' + extension, function_name='Read', verb='check-overflow',
        source=source, hypothesis=row['mechanism'], integer_abi='lp64')
    assert result.outcome == 'confirmed', result.details


@pytest.mark.parametrize('types,expression', [
    ('int', 'Value * 0'), ('int', 'Value * 1'), ('int', 'Value + 0'),
    ('int', 'Value - 0'), ('int', 'Value - Value'),
    ('short', 'Value * Count'), ('unsigned char', 'Value + Count'),
])
def test_storage_ranges_and_promotions_filter_non_wrapping_operations(types, expression):
    source = f'int Read({types} Value,{types} Count){{return {expression};}}'
    assert discover(source) == []


def test_target_int_width_changes_the_product_candidate():
    source = 'int Read(short Value,short Count){return Value*Count;}'
    assert discover(source, abi='lp64') == []
    rows = discover(source, abi='i16')
    assert len(rows) == 1 and rows[0]['arithmetic_site']['integer_abi']['int_bits'] == 16


def test_pure_candidate_does_not_claim_a_defined_prefix():
    source = 'int Read(int Value,int Count){int Prior=1/0;return Value*Count;}'
    rows = [row for row in discover(source) if row['arithmetic_site']['claim_kind'] == 'integer-wrap']
    assert len(rows) == 1 and 'verdict' not in rows[0]
    result = sweep._run_smt_verb_inner(
        file_path='unit.c', function_name='Read', verb='check-overflow', source=source,
        hypothesis=rows[0]['mechanism'], integer_abi='lp64')
    assert result.outcome == 'inconclusive' and result.matches == []


def test_many_new_candidates_cannot_evict_existing_division_leads():
    source = ('int Read(int Value,int Count){'
              + ''.join(f'int Slot{i}=Value*{i + 2};' for i in range(20))
              + 'return Value/Count;}')
    rows = discover(source)
    assert len(rows) == 4
    assert [row['arithmetic_site']['claim_kind'] for row in rows[:2]] == [
        'zero-divisor', 'signed-division-overflow']
    assert all(row['arithmetic_site']['claim_kind'] == 'integer-wrap' for row in rows[2:])


def test_existing_fixed_array_leads_keep_their_budget_before_new_wraps():
    source = ('int Read(unsigned Index,int Value,int Count){int Data[4]={0};'
              'int Ratio=Value/Count;int Product=Value*Count;'
              'if(Index<0)return 0;return Data[Index];}')
    rows = discover(source)
    assert len(rows) == 4
    assert [row['arithmetic_site']['claim_kind'] for row in rows] == [
        'zero-divisor', 'signed-division-overflow', 'constant-comparison-false', 'fixed-array-read']


@pytest.mark.parametrize('mode,abi', [('security', 'lp64'), ('quality', None)])
def test_new_candidates_still_require_quality_and_an_explicit_abi(mode, abi):
    assert discover('int Read(int Value,int Count){return Value*Count;}', mode=mode, abi=abi) == []


def test_mixed_unsigned_parameter_conversions_do_not_guess_an_operation_frame():
    assert discover('int Read(int Value,unsigned Count){return Value*Count;}') == []
