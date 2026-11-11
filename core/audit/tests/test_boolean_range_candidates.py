"""Conservative interval discovery leaves proof authority with the source oracle."""
import operator
import pytest
from core.audit import arithmetic_seeds, integer_conjunction, sweep
from core.audit.integer_comparison import check_integer_comparison

@pytest.fixture(autouse=True)
def dependencies():
    pytest.importorskip('tree_sitter_c')


def source(expression, spelling='int'):
    return f'int Read({spelling} Value){{if({expression})return 1;return 0;}}'


def test_interval_kernel_matches_every_signed_byte_value_at_boundary_thresholds():
    comparisons = {'<':operator.lt, '<=':operator.le, '>':operator.gt, '>=':operator.ge, '==':operator.eq, '!=':operator.ne}
    for op, compare in comparisons.items():
        for threshold in (-129, -128, -1, 0, 1, 127, 128):
            intervals = integer_conjunction._literal_intervals(op, threshold, -128, 127)
            actual = {value for start, end in intervals for value in range(start, end+1)}
            assert actual == {value for value in range(-128,128) if compare(value,threshold)}

@pytest.mark.parametrize('expression,truth', [
    ('Value < 0 && Value >= 1', False), ('Value <= 0 && Value >= 0', None),
    ('Value < 10 || Value > 5', True), ('Value < 10 || Value > 10', None),
    ('Value <= 10 || Value >= 11', True), ('Value < 10 || Value >= 11', None),
    ('Value == 0 && Value == 1', False), ('Value != 0 && Value == 1', None),
    ('Value != 0 || Value != 1', None),  # existing exclusion producer owns this case
    ('Value != 1 || Value != 0x1', None),
])
def test_strict_inclusive_hole_and_existing_producer_boundaries(expression, truth):
    rows = integer_conjunction.range_condition_candidates(source(expression), language='c', integer_abi='lp64')
    assert [row[3] for row in rows] == ([] if truth is None else [truth])

@pytest.mark.parametrize('spelling,expression,truth', [
    ('_Bool','Value == 0 || Value == 1',True),
    ('_Bool','Value != 0 && Value != 1',False),
    ('signed char','Value <= 127 || Value >= 128',True),
    ('unsigned char','Value < 0 && Value >= 1',False),
    ('unsigned','Value < -1 && Value >= 1',None),
    ('volatile int','Value < 0 && Value >= 1',None),
    ('int *','Value < 0 && Value >= 1',None),
])
def test_storage_domains_and_conversion_refusals(spelling, expression, truth):
    rows = integer_conjunction.range_condition_candidates(source(expression, spelling), language='c', integer_abi='lp64')
    assert [row[3] for row in rows] == ([] if truth is None else [truth])

@pytest.mark.parametrize('language', ['c','cpp'])
@pytest.mark.parametrize('abi', ['lp64','llp64','i16'])
def test_discovered_distinct_bound_claim_reaches_existing_oracle(language, abi):
    pytest.importorskip('z3')
    pytest.importorskip('tree_sitter_'+language)
    for expression,truth in [('Value < 0 && Value >= 1',False),('Value < 10 || Value > 5',True)]:
        rows = integer_conjunction.range_condition_candidates(source(expression), language=language, integer_abi=abi)
        assert len(rows)==1 and rows[0][3] is truth
        result = check_integer_comparison(source(expression),f'Condition is always {str(truth).lower()} in `{expression}`.',language=language,integer_abi=abi)
        assert result['matches_claim'] is True and result['entry_witness_validated'],result
        assert result['source_operation']['premises']==[]


def test_discovery_is_solver_free_idempotent_and_respects_modes(monkeypatch):
    def forbidden(*args,**kwargs):
        raise AssertionError('range candidate discovery entered proof')
    for name in ('ComparisonModel','guards_for_operation','new_solver'):
        monkeypatch.setattr(integer_conjunction,name,forbidden)
    text=source('Value < 0 && Value >= 1')
    gap=dict(file='unit.c',name='Read',line_start=1,line_end=1)
    assert arithmetic_seeds.seed_arithmetic_hypotheses([gap],{'unit.c':text},mode='quality',integer_abi='lp64')==1
    row=gap['injected_hypotheses'][0]
    assert row['mechanism']=='Condition is always false in `Value < 0 && Value >= 1`.'
    assert row['arithmetic_site']['binding_status']=='candidate'
    assert arithmetic_seeds.seed_arithmetic_hypotheses([gap],{'unit.c':text},mode='quality',integer_abi='lp64')==0
    other=dict(file='unit.c',name='Read',line_start=1,line_end=1)
    assert arithmetic_seeds.seed_arithmetic_hypotheses([other],{'unit.c':text},mode='security',integer_abi='lp64')==0


def test_existing_disjunction_lead_is_not_duplicated():
    gap=dict(file='unit.c',name='Read',line_start=1,line_end=1)
    text=source('Value != 0 || Value != 1')
    assert arithmetic_seeds.seed_arithmetic_hypotheses([gap],{'unit.c':text},mode='quality',integer_abi='lp64')==1
    assert len(gap['injected_hypotheses'])==1


def test_candidate_does_not_admit_a_mutated_prefix_to_the_oracle():
    pytest.importorskip('z3')
    text=source('Value < 0 && Value >= 1').replace('if(','Value=0;if(',1)
    assert integer_conjunction.range_condition_candidates(text,language='c',integer_abi='lp64')
    result=check_integer_comparison(text,'Condition is always false in `Value < 0 && Value >= 1`.',language='c',integer_abi='lp64')
    assert result['matches_claim'] is None and not result['entry_witness_validated']

@pytest.mark.slow
def test_real_confined_receipt_for_discovered_range_condition():
    pytest.importorskip('z3')
    text=source('Value < 0 && Value >= 1')
    gap=dict(file='unit.c',name='Read',line_start=1,line_end=1)
    assert arithmetic_seeds.seed_arithmetic_hypotheses([gap],{'unit.c':text},mode='quality',integer_abi='lp64')==1
    claim=gap['injected_hypotheses'][0]['mechanism']
    result=sweep.run_smt_verb_direct(file_path='unit.c',function_name='Read',verb='check-integer-comparison',source=text,hypothesis=claim,integer_abi='lp64')
    assert result.outcome=='confirmed',result.errors
    assert result.details['source_scope']['query_contract']=='source-integer-comparison-v10'
    assert result.details['entry_witness_validated']
