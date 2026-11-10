"""Actual chain receipts are diagnostic; discovery never runs a solver."""
import pytest
from core.audit import arithmetic_seeds, integer_chain_condition, sweep
from core.audit.hypothesis_mapping import hypothesis_to_smt_verb
from core.audit.probe_function_scope import source_binding
from core.audit.smt_evidence import is_diagnostic_smt_rule,is_non_refuting_smt_rule

SOURCE='int Read(int Value){if(0 <= Value < 10)return 1;return 0;}'
CLAIM='Condition is always true in `(0 <= Value) < 10`.'
VERB='check-integer-comparison'

@pytest.fixture(autouse=True)
def dependencies():
    pytest.importorskip('z3')
    pytest.importorskip('tree_sitter_c')


def test_chain_receipt_is_exact_source_bound_and_non_refuting():
    result=sweep._run_smt_verb_inner(file_path='unit.c',function_name='Read',verb=VERB,source=SOURCE,hypothesis=CLAIM,integer_abi='lp64')
    assert result.outcome=='confirmed' and result.matches,result.errors
    assert result.details['source_scope']==source_binding(SOURCE,'Read',verb=VERB,hypothesis=CLAIM,integer_abi='lp64')
    assert result.details['source_scope']['query_contract']=='source-integer-comparison-v8'
    assert result.details['checked_property']=='constant-chained-comparison'
    assert is_diagnostic_smt_rule('smt:'+VERB) and is_non_refuting_smt_rule('smt:'+VERB)


def test_discovery_uses_both_boolean_outcomes_without_solver_or_guard_calls(monkeypatch):
    def forbidden(*args,**kwargs):
        raise AssertionError('candidate discovery entered chain proof')
    for name in ('ComparisonModel','guards_for_operation','new_solver'):
        monkeypatch.setattr(integer_chain_condition,name,forbidden)
    gap=dict(file='unit.c',name='Read',line_start=1,line_end=1)
    assert arithmetic_seeds.seed_arithmetic_hypotheses([gap],{'unit.c':SOURCE},mode='quality',integer_abi='lp64')==1
    row=gap['injected_hypotheses'][0]
    assert row['mechanism']==CLAIM and hypothesis_to_smt_verb(CLAIM)==VERB
    assert row['arithmetic_site']['binding_status']=='candidate'
    assert arithmetic_seeds.seed_arithmetic_hypotheses([gap],{'unit.c':SOURCE},mode='quality',integer_abi='lp64')==0
    for text,mode in [(SOURCE.replace('Value < 10','Value < 1'),'quality'),(SOURCE,'security')]:
        other=dict(file='unit.c',name='Read',line_start=1,line_end=1)
        assert arithmetic_seeds.seed_arithmetic_hypotheses([other],{'unit.c':text},mode=mode,integer_abi='lp64')==0

@pytest.mark.slow
def test_real_confined_chain_receipt():
    result=sweep.run_smt_verb_direct(file_path='unit.c',function_name='Read',verb=VERB,source=SOURCE,hypothesis=CLAIM,integer_abi='lp64')
    assert result.outcome=='confirmed',result.errors
    assert result.details['source_scope']['query_contract']=='source-integer-comparison-v8'
    assert result.details['checked_property']=='constant-chained-comparison'
    assert result.details['entry_witness_validated']


def test_grouped_equality_seeds_preserve_actual_precedence_through_the_oracle():
    from core.audit.integer_comparison import check_integer_comparison
    for language in ('c','cpp'):
        pytest.importorskip('tree_sitter_'+language)
        for op in ('==','!='):
            source=f'int Read(int Value){{if((0 {op} Value) < 10)return 1;return 0;}}'
            file='unit.'+('c' if language=='c' else 'cpp')
            gap=dict(file=file,name='Read',line_start=1,line_end=1)
            assert arithmetic_seeds.seed_arithmetic_hypotheses([gap],{file:source},mode='quality',integer_abi='lp64')==1
            claim=gap['injected_hypotheses'][0]['mechanism']
            result=check_integer_comparison(source,claim,language=language,integer_abi='lp64')
            assert result['matches_claim'] is True,(claim,result)
