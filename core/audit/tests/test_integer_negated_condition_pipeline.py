"""Exact whole-NOT receipts replace unadmitted inner discovery claims."""
import pytest
from core.audit import arithmetic_seeds,integer_negated_condition,sweep
from core.audit.hypothesis_mapping import hypothesis_to_smt_verb
from core.audit.probe_function_scope import source_binding
from core.audit.smt_evidence import is_diagnostic_smt_rule,is_non_refuting_smt_rule

SOURCE='int Read(unsigned Value){if(!(Value < 0))return 1;return 0;}'
CLAIM='Condition is always true in `!(Value < 0)`.'
VERB='check-integer-comparison'

@pytest.fixture(autouse=True)
def dependencies():
    pytest.importorskip('z3')
    pytest.importorskip('tree_sitter_c')


def test_whole_not_receipt_is_exact_and_non_refuting():
    result=sweep._run_smt_verb_inner(file_path='unit.c',function_name='Read',verb=VERB,source=SOURCE,hypothesis=CLAIM,integer_abi='lp64')
    assert result.outcome=='confirmed' and result.matches,result.errors
    assert result.details['source_scope']==source_binding(SOURCE,'Read',verb=VERB,hypothesis=CLAIM,integer_abi='lp64')
    assert result.details['source_scope']['query_contract']=='source-integer-comparison-v10'
    assert result.details['checked_property']=='constant-negated-comparison'
    assert is_diagnostic_smt_rule('smt:'+VERB) and is_non_refuting_smt_rule('smt:'+VERB)


def test_existing_inner_candidate_is_translated_once_without_solver_calls(monkeypatch):
    def forbidden(*args,**kwargs):
        raise AssertionError('candidate translation entered proof')
    for name in ('ComparisonModel','guards_for_operation','new_solver'):
        monkeypatch.setattr(integer_negated_condition,name,forbidden)
    gap=dict(file='unit.c',name='Read',line_start=1,line_end=1)
    assert arithmetic_seeds.seed_arithmetic_hypotheses([gap],{'unit.c':SOURCE},mode='quality',integer_abi='lp64')==1
    row=gap['injected_hypotheses'][0]
    assert row['mechanism']==CLAIM and hypothesis_to_smt_verb(CLAIM)==VERB
    assert row['arithmetic_site']['operator']=='!' and row['arithmetic_site']['binding_status']=='candidate'
    assert arithmetic_seeds.seed_arithmetic_hypotheses([gap],{'unit.c':SOURCE},mode='quality',integer_abi='lp64')==0
    assert len(gap['injected_hypotheses'])==1
    for text,mode in [(SOURCE.replace('unsigned Value','int Value'),'quality'),(SOURCE,'security')]:
        other=dict(file='unit.c',name='Read',line_start=1,line_end=1)
        assert arithmetic_seeds.seed_arithmetic_hypotheses([other],{'unit.c':text},mode=mode,integer_abi='lp64')==0


def test_plain_comparison_lead_remains_unchanged_and_not_globally_suppressed():
    gap=dict(file='unit.c',name='Read',line_start=1,line_end=1)
    text=SOURCE.replace('!(Value < 0)','Value < 0')
    assert arithmetic_seeds.seed_arithmetic_hypotheses([gap],{'unit.c':text},mode='quality',integer_abi='lp64')==1
    assert gap['injected_hypotheses'][0]['mechanism']=='Comparison is always false in `Value < 0`.'


def test_ancestor_guard_candidate_translates_with_its_premise():
    from core.audit.integer_comparison import check_integer_comparison
    text='int Read(int Value){if(Value>=0){if(!(Value<0))return 1;}return 0;}'
    gap=dict(file='unit.c',name='Read',line_start=1,line_end=1)
    assert arithmetic_seeds.seed_arithmetic_hypotheses([gap],{'unit.c':text},mode='quality',integer_abi='lp64')==1
    claim=gap['injected_hypotheses'][0]['mechanism']
    assert claim==CLAIM
    result=check_integer_comparison(text,claim,language='c',integer_abi='lp64')
    assert result['matches_claim'] is True and result['source_operation']['premises']==['Value >= 0']

@pytest.mark.slow
def test_real_confined_not_receipt():
    result=sweep.run_smt_verb_direct(file_path='unit.c',function_name='Read',verb=VERB,source=SOURCE,hypothesis=CLAIM,integer_abi='lp64')
    assert result.outcome=='confirmed',result.errors
    assert result.details['source_scope']['query_contract']=='source-integer-comparison-v10'
    assert result.details['checked_property']=='constant-negated-comparison'
    assert result.details['entry_witness_validated']
