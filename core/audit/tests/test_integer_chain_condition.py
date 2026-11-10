"""Comparison-result promotion preserves the actual C/C++ comparison chain."""
import pytest
from core.audit import integer_chain_condition as subject
from core.audit.integer_comparison import check_integer_comparison
from core.smt_solver.session import query_budget

EXPRESSION='0 <= Value < 10'
SOURCE=f'int Read(int Value){{if({EXPRESSION})return 1;return 0;}}'

@pytest.fixture(autouse=True)
def dependencies():
    pytest.importorskip('z3')
    pytest.importorskip('tree_sitter_c')


def check(source=SOURCE,expression=EXPRESSION,*,truth='true',language='c',abi='lp64'):
    return check_integer_comparison(source,f'Condition is always {truth} in `{expression}`.',language=language,integer_abi=abi)

@pytest.mark.parametrize('language',['c','cpp'])
@pytest.mark.parametrize('abi,width',[('lp64',32),('llp64',32),('i16',16)])
@pytest.mark.parametrize('spelling',['int','unsigned','unsigned long long','signed char'])
def test_actual_chain_is_true_and_outer_frame_is_promoted_int(language,abi,width,spelling):
    pytest.importorskip('tree_sitter_'+language)
    result=check(SOURCE.replace('int Value',spelling+' Value'),language=language,abi=abi)
    assert result['matches_claim'] is True and result['constant_truth'] is True,result
    assert result['entry_witness_validated'] and result['checked_property']=='constant-chained-comparison'
    operation=result['source_operation']
    assert operation['comparison_result_width']==width and operation['comparison_result_signed']
    assert operation['inner_comparison']==['0','<=','Value'] and operation['outer_literal']=='10'
    assert operation['premises']==[]

@pytest.mark.parametrize('truth',['true','false'])
def test_bound_one_signed_control_is_not_constant(truth):
    expression='0 <= Value < 1'
    assert check(SOURCE.replace(EXPRESSION,expression),expression,truth=truth)['matches_claim'] is False

@pytest.mark.parametrize('language',['c','cpp'])
def test_unsigned_inner_constant_and_negative_outer_literal_use_different_frames(language):
    pytest.importorskip('tree_sitter_'+language)
    for expression in ['0 <= Value < 1','0 <= Value < -1']:
        source=SOURCE.replace('int Value','unsigned long long Value').replace(EXPRESSION,expression)
        result=check(source,expression,truth='false',language=language)
        assert result['matches_claim'] is True and result['source_operation']['comparison_result_width']==32,result


def test_outer_guards_and_empty_entry_are_not_dropped():
    source=f'int Read(int Value){{if(Value<0){{if({EXPRESSION})return 1;}}return 0;}}'
    result=check(source)
    assert result['matches_claim'] is True and result['source_operation']['premises']==['Value < 0']
    assert check(source.replace('Value<0','Value<0 && Value>=0'))['matches_claim'] is None

@pytest.mark.parametrize('expression',[
    '0 <= (Value < 10)','0 == Value < 10','0 <= Value < 10 < 20','0 <= Value++ < 10',
    '0 <= unknown() < 10','0 <= (unsigned)Value < 10',
    '0U <= Value < 10','0 <= Value < 10U','0 <= Value < 2147483648',
])
def test_right_nesting_extra_nodes_effects_casts_and_unsupported_literals_refuse(expression):
    assert check(SOURCE.replace(EXPRESSION,expression),expression)['matches_claim'] is None

@pytest.mark.parametrize('source',[
    SOURCE.replace('int Value','volatile int Value'),SOURCE.replace('int Value','int *Value'),
    SOURCE.replace('if(','Value=0;if(',1),SOURCE.replace('if(','unknown();if(',1),
    f'int Read(int Value){{return {EXPRESSION};}}',
    SOURCE.replace('return 0;',f'if({EXPRESSION})return 2;return 0;'),
])
def test_source_prefix_position_type_and_ambiguity_refusals(source):
    assert check(source)['matches_claim'] is None


def test_actual_ast_cannot_be_replaced_with_a_mathematical_range():
    assert check(expression='0 <= Value && Value < 10')['matches_claim'] is None
    assert check(SOURCE.replace('0 <= Value','1 <= Value'))['matches_claim'] is None
    assert check(truth='false')['matches_claim'] is False

@pytest.mark.parametrize('call',[1,2])
def test_unknown_query_cannot_grant_truth_credit(monkeypatch,call):
    from core.smt_solver import z3
    original=subject.check_solver
    calls=[]
    def undecided(solver):
        calls.append(1)
        return z3.unknown if len(calls)==call else original(solver)
    monkeypatch.setattr(subject,'check_solver',undecided)
    result=check()
    assert len(calls)==call and result['matches_claim'] is None and not result['entry_witness_validated']


def test_budget_and_forged_entry_replay_remain_inconclusive(monkeypatch):
    with query_budget(0):
        assert check()['matches_claim'] is None
    monkeypatch.setattr(subject,'format_vars',lambda *args,**kwargs:{'Value':0})
    source=f'int Read(int Value){{if(Value>2){{if({EXPRESSION})return 1;}}return 0;}}'
    assert check(source)['matches_claim'] is None
