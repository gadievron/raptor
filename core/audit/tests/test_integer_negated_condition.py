"""Whole logical-NOT truth keeps exact AST, typed operands and entry scope."""
import pytest
from core.audit import integer_negated_condition as subject
from core.audit.integer_comparison import check_integer_comparison
from core.smt_solver.session import query_budget

EXPRESSION='!(Value < 0)'
SOURCE=f'int Read(unsigned Value){{if({EXPRESSION})return 1;return 0;}}'

@pytest.fixture(autouse=True)
def dependencies():
    pytest.importorskip('z3')
    pytest.importorskip('tree_sitter_c')


def check(source=SOURCE,expression=EXPRESSION,*,truth='true',language='c',abi='lp64'):
    return check_integer_comparison(source,f'Condition is always {truth} in `{expression}`.',language=language,integer_abi=abi)

@pytest.mark.parametrize('language',['c','cpp'])
@pytest.mark.parametrize('abi',['lp64','llp64','i16'])
def test_unsigned_whole_not_is_true_without_own_premises(language,abi):
    pytest.importorskip('tree_sitter_'+language)
    result=check(language=language,abi=abi)
    assert result['matches_claim'] is True and result['constant_truth'] is True,result
    assert result['entry_witness_validated'] and result['checked_property']=='constant-negated-comparison'
    assert result['source_operation']['comparison']==['Value','<','0']
    assert result['source_operation']['operator']=='!' and result['source_operation']['premises']==[]

@pytest.mark.parametrize('truth',['true','false'])
def test_signed_control_is_nonconstant(truth):
    assert check(SOURCE.replace('unsigned Value','int Value'),truth=truth)['matches_claim'] is False


def test_identical_operand_negation_is_false():
    expression='!(Value == Value)'
    result=check(SOURCE.replace(EXPRESSION,expression),expression,truth='false')
    assert result['matches_claim'] is True and result['constant_truth'] is False

@pytest.mark.parametrize('truth',['true','false'])
def test_mixed_signed_comparison_uses_actual_conversion(truth):
    expression='!(Value < Limit)'
    source=f'int Read(int Value,unsigned Limit){{if({expression})return 1;return 0;}}'
    assert check(source,expression,truth=truth)['matches_claim'] is False


def test_outer_guard_truth_and_contradictory_entry_are_separate():
    source=f'int Read(int Value){{if(Value>=0){{if({EXPRESSION})return 1;}}return 0;}}'
    result=check(source)
    assert result['matches_claim'] is True and result['source_operation']['premises']==['Value >= 0']
    assert check(source.replace('Value>=0','Value<0 && Value>=0'))['matches_claim'] is None

@pytest.mark.parametrize('expression',[
    '!Value < 0','!!(Value < 0)','!(Value < 0 && Value > 1)',
    '!(Value++ < 0)','!(unknown() < 0)','!((unsigned)Value < 0)',
    '!(Value < 0U)','!(Value < 2147483648)',
])
def test_nonwhole_negation_compound_effect_cast_and_literal_refusals(expression):
    assert check(SOURCE.replace(EXPRESSION,expression),expression)['matches_claim'] is None

@pytest.mark.parametrize('source',[
    SOURCE.replace('unsigned Value','volatile unsigned Value'),
    SOURCE.replace('unsigned Value','unsigned *Value'),
    SOURCE.replace('if(','Value=0;if(',1),SOURCE.replace('if(','unknown();if(',1),
    f'int Read(unsigned Value){{return {EXPRESSION};}}',
    SOURCE.replace('return 0;',f'if({EXPRESSION})return 2;return 0;'),
])
def test_type_prefix_position_and_duplicate_site_refusals(source):
    assert check(source)['matches_claim'] is None


def test_inner_truth_or_different_claim_cannot_replace_whole_not():
    assert check(expression='Value < 0')['matches_claim'] is None
    assert check(truth='false')['matches_claim'] is False
    assert check(SOURCE.replace('Value < 0','Value <= 0'))['matches_claim'] is None

@pytest.mark.parametrize('call',[1,2])
def test_unknown_never_grants_credit(monkeypatch,call):
    from core.smt_solver import z3
    original=subject.check_solver
    calls=[]
    def undecided(solver):
        calls.append(1)
        return z3.unknown if len(calls)==call else original(solver)
    monkeypatch.setattr(subject,'check_solver',undecided)
    result=check()
    assert len(calls)==call and result['matches_claim'] is None and not result['entry_witness_validated']


def test_budget_and_forged_replay_remain_inconclusive(monkeypatch):
    with query_budget(0):
        assert check()['matches_claim'] is None
    monkeypatch.setattr(subject,'format_vars',lambda *args,**kwargs:{'Value':0})
    source=f'int Read(unsigned Value){{if(Value>2){{if({EXPRESSION})return 1;}}return 0;}}'
    assert check(source)['matches_claim'] is None
