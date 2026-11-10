"""Compound arithmetic follows promoted result types, not storage widths."""
import pytest
from core.audit import integer_update as subject
from core.smt_solver.session import query_budget

@pytest.fixture(autouse=True)
def dependencies():
    pytest.importorskip('z3')
    pytest.importorskip('tree_sitter_c')


def check(source,expression='Value *= 2',abi='lp64',language='c'):
    return subject.check_integer_update(source,f'Potential signed compound overflow in `{expression}`.',language=language,integer_abi=abi)

@pytest.mark.parametrize('op,rhs',[('+=','1'),('-=','1'),('*=','2'),('+=','-1'),('*=','-1')])
@pytest.mark.parametrize('language',['c','cpp'])
def test_literal_compound_fault_has_independent_replay(op,rhs,language):
    pytest.importorskip('tree_sitter_'+language)
    result=check(f'int Scale(int Value){{Value {op} {rhs};return Value;}}',f'Value {op} {rhs}',language=language)
    assert result['violation'] is True and result['witness_validated'],result
    assert not -(1<<31)<=result['mathematical_result']<=(1<<31)-1
    assert result['source_operation']['operator']==op


def test_unsigned_narrow_lhs_can_overflow_signed_promoted_arithmetic():
    result=check('int Scale(unsigned char Value,int Count){Value += Count;return Value;}','Value += Count')
    assert result['violation'] is True and result['source_operation']['promoted_width']==32,result
    assert 0<=result['model']['Value']<=255

@pytest.mark.parametrize('abi,violation,width',[('lp64',False,64),('llp64',True,32)])
def test_wider_rhs_controls_arithmetic_before_storage_conversion(abi,violation,width):
    source='int Scale(int Value,long Count){if(Value==2&&Count==2147483647){Value *= Count;}return Value;}'
    result=check(source,'Value *= Count',abi)
    assert result['violation'] is violation,result
    if violation:
        assert result['source_operation']['promoted_width']==width
        assert result['mathematical_result']==4294967294
    else:assert not result['witness_validated']

@pytest.mark.parametrize('source,expression',[
    ('int Scale(short Value){Value += 1;return Value;}','Value += 1'),
    ('int Scale(short Value){Value *= 2;return Value;}','Value *= 2'),
    ('int Scale(int Value){Value -= Value;return Value;}','Value -= Value'),
    ('int Scale(int Value,int Count){if(Count==0){Value *= Count;}return Value;}','Value *= Count'),
])
def test_safe_arithmetic_is_not_narrow_storage_or_source_safety_proof(source,expression):
    result=check(source,expression)
    assert result['violation'] is False and not result['witness_validated'],result

@pytest.mark.parametrize('op',['+=','*='])
def test_repeated_operands_share_the_same_preupdate_symbol(op):
    value=2147483647 if op=='+=' else 65536
    result=check(f'int Scale(int Value){{if(Value=={value}){{Value {op} Value;}}return Value;}}',f'Value {op} Value')
    assert result['violation'] is True and set(result['model'])=={'Value'},result


def test_const_rhs_is_a_readable_parameter():
    result=check('int Scale(int Value,const int Count){if(Count==1){Value += Count;}return Value;}','Value += Count')
    assert result['violation'] is True,result

@pytest.mark.parametrize('source,expression',[
    ('int Scale(const int Value){Value *= 2;return Value;}','Value *= 2'),
    ('int Scale(volatile int Value){Value *= 2;return Value;}','Value *= 2'),
    ('int Scale(int *Value){*Value *= 2;return 0;}','Value *= 2'),
    ('int Scale(int Value){int Other=Value;Other *= 2;return Other;}','Other *= 2'),
    ('int Scale(int Value){Value=1;Value *= 2;return Value;}','Value *= 2'),
    ('int Scale(int Value){return Value *= 2;}','Value *= 2'),
    ('int Scale(int Value,int Count){Value *= Count++;return Value;}','Value *= Count'),
    ('int Scale(unsigned Value,unsigned Count){Value *= Count;return Value;}','Value *= Count'),
    ('int Scale(int Value,unsigned Count){Value *= Count;return Value;}','Value *= Count'),
    ('int Scale(int Value){Value *= 2U;return Value;}','Value *= 2U'),
    ('int Scale(int Value){Value *= 2;Value *= 2;return Value;}','Value *= 2'),
])
def test_effects_invalid_writability_or_unadmitted_frames_refuse(source,expression):
    result=check(source,expression)
    assert result['violation'] is None and not result['witness_validated'],result

@pytest.mark.parametrize('expression',['Value += 2','Value *= Other','Other *= Value','Value *= 2;return 0'])
def test_exact_operator_operand_order_and_complete_expression_required(expression):
    assert check('int Scale(int Value){Value *= 2;return Value;}',expression)['violation'] is None

@pytest.mark.parametrize('call',[1,2])
def test_unknown_never_becomes_a_fault_or_safe_result(monkeypatch,call):
    from core.smt_solver import z3
    original=subject.check_solver
    calls=[]
    def undecided(solver):
        calls.append(1)
        return z3.unknown if len(calls)==call else original(solver)
    monkeypatch.setattr(subject,'check_solver',undecided)
    result=check('int Scale(int Value){Value *= 2;return Value;}')
    assert len(calls)==call and result['violation'] is None and not result['witness_validated']


def test_empty_budget_and_forged_model_cannot_grant_credit(monkeypatch):
    source='int Scale(int Value){Value *= 2;return Value;}'
    with query_budget(0):assert check(source)['violation'] is None
    monkeypatch.setattr(subject,'format_vars',lambda *a,**kw:{'Value':0})
    assert check(source)['violation'] is None
