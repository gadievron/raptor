"""Unsigned object wrap differs from promoted arithmetic and expression values."""
import pytest
from core.audit import unsigned_update as subject
from core.audit.integer_update import check_integer_update
from core.smt_solver.session import query_budget

@pytest.fixture(autouse=True)
def dependencies():
    pytest.importorskip('z3')
    pytest.importorskip('tree_sitter_c')


def check(source,expression='Value++',*,goal='increment',language='c',abi='lp64'):
    return check_integer_update(source,f'Unsigned {goal} wrap in `{expression}`.',language=language,integer_abi=abi)

@pytest.mark.parametrize('language',['c','cpp'])
@pytest.mark.parametrize('abi',['lp64','llp64','i16'])
@pytest.mark.parametrize('spelling,width',[('unsigned char',8),('unsigned short',16),('unsigned',None),('unsigned long long',64)])
@pytest.mark.parametrize('op,goal',[('++','increment'),('--','decrement')])
def test_unsigned_prestate_and_stored_value_replay(language,abi,spelling,width,op,goal):
    pytest.importorskip('tree_sitter_'+language)
    width=width or (16 if abi=='i16' else 32)
    expression='Value'+op
    source=f'int Read({spelling} Value){{{expression};return 0;}}'
    result=check(source,expression,goal=goal,language=language,abi=abi)
    assert result['violation'] is True and result['witness_validated'],result
    assert result['checked_property']=='unsigned-update-wrap'
    maximum=(1<<width)-1
    before,mathematical,stored=(maximum,maximum+1,0) if op=='++' else (0,-1,maximum)
    assert result['model']=={'Value':before}
    assert result['mathematical_result']==mathematical and result['stored_result']==stored
    assert result['storage_range']==[0,maximum]
    assert result['source_operation']['storage_width']==width
    assert result['source_operation']['premises']==[]


def test_narrow_wrap_is_not_reported_as_promoted_signed_overflow():
    source='int Read(unsigned char Value){Value++;return 0;}'
    unsigned=check(source)
    signed=check_integer_update(source,'Signed increment overflow in `Value++`.',language='c',integer_abi='lp64')
    assert unsigned['violation'] is True and unsigned['source_operation']['promoted_signed']
    assert unsigned['mathematical_result']==256 and unsigned['source_operation']['promoted_width']==32
    assert signed['violation'] is False

@pytest.mark.parametrize('expression,goal',[('++Value','increment'),('--Value','decrement')])
def test_prefix_source_fixity_is_bound(expression,goal):
    source=f'int Read(unsigned char Value){{{expression};return 0;}}'
    result=check(source,expression,goal=goal)
    assert result['violation'] is True and result['source_operation']['prefix']
    assert check(source,'Value'+expression[:2],goal=goal)['violation'] is None

@pytest.mark.parametrize('op,goal,guard',[('++','increment','Value<255'),('--','decrement','Value>0')])
def test_guarded_no_wrap_and_impossible_entry_remain_distinct(op,goal,guard):
    source=f'int Read(unsigned char Value){{if({guard})Value{op};return 0;}}'
    result=check(source,'Value'+op,goal=goal)
    assert result['violation'] is False and not result['witness_validated']
    assert check(source.replace(guard,'Value<0'),'Value'+op,goal=goal)['violation'] is None

@pytest.mark.parametrize('spelling',['int','signed char','_Bool','const unsigned','volatile unsigned','unsigned *'])
def test_non_unsigned_integer_objects_or_mutable_binding_refuse(spelling):
    source=f'int Read({spelling} Value){{Value++;return 0;}}'
    assert check(source)['violation'] is None

@pytest.mark.parametrize('body',[
    'return Value++;','return ++Value;','int Local=Value++;return Local;',
    'Value++ + Value;return 0;','unknown(Value++);return 0;',
    'Value=0;Value++;return 0;','unknown();Value++;return 0;',
    'Value++;Value++;return 0;',
])
def test_result_uses_effects_and_ambiguous_sites_refuse(body):
    assert check('int Read(unsigned Value){'+body+'}')['violation'] is None


def test_mismatched_goal_is_not_relabelled_as_the_selected_operation():
    source='int Read(unsigned Value){Value++;return 0;}'
    assert check(source,goal='decrement')['violation'] is None
    assert check_integer_update(source,'No unsigned increment wrap in `Value++`.',language='c',integer_abi='lp64')['violation'] is None


def test_cpp_boolean_update_never_uses_unsigned_modular_storage():
    pytest.importorskip('tree_sitter_cpp')
    assert check('int Read(bool Value){Value++;return 0;}',language='cpp')['violation'] is None

@pytest.mark.parametrize('call',[1,2])
def test_unknown_entry_or_fault_never_grants_a_witness(monkeypatch,call):
    from core.smt_solver import z3
    original=subject.check_solver
    calls=[]
    def undecided(solver):
        calls.append(1)
        return z3.unknown if len(calls)==call else original(solver)
    monkeypatch.setattr(subject,'check_solver',undecided)
    result=check('int Read(unsigned Value){Value++;return 0;}')
    assert len(calls)==call and result['violation'] is None and not result['witness_validated']


def test_zero_budget_and_forged_nonboundary_value_do_not_get_wrap_credit(monkeypatch):
    source='int Read(unsigned char Value){Value++;return 0;}'
    with query_budget(0):
        assert check(source)['violation'] is None
    monkeypatch.setattr(subject,'format_vars',lambda *args,**kwargs:{'Value':0})
    assert check(source)['violation'] is None


@pytest.mark.parametrize("body,expected", [('Value++;Value++;', []), ('Value++;Value++;Other++;', [('Other', '++', False)]), ('Value++;++Value;', [('Value', '++', False), ('Value', '++', True)]), ('Value++;Value--;', [('Value', '++', False), ('Value', '--', False)])], ids=['duplicate', 'other-operand', 'fixity', 'operator'])
def test_discovery_preserves_only_unambiguous_update_objectives(body, expected):
    source = "int Read(unsigned Value,unsigned Other){" + body + "return 0;}"
    rows = subject.unsigned_update_candidates(source, language="c", integer_abi="lp64")
    assert [row[1:4] for row in rows] == expected
