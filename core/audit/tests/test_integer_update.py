"""Selected updates require exact spelling, promotions and sequencing."""
import pytest
from core.audit import integer_update as subject

@pytest.fixture(autouse=True)
def dependencies():
    pytest.importorskip('z3')
    pytest.importorskip('tree_sitter_c')


def check(source,expression='++Value',goal='increment',language='c',abi='lp64'):
    return subject.check_integer_update(source,f'Potential signed {goal} overflow in `{expression}`.',
                                        language=language,integer_abi=abi)

@pytest.mark.parametrize('expression,goal,witness', [
    ('++Value','increment',2147483647),('Value++','increment',2147483647),
    ('--Value','decrement',-2147483648),('Value--','decrement',-2147483648),
])
@pytest.mark.parametrize('language',['c','cpp'])
def test_prefix_and_postfix_promoted_faults(expression,goal,witness,language):
    result=check(f'int Update(int Value){{return {expression};}}',expression,goal,language)
    assert result['violation'] is True and result['witness_validated']
    assert result['model']=={'Value':witness}
    assert result['mathematical_result']==witness+(1 if goal=='increment' else -1)
    assert result['source_operation']['promoted_width']==32

@pytest.mark.parametrize('source', [
    'int Update(short Value){return ++Value;}',
    'int Update(unsigned short Value){return ++Value;}',
    'int Update(int Value){if(Value<100)return ++Value;return 0;}',
])
def test_narrow_storage_conversion_is_not_promoted_arithmetic_overflow(source):
    result=check(source)
    assert result['violation'] is False and not result['witness_validated']

@pytest.mark.parametrize('source', [
    'int Update(int Value){Value=1;return ++Value;}',
    'int Update(int Value){Value++;return ++Value;}',
    'int Update(int Value){return Value++ + Value;}',
    'int Update(int Value){return ++Value + Value;}',
    'int Update(int Value){return sizeof(++Value);}',
    'int Update(int Value){return sizeof(int[++Value]);}',
    'int Update(int *Value){return *++Value;}',
    'int Update(volatile int Value){return ++Value;}',
    'int Update(const int Value){return ++Value;}',
    'unsigned Update(unsigned Value){return ++Value;}',
    'int Update(_Bool Value){return ++Value;}',
    'int Update(int Value){unknown();return ++Value;}',
    'int Update(int Value){if(Value>0 && Value<0)return ++Value;return 0;}',
])
def test_effects_evaluation_mutation_and_invalid_types_refuse(source):
    expression='Value++' if 'Value++ + Value' in source else '++Value'
    result=check(source,expression)
    assert result['violation'] is None and not result['witness_validated']

@pytest.mark.parametrize('expression,goal', [('Value++','increment'),('--Value','decrement'),('++Other','increment'),('++Value;return 0','increment')])
def test_claim_cannot_change_fixity_operator_or_operand(expression,goal):
    assert check('int Update(int Value){return ++Value;}',expression,goal)['violation'] is None

@pytest.mark.parametrize('call',[1,2])
def test_unknown_is_inconclusive(monkeypatch,call):
    from core.smt_solver import z3
    original=subject.check_solver
    calls=[]
    def undecided(solver):
        calls.append(1)
        return z3.unknown if len(calls)==call else original(solver)
    monkeypatch.setattr(subject,'check_solver',undecided)
    result=check('int Update(int Value){return ++Value;}')
    assert len(calls)==call and result['violation'] is None and not result['witness_validated']


def test_forged_model_cannot_grant_a_fault(monkeypatch):
    monkeypatch.setattr(subject,'format_vars',lambda *a,**kw:{'Value':0})
    assert check('int Update(int Value){return ++Value;}')['violation'] is None


@pytest.mark.parametrize("body,expected", [('Value++;Value++;', []), ('Value++;Value++;Other++;', [('Other', '++', False)]), ('Value++;++Value;', [('Value', '++', False), ('Value', '++', True)]), ('Value++;Value--;', [('Value', '++', False), ('Value', '--', False)]), ('Value++;return Value++;', [])], ids=['duplicate', 'other-operand', 'fixity', 'operator', 'return-occurrence'])
def test_discovery_preserves_only_unambiguous_update_objectives(body, expected):
    from core.audit import integer_update as subject

    source = "int Read(int Value,int Other){" + body + "return 0;}"
    rows = subject.update_candidates(source, language="c", integer_abi="lp64")
    assert [row[1:4] for row in rows] == expected
