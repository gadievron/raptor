"""Unary source identity, promotions, guards and independent model replay."""
import pytest
from core.audit import integer_negation as subject

CLAIM = 'Potential signed negation overflow in `-Value`.'

@pytest.fixture(autouse=True)
def dependencies():
    pytest.importorskip('z3')
    pytest.importorskip('tree_sitter_c')


def check(source, claim=CLAIM, abi='lp64', language='c'):
    return subject.check_integer_negation(source,claim,language=language,integer_abi=abi)

@pytest.mark.parametrize('language', ['c','cpp'])
def test_signed_minimum_is_replayed_at_promoted_width(language):
    result=check('int Negate(int Value){return -Value;}',language=language)
    assert result['violation'] is True and result['witness_validated']
    assert result['model']=={'Value':-2147483648}
    assert result['mathematical_result']==2147483648
    assert result['source_operation']['promoted_width']==32

@pytest.mark.parametrize('source', [
    'int Negate(int Value){if(Value>=0)return -Value;return 0;}',
    'int Negate(short Value){return -Value;}',
    'int Negate(unsigned short Value){return -Value;}',
])
def test_defined_promotions_and_guards_find_no_fault(source):
    result=check(source)
    assert result['violation'] is False and not result['witness_validated']

@pytest.mark.parametrize('source', [
    'unsigned Negate(unsigned Value){return -Value;}',
    'int Negate(int Value){Value=1;return -Value;}',
    'int Negate(int Value){int A=-Value;return -Value;}',
    'int Negate(int Value){return 0-Value;}',
    'int Negate(int Value){return -(Value+1);}',
    'int Negate(volatile int Value){return -Value;}',
    'int Negate(int Value){unknown();return -Value;}',
    'int Negate(int Value){if(Value>0 && Value<0)return -Value;return 0;}',
])
def test_unsupported_or_unreachable_source_has_no_fault_receipt(source):
    result=check(source)
    assert result['violation'] is None and not result['witness_validated']

@pytest.mark.parametrize('claim', [
    'No signed negation overflow in `-Value`.',
    'Potential signed negation overflow unless guarded in `-Value`.',
    'Potential signed negation overflow in `-Other`.',
    'Potential signed negation overflow in `-Value;return 0`.',
])
def test_closed_goal_and_exact_operand_required(claim):
    assert check('int Negate(int Value){return -Value;}',claim)['violation'] is None

@pytest.mark.parametrize('call', [1,2])
def test_unknown_never_grants_credit(monkeypatch,call):
    from core.smt_solver import z3
    original=subject.check_solver
    calls=[]
    def undecided(solver):
        calls.append(1)
        return z3.unknown if len(calls)==call else original(solver)
    monkeypatch.setattr(subject,'check_solver',undecided)
    result=check('int Negate(int Value){return -Value;}')
    assert len(calls)==call and result['violation'] is None and not result['witness_validated']


def test_forged_fault_model_cannot_pass_python_replay(monkeypatch):
    monkeypatch.setattr(subject,'format_vars',lambda *a,**kw:{'Value':0})
    assert check('int Negate(int Value){return -Value;}')['violation'] is None


@pytest.mark.parametrize('source,language', [
    ('int Negate(int Value){return sizeof(-Value);}', 'c'),
    ('int Negate(int Value){return sizeof(int[-Value]);}', 'c'),
    ('int Negate(int Value){return sizeof(-Value);}', 'cpp'),
    ('int Negate(int Value){return noexcept(-Value);}', 'cpp'),
])
def test_unevaluated_and_variable_sizeof_contexts_are_not_fault_sites(source,language):
    result=check(source,language=language)
    assert result['violation'] is None and not result['witness_validated']
    assert subject.negation_candidates(source,language=language,integer_abi='lp64')==[]


@pytest.mark.parametrize("language", ["c", "cpp"])
@pytest.mark.parametrize("source,expected", [
    ("int Negate(int Value){return -Value + -Value;}", []),
    ("int Negate(int Value,int Other){return -Value + -Value + -Other;}", ["Other"]),
    ("int Negate(int Value,int Other){return -Value + -Other;}", ["Value", "Other"]),
    ("int Negate(int Value){return -Value + sizeof(-Value);}", ["Value"]),
    ("int Negate(int Value){int Result=-Value;{unsigned Value=1;Result=-Value;}return Result;}", []),
], ids=["duplicate", "other-name", "distinct", "unevaluated", "later-type-refusal"])
def test_discovery_requires_an_unambiguous_negation_name(source, expected, language):
    pytest.importorskip("tree_sitter_" + language)
    rows = subject.negation_candidates(source, language=language, integer_abi="lp64")
    assert [row[1] for row in rows] == expected
