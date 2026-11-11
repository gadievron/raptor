"""Actual C precedence, explicit condition goals and nonvacuous typed truth."""
import pytest
from core.audit import integer_condition as subject
from core.audit.integer_comparison import check_integer_comparison
from core.smt_solver.session import query_budget

SOURCE='int Read(unsigned Flags){if(Flags & 4 == 0)return 1;return 0;}'
CLAIM='Condition is always false in `Flags & 4 == 0`.'

@pytest.fixture(autouse=True)
def dependencies():
    pytest.importorskip('z3')
    pytest.importorskip('tree_sitter_c')


def check(source=SOURCE,claim=CLAIM,language='c',abi='lp64'):
    return check_integer_comparison(source,claim,language=language,integer_abi=abi)

@pytest.mark.parametrize('language',['c','cpp'])
@pytest.mark.parametrize('abi',['lp64','llp64','i16'])
@pytest.mark.parametrize('spelling',['int','unsigned','signed char','unsigned char','unsigned long long'])
def test_actual_precedence_condition_is_false_across_promotions(language,abi,spelling):
    pytest.importorskip('tree_sitter_'+language)
    result=check(SOURCE.replace('unsigned Flags',spelling+' Flags'),language=language,abi=abi)
    assert result['matches_claim'] is True and result['constant_truth'] is False,result
    assert result['entry_witness_validated'] and result['checked_property']=='constant-bitwise-condition'
    assert result['source_operation']['operator']=='&'
    assert result['source_operation']['literal_comparison']==['4','==','0']
    assert result['source_operation']['premises']==[]  # never assume the selected test itself

@pytest.mark.parametrize('source,language',[(SOURCE.replace('unsigned Flags','_Bool Flags'),'c'),(SOURCE.replace('unsigned Flags','bool Flags'),'cpp')])
def test_boolean_inputs_promote_without_guessing_bool_storage(source,language):
    assert check(source,language=language)['matches_claim'] is True


def test_complete_direct_return_uses_the_same_pure_condition_contract():
    assert check('int Read(unsigned Flags){return Flags & 4 == 0;}')['matches_claim'] is True

@pytest.mark.parametrize('truth',['true','false'])
def test_literal_comparison_true_gives_a_nonconstant_low_bit(truth):
    result=check(SOURCE.replace('4 == 0','4 != 0'),f'Condition is always {truth} in `Flags & 4 != 0`.')
    assert result['matches_claim'] is not True and not result['entry_witness_validated'],result


def test_grouped_claim_cannot_replace_ungrouped_source_or_change_the_objective():
    assert check(SOURCE,'Condition is always false in `(Flags & 4) == 0`.')['matches_claim'] is None
    assert check(SOURCE,'Comparison is always false in `(Flags & 4) == 0`.')['matches_claim'] is None
    assert check(SOURCE.replace('Flags & 4 == 0','(Flags & 4) == 0'))['matches_claim'] is None

@pytest.mark.parametrize('source',[
    SOURCE.replace('unsigned Flags','volatile unsigned Flags'),
    SOURCE.replace('unsigned Flags','unsigned *Flags'),
    SOURCE.replace('if(Flags','Flags=0;if(Flags'),
    SOURCE.replace('if(Flags','unknown();if(Flags'),
    'int Read(unsigned Flags){unsigned Local=Flags;if(Local & 4 == 0)return 1;return 0;}',
])
def test_unknown_types_prefixes_mutations_and_empty_entry_refuse(source):
    result=check(source)
    assert result['matches_claim'] is not True and not result['entry_witness_validated'],result

@pytest.mark.parametrize('source,claim',[
    (SOURCE.replace('Flags & 4 == 0','Flags && (4 == 0)'),CLAIM.replace('Flags & 4 == 0','Flags && (4 == 0)')),
    (SOURCE.replace('Flags & 4 == 0','Flags & (Flags == 0)'),CLAIM.replace('Flags & 4 == 0','Flags & (Flags == 0)')),
    (SOURCE.replace('Flags & 4 == 0','Flags & 4U == 0'),CLAIM.replace('Flags & 4 == 0','Flags & 4U == 0')),
    (SOURCE.replace('Flags & 4 == 0','Flags & 2147483648 == 0'),CLAIM.replace('Flags & 4 == 0','Flags & 2147483648 == 0')),
    (SOURCE,CLAIM.replace('4 == 0','4 != 0')),
    (SOURCE,'No '+CLAIM),
    (SOURCE,CLAIM.replace('Flags & 4 == 0','Flags & 4 == 0;return 0')),
])
def test_complete_ast_literal_source_and_goal_refusals(source,claim):
    assert check(source,claim)['matches_claim'] is None


def test_const_input_is_readable():
    assert check(SOURCE.replace('unsigned Flags','const unsigned Flags'))['matches_claim'] is True

@pytest.mark.parametrize('call',[1,2])
def test_unknown_entry_or_contrary_query_never_grants_truth_credit(monkeypatch,call):
    from core.smt_solver import z3
    original=subject.check_solver
    calls=[]
    def undecided(solver):
        calls.append(1)
        return z3.unknown if len(calls)==call else original(solver)
    monkeypatch.setattr(subject,'check_solver',undecided)
    result=check()
    assert len(calls)==call and result['matches_claim'] is None and not result['entry_witness_validated']


def test_budget_and_forged_entry_cannot_override_guards(monkeypatch):
    with query_budget(0):assert check()['matches_claim'] is None
    source='int Read(unsigned Flags){if(Flags==2){if(Flags & 4 == 0)return 1;}return 0;}'
    monkeypatch.setattr(subject,'format_vars',lambda *a,**kw:{'Flags':1})
    assert check(source)['matches_claim'] is None



def test_contradictory_entry_is_checked_but_never_gets_truth_credit():
    source='int Read(unsigned Flags){if(Flags>1 && Flags<0){if(Flags & 4 == 0)return 1;}return 0;}'
    result=check(source)
    assert result['comparison_status']=='checked',result
    assert result['matches_claim'] is None and not result['entry_witness_validated']


@pytest.mark.parametrize("language", ["c", "cpp"])
@pytest.mark.parametrize("body,expected", [('if(Flags & 4 == 0)return 1;if(Flags & 4 == 0)return 2;return 0;', []), ('if(Flags & 4 == 0)return 1;if(Flags & (4 == 0))return 2;return 0;', []), ('if(Flags & 4 == 0)return 1;if(Flags & 8 == 0)return 2;return 0;', [('Flags', '4', '==', '0'), ('Flags', '8', '==', '0')]), ('if(Flags & 4 == 0)return 1;return Flags & 4 == 0;', []), ('if(Flags & 4 == 0)return 1;{void *Flags=0;if(Flags & 4 == 0)return 2;}return 0;', []), ('if(Flags & 4 == 0)return 1;if(Flags & 0x4 == 0)return 2;return 0;', [('Flags', '4', '==', '0'), ('Flags', '0x4', '==', '0')])], ids=["duplicate", "parenthesized", "distinct", "return-context", "later-type-refusal", "literal-spelling"])
def test_discovery_requires_a_unique_condition_objective(body, expected, language):
    pytest.importorskip("tree_sitter_" + language)
    source = "int Read(unsigned Flags){" + body + "}"
    rows = subject.condition_candidates(source, language=language, integer_abi="lp64")
    assert [row[1:] for row in rows] == expected
