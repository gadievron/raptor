"""Whole-if OR truth retains typed leaves, entry feasibility and refusal scope."""
import pytest
from core.audit import integer_conjunction as subject
from core.audit.integer_comparison import check_integer_comparison
from core.smt_solver.session import query_budget

EXPRESSION = 'Value != 0 || Value != 1'
SOURCE = f'int Read(int Value){{if({EXPRESSION})return 1;return 0;}}'

@pytest.fixture(autouse=True)
def dependencies():
    pytest.importorskip('z3')
    pytest.importorskip('tree_sitter_c')


def check(source=SOURCE, expression=EXPRESSION, *, truth='true', language='c', abi='lp64'):
    return check_integer_comparison(source, f'Condition is always {truth} in `{expression}`.',
                                    language=language, integer_abi=abi)

@pytest.mark.parametrize('language', ['c', 'cpp'])
@pytest.mark.parametrize('abi', ['lp64', 'llp64', 'i16'])
@pytest.mark.parametrize('expression', [EXPRESSION, 'Value < 0 || Value >= 0'])
def test_tautology_has_replayed_nonempty_entry_without_own_premises(language, abi, expression):
    pytest.importorskip('tree_sitter_'+language)
    result = check(SOURCE.replace(EXPRESSION, expression), expression, language=language, abi=abi)
    assert result['matches_claim'] is True and result['constant_truth'] is True, result
    assert result['entry_witness_validated'] and result['source_operation']['premises'] == []
    assert result['checked_property'] == 'constant-integer-disjunction'
    assert result['source_operation']['operator'] == '||'

@pytest.mark.parametrize('expression', ['Value != 0 || Value != 0', 'Value < 0 || Value > 0'])
def test_nonconstant_disjunction_does_not_get_either_truth_credit(expression):
    source = SOURCE.replace(EXPRESSION, expression)
    assert check(source, expression)['matches_claim'] is False
    assert check(source, expression, truth='false')['matches_claim'] is False

@pytest.mark.parametrize('abi', ['lp64', 'llp64', 'i16'])
def test_mixed_sign_predicates_keep_separate_conversion_frames(abi):
    expression = 'Value < 0 || Value > Limit'
    source = f'int Read(int Value,unsigned Limit){{if({expression})return 1;return 0;}}'
    assert check(source, expression, abi=abi)['matches_claim'] is False
    assert check(source, expression, truth='false', abi=abi)['matches_claim'] is False


def test_outer_guards_are_preserved_and_contradictory_entry_has_no_credit():
    source = f'int Read(int Value){{if(Value==0){{if({EXPRESSION})return 1;}}return 0;}}'
    result = check(source)
    assert result['matches_claim'] is True and result['source_operation']['premises'] == ['Value == 0']
    assert check(source.replace('Value==0', 'Value<0 && Value>=0'))['matches_claim'] is None

@pytest.mark.parametrize('expression', [
    'Value != 0 || Value != 1 || Value != 2', 'Value != 0 || (Value != 1 && Value != 2)',
    'Value != 0 || unknown() != 1', 'Value != 0 || Value++ != 1',
    'Value != 0 || (Value=1) != 1', 'Value != 0 || Value+1 != 1',
    'Value != 0 || (unsigned)Value != 1', 'Value != 0 || Value != 1U',
])
def test_unsupported_subtrees_do_not_borrow_selected_subtree_credit(expression):
    assert check(SOURCE.replace(EXPRESSION, expression), expression)['matches_claim'] is None

@pytest.mark.parametrize('source', [
    SOURCE.replace('int Value', 'volatile int Value'),
    SOURCE.replace('if(', 'Value=0;if(', 1),
    SOURCE.replace('if(', 'unknown();if(', 1),
    f'int Read(int Value){{return {EXPRESSION};}}',
    SOURCE.replace('return 0;', f'if({EXPRESSION})return 2;return 0;'),
])
def test_unknown_type_prefix_return_or_ambiguous_source_refuses(source):
    assert check(source)['matches_claim'] is None


def test_source_order_and_truth_goal_remain_exact():
    assert check(expression='Value != 1 || Value != 0')['matches_claim'] is None
    assert check(truth='false')['matches_claim'] is False
    assert check(SOURCE.replace('Value != 1', 'Value != 2'))['matches_claim'] is None

@pytest.mark.parametrize('call', [1, 2])
def test_query_unknown_never_grants_truth_credit(monkeypatch, call):
    from core.smt_solver import z3
    original = subject.check_solver
    calls = []
    def undecided(solver):
        calls.append(1)
        return z3.unknown if len(calls) == call else original(solver)
    monkeypatch.setattr(subject, 'check_solver', undecided)
    result = check()
    assert len(calls) == call and result['matches_claim'] is None and not result['entry_witness_validated']


def test_budget_and_forged_replay_remain_inconclusive(monkeypatch):
    with query_budget(0):
        assert check()['matches_claim'] is None
    monkeypatch.setattr(subject, 'format_vars', lambda *args, **kwargs: {'Value': 0})
    source = f'int Read(int Value){{if(Value>2){{if({EXPRESSION})return 1;}}return 0;}}'
    assert check(source)['matches_claim'] is None
