"""Typed whole-condition truth and refusal boundaries."""
import pytest
from core.audit import integer_conjunction as subject
from core.audit.integer_comparison import check_integer_comparison
from core.smt_solver.session import query_budget

EXPRESSION = 'Value < 0 && Value >= 0'
SOURCE = f'int Read(int Value){{if({EXPRESSION})return 1;return 0;}}'

@pytest.fixture(autouse=True)
def dependencies():
    pytest.importorskip('z3')
    pytest.importorskip('tree_sitter_c')


def check(source=SOURCE, expression=EXPRESSION, *, truth='false', language='c', abi='lp64'):
    return check_integer_comparison(source, f'Condition is always {truth} in `{expression}`.',
                                    language=language, integer_abi=abi)

@pytest.mark.parametrize('language', ['c', 'cpp'])
@pytest.mark.parametrize('abi', ['lp64', 'llp64', 'i16'])
def test_contradictory_signed_range_uses_whole_condition_without_own_premises(language, abi):
    pytest.importorskip('tree_sitter_'+language)
    result = check(language=language, abi=abi)
    assert result['matches_claim'] is True and result['constant_truth'] is False, result
    assert result['entry_witness_validated'] and result['source_operation']['premises'] == []
    assert result['checked_property'] == 'constant-integer-conjunction'

@pytest.mark.parametrize('abi', ['lp64', 'llp64', 'i16'])
def test_mixed_sign_comparisons_are_not_flattened_into_a_contradiction(abi):
    expression = 'Value < 0 && Value > Limit'
    source = f'int Read(int Value,unsigned Limit){{if({expression})return 1;return 0;}}'
    assert check(source, expression, abi=abi)['matches_claim'] is False


def test_outer_guard_can_prove_truth_but_empty_entry_has_no_credit():
    expression = 'Value > 0 && Value < 10'
    source = f'int Read(int Value){{if(Value==2){{if({expression})return 1;}}return 0;}}'
    result = check(source, expression, truth='true')
    assert result['matches_claim'] is True and result['source_operation']['premises'] == ['Value == 2']
    assert check(source.replace('Value==2', 'Value<0 && Value>=0'), expression, truth='true')['matches_claim'] is None

@pytest.mark.parametrize('expression', [
    'Value < 0 && Value >= 0 && Value == 0',
    'Value < 0 && unknown() == 0', 'Value < 0 && Value++ == 0',
    'Value < 0 && (Value=1) == 0', 'Value < 0 && Value+1 == 0',
    'Value < 0 && (unsigned)Value == 0', 'Value < 0 && Value < 4U',
])
def test_unsupported_selected_subtrees_never_borrow_guard_skip_credit(expression):
    source = f'int Read(int Value){{if({expression})return 1;return 0;}}'
    assert check(source, expression)['matches_claim'] is None

@pytest.mark.parametrize('source', [
    SOURCE.replace('int Value', 'volatile int Value'),
    SOURCE.replace('if(', 'Value=0;if(', 1),
    SOURCE.replace('if(', 'unknown();if(', 1),
    'int Read(int Value){return Value < 0 && Value >= 0;}',
    SOURCE.replace('return 0;', f'if({EXPRESSION})return 2;return 0;'),
])
def test_types_prefix_direct_return_and_duplicate_sites_refuse(source):
    assert check(source)['matches_claim'] is None


def test_claim_order_source_and_goal_are_exact():
    assert check(expression='Value >= 0 && Value < 0')['matches_claim'] is None
    assert check(truth='true')['matches_claim'] is False
    assert check(SOURCE.replace('Value >= 0','Value > 0'))['matches_claim'] is None

@pytest.mark.parametrize('call', [1, 2])
def test_unknown_query_cannot_grant_truth_credit(monkeypatch, call):
    from core.smt_solver import z3
    original = subject.check_solver
    calls = []
    def undecided(solver):
        calls.append(1)
        return z3.unknown if len(calls) == call else original(solver)
    monkeypatch.setattr(subject, 'check_solver', undecided)
    result = check()
    assert len(calls) == call and result['matches_claim'] is None and not result['entry_witness_validated']


def test_budget_and_forged_entry_remain_inconclusive(monkeypatch):
    with query_budget(0):
        assert check()['matches_claim'] is None
    monkeypatch.setattr(subject, 'format_vars', lambda *args, **kwargs: {'Value': 0})
    source = f'int Read(int Value){{if(Value>2){{if({EXPRESSION})return 1;}}return 0;}}'
    assert check(source)['matches_claim'] is None
