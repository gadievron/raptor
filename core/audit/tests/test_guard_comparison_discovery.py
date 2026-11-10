"""Source guards can make a test constant even when its raw type cannot."""

import pytest

from core.audit.arithmetic_seeds import seed_arithmetic_hypotheses
from core.audit.integer_comparison import check_integer_comparison


@pytest.fixture(autouse=True)
def native_dependencies():
    pytest.importorskip('z3')
    pytest.importorskip('tree_sitter_c')


def discover(source, extension='c'):
    gap = {'file': 'unit.' + extension, 'name': 'Read', 'line_start': 1, 'line_end': 1}
    seed_arithmetic_hypotheses([gap], {gap['file']: source}, mode='quality', integer_abi='lp64')
    return gap.get('injected_hypotheses', [])


def test_quality_discovers_an_existing_guard_implied_comparison_proof():
    source = 'int Read(int Value){if(Value<10){if(Value>20)return 1;}return 0;}'
    goal = 'Comparison is always false in `Value > 20`.'
    result = check_integer_comparison(source, goal, language='c', integer_abi='lp64')
    assert result['matches_claim'] is True and result['constant_truth'] is False, result
    assert result['entry_witness_validated']
    assert result['source_operation']['premises'] == ['Value < 10']
    gap = {'file': 'unit.c', 'name': 'Read', 'line_start': 1, 'line_end': 1}
    count = seed_arithmetic_hypotheses([gap], {'unit.c': source}, mode='quality', integer_abi='lp64')
    assert count == 1, gap
    assert gap['injected_hypotheses'][0]['mechanism'] == goal


@pytest.mark.parametrize('source,expression,truth', [
    ('int Read(int Value){if(Value>=10)return 0;if(Value>20)return 1;return 0;}', 'Value > 20', False),
    ('int Read(int Value){if(Value<10)return 0;else{if(Value>=10)return 1;}return 0;}', 'Value >= 10', True),
    ('int Read(int Value){if(10>Value){if(Value>20)return 1;}return 0;}', 'Value > 20', False),
    ('int Read(int Value){if(!(Value>=10)){if(Value>20)return 1;}return 0;}', 'Value > 20', False),
    ('int Read(int Value){if(Value>=0){if(Value<=10){if(Value<20)return 1;}}return 0;}', 'Value < 20', True),
    ('int Read(unsigned Value){if(Value<10){if(Value == -1)return 1;}return 0;}', 'Value == -1', False),
    ('int Read(int Value){if(Value!=5)return 0;if(Value==5)return 1;return 0;}', 'Value == 5', True),
])
@pytest.mark.parametrize('extension', ['c', 'cpp'])
def test_controlling_comparison_hint_reaches_the_existing_native_oracle(source, expression, truth, extension):
    if extension == 'cpp':
        pytest.importorskip('tree_sitter_cpp')
    rows = discover(source, extension)
    assert len(rows) == 1, rows
    row = rows[0]
    assert row['mechanism'] == f"Comparison is always {'true' if truth else 'false'} in `{expression}`."
    assert row['confidence'] == 'low' and 'verdict' not in row and 'confirmed' not in row
    assert row['arithmetic_site']['candidate_basis'] == 'controlling-comparison-range'
    assert row['arithmetic_site']['binding_status'] == 'candidate'
    result = check_integer_comparison(source, row['mechanism'], language=extension if extension == 'c' else 'cpp', integer_abi='lp64')
    assert result['matches_claim'] is True and result['constant_truth'] is truth, result
    assert result['entry_witness_validated']


@pytest.mark.parametrize('source', [
    'int Read(int Value){if(Value>20)return 1;return 0;}',
    'int Read(int Value){if(Value<10 || Value>30){if(Value>20)return 1;}return 0;}',
    'int Read(int Value){if(Value<10 && Value>20)return 1;return 0;}',
    'int Read(unsigned Value){if(Value< -1){if(Value>20)return 1;}return 0;}',
    'int Read(int Value){if(Value<LIMIT){if(Value>20)return 1;}return 0;}',
    'int Read(int Value,int Other){if(Other<10){if(Value>20)return 1;}return 0;}',
])
def test_own_truth_disjunctions_and_unmodeled_guard_literals_do_not_invent_constants(source):
    assert discover(source) == []


def test_empty_guard_range_does_not_generate_a_vacuous_inner_constant():
    source = 'int Read(int Value){if(Value<0){if(Value>=0){if(Value>20)return 1;}}return 0;}'
    rows = discover(source)
    assert [row['mechanism'] for row in rows] == ['Comparison is always false in `Value >= 0`.']


def test_syntactic_hint_cannot_override_a_source_mutation_refusal():
    source = 'int Read(int Value){if(Value<10){Value=100;if(Value>20)return 1;}return 0;}'
    rows = discover(source)
    assert len(rows) == 1 and rows[0]['arithmetic_site']['binding_status'] == 'candidate'
    result = check_integer_comparison(source, rows[0]['mechanism'], language='c', integer_abi='lp64')
    assert result['matches_claim'] is None and not result['entry_witness_validated']


def test_new_guard_hints_do_not_displace_prior_quality_objectives():
    source = ('int Read(unsigned Index,int Value,int Count){int Data[4]={0};int Ratio=Value/Count;'
              'if(Index<0)return 0;if(Value<10){if(Value>20)return 0;}return Data[Index];}')
    rows = discover(source)
    assert len(rows) == 4
    assert [row['arithmetic_site']['claim_kind'] for row in rows] == [
        'zero-divisor', 'signed-division-overflow', 'constant-comparison-false', 'fixed-array-read']


def test_guard_candidates_never_call_the_full_oracle_during_preparation():
    import builtins
    from types import SimpleNamespace

    from core.audit import arithmetic_seeds
    from core.testing.module_views import module_function_view

    def forbidden(*a, **kw):
        raise AssertionError('guard candidate entered native comparison proof')

    def local_import(name, globals=None, locals=None, fromlist=(), level=0):
        if level == 1 and name == 'integer_comparison':
            return SimpleNamespace(check_integer_comparison=forbidden)
        return builtins.__import__(name, globals, locals, fromlist, level)

    view = module_function_view(arithmetic_seeds, import_hook=local_import, bindings={
        'check_integer_comparison': forbidden, 'guards_for_operation': forbidden,
        'ComparisonModel': forbidden, 'new_solver': forbidden,
    })
    source = 'int Read(int Value){if(Value<10){if(Value>20)return 1;}return 0;}'
    gap = {'file': 'unit.c', 'name': 'Read', 'line_start': 1, 'line_end': 1}
    assert view.seed_arithmetic_hypotheses([gap], {'unit.c': source}, mode='quality', integer_abi='lp64') == 1
    assert gap['injected_hypotheses'][0]['arithmetic_site']['binding_status'] == 'candidate'


def test_two_parameter_ranges_supply_a_candidate_relation():
    source = 'int Read(int Value,int Other){if(Value<10){if(Other>20){if(Value<Other)return 1;}}return 0;}'
    rows = discover(source)
    assert len(rows) == 1
    assert rows[0]['mechanism'] == 'Comparison is always true in `Value < Other`.'
    result = check_integer_comparison(source, rows[0]['mechanism'], language='c', integer_abi='lp64')
    assert result['matches_claim'] is True and result['entry_witness_validated'], result
