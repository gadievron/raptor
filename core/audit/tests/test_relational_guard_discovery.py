"""Direct controlling relations remain hints until native source validation."""

import pytest

from core.audit.arithmetic_seeds import seed_arithmetic_hypotheses
from core.audit.integer_comparison import check_integer_comparison


@pytest.fixture(autouse=True)
def native_dependencies():
    pytest.importorskip('z3')
    pytest.importorskip('tree_sitter_c')


def discover(source, language='c'):
    gap = {'file': 'unit.' + language, 'name': 'Read', 'line_start': 1, 'line_end': 1}
    seed_arithmetic_hypotheses([gap], {gap['file']: source}, mode='quality', integer_abi='lp64')
    return gap.get('injected_hypotheses', [])


@pytest.mark.parametrize('language', ['c', 'cpp'])
@pytest.mark.parametrize('guard,target,truth', [
    ('Left<Right', 'Left >= Right', False),
    ('Right>Left', 'Left < Right', True),
    ('!(Left>=Right)', 'Left != Right', True),
    ('Left==Right', 'Left <= Right', True),
    ('Left<=Right', 'Left > Right', False),
])
def test_direct_relation_candidate_reaches_the_native_oracle(guard, target, truth, language):
    if language == 'cpp':
        pytest.importorskip('tree_sitter_cpp')
    source = f'int Read(int Left,int Right){{if({guard}){{if({target})return 1;}}return 0;}}'
    goal = f"Comparison is always {'true' if truth else 'false'} in `{target}`."
    rows = discover(source, language)
    assert len(rows) == 1 and rows[0]['mechanism'] == goal, rows
    assert rows[0]['confidence'] == 'low' and 'verdict' not in rows[0]
    assert rows[0]['arithmetic_site']['binding_status'] == 'candidate'
    result = check_integer_comparison(source, goal, language=language, integer_abi='lp64')
    assert result['matches_claim'] is True and result['constant_truth'] is truth, result
    assert result['entry_witness_validated']


@pytest.mark.parametrize('source', [
    'int Read(int Left,int Right){if(Left<Right)return 0;if(Left>=Right)return 1;return 0;}',
    'int Read(int Left,int Right){if(Left<Right)return 0;else{if(Left>=Right)return 1;}return 0;}',
])
def test_false_branch_relation_is_discovered(source):
    rows = discover(source)
    assert len(rows) == 1, rows
    result = check_integer_comparison(source, rows[0]['mechanism'], language='c', integer_abi='lp64')
    assert result['matches_claim'] is True and result['constant_truth'] is True, result
    assert result['entry_witness_validated']


@pytest.mark.parametrize('source', [
    'int Read(int Left,int Right){if(Left<=Right){if(Left==Right)return 1;}return 0;}',
    'int Read(int Left,int Right){if(Left<Right || Left==0){if(Left>=Right)return 1;}return 0;}',
    'int Read(int Left,int Right,int Other){if(Left<Other){if(Left>=Right)return 1;}return 0;}',
    'int Read(int Left,int Right){if(Left>=Right)return 1;return 0;}',
])
def test_nonconstant_unrelated_disjunctive_and_own_tests_do_not_generate_leads(source):
    assert discover(source) == []


def test_mutation_cannot_turn_a_relation_hint_into_a_native_proof():
    source = 'int Read(int Left,int Right){if(Left<Right){Left=Right;if(Left>=Right)return 1;}return 0;}'
    rows = discover(source)
    assert len(rows) == 1, rows
    result = check_integer_comparison(source, rows[0]['mechanism'], language='c', integer_abi='lp64')
    assert result['matches_claim'] is None and not result['entry_witness_validated'], result


def test_contradictory_relations_do_not_emit_a_vacuous_deeper_hint():
    source = 'int Read(int Left,int Right){if(Left<Right){if(Left>=Right){if(Left!=Right)return 1;}}return 0;}'
    rows = discover(source)
    assert [row['mechanism'] for row in rows] == ['Comparison is always false in `Left >= Right`.']
