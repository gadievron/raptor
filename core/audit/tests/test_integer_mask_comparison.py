"""Mask comparisons bind actual precedence, entry identities and typed bits."""

import pytest

from core.audit.integer_comparison import check_integer_comparison


@pytest.fixture(autouse=True)
def native_dependencies():
    pytest.importorskip('z3')
    pytest.importorskip('tree_sitter_c')


def check(source, expression='(Flags & 5) == 2', truth=False, language='c', abi='lp64'):
    return check_integer_comparison(source,
                                    f"Comparison is always {'true' if truth else 'false'} in `{expression}`.",
                                    language=language, integer_abi=abi)


@pytest.mark.parametrize('language', ['c', 'cpp'])
@pytest.mark.parametrize('spelling,mask,value,op,truth', [
    ('unsigned', 3, 4, '==', False), ('int', 5, 2, '==', False),
    ('unsigned long', 5, 2, '!=', True), ('unsigned short', 0, 0, '==', True),
    ('signed char', 7, -1, '==', False),
])
@pytest.mark.parametrize('abi', ['lp64', 'llp64', 'i16'])
def test_grouped_mask_comparisons_prove_constant_truth(language, spelling, mask, value, op, truth, abi):
    pytest.importorskip('tree_sitter_' + language)
    expression = f'(Flags & {mask}) {op} {value}'
    result = check(f'int Read({spelling} Flags){{if({expression})return 1;return 0;}}',
                   expression, truth, language, abi)
    assert result['matches_claim'] is True and result['constant_truth'] is truth, result
    assert result['entry_witness_validated'] and 'Flags' in result['entry_witness']
    assert result['checked_property'] == 'constant-mask-comparison'
    assert result['proof_scope'] == 'function-entry-source-model'


@pytest.mark.parametrize('source', [
    'int Read(unsigned Flags){if((Flags & 5)==2)return 1;if((Flags & 5)==2)return 1;return 0;}',
    'int Read(unsigned Flags){Flags=0;if((Flags & 5)==2)return 1;return 0;}',
    'int Read(unsigned Flags){if(Flags<0){if((Flags & 5)==2)return 1;}return 0;}',
    'int Read(unsigned Flags){if(Flags & 5==2)return 1;return 0;}',
    'int Read(unsigned Flags){if((Flags & MASK)==2)return 1;return 0;}',
    'int Read(float Flags){if((Flags & 5)==2)return 1;return 0;}',
    'int Read(unsigned Flags){unknown();if((Flags & 5)==2)return 1;return 0;}',
])
def test_ambiguous_mutated_unreachable_precedence_macro_type_and_prefix_refuse(source):
    result = check(source)
    assert result['matches_claim'] is None and not result['entry_witness_validated'], result


@pytest.mark.parametrize('truth', [False, True])
def test_reachable_mask_comparison_is_not_constant(truth):
    result = check('int Read(unsigned Flags){if((Flags & 5)==1)return 1;return 0;}',
                   '(Flags & 5) == 1', truth)
    assert result['matches_claim'] is not True and not result['entry_witness_validated'], result


@pytest.mark.parametrize('claim', [
    'No comparison is always false in `(Flags & 5) == 2`.',
    'Comparison is always false unless configured in `(Flags & 5) == 2`.',
    'Comparison is always false in `Flags & 5 == 2`.',
    'Comparison is always false in `(Flags & 3) == 2`.',
    'Comparison is always false in `(Flags & 5) == 2; return 0`.',
])
def test_complete_claim_and_matching_source_expression_are_required(claim):
    result = check_integer_comparison('int Read(unsigned Flags){if((Flags & 5)==2)return 1;return 0;}',
                                      claim, language='c', integer_abi='lp64')
    assert result['matches_claim'] is None, result


@pytest.mark.parametrize('unknown_check', [1, 2])
def test_unknown_entry_or_contrary_query_never_grants_a_proof(monkeypatch, unknown_check):
    import z3
    from core.audit import integer_mask_comparison
    original = integer_mask_comparison.check_solver
    calls = []

    def undecided(solver):
        calls.append(solver)
        return z3.unknown if len(calls) == unknown_check else original(solver)

    monkeypatch.setattr(integer_mask_comparison, 'check_solver', undecided)
    result = check('int Read(unsigned Flags){if((Flags & 5)==2)return 1;return 0;}')
    assert len(calls) == unknown_check
    assert result['matches_claim'] is None and not result['entry_witness_validated'], result


def test_forged_entry_witness_cannot_override_guard_replay(monkeypatch):
    from core.audit import integer_mask_comparison
    monkeypatch.setattr(integer_mask_comparison, 'format_vars', lambda *a, **kw: {'Flags': 1})
    result = check('int Read(unsigned Flags){if(Flags==0){if((Flags & 5)==2)return 1;}return 0;}')
    assert result['matches_claim'] is None and not result['entry_witness_validated'], result


def test_quality_mask_discovery_is_pure_and_still_needs_native_admission(monkeypatch):
    from core.audit import integer_mask_comparison
    from core.audit.arithmetic_seeds import seed_arithmetic_hypotheses

    def forbidden(*a, **kw):
        raise AssertionError('candidate preparation entered native proof')

    for name in ['check_mask_comparison', 'new_solver', 'check_solver', 'query_budget']:
        monkeypatch.setattr(integer_mask_comparison, name, forbidden)
    gap = {'file': 'unit.c', 'name': 'Read', 'line_start': 1, 'line_end': 1}
    source = 'int Read(unsigned Flags){if((Flags & 5)==2)return 1;return 0;}'
    assert seed_arithmetic_hypotheses([gap], {'unit.c': source}, mode='quality', integer_abi='lp64') == 1
    row = gap['injected_hypotheses'][0]
    assert row['mechanism'] == 'Comparison is always false in `(Flags & 5) == 2`.'
    assert row['arithmetic_site']['candidate_basis'] == 'masked-out-bits'
    assert row['arithmetic_site']['binding_status'] == 'candidate'
    assert row['confidence'] == 'low' and 'verdict' not in row
