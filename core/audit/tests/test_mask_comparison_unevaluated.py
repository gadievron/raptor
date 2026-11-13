"""Source mask-comparison proofs require an evaluated expression."""

import pytest

from core.audit.integer_comparison import check_integer_comparison
from core.audit.integer_mask_comparison import mask_comparison_candidates

CLAIM = 'Comparison is always false in `(Flags & 5) == 2`.'


def test_sizeof_mask_comparison_cannot_establish_a_source_comparison():
    pytest.importorskip('z3')
    pytest.importorskip('tree_sitter_c')
    source = 'int Read(unsigned Flags){return sizeof((Flags & 5)==2);}'
    result = check_integer_comparison(source, CLAIM, language='c', integer_abi='lp64')
    assert result['matches_claim'] is None and not result['entry_witness_validated'], result


@pytest.mark.parametrize('language,expression', [
    ('c', 'sizeof((Flags & 5)==2)'),
    ('cpp', 'sizeof((Flags & 5)==2)'),
    ('cpp', 'noexcept((Flags & 5)==2)'),
])
def test_unevaluated_mask_comparisons_produce_no_candidate_or_source_proof(language, expression):
    pytest.importorskip('z3')
    pytest.importorskip('tree_sitter_' + language)
    source = f'int Read(unsigned Flags){{return {expression};}}'
    assert mask_comparison_candidates(source, language=language, integer_abi='lp64') == []
    result = check_integer_comparison(source, CLAIM, language=language, integer_abi='lp64')
    assert result['matches_claim'] is None and not result['entry_witness_validated'], result


@pytest.mark.parametrize('language', ['c', 'cpp'])
def test_evaluated_mask_comparison_retains_its_constant_truth_proof(language):
    pytest.importorskip('z3')
    pytest.importorskip('tree_sitter_' + language)
    source = 'int Read(unsigned Flags){if((Flags & 5)==2)return 1;return 0;}'
    assert len(mask_comparison_candidates(source, language=language, integer_abi='lp64')) == 1
    result = check_integer_comparison(source, CLAIM, language=language, integer_abi='lp64')
    assert result['matches_claim'] is True and result['entry_witness_validated'], result
