"""Affine division sites require evaluated source operands."""

import pytest

from core.audit.integer_affine_division import affine_division_candidates
from core.audit.integer_division import check_integer_division

CLAIM = 'Potential division by zero in `Value / (Count-1)`.'


def test_sizeof_affine_division_cannot_produce_a_fault_witness():
    pytest.importorskip('z3')
    pytest.importorskip('tree_sitter_c')
    source = 'unsigned Read(unsigned Value,unsigned Count){return sizeof(Value/(Count-1));}'
    result = check_integer_division(source, CLAIM, language='c', integer_abi='lp64')
    assert result['violation'] is None and not result['witness_validated'], result


@pytest.mark.parametrize('language,expression', [
    ('c', 'sizeof(Value/(Count-1))'),
    ('cpp', 'sizeof(Value/(Count-1))'),
    ('cpp', 'noexcept(Value/(Count-1))'),
])
def test_unevaluated_affine_operands_produce_neither_candidate_nor_proof(language, expression):
    pytest.importorskip('z3')
    pytest.importorskip('tree_sitter_' + language)
    source = f'unsigned Read(unsigned Value,unsigned Count){{return {expression};}}'
    assert affine_division_candidates(source, language=language, integer_abi='lp64') == []
    result = check_integer_division(source, CLAIM, language=language, integer_abi='lp64')
    assert result['violation'] is None and not result['witness_validated'], result


@pytest.mark.parametrize('language', ['c', 'cpp'])
def test_evaluated_affine_division_retains_its_source_witness(language):
    pytest.importorskip('z3')
    pytest.importorskip('tree_sitter_' + language)
    source = 'unsigned Read(unsigned Value,unsigned Count){return Value/(Count-1);}'
    assert len(affine_division_candidates(source, language=language, integer_abi='lp64')) == 1
    result = check_integer_division(source, CLAIM, language=language, integer_abi='lp64')
    assert result['violation'] is True and result['witness_validated'], result
