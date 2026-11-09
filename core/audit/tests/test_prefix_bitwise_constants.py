"""Exact bitwise prefixes retain values without consuming solver queries."""

import pytest

from core.audit.arithmetic_prefix import PrefixIntegerModel
from core.audit.condition_extraction import _get_parser
from core.audit.integer_abi import resolve_integer_abi


def test_literal_mask_retains_its_exact_value_without_a_query():
    pytest.importorskip('z3')
    pytest.importorskip('tree_sitter_c')
    data = b'int Read(void){return 7 & 3;}'
    root = _get_parser('c').parse(data).root_node
    assert not root.has_error
    body = root.named_children[0].child_by_field_name('body')
    expression = body.named_children[0].named_children[0]
    model = PrefixIntegerModel(data, 'c', resolve_integer_abi('ilp32'))
    actual = model.value_domain(expression)
    assert (actual, model.proofs.checks) == ((3, 3), 0)


@pytest.mark.parametrize('signed,a,b,operator,expected', [
    (True, 7, 3, '&', 3), (True, 7, 3, '|', 7), (True, 7, 3, '^', 4),
    (True, -1, 3, '&', 3), (True, -8, 3, '|', -5), (True, -1, 3, '^', -4),
    (False, 15, 3, '&', 3), (False, 8, 3, '|', 11), (False, 15, 3, '^', 12),
    (False, 0, 0, '|', 0),
])
def test_exact_promoted_values_need_no_remaining_query_budget(signed, a, b, operator, expected):
    from types import SimpleNamespace
    from core.audit.arithmetic_bitwise_domains import bitwise_domain
    from core.audit.arithmetic_prefix_obligations import PrefixProofBudget
    from core.audit.arithmetic_types import IntegerType

    budget = PrefixProofBudget()
    budget.checks = 8
    result = bitwise_domain(SimpleNamespace(proofs=budget), operator,
                            IntegerType(4, signed, 4, signed), [(a, a), (b, b)])
    assert result == (expected, expected)
    assert budget.checks == 8


@pytest.mark.parametrize('language', ['c', 'cpp'])
@pytest.mark.parametrize('abi', ['i16', 'ilp32'])
@pytest.mark.parametrize('expression,expected', [
    ('7 & 3', 3), ('7 | 3', 7), ('7 ^ 3', 4),
    ('(-1) & 3', 3), ('(-8) | 3', -5), ('(-1) ^ 3', -4),
])
def test_source_constants_preserve_exact_values_in_the_target_frame(language, abi, expression, expected):
    pytest.importorskip('z3')
    pytest.importorskip('tree_sitter_' + language)
    data = ('int Read(void){return ' + expression + ';}').encode()
    root = _get_parser(language).parse(data).root_node
    assert not root.has_error
    body = root.named_children[0].child_by_field_name('body')
    node = body.named_children[0].named_children[0]
    model = PrefixIntegerModel(data, language, resolve_integer_abi(abi))
    assert model.value_domain(node) == (expected, expected)
    assert model.proofs.checks == 0


@pytest.mark.parametrize('language', ['c', 'cpp'])
@pytest.mark.parametrize('divisor,expected', [
    ('7 & 3', 'refuted'), ('7 | 3', 'refuted'), ('7 ^ 3', 'refuted'),
    ('7 ^ 7', 'inconclusive'), ('Extra & 3', 'inconclusive'),
    ('(1/0) & 3', 'inconclusive'), ('(unsigned)7 & -1', 'inconclusive'),
])
def test_exact_bitwise_divisors_reach_source_verification_without_hiding_faults(language, divisor, expected):
    from core.audit import sweep

    pytest.importorskip('z3')
    pytest.importorskip('tree_sitter_' + language)
    text = ('unsigned Read(unsigned Value,unsigned Step,int Extra){int Local=1/(' + divisor
            + ');if(Value<10 && Step<10)return Value+Step;return 0;}')
    result = sweep._run_smt_verb_inner(
        file_path='record.' + language, function_name='Read', verb='check-overflow',
        source=text, hypothesis='integer overflow in `Value + Step`', integer_abi='ilp32')
    assert result.outcome == expected, result.details
    if expected == 'inconclusive':
        assert result.matches == []
