"""Existing overflow predicates now guard source-prefix arithmetic too."""

import pytest

from core.audit import sweep
from core.audit.arithmetic_prefix import PrefixIntegerModel
from core.audit.condition_extraction import _get_parser
from core.audit.integer_abi import resolve_integer_abi


@pytest.fixture(autouse=True)
def dependencies():
    pytest.importorskip('z3')
    pytest.importorskip('tree_sitter')
    pytest.importorskip('tree_sitter_c')


def source(prefix, extra='unsigned Extra'):
    return ('unsigned Read(unsigned Value,unsigned Step,' + extra + '){' + prefix
            + 'if(Value<10 && Step<10){return Value+Step;}return 0;}')


@pytest.mark.parametrize('language', ['c', 'cpp'])
@pytest.mark.parametrize('prefix,extra', [
    ('unsigned Local=Extra+1;', 'unsigned Extra'),
    ('unsigned Local=Extra-1;', 'unsigned Extra'),
    ('unsigned Local=Extra*2;', 'unsigned Extra'),
    ('int Local=Extra+0;', 'int Extra'),
    ('int Local=Extra-0;', 'int Extra'),
    ('int Local=Extra*1;', 'int Extra'),
    ('int Local=Extra*0;', 'int Extra'),
    ('int Local=Extra*2;', 'unsigned char Extra'),
    ('int Local=Extra+1;', 'unsigned short Extra'),
    ('int Local=Extra-1;', 'unsigned char Extra'),
])
def test_mechanically_defined_arithmetic_reaches_audit_verification(prefix, extra, language):
    if language == 'cpp':
        pytest.importorskip('tree_sitter_cpp')
    result = sweep._run_smt_verb_inner(file_path='record.' + language, function_name='Read', verb='check-overflow',
                                     source=source(prefix, extra), hypothesis='integer overflow in `Value + Step`',
                                     integer_abi='ilp32')
    assert result.outcome == 'refuted', result.details


@pytest.mark.parametrize('prefix,extra', [
    ('int Local=Extra+1;', 'int Extra'),
    ('int Local=Extra-1;', 'int Extra'),
    ('int Local=Extra*2;', 'int Extra'),
    ('int Local=Extra*-1;', 'int Extra'),
    ('int Local=Extra+1;', 'unsigned Extra'),
    ('signed char Local=Extra*2;', 'unsigned char Extra'),
])
def test_possible_signed_overflow_or_narrowing_never_gets_prefix_credit(prefix, extra):
    result = sweep._run_smt_verb_inner(file_path='record.c', function_name='Read', verb='check-overflow',
                                     source=source(prefix, extra), hypothesis='integer overflow in `Value + Step`',
                                     integer_abi='ilp32')
    assert result.outcome == 'inconclusive' and result.matches == []


@pytest.mark.parametrize('abi', ['i16', 'ilp32'])
@pytest.mark.parametrize('spelling', ['signed char', 'unsigned char', 'unsigned'])
@pytest.mark.parametrize('operator,operand', [('+', 1), ('-', 1), ('*', 2), ('<<', 1), ('<<', 8), ('<<', 15)])
def test_prefix_result_domains_match_independent_integer_ranges(abi, spelling, operator, operand, monkeypatch):
    from core.audit.arithmetic_types import integer_type
    from core.audit import arithmetic_prefix_obligations
    # This oracle tests arithmetic intervals, not the production deadline.
    # Expiry and query caps have separate conservative-refusal tests.
    monkeypatch.setattr(arithmetic_prefix_obligations, '_BUDGET_MS', 5000)
    integer_abi = resolve_integer_abi(abi)
    data = f'int Read({spelling} Extra){{return Extra {operator} {operand};}}'.encode()
    pending = [_get_parser('c').parse(data).root_node]
    while pending:
        node = pending.pop()
        if node.type == 'binary_expression':
            break
        pending.extend(node.named_children)
    else:
        pytest.fail('arithmetic fixture did not parse')
    storage = integer_type(spelling, integer_abi)
    low = -(1 << (storage.width - 1)) if storage.signed else 0
    high = (1 << (storage.width - (1 if storage.signed else 0))) - 1
    operation_width, signed = storage.promoted_width, storage.promoted_signed

    def calculate(value):
        if operator == '+':
            return value + operand
        if operator == '-':
            return value - operand
        if operator == '*':
            return value * operand
        return value * (2 ** operand)

    minimum, maximum = (-(1 << (operation_width - 1)), (1 << (operation_width - 1)) - 1) if signed else (0, (1 << operation_width) - 1)
    valid = operator != '<<' or (operand < operation_width and (not signed or low >= 0))
    if signed:
        valid = valid and minimum <= calculate(low) <= calculate(high) <= maximum
    domain = PrefixIntegerModel(data, 'c', integer_abi).value_domain(node)
    assert (domain is not None) is valid, (abi, spelling, operator, operand, domain)
    if domain is None:
        return
    values = range(low, high + 1) if storage.width == 8 else (low, low + 1, high // 2, high - 1, high)
    for value in values:
        result = calculate(value)
        if not signed:
            result %= 1 << operation_width
        assert domain[0] <= result <= domain[1], (abi, spelling, operator, operand, value, domain)
