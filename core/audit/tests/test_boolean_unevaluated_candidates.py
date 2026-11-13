"""Boolean discovery does not borrow conditions from unevaluated contexts."""

import pytest

from core.audit import integer_conjunction as subject

SPECS = [
    ('conjunction_candidates', 'Value < Limit && Value > Limit'),
    ('disjunction_candidates', 'Value < Limit || Value >= Limit'),
    ('range_condition_candidates', 'Value < 10 && Value > 20'),
    ('range_condition_candidates', 'Value < 20 || Value > 10'),
]


def source(expression, unevaluated):
    statement = f'if({expression}){{}}'
    body = f'return sizeof(({{{statement}0;}}));' if unevaluated else statement + 'return 0;'
    return 'int Read(int Value,int Limit){' + body + '}'


def test_sizeof_statement_expression_has_no_boolean_discovery_objective():
    pytest.importorskip('tree_sitter_c')
    rows = subject.conjunction_candidates(source(SPECS[0][1], True), language='c', integer_abi='lp64')
    assert rows == []


@pytest.mark.parametrize('language', ['c', 'cpp'])
@pytest.mark.parametrize('function,expression', SPECS)
def test_unevaluated_conditions_refuse_while_evaluated_candidates_survive(language, function, expression, monkeypatch):
    pytest.importorskip('tree_sitter_' + language)

    def forbidden(*args, **kwargs):
        raise AssertionError('candidate context filtering entered proof')

    for name in ('ComparisonModel', 'guards_for_operation', 'new_solver'):
        monkeypatch.setattr(subject, name, forbidden)
    discover = getattr(subject, function)
    assert discover(source(expression, True), language=language, integer_abi='lp64') == []
    assert len(discover(source(expression, False), language=language, integer_abi='lp64')) == 1
