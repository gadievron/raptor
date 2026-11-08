"""Unsupported casts must not become arithmetic on invented scalar names."""

import pytest

from core.smt_solver import BV_C_UINT8
from core.smt_solver import path_feasibility as paths

pytestmark = pytest.mark.usefixtures("native_solver")


@pytest.fixture
def native_solver():
    pytest.importorskip("z3")


def verb_query(conditions, **kwargs):
    return paths.check_verb_feasibility([], conditions, {}, **kwargs)


ENTRIES = [paths.check_path_feasibility, paths.check_path_feasibility_dual, verb_query]


def guards(*texts):
    return [paths.PathCondition(text, n) for n, text in enumerate(texts)]


@pytest.mark.parametrize("entry", ENTRIES)
@pytest.mark.parametrize("reduce", [False, True])
@pytest.mark.parametrize("expression", [
    "(unsigned) +Value != 0", "(Alias) +Value != 0", "(Alias) -Value != 0",
], ids=["builtin-cast", "alias-positive", "alias-negative"])
def test_unbound_cast_spelling_cannot_become_an_invented_scalar(entry, reduce, expression):
    result = entry(guards("Value == 0", expression), profile=BV_C_UINT8, reduce_constraints=reduce)
    assert result.feasible is None, result
    assert result.unknown == [expression]
    assert "ambiguous cast" in result.unknown_reasons[0].detail
    assert "unsigned" not in result.model and "Alias" not in result.model
    assert result.wp_complete is False


@pytest.mark.parametrize("entry", ENTRIES)
@pytest.mark.parametrize("expression", ["(Value) +1 == 1", "(Value) -1 == 255"], ids=["add", "subtract"])
def test_previously_bound_scalar_grouping_keeps_its_meaning(entry, expression):
    result = entry(guards("Value == 0", expression), profile=BV_C_UINT8, reduce_constraints=False)
    assert result.feasible is True and result.unknown == []
    assert result.model["Value"] == 0


@pytest.mark.parametrize("expression", [
    "(probe()) +1 == 2", "(NULL) +1 == 1", "(Value + 1) +1 == 2",
], ids=["call-result", "null-literal", "grouped-arithmetic"])
def test_unambiguous_grouping_remains_supported(expression):
    result = paths.check_path_feasibility(guards(expression), profile=BV_C_UINT8, reduce_constraints=False)
    assert result.feasible is True and result.unknown == []


def test_explicit_verb_registry_binds_grouped_scalar_operands():
    from core.smt_solver import z3

    value = z3.BitVec("bound_value", 8)
    result = paths.check_verb_feasibility([], guards("(Value) +1 == 1"), {"Value": value},
                                          profile=BV_C_UINT8, reduce_constraints=False)
    assert result.feasible is True and result.unknown == []
    assert result.model["Value"] == 0


@pytest.mark.parametrize("entry", ENTRIES)
def test_a_rejected_cast_cannot_bind_its_name_for_a_later_cast(entry):
    expressions = ["(Alias) +Value != 0", "(Alias) -Value != 0"]
    result = entry(guards("Value == 0", *expressions), profile=BV_C_UINT8, reduce_constraints=False)
    assert result.feasible is None
    assert result.unknown == expressions
    assert "Alias" not in result.model


def test_a_lazy_source_name_reservation_does_not_establish_scalar_identity():
    result = paths.check_path_feasibility(guards("Value == 0", "(_anon_0) +Value != 0"),
                                          profile=BV_C_UINT8, reduce_constraints=False)
    assert result.feasible is None
    assert result.unknown == ["(_anon_0) +Value != 0"]
    assert "ambiguous cast" in result.unknown_reasons[0].detail
    assert "_anon_0" not in result.model
