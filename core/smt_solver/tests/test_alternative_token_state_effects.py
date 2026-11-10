"""C++ alternative mutation tokens cannot preserve scalar snapshots."""

import pytest

from core.smt_solver import BVProfile
from core.smt_solver import path_feasibility as paths


@pytest.fixture(autouse=True)
def native():
    pytest.importorskip("z3")


def guards(*texts):
    return [paths.PathCondition(text, n) for n, text in enumerate(texts)]


@pytest.mark.parametrize("change,before,after", [
    ("Value or_eq 1", 0, 1), ("Value xor_eq 1", 0, 1), ("Value and_eq 0", 1, 0),
    ("(Value)or_eq 1", 0, 1), ("Value\nor_eq 1", 0, 1),
    ("update(bitand Value) == 0", 0, 1), ("update(bitand(Value)) == 0", 0, 1),
])
@pytest.mark.parametrize("reduce", [False, True])
def test_alternative_mutation_forms_separate_scalar_epochs(change, before, after, reduce):
    result = paths.check_path_feasibility(guards(f"Value == {before}", change, f"Value == {after}"),
                                          profile=BVProfile(8, False), reduce_constraints=reduce)
    assert result.feasible is None
    assert result.model == {} and result.wp_complete is False
    assert result.unknown_reasons[0].kind.value in {"assignment_shaped", "unmodeled_state_effect"}


@pytest.mark.parametrize("text", [
    "or_eq == 0", "and_eq == Value", "Value == xor_eq", "Valueor_eq == 1",
    "probe(bitand) == 0", 'probe("Value or_eq 1; bitand Value") == 0',
])
def test_literal_and_identifier_spellings_keep_the_existing_profile(text):
    result = paths.check_path_feasibility(guards(text), profile=BVProfile(8, False), reduce_constraints=False)
    assert result.feasible is True
    assert result.unknown == []
