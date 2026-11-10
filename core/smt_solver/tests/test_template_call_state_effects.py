"""Unsupported C++ callable forms still expose possible scalar writes."""

import pytest

from core.smt_solver import BVProfile
from core.smt_solver import path_feasibility as paths

pytestmark = pytest.mark.usefixtures("native")


@pytest.fixture
def native():
    pytest.importorskip("z3")


def guards(*texts):
    return [paths.PathCondition(text, index) for index, text in enumerate(texts)]


@pytest.mark.parametrize("call", [
    "update<int>(&Value) == 0", "ns::update<Box<int>>(&Value) == 0",
    "update<int> /* marker */ (&Value) == 0",
    "[](int* p) { return update(p); }(&Value) == 0",
    "Updater{&Value}.result() == 0", "Updater<int>{Nested{}, &Value}.result() == 0",
], ids=["template", "nested-template", "comment-separated", "lambda", "braced", "nested-braced"])
@pytest.mark.parametrize("entry", [paths.check_path_feasibility, paths.check_path_feasibility_dual])
def test_unsupported_callable_address_exposure_separates_epochs(call, entry):
    result = entry(guards("Value == 0", call, "Value == 1"),
                   profile=BVProfile(8, False), reduce_constraints=False)
    assert result.feasible is None
    assert result.model == {} and result.wp_complete is False
    assert result.unknown == [call]
    assert result.unknown_reasons[0].kind.value == "unmodeled_state_effect"


@pytest.mark.parametrize("text", [
    "Value > (Flags & 1)", "(Flags & 1) > Value",
    'update<int>("&Value") == 0', "update<int>(Value) == 0",
    "Updater{} == (Flags & 1)", 'Updater{"&Value"}.result() == 0',
])
def test_comparisons_and_quoted_or_address_free_arguments_are_not_state_barriers(text):
    result = paths.check_path_feasibility(guards(text), profile=BVProfile(8, False), reduce_constraints=False)
    assert all(reason.kind.value != "unmodeled_state_effect" for reason in result.unknown_reasons)


@pytest.mark.parametrize("before", [True, False])
def test_independent_segment_contradiction_remains_valid(before):
    call = "update<int>(&Other) == 0"
    contradiction = ["Value == 0", "Value == 1"]
    texts = contradiction + [call] if before else [call] + contradiction
    result = paths.check_path_feasibility(guards(*texts), profile=BVProfile(8, False), reduce_constraints=False)
    assert result.feasible is False
    assert "mutation-free segment" in result.reasoning
