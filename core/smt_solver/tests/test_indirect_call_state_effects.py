"""Indirect address-exposing calls separate scalar value snapshots."""

import pytest

from core.smt_solver import BVProfile
from core.smt_solver import path_feasibility as paths

pytestmark = pytest.mark.usefixtures("native_solver")


@pytest.fixture
def native_solver():
    pytest.importorskip("z3")


def verb_query(conditions, **kwargs):
    return paths.check_verb_feasibility([], conditions, {}, **kwargs)


ENTRIES = [paths.check_path_feasibility, paths.check_path_feasibility_dual, verb_query]
CALLS = ["(*update)(&Value) == 0", "handlers[Index](&Value) == 0",
         "(update)(&Value) == 0", "(*State->update) (&Value) == 0",
         "((update))\n(&Value) == 0", "factory()(&Value) == 0"]


def guards(texts):
    return [paths.PathCondition(text, n) for n, text in enumerate(texts)]


@pytest.mark.parametrize("entry", ENTRIES)
@pytest.mark.parametrize("reduce", [False, True])
@pytest.mark.parametrize("call", CALLS, ids=["pointer", "table", "grouped-name", "member-pointer", "nested-newline", "returned-pointer"])
def test_indirect_address_exposure_cannot_freeze_scalar_values(entry, reduce, call):
    result = entry(guards(["Value == 0", call, "Value == 1"]),
                   profile=BVProfile(8, False), reduce_constraints=reduce)
    assert result.feasible is None, result
    assert result.model == {} and result.wp_complete is False
    assert result.unknown == [call]
    assert result.unknown_reasons[0].kind.value == "unmodeled_state_effect"
    assert "unmodeled scalar value flow" in result.reasoning


@pytest.mark.parametrize("entry", ENTRIES)
@pytest.mark.parametrize("before", [True, False])
def test_independent_segment_contradictions_still_refute(entry, before):
    call = CALLS[0]
    contradiction = ["Value == 0", "Value == 1"]
    texts = contradiction + [call] if before else [call] + contradiction
    result = entry(guards(texts), profile=BVProfile(8, False), reduce_constraints=False)
    assert result.feasible is False
    assert "mutation-free segment" in result.reasoning
    assert result.unknown == [call]


@pytest.mark.parametrize("text", ["(Flags & 1) == 0", "((Flags & 1)) == 0", "(Flags) & 1 == 0"], ids=["grouped", "nested", "grouped-scalar"])
def test_grouped_bitmasks_do_not_create_state_barriers(text):
    result = paths.check_path_feasibility(guards([text]), profile=BVProfile(8, False), reduce_constraints=False)
    assert result.feasible is not False
    assert all(reason.kind.value != "unmodeled_state_effect" for reason in result.unknown_reasons)


@pytest.mark.parametrize("call", ['(*update)("&Value") == 0', "handlers[Index]('&') == 0"], ids=["string", "character"])
def test_quoted_indirect_arguments_do_not_imply_address_exposure(call):
    result = paths.check_path_feasibility(guards([call]), profile=BVProfile(8, False), reduce_constraints=False)
    assert result.feasible is None
    assert all(reason.kind.value != "unmodeled_state_effect" for reason in result.unknown_reasons)
