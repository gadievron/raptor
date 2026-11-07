"""Path witnesses must evaluate registry identities, not printed declarations."""

import pytest

z3 = pytest.importorskip("z3")

from core.smt_solver import BVProfile, new_optimizer  # noqa: E402
from core.smt_solver import path_feasibility as paths  # noqa: E402


@pytest.mark.parametrize("reduce_constraints", [False, True])
def test_verb_witness_evaluates_alias_instead_of_unrelated_same_named_declaration(reduce_constraints):
    underlying, unrelated = z3.BitVecs("Underlying Alias", 8)
    registry = {"Alias": underlying + 1}
    result = paths.check_verb_feasibility(
        [("underlying", underlying == 2), ("unrelated", unrelated == 99)],
        [paths.PathCondition("Alias == 3", 0)], registry,
        profile=BVProfile(8, False), reduce_constraints=reduce_constraints,
    )
    assert result.feasible is True
    assert result.model["Alias"] == 3
    assert result.model["Underlying"] == 2


@pytest.mark.parametrize("signed,expected", [(False, 255), (True, -1)])
def test_registered_expression_and_constant_use_profile_signedness(signed, expected):
    value = z3.BitVec("Underlying", 8)
    registry = {"Alias": value + 1, "Constant": z3.BitVecVal(255, 8)}
    result = paths.check_verb_feasibility(
        [("underlying", value == 254)], [], registry,
        profile=BVProfile(8, signed), reduce_constraints=False,
    )
    assert result.feasible is True
    assert result.model["Alias"] == result.model["Constant"] == expected


def test_unassigned_registry_name_cannot_borrow_native_value_or_mutate_registry():
    unrelated = z3.BitVec("Reserved", 16)
    free = z3.BitVec("Free", 8)
    registry = {"Reserved": None, "FreeAlias": free}
    result = paths.check_verb_feasibility(
        [("unrelated", unrelated == 7)], [], registry,
        profile=BVProfile(8, False), reduce_constraints=False,
    )
    assert result.feasible is True
    assert "Reserved" not in result.model
    assert "FreeAlias" not in result.model
    assert registry["Reserved"] is None
    assert registry["FreeAlias"] is free


def test_low_level_private_context_witness_retains_expression_identity():
    context = z3.Context()
    value = z3.BitVec("Underlying", 8, ctx=context)
    result = paths._solve_pending(
        [("value", value == 2)], new_optimizer(ctx=context), [], [], [],
        profile=BVProfile(8, False), vars_={"Alias": value + 1},
        reduce_constraints=False,
    )
    assert result.feasible is True
    assert result.model["Alias"] == 3
