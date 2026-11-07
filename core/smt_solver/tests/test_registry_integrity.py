"""Registered symbols must agree with the query's declared arithmetic frame."""

import pytest

z3 = pytest.importorskip("z3")

from core.smt_solver import BVProfile, new_optimizer  # noqa: E402
from core.smt_solver import path_feasibility as paths  # noqa: E402


@pytest.mark.parametrize("width", [8, 16, 64])
def test_registry_cannot_change_a_32_bit_query_into_another_width(width):
    value = z3.BitVec("Value", width)
    registry = {"Value": value}
    with pytest.raises(ValueError, match="profile width"):
        paths.check_verb_feasibility([
            ("Value is small", value == 255), ("sum shrinks", z3.ULT(value + value, value)),
        ], [], registry, profile=BVProfile(32, False), reduce_constraints=False)
    assert list(registry) == ["Value"]


@pytest.mark.parametrize("value_factory", [
    lambda: z3.Int("Bad"), lambda: z3.Bool("Bad"), lambda: z3.BitVecSort(32),
    lambda: 7, lambda: True, lambda: z3.BitVec("Bad", 32, ctx=z3.Context()),
])
@pytest.mark.parametrize("entry", ["variable", "call", "verb"])
def test_invalid_bindings_decline_before_mutation_or_query(monkeypatch, value_factory, entry):
    value = value_factory()
    registry = {"Bad": value}
    monkeypatch.setattr(paths, "_new_solver", lambda *a, **k: pytest.fail("invalid registry reached a query"))
    with pytest.raises(ValueError, match="bitvector|context"):
        if entry == "variable":
            paths.make_var("Bad", registry, profile=BVProfile(32, False))
        elif entry == "call":
            paths.make_anon_call_var(registry, profile=BVProfile(32, False))
        else:
            paths.check_verb_feasibility([], [paths.PathCondition("New == 1", 0)], registry,
                                         profile=BVProfile(32, False))
    assert list(registry) == ["Bad"]
    assert registry["Bad"] is value


@pytest.mark.parametrize("name", [None, 1, True, "", "NULL"])
def test_invalid_or_literal_registry_keys_cannot_be_materialized(name):
    registry = {}
    with pytest.raises(ValueError, match="name|NULL"):
        paths.make_var(name, registry, profile=BVProfile(32, False))
    assert registry == {}


def test_matching_expressions_aliases_and_lazy_names_remain_supported():
    value = z3.BitVec("Underlying", 32)
    registry = {"Alias": value + 1, "Reserved": None}
    assert paths.make_var("Alias", registry, profile=BVProfile(32, False)).eq(value + 1)
    reserved = paths.make_var("Reserved", registry, profile=BVProfile(32, False))
    assert reserved.size() == 32
    result = paths.check_verb_feasibility([("owned source", value == 2)],
                                        [paths.PathCondition("Alias == 3", 0)], registry,
                                        profile=BVProfile(32, False), reduce_constraints=False)
    assert result.feasible is True
    assert result.model["Underlying"] == 2


def test_valid_call_aliases_still_use_the_shared_profile():
    result = paths.check_path_feasibility([paths.PathCondition("read_value() == 7", 0)],
                                          profile=BVProfile(32, False), reduce_constraints=False)
    assert result.feasible is True
    assert len(result.anon_var_map) == 1


def test_private_solver_context_is_supported_by_low_level_objective_helper():
    context = z3.Context()
    value = z3.BitVec("Value", 8, ctx=context)
    result = paths._solve_pending([("bounded", z3.ULE(value, 7))], new_optimizer(ctx=context), [], [], [],
                                  profile=BVProfile(8, False), vars_={"Value": value}, prefer_witness=("Value", "max"))
    assert result.feasible is True and result.model["Value"] == 7


def test_low_level_objective_cannot_optimize_at_a_different_profile_width():
    value = z3.BitVec("Value", 8)
    optimizer = new_optimizer()
    with pytest.raises(ValueError, match="profile width"):
        paths._solve_pending([("small", z3.ULE(value, 7))], optimizer, [], [], [],
                              profile=BVProfile(32, False), vars_={"Value": value}, prefer_witness=("Value", "max"))
    assert len(optimizer.assertions()) == 0
    assert len(optimizer.objectives()) == 0
