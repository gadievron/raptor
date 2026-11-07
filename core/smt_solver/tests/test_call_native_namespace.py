"""Call occurrences must not alias native declarations hidden behind registry keys."""

import pytest

z3 = pytest.importorskip("z3")

from core.smt_solver import BVProfile  # noqa: E402
from core.smt_solver import path_feasibility as paths  # noqa: E402


@pytest.mark.parametrize("binding_kind", ["plain", "derived", "quantified"])
@pytest.mark.parametrize("reduce", [False, True])
def test_guard_call_does_not_reuse_a_native_variable_behind_an_alias(binding_kind, reduce):
    source = z3.BitVec("_anon_0", 8)
    binding = source if binding_kind == "plain" else source + 1
    if binding_kind == "quantified":
        flag = z3.Bool("Bound")
        binding = z3.If(z3.ForAll([flag], z3.Or(flag, z3.Not(flag))), binding, binding)
    registry = {"Source": binding}
    result = paths.check_verb_feasibility(
        [("source value", source == 0)], [paths.PathCondition("opaque() == 2", 0)], registry,
        profile=BVProfile(8, False), reduce_constraints=reduce,
    )
    assert result.feasible is True
    assert result.model["Source"] == (0 if binding_kind == "plain" else 1)
    call, = result.anon_var_map
    assert call != "_anon_0"
    assert result.model[call] == 2
    assert registry["Source"] is binding


@pytest.mark.parametrize("location", ["intrinsic", "operand-axiom"])
def test_guard_call_reserves_native_names_across_the_complete_frame(location):
    source = z3.BitVec("_anon_0", 8)
    facts = [("source value", source == 0)]
    model = paths.CallOperandModel(axioms=facts if location == "operand-axiom" else [])
    result = paths.check_verb_feasibility(
        facts if location == "intrinsic" else [], [paths.PathCondition("opaque() == 2", 0)], {},
        profile=BVProfile(8, False), reduce_constraints=False, operand_model=model,
    )
    assert result.feasible is True
    assert result.model["_anon_0"] == 0
    call, = result.anon_var_map
    assert call != "_anon_0" and result.model[call] == 2


@pytest.mark.parametrize("where", ["key", "alias", "derived"])
def test_fresh_operand_skips_explicit_native_name_collisions(monkeypatch, where):
    occupied = z3.BitVec("_anon_operand!occupied", 8)
    original = occupied + 1 if where == "derived" else occupied
    key = str(occupied) if where == "key" else "Source"
    registry = {key: original}
    free = z3.BitVec("_anon_operand!free", 8)
    choices = iter([occupied, free])
    monkeypatch.setattr(z3, "FreshConst", lambda *a, **k: next(choices))
    result = paths.make_anon_call_var(registry, profile=BVProfile(8, False))
    assert result.eq(free)
    assert registry[key] is original
    solver = z3.Solver()
    solver.add(occupied == 0, result == 2)
    assert solver.check() == z3.sat
