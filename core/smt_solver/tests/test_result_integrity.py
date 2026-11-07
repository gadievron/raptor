"""Optional summaries and witness preferences cannot overstate solver results."""

import pytest

z3 = pytest.importorskip("z3")

from core.smt_solver import BVProfile, new_solver  # noqa: E402
from core.smt_solver import path_feasibility as paths  # noqa: E402


@pytest.mark.parametrize("width", [2, 8, 32, 64])
@pytest.mark.parametrize("direction", ["min", "max"])
def test_signed_witness_preferences_use_signed_order(width, direction):
    low, high = (-1, 1) if width == 2 else (-3, 3)
    conditions = [paths.PathCondition(f"Value >= {low}", 0), paths.PathCondition(f"Value <= {high}", 1)]
    result = paths.check_path_feasibility(conditions, profile=BVProfile(width, True), prefer_witness=("Value", direction))
    assert result.feasible is True
    assert result.model["Value"] == (low if direction == "min" else high)


@pytest.mark.parametrize("direction,expected", [("min", 0), ("max", 255)])
def test_unsigned_witness_preferences_keep_unsigned_order(direction, expected):
    result = paths.check_path_feasibility([paths.PathCondition("Value <= 255", 0)], profile=BVProfile(16, False),
                                          prefer_witness=("Value", direction))
    assert result.feasible is True and result.model["Value"] == expected


def test_undecided_redundancy_keeps_constraints_and_marks_the_summary_incomplete(monkeypatch):
    def auxiliary(timeout_ms):
        solver = new_solver(timeout_ms)
        monkeypatch.setattr(solver, "check", lambda: z3.unknown)
        return solver
    monkeypatch.setattr(paths, "_new_solver", auxiliary)
    value = z3.BitVec("Value", 8)
    predicate, conjuncts, complete = paths._extract_wp([("Value > 5", value > 5), ("Value > 0", value > 0)])
    assert predicate is not None and set(conjuncts) == {"Value > 5", "Value > 0"}
    assert complete is False


@pytest.mark.parametrize("error", [z3.Z3Exception("owned auxiliary failure"), RuntimeError("owned scope failure")])
def test_auxiliary_failure_cannot_erase_a_definitive_primary_sat_model(monkeypatch, error):
    def unavailable(*args, **kwargs):
        raise error
    monkeypatch.setattr(paths, "_extract_wp", unavailable)
    result = paths.check_path_feasibility([paths.PathCondition("Value > 1", 0), paths.PathCondition("Value < 10", 1)],
                                          profile=BVProfile(8, False))
    assert result.feasible is True and 1 < result.model["Value"] < 10
    assert result.wp_predicate is None and result.wp_complete is False
    assert set(result.wp_conjuncts) == {"Value > 1", "Value < 10"}


def test_unencoded_inputs_prevent_a_complete_constraint_summary():
    result = paths.check_path_feasibility([paths.PathCondition("Value > 1", 0),
                                           paths.PathCondition("unsupported @@@ expression", 1)], profile=BVProfile(8, False))
    assert result.feasible is None and result.unknown
    assert result.wp_predicate is not None and result.wp_complete is False


def test_unavailable_reduction_preserves_only_diagnostic_texts(monkeypatch):
    monkeypatch.setattr(paths, "_z3_available", lambda: False)
    assert paths._extract_wp([("Value > 1", object())]) == (None, ["Value > 1"], False)


def test_failed_serialization_is_not_a_complete_summary(monkeypatch):
    value = z3.BitVec("Value", 8)
    def unavailable(self):
        raise z3.Z3Exception("owned serialization failure")
    monkeypatch.setattr(z3.BoolRef, "sexpr", unavailable)
    predicate, conjuncts, complete = paths._extract_wp([("Value > 1", value > 1)])
    assert predicate is None and conjuncts == ["Value > 1"] and complete is False


@pytest.mark.parametrize("direction,expected", [("min", -3), ("max", 3)])
def test_signed_objectives_are_constructed_in_the_target_context(direction, expected):
    ctx = z3.Context()
    value = z3.BitVec("Value", 8, ctx=ctx)
    pending = [("low", value >= -3), ("high", value <= 3)]
    result = paths._solve_pending(pending, z3.Optimize(ctx=ctx), [], [], [], profile=BVProfile(8, True),
                                  prefer_witness=("Value", direction), vars_={"Value": value})
    assert result.feasible is True and result.model["Value"] == expected


@pytest.mark.parametrize("check", [paths.check_path_feasibility, paths.check_path_feasibility_dual])
@pytest.mark.parametrize("reduce_constraints", [False, True])
def test_partial_sat_cannot_certify_an_unencoded_conjunction(check, reduce_constraints):
    result = check([
        paths.PathCondition("Value == 0", 0),
        paths.PathCondition("Value / 2 == 1", 1),
    ], profile=BVProfile(8, False), reduce_constraints=reduce_constraints)
    assert result.feasible is None
    assert result.model["Value"] == 0
    assert result.unknown == ["Value / 2 == 1"]
    assert result.unknown_reasons
    assert result.wp_complete is False
    assert "encoded subset is satisfiable" in result.reasoning


def test_partial_unsat_still_refutes_a_sound_weakening():
    result = paths.check_path_feasibility([
        paths.PathCondition("Value == 0", 0),
        paths.PathCondition("Value == 1", 1),
        paths.PathCondition("Value / 2 == 1", 2),
    ], profile=BVProfile(8, False))
    assert result.feasible is False
    assert result.unknown == ["Value / 2 == 1"]
    assert result.model == {}


def test_intrinsic_sat_with_an_unencoded_guard_is_inconclusive():
    value = z3.BitVec("Value", 8)
    result = paths.check_verb_feasibility(
        [("Value == 0", value == 0)],
        [paths.PathCondition("Value / 2 == 1", 0)],
        vars_={"Value": value}, profile=BVProfile(8, False),
    )
    assert result.feasible is None
    assert result.model["Value"] == 0
    assert result.wp_complete is False
