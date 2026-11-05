"""Direct predicate verbs have the same whole-obligation budget as paths."""

import pytest

from core.smt_solver import BV_C_UINT32
from core.smt_solver import path_feasibility as paths
from core.smt_solver.rejection import RejectionKind


@pytest.mark.parametrize("intrinsic_count,guard_count", [(65, 0), (0, 65), (32, 33)])
def test_over_budget_verb_refuses_before_any_parser_or_solver_work(monkeypatch, intrinsic_count, guard_count):
    def forbidden(*args, **kwargs):
        pytest.fail("over-budget obligations must stop before creating a solver")
    monkeypatch.setattr(paths, "_new_solver", forbidden)
    monkeypatch.setattr(paths, "_classify_text_condition", forbidden)
    intrinsic = [(f"predicate-{n}", object()) for n in range(intrinsic_count)]
    guards = [paths.PathCondition(f"Value > {n}", n) for n in range(guard_count)]
    result = paths.check_verb_feasibility(intrinsic, guards, {}, profile=BV_C_UINT32)
    assert result.feasible is None and result.model == {}
    assert len(result.unknown) == 65
    assert result.unknown_reasons[0].kind == RejectionKind.TOO_MANY_CONDITIONS


def test_exact_budget_still_solves_the_complete_obligation():
    z3 = pytest.importorskip("z3")
    value = z3.BitVec("Value", 32)
    intrinsic = [("Value == 4", value == 4)]
    guards = [paths.PathCondition("Value <= 3", n) for n in range(63)]
    result = paths.check_verb_feasibility(intrinsic, guards, {"Value": value}, profile=BV_C_UINT32)
    assert result.feasible is False
    assert not result.unknown
