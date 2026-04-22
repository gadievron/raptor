"""Tests for core.smt_solver — Z3 dependency management."""

import sys
import unittest.mock
from pathlib import Path
import pytest

# core/smt_solver/tests/ -> repo root
sys.path.insert(0, str(Path(__file__).parents[3]))

from core.smt_solver import z3_available

class TestSMTSolver:
    """Basic tests for SMT solver availability checking."""

    def test_z3_available_is_boolean(self):
        """Ensure z3_available returns a boolean value."""
        enabled = z3_available()
        assert isinstance(enabled, bool)

    def test_z3_import_exposure(self):
        """Verify that z3 is either the module or None."""
        from core.smt_solver import z3
        if z3_available():
            assert z3 is not None
            # Basic check to confirm it's actually the Z3 library
            assert hasattr(z3, 'BitVec')
        else:
            # If disabled, z3 should be None or a non-functional stub
            assert z3 is None or not hasattr(z3, 'BitVec')

    def test_basic_arithmetic_sat(self):
        """Verify Z3 can solve a basic bitvector arithmetic problem."""
        if not z3_available():
            pytest.skip("Z3 not installed, skipping SAT test")

        from core.smt_solver import z3

        solver = z3.Solver()
        x = z3.BitVec('x', 64)
        y = z3.BitVec('y', 64)

        solver.add(x + y == 20)
        solver.add(x == 10)

        assert solver.check() == z3.sat
        model = solver.model()
        assert model[y].as_long() == 10

    def test_basic_unsat(self):
        """Verify Z3 correctly identifies an UNSAT problem."""
        if not z3_available():
            pytest.skip("Z3 not installed, skipping UNSAT test")

        from core.smt_solver import z3

        solver = z3.Solver()
        x = z3.BitVec('x', 64)

        # These are 'impassable' constraints...
        solver.add(x == 1)
        solver.add(x == 2)

        assert solver.check() == z3.unsat


_requires_z3 = pytest.mark.skipif(
    not z3_available(),
    reason="z3-solver not installed",
)


class TestScoped:
    """``session.scoped`` must push/pop correctly around a block, including
    when the block is exited via exception or ``continue``."""

    @_requires_z3
    def test_rollback_on_normal_exit(self):
        from core.smt_solver import new_solver, scoped, z3
        solver = new_solver()
        x = z3.BitVec("x", 64)
        solver.add(x == 1)

        with scoped(solver):
            solver.add(x == 2)
            assert solver.check() == z3.unsat

        # Hypothesis removed: only x == 1 remains, which is sat.
        assert solver.check() == z3.sat

    @_requires_z3
    def test_rollback_on_exception(self):
        from core.smt_solver import new_solver, scoped, z3
        solver = new_solver()
        x = z3.BitVec("x", 64)
        solver.add(x == 1)

        class Boom(Exception):
            pass

        with pytest.raises(Boom):
            with scoped(solver):
                solver.add(x == 2)
                raise Boom

        # Even though the block raised, pop() ran in finally — hypothesis gone.
        assert solver.check() == z3.sat

    @_requires_z3
    def test_nested_push_pop(self):
        from core.smt_solver import new_solver, scoped, z3
        solver = new_solver()
        x = z3.BitVec("x", 64)
        solver.add(x >= 0)

        with scoped(solver):
            solver.add(x <= 10)
            with scoped(solver):
                solver.add(x == 42)
                assert solver.check() == z3.unsat  # 42 outside [0, 10]
            # Inner rolled back; outer (x <= 10) still holds.
            assert solver.check() == z3.sat
        # Outer rolled back; only x >= 0 remains.
        assert solver.check() == z3.sat


class TestExplain:
    """``explain.track`` + ``explain.core_names`` must identify which
    tracked assertions Z3 used to derive an unsat result."""

    @_requires_z3
    def test_core_names_round_trip(self):
        from core.smt_solver import core_names, new_solver, track, z3
        solver = new_solver()
        x = z3.BitVec("x", 64)

        rev = track(solver, [("x_is_1", x == 1), ("x_is_2", x == 2)])
        assert solver.check() == z3.unsat

        names = core_names(solver, rev)
        assert set(names) == {"x_is_1", "x_is_2"}

    @_requires_z3
    def test_core_names_empty_when_sat(self):
        """Calling core_names on a sat solver yields no names.

        ``solver.unsat_core()`` is only meaningful after unsat; for sat
        solvers Z3 typically returns an empty sequence.
        """
        from core.smt_solver import core_names, new_solver, track, z3
        solver = new_solver()
        x = z3.BitVec("x", 64)

        rev = track(solver, [("x_is_1", x == 1)])
        assert solver.check() == z3.sat
        assert core_names(solver, rev) == []

    @_requires_z3
    def test_core_names_ignores_unknown_labels(self):
        """Labels not present in ``rev`` are silently omitted — lets
        callers track only the assertions they care about naming."""
        from core.smt_solver import core_names, new_solver, track, z3
        solver = new_solver()
        x = z3.BitVec("x", 64)

        rev = track(solver, [("keep", x == 1), ("drop", x == 2)])
        # Simulate a caller that only cares about one label.
        partial_rev = {k: v for k, v in rev.items() if v == "keep"}
        assert solver.check() == z3.unsat

        names = core_names(solver, partial_rev)
        assert names == ["keep"]

    @_requires_z3
    def test_track_does_not_affect_untracked_assertions(self):
        """Pre-existing untracked assertions stay in force but don't
        appear in the unsat core."""
        from core.smt_solver import core_names, new_solver, track, z3
        solver = new_solver()
        x = z3.BitVec("x", 64)
        solver.add(x == 1)  # untracked

        rev = track(solver, [("clash", x == 2)])
        assert solver.check() == z3.unsat

        names = core_names(solver, rev)
        # Only the tracked assertion is named; the untracked `x == 1`
        # pulled us into unsat but isn't reported by core_names.
        assert names == ["clash"]
