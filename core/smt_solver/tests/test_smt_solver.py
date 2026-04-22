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
