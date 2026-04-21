"""Tests for core.smt_solver — Z3 dependency management."""

import sys
import unittest.mock
from pathlib import Path
import pytest

# core/smt_solver/tests/ -> repo root
sys.path.insert(0, str(Path(__file__).parents[3]))

from core.smt_solver import smt_enabled

class TestSMTSolver:
    """Basic tests for SMT solver availability checking."""

    def test_smt_enabled_is_boolean(self):
        """Ensure smt_enabled returns a boolean value."""
        enabled = smt_enabled()
        assert isinstance(enabled, bool)

    def test_z3_import_exposure(self):
        """Verify that z3 is either the module or None."""
        from core.smt_solver import z3
        if smt_enabled():
            assert z3 is not None
            # Basic check to confirm it's actually the Z3 library
            assert hasattr(z3, 'BitVec')
        else:
            # If disabled, z3 should be None or a non-functional stub
            assert z3 is None or not hasattr(z3, 'BitVec')
