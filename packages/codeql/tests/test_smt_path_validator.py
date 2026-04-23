"""Tests for packages.codeql.smt_path_validator."""

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# packages/codeql/tests/ -> repo root
sys.path.insert(0, str(Path(__file__).parents[3]))

from core.smt_solver import z3_available
from packages.codeql.smt_path_validator import (
    PathCondition,
    PathSMTResult,
    check_path_feasibility,
)

_requires_z3 = pytest.mark.skipif(
    not z3_available(),
    reason="z3-solver not installed",
)


# ---------------------------------------------------------------------------
# check_path_feasibility — no Z3
# ---------------------------------------------------------------------------

class TestNoZ3:
    """Behaviour when Z3 is unavailable — must degrade gracefully."""

    def test_returns_none_feasible(self):
        with patch("packages.codeql.smt_path_validator._z3_available", return_value=False):
            r = check_path_feasibility([PathCondition("size > 0", step_index=0)])
        assert r.feasible is None
        assert r.smt_available is False

    def test_all_conditions_go_to_unknown(self):
        conditions = [
            PathCondition("size > 0", step_index=0),
            PathCondition("offset < 1024", step_index=1),
        ]
        with patch("packages.codeql.smt_path_validator._z3_available", return_value=False):
            r = check_path_feasibility(conditions)
        assert set(r.unknown) == {"size > 0", "offset < 1024"}

    def test_empty_conditions_still_returns_none(self):
        with patch("packages.codeql.smt_path_validator._z3_available", return_value=False):
            r = check_path_feasibility([])
        assert r.feasible is None
        assert r.smt_available is False


# ---------------------------------------------------------------------------
# check_path_feasibility — with Z3
# ---------------------------------------------------------------------------

class TestFeasibility:
    """Core sat/unsat/unknown results."""

    @_requires_z3
    def test_empty_conditions_feasible(self):
        r = check_path_feasibility([])
        assert r.feasible is True
        assert r.smt_available is True

    @_requires_z3
    def test_satisfiable_range(self):
        """size > 0 AND size < 1024 — clearly satisfiable."""
        r = check_path_feasibility([
            PathCondition("size > 0", step_index=0),
            PathCondition("size < 1024", step_index=1),
        ])
        assert r.feasible is True
        assert "size" in r.model
        assert 0 < r.model["size"] < 1024

    @_requires_z3
    def test_infeasible_contradiction(self):
        """size > 0 AND size < 0 — mutually exclusive."""
        r = check_path_feasibility([
            PathCondition("size > 0", step_index=0),
            PathCondition("size < 0", step_index=1),
        ])
        assert r.feasible is False
        assert len(r.unsatisfied) >= 1

    @_requires_z3
    def test_infeasible_names_conflicting_conditions(self):
        """Unsat core must name the specific conflicting conditions."""
        r = check_path_feasibility([
            PathCondition("size > 100", step_index=0),
            PathCondition("size < 50", step_index=1),
        ])
        assert r.feasible is False
        assert "size > 100" in r.unsatisfied or "size < 50" in r.unsatisfied

    @_requires_z3
    def test_unparseable_condition_goes_to_unknown(self):
        """Function-call syntax is rejected by the parser — goes to unknown, not crash."""
        r = check_path_feasibility([
            PathCondition("size > 0", step_index=0),
            PathCondition("validate(ptr, len) == 0", step_index=1),
        ])
        assert "validate(ptr, len) == 0" in r.unknown
        # The parseable condition still runs; result is sat or None, not outright infeasible
        assert r.feasible is not False

    @_requires_z3
    def test_all_unknown_returns_none(self):
        """If nothing is parseable, feasible must be None (not True)."""
        r = check_path_feasibility([
            PathCondition("foo(bar) > baz(qux)", step_index=0),
        ])
        assert r.feasible is None

    @_requires_z3
    def test_negated_condition(self):
        """negated=True means the guard was bypassed (condition is false on path)."""
        # ptr != NULL with negated=True means ptr IS NULL on this path
        r = check_path_feasibility([
            PathCondition("ptr != NULL", step_index=0, negated=True),
        ])
        # ptr == NULL is satisfiable (ptr = 0)
        assert r.feasible is True

    @_requires_z3
    def test_negated_makes_path_infeasible(self):
        """ptr != NULL negated (ptr must be NULL) contradicts ptr > 0."""
        r = check_path_feasibility([
            PathCondition("ptr != NULL", step_index=0, negated=True),  # ptr == 0
            PathCondition("ptr > 0", step_index=1),                    # ptr > 0
        ])
        assert r.feasible is False


class TestConditionForms:
    """Parser coverage — each accepted condition form."""

    @_requires_z3
    def test_equality(self):
        r = check_path_feasibility([PathCondition("x == 42", step_index=0)])
        assert r.feasible is True
        assert r.model.get("x") == 42

    @_requires_z3
    def test_inequality(self):
        r = check_path_feasibility([PathCondition("x != 0", step_index=0)])
        assert r.feasible is True

    @_requires_z3
    def test_null_literal(self):
        r = check_path_feasibility([PathCondition("ptr == NULL", step_index=0)])
        assert r.feasible is True
        assert r.model.get("ptr") == 0

    @_requires_z3
    def test_hex_literal(self):
        r = check_path_feasibility([PathCondition("flags == 0xff", step_index=0)])
        assert r.feasible is True
        assert r.model.get("flags") == 0xFF

    @_requires_z3
    def test_addition_in_condition_sat(self):
        """offset + length <= buffer_size — guard holds when values fit."""
        r = check_path_feasibility([
            PathCondition("offset + length <= buffer_size", step_index=0),
            PathCondition("buffer_size == 64", step_index=1),
            PathCondition("offset > 0", step_index=2),
            PathCondition("length > 0", step_index=3),
        ])
        assert r.feasible is True
        assert r.model.get("buffer_size") == 64

    @_requires_z3
    def test_addition_overflow_path_is_sat(self):
        """Z3 correctly finds an integer overflow path when the guard can be bypassed
        via wraparound — this is the desired behaviour for CWE-190 detection.
        offset(60) + length(very large) overflows, satisfying <= buffer_size(64)."""
        r = check_path_feasibility([
            PathCondition("offset + length <= buffer_size", step_index=0),
            PathCondition("buffer_size == 64", step_index=1),
            PathCondition("offset == 60", step_index=2),
            PathCondition("length > 10", step_index=3),
        ])
        # sat — Z3 finds a wraparound value for length that bypasses the guard
        assert r.feasible is True
        assert r.smt_available is True

    @_requires_z3
    def test_bitmask_alignment(self):
        """rsp & 0xf == 0 — stack alignment check."""
        r = check_path_feasibility([
            PathCondition("rsp & 0xf == 0", step_index=0),
        ])
        assert r.feasible is True

    @_requires_z3
    def test_bitmask_infeasible(self):
        r = check_path_feasibility([
            PathCondition("flags & 0x1 == 0", step_index=0),
            PathCondition("flags & 0x1 == 1", step_index=1),
        ])
        assert r.feasible is False


class TestResultStructure:
    """PathSMTResult fields are populated correctly."""

    @_requires_z3
    def test_sat_result_has_empty_unsatisfied(self):
        r = check_path_feasibility([PathCondition("x > 0", step_index=0)])
        assert r.feasible is True
        assert r.unsatisfied == []
        assert r.smt_available is True

    @_requires_z3
    def test_unsat_result_has_empty_model(self):
        r = check_path_feasibility([
            PathCondition("x > 10", step_index=0),
            PathCondition("x < 5", step_index=1),
        ])
        assert r.feasible is False
        assert r.model == {}
        assert r.smt_available is True

    @_requires_z3
    def test_reasoning_string_populated(self):
        r = check_path_feasibility([PathCondition("x == 1", step_index=0)])
        assert isinstance(r.reasoning, str)
        assert len(r.reasoning) > 0
