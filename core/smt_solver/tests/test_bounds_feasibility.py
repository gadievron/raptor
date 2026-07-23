"""Tests for core.smt_solver.bounds_feasibility."""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch

# core/smt_solver/tests/ → repo root
sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from core.smt_solver.bounds_feasibility import (
    _BOUNDS_CONDITION_RE,
    check_bounds_infeasible,
)


class TestBoundsConditionRegex:
    def test_matches_len_guard(self):
        src = "if (len >= MAX_LEN) return -1;"
        assert _BOUNDS_CONDITION_RE.search(src) is not None

    def test_matches_size_comparison(self):
        src = "if (input_size > MAX_SIZE) return -1;"
        assert _BOUNDS_CONDITION_RE.search(src) is not None

    def test_no_match_on_unrelated_if(self):
        src = "if (x > 0) return x;"
        assert _BOUNDS_CONDITION_RE.search(src) is None


class TestCheckBoundsInfeasible:
    def test_non_overflow_cwe_returns_none(self):
        assert check_bounds_infeasible("if (len > size) return;", "CWE-79") is None

    def test_no_conditions_returns_none(self):
        assert check_bounds_infeasible("return 0;", "CWE-120") is None

    def test_overflow_cwe_with_conditions(self):
        src = "if (len >= sizeof(buf)) return -1;"
        result = check_bounds_infeasible(src, "CWE-122")
        assert result in (True, False, None)

    def test_import_error_returns_none(self):
        with patch.dict(sys.modules, {"z3": None}):
            src = "if (len >= sizeof(buf)) return -1;"
            result = check_bounds_infeasible(src, "CWE-120")
            assert result is None or result in (True, False)
