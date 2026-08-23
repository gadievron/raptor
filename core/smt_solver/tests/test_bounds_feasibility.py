"""Tests for core.smt_solver.bounds_feasibility."""

from __future__ import annotations

import sys
import time
from pathlib import Path
from unittest.mock import patch

import pytest

# core/smt_solver/tests/ → repo root
sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from core.smt_solver.bounds_feasibility import (
    _BOUNDS_CONDITION_RE,
    check_bounds_infeasible,
)

# Generous wall-clock budget: the current pattern finishes in well under
# 10ms on every adversarial input below; the previous pattern (three
# sequential [^)]* segments) backtracked super-linearly (cubic) and
# needed ~27s on the 8KB case.
_TIME_BUDGET_S = 2.0


def _assert_scans_fast(source: str) -> None:
    start = time.perf_counter()
    matches = list(_BOUNDS_CONDITION_RE.finditer(source))
    elapsed = time.perf_counter() - start
    assert elapsed < _TIME_BUDGET_S, f"regex took {elapsed:.2f}s on {len(source)}B input"
    assert matches == []


class TestBoundsConditionRegex:
    def test_matches_len_guard(self):
        m = _BOUNDS_CONDITION_RE.search("if (len >= MAX_LEN) return -1;")
        assert m is not None
        assert m.group(1).strip() == "len >= MAX_LEN"

    def test_matches_size_comparison(self):
        m = _BOUNDS_CONDITION_RE.search("if (input_size > MAX_SIZE) return -1;")
        assert m is not None
        assert m.group(1).strip() == "input_size > MAX_SIZE"

    def test_matches_without_space_after_if(self):
        m = _BOUNDS_CONDITION_RE.search("if(count!=0) {}")
        assert m is not None
        assert m.group(1).strip() == "count!=0"

    def test_matches_case_insensitively(self):
        m = _BOUNDS_CONDITION_RE.search("if (LEN > Max) x;")
        assert m is not None
        assert m.group(1).strip() == "LEN > Max"

    def test_sizeof_capture_cut_at_first_close_paren(self):
        # Pre-existing behaviour: the capture stops at the first ')'.
        m = _BOUNDS_CONDITION_RE.search("if (len >= sizeof(buf)) return -1;")
        assert m is not None
        assert m.group(1).strip() == "len >= sizeof(buf"

    def test_no_match_on_unrelated_if(self):
        assert _BOUNDS_CONDITION_RE.search("if (x > 0) return x;") is None

    def test_no_match_on_keyword_without_comparator(self):
        assert _BOUNDS_CONDITION_RE.search("if (size) {}") is None

    def test_no_match_on_while_guard(self):
        assert _BOUNDS_CONDITION_RE.search("while (len < max) {}") is None

    def test_finds_all_conditions_across_source(self):
        src = "if (a && b) {}\nif (len < n) {}\nif (count >= LIMIT) {}\n"
        found = [m.group(1).strip() for m in _BOUNDS_CONDITION_RE.finditer(src)]
        assert found == ["len < n", "count >= LIMIT"]


class TestBoundsConditionRegexLinear:
    """The pattern must stay linear on unclosed-paren adversarial input."""

    def test_unclosed_paren_repeating_keyword_comparator(self):
        # Empirical worst case: 8KB of 'len< ' after an unclosed 'if ('.
        _assert_scans_fast("if (" + "len< " * 1600)

    def test_unclosed_paren_repeating_keyword_only(self):
        _assert_scans_fast("if (" + "len " * 2000)

    def test_many_unclosed_ifs(self):
        _assert_scans_fast("if (len< " * 3200)

    def test_whitespace_flood_before_keyword(self):
        _assert_scans_fast("if (" + " " * 8000 + "len<")

    def test_comparator_run_flood(self):
        _assert_scans_fast("if (len" + "<" * 8000)


class TestCheckBoundsInfeasible:
    def test_non_overflow_cwe_returns_none(self):
        assert check_bounds_infeasible("if (len > size) return;", "CWE-79") is None

    def test_no_conditions_returns_none(self):
        assert check_bounds_infeasible("return 0;", "CWE-120") is None

    def test_single_satisfiable_guard_is_not_infeasible(self):
        pytest.importorskip("z3")
        src = "if (len >= MAX_LEN) return -1;"
        assert check_bounds_infeasible(src, "CWE-122") is False

    def test_import_error_returns_none(self):
        # The solver module failing to import must read as
        # inconclusive — never as a feasibility verdict.
        with patch.dict(
            sys.modules, {"core.smt_solver.path_feasibility": None},
        ):
            src = "if (len >= MAX_LEN) return -1;"
            assert check_bounds_infeasible(src, "CWE-120") is None

    def test_pathological_source_returns_none_quickly(self):
        source = "if (" + "len< " * 1600
        start = time.perf_counter()
        result = check_bounds_infeasible(source, "CWE-120")
        elapsed = time.perf_counter() - start
        assert result is None
        assert elapsed < _TIME_BUDGET_S

    def test_refuses_to_conjoin_distinct_guards(self):
        """Multiple DISTINCT guards carry no path structure — they may
        sit on mutually exclusive branches, where the conjunction is
        UNSAT by construction. The checker must answer inconclusive,
        never mint an "overflow provably impossible" receipt."""
        pytest.importorskip("z3")
        # The standard C size-dispatch idiom: the overflow lives in
        # the else-if branch; conjoining the two guards is UNSAT.
        dispatch = (
            "void f(char *s, size_t len) {\n"
            "    char buf[16];\n"
            "    if (len < 16) { small(); }\n"
            "    else if (len >= 16) { memcpy(buf, s, len); }\n"
            "}\n"
        )
        assert check_bounds_infeasible(dispatch, "CWE-121") is None
        # Disjoint sequential early-return guards — same class.
        disjoint = (
            "void f(char *s, size_t size) {\n"
            "    char buf[8];\n"
            "    if (size == 0) return;\n"
            "    if (size != 0) { memcpy(buf, s, size); }\n"
            "}\n"
        )
        assert check_bounds_infeasible(disjoint, "CWE-121") is None

    def test_repeated_identical_guard_still_evaluates(self):
        # The same guard text twice is an idempotent conjunct, not a
        # distinct guard — it keeps the single-guard evaluation.
        pytest.importorskip("z3")
        src = (
            "if (len >= MAX_LEN) return -1;\n"
            "if (len >= MAX_LEN) abort();\n"
        )
        assert check_bounds_infeasible(src, "CWE-120") is False

    def test_single_contradictory_guard_reads_infeasible(self):
        # The retained single-guard lane: one guard whose truth is
        # unsatisfiable.
        pytest.importorskip("z3")
        src = "if (len < 4 && len > 8) { memcpy(buf, s, len); }"
        result = check_bounds_infeasible(src, "CWE-120")
        # ``&&`` conjunction support depends on the condition parser;
        # accept the honest None, forbid the unsound False→True flip
        # only when the parser understood the guard.
        assert result in (True, None)

    def test_extracted_condition_reaches_solver_stripped(self):
        captured = {}

        def fake_check(conditions, timeout_ms):
            captured["texts"] = [c.text for c in conditions]

            class _Result:
                feasible = False

            return _Result()

        with patch(
            "core.smt_solver.path_feasibility.check_path_feasibility",
            side_effect=fake_check,
        ):
            result = check_bounds_infeasible(
                "if (len >= MAX_LEN) return -1;", "CWE-122"
            )
        assert result is True
        assert captured["texts"] == ["len >= MAX_LEN"]
