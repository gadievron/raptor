"""Tests for the shared cost sanitiser."""

from __future__ import annotations

import math

import pytest

from core.llm.cost import sanitize_cost, sanitize_iterations


class TestSanitizeCost:
    @pytest.mark.parametrize("raw,expected", [
        (0.05, 0.05),
        (0, 0.0),
        (5.0, 5.0),
        (1_000_000.0, 1_000_000.0),
    ])
    def test_normal_values_passthrough(self, raw, expected):
        assert sanitize_cost(raw) == expected

    @pytest.mark.parametrize("raw", [
        None,
        "0.05",       # string not parsed — silent stringification is
                      # exactly how NaN got into records historically.
        [0.05],
        {"cost": 0.05},
    ])
    def test_non_numeric_zeros(self, raw):
        assert sanitize_cost(raw) == 0.0

    def test_nan_zeros(self):
        assert sanitize_cost(float("nan")) == 0.0

    def test_positive_inf_zeros(self):
        assert sanitize_cost(float("inf")) == 0.0

    def test_negative_inf_zeros(self):
        assert sanitize_cost(float("-inf")) == 0.0

    def test_negative_zeros(self):
        assert sanitize_cost(-0.5) == 0.0

    def test_bool_zeros(self):
        """``bool`` is an int subclass; ``True`` would coerce to 1.0
        without the guard. A cost field with True is a caller bug —
        surface as 0.0 rather than absorb the value."""
        assert sanitize_cost(True) == 0.0
        assert sanitize_cost(False) == 0.0

    def test_int_returns_float(self):
        got = sanitize_cost(5)
        assert isinstance(got, float)
        assert got == 5.0

    def test_return_type_is_always_finite_float(self):
        for raw in (0.0, 5.0, float("nan"), float("inf"), None, "x"):
            got = sanitize_cost(raw)
            assert isinstance(got, float)
            assert math.isfinite(got)
            assert got >= 0


class TestSanitizeIterations:
    @pytest.mark.parametrize("raw,expected", [
        (0, 0),
        (1, 1),
        (100, 100),
    ])
    def test_normal_values(self, raw, expected):
        assert sanitize_iterations(raw) == expected

    def test_negative_clamps_to_zero(self):
        assert sanitize_iterations(-1) == 0

    def test_none_zeros(self):
        assert sanitize_iterations(None) == 0

    def test_float_zeros(self):
        assert sanitize_iterations(1.5) == 0

    def test_bool_zeros(self):
        assert sanitize_iterations(True) == 0
        assert sanitize_iterations(False) == 0
