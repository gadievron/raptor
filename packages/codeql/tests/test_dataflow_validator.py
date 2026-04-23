"""Tests for packages.codeql.dataflow_validator.

Scoped to the pure helpers — profile inference, hint normalisation —
not to the LLM-driven ``validate_dataflow_path`` flow (which needs a
mock LLM client and is exercised end-to-end elsewhere).
"""

import sys
from pathlib import Path

import pytest

# packages/codeql/tests/ -> repo root
sys.path.insert(0, str(Path(__file__).parents[3]))

from packages.codeql.dataflow_validator import _infer_bv_profile


class TestInferBVProfileHeuristic:
    """When the LLM hint is absent the rule_id heuristic picks a profile.

    CodeQL rule names that mention overflow / wraparound / CWE-190 family
    get 32-bit unsigned; everything else defaults to 64-bit unsigned."""

    def test_non_overflow_rule_defaults_to_64_bit(self):
        p = _infer_bv_profile("java/sql-injection", {})
        assert p.width == 64
        assert p.signed is False

    def test_no_rule_id_defaults_to_64_bit(self):
        p = _infer_bv_profile(None, {})
        assert p.width == 64

    def test_empty_rule_id_defaults_to_64_bit(self):
        p = _infer_bv_profile("", {})
        assert p.width == 64

    @pytest.mark.parametrize("rule_id", [
        "cpp/cwe-190-integer-overflow",
        "CPP/CWE-190/ArithmeticOverflow",
        "cpp/overflow-check-missing",
        "cpp/integer-overflow",
        "java/IntegerOverflow",
        "cpp/integeroverflow-in-loop",
        "cpp/unsigned-wraparound",
        "cpp/wrap-around-bug",
        "cpp/CWE-191-underflow",
        "cpp/CWE-680-int-to-buf",
    ])
    def test_overflow_markers_trigger_32_bit(self, rule_id):
        p = _infer_bv_profile(rule_id, {})
        assert p.width == 32
        assert p.signed is False

    def test_matching_is_case_insensitive(self):
        p = _infer_bv_profile("CPP/Cwe-190-overflow", {})
        assert p.width == 32


class TestInferBVProfileHint:
    """LLM-emitted hints take precedence over the heuristic when valid."""

    def test_hint_width_only_combines_with_heuristic_signed(self):
        # LLM says width=32; rule isn't overflow, so heuristic signed=False.
        p = _infer_bv_profile("java/sql-injection", {"width": 32})
        assert p.width == 32
        assert p.signed is False

    def test_hint_signed_only_combines_with_heuristic_width(self):
        p = _infer_bv_profile("cpp/overflow-bug", {"signed": True})
        assert p.width == 32   # from heuristic (overflow rule)
        assert p.signed is True  # from hint

    def test_hint_beats_heuristic_when_both_supplied(self):
        # LLM says 64-bit signed even though rule would default to 32-bit unsigned.
        p = _infer_bv_profile("cpp/overflow-bug", {"width": 64, "signed": True})
        assert p.width == 64
        assert p.signed is True


class TestInferBVProfileInvalidHints:
    """Garbage values in the hint dict must be ignored, not crash."""

    def test_string_width_ignored(self):
        p = _infer_bv_profile("cpp/overflow-bug", {"width": "not-an-int"})
        assert p.width == 32  # heuristic fallback, not ValueError

    def test_negative_width_ignored(self):
        p = _infer_bv_profile("cpp/overflow-bug", {"width": -1})
        assert p.width == 32

    def test_zero_width_ignored(self):
        p = _infer_bv_profile("cpp/overflow-bug", {"width": 0})
        assert p.width == 32

    def test_string_signed_ignored(self):
        p = _infer_bv_profile("cpp/overflow-bug", {"signed": "yes"})
        assert p.signed is False

    def test_none_values_ignored(self):
        p = _infer_bv_profile("cpp/overflow-bug", {"width": None, "signed": None})
        assert p.width == 32

    def test_missing_keys_tolerated(self):
        p = _infer_bv_profile("cpp/overflow-bug", {})
        assert p.width == 32
