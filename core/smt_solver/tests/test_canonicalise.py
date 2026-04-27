"""Tests for core.smt_solver.canonicalise — english→symbolic rewrites."""

import sys
from pathlib import Path

# core/smt_solver/tests/ -> repo root
sys.path.insert(0, str(Path(__file__).parents[3]))

from core.smt_solver import canonicalise


class TestRelationalRewrites:
    """English relational phrases map to their symbolic counterparts."""

    def test_is_greater_than(self):
        assert canonicalise("size is greater than 0") == "size > 0"

    def test_is_less_than(self):
        assert canonicalise("size is less than 1024") == "size < 1024"

    def test_is_greater_than_or_equal_to(self):
        # The longer phrase wins over the prefix "is greater than".
        assert canonicalise("len is greater than or equal to 8") == "len >= 8"

    def test_is_less_than_or_equal_to(self):
        assert canonicalise("len is less than or equal to 64") == "len <= 64"

    def test_is_at_least(self):
        assert canonicalise("count is at least 16") == "count >= 16"

    def test_is_at_most(self):
        assert canonicalise("count is at most 32") == "count <= 32"


class TestEqualityRewrites:
    """Equality-style phrases map to == / !=."""

    def test_equals(self):
        assert canonicalise("x equals y") == "x == y"

    def test_is_equal_to(self):
        assert canonicalise("x is equal to y") == "x == y"

    def test_is_not_equal_to(self):
        assert canonicalise("x is not equal to y") == "x != y"

    def test_does_not_equal(self):
        assert canonicalise("x does not equal y") == "x != y"


class TestNonZeroNonNull:
    """'is non-zero' / 'is non-null' specialise to '!= 0' / '!= NULL'."""

    def test_is_nonzero_hyphen(self):
        assert canonicalise("count is non-zero") == "count != 0"

    def test_is_nonzero_space(self):
        assert canonicalise("count is non zero") == "count != 0"

    def test_is_nonzero_compound(self):
        # "nonzero" without separator
        assert canonicalise("count is nonzero") == "count != 0"

    def test_is_nonnull_hyphen(self):
        assert canonicalise("ptr is non-null") == "ptr != NULL"

    def test_is_nonnull_compound(self):
        assert canonicalise("ptr is nonnull") == "ptr != NULL"


class TestPositiveZeroNullForms:
    """``is null`` / ``is zero`` close the asymmetry with the negated forms."""

    def test_is_null(self):
        assert canonicalise("ptr is null") == "ptr == NULL"

    def test_is_null_does_not_clash_with_is_non_null(self):
        # The negated form must win; the positive ``is null`` rewrite
        # must not trip on the residual ``null`` left behind.
        assert canonicalise("ptr is non-null") == "ptr != NULL"

    def test_is_zero(self):
        assert canonicalise("count is zero") == "count == 0"

    def test_is_zero_does_not_clash_with_is_non_zero(self):
        assert canonicalise("count is non-zero") == "count != 0"


class TestSynonyms:
    """Single-word and short synonyms covering common LLM phrasings."""

    def test_exceeds(self):
        assert canonicalise("count exceeds 100") == "count > 100"

    def test_below(self):
        assert canonicalise("index below limit") == "index < limit"

    def test_does_not_exceed(self):
        # The longer ``does not exceed`` must win over the bare ``exceeds``.
        assert canonicalise("len does not exceed buffer") == "len <= buffer"

    def test_does_not_exceed_does_not_leak_to_exceeds(self):
        # If ordering broke, ``does not exceed`` would become ``does not >``
        # then collapse to ``does not >`` — assert the full sentence resolves.
        out = canonicalise("len does not exceed buffer_size")
        assert out == "len <= buffer_size"

    def test_up_to_inclusive(self):
        # Documented choice: ``up to N`` means ``<= N`` (inclusive).
        assert canonicalise("count up to 16") == "count <= 16"


class TestIdempotenceAndIdentifierSafety:
    """Symbolic input passes through unchanged; identifiers aren't mangled."""

    def test_already_symbolic(self):
        assert canonicalise("size > 0") == "size > 0"

    def test_idempotent(self):
        once = canonicalise("count is at least 1")
        twice = canonicalise(once)
        assert once == twice == "count >= 1"

    def test_word_boundary_protects_identifiers(self):
        # 'equalsValue' must NOT become '==Value'.
        assert canonicalise("equalsValue == 1") == "equalsValue == 1"

    def test_word_boundary_inside_underscore(self):
        # 'is_greater_than_zero' is an identifier, not the english phrase.
        # The pattern uses \s+ between words so underscore-separated
        # identifier names are not rewritten.
        assert canonicalise("is_greater_than_zero == 1") == "is_greater_than_zero == 1"

    def test_case_insensitive(self):
        assert canonicalise("SIZE Is Greater Than 0") == "SIZE > 0"

    def test_whitespace_collapsed(self):
        # Multiple spaces around english phrases collapse to single spaces.
        assert canonicalise("size   is   greater   than   0") == "size > 0"


class TestCanonicalisedFeedsParser:
    """Smoke-test that canonicalised output is parseable by the path validator."""

    def test_path_validator_accepts_english_form(self):
        # If z3 isn't installed, the validator returns feasible=None with
        # the input in `unknown` — but the parser still runs over the
        # canonicalised text, so a clean parse means `unknown` stays empty.
        from core.smt_solver import z3_available
        if not z3_available():
            return  # parser exercised regardless, but feasibility undefined
        from packages.codeql.smt_path_validator import (
            PathCondition, check_path_feasibility,
        )
        result = check_path_feasibility([
            PathCondition(text="size is greater than 0", step_index=0),
            PathCondition(text="size is less than 1024", step_index=1),
        ])
        assert result.unknown == []
        assert result.feasible is True

    def test_one_gadget_accepts_english_form(self):
        from core.smt_solver import z3_available
        if not z3_available():
            return
        from packages.exploit_feasibility.smt_onegadget import check_onegadget
        from packages.exploit_feasibility.context import OneGadget
        gadget = OneGadget(
            offset=0x1234,
            constraints=["rax equals 0", "rbx is not equal to 0"],
        )
        result = check_onegadget(gadget)
        assert result.unknown == []
        assert result.feasible is True
