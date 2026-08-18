"""Tests for the shared security-fix commit-message classifier."""

from __future__ import annotations

import re

from core.git.security_fixes import (
    GREP_UNION,
    SECURITY_FIX_PATTERNS,
    classify,
    is_security_fix,
    match_categories,
)


class TestPatternData:
    def test_shape_is_regex_category_pairs(self):
        """The pattern set is data: (regex, category) string pairs that
        future consumers extend without forking the logic."""
        assert isinstance(SECURITY_FIX_PATTERNS, tuple)
        assert SECURITY_FIX_PATTERNS  # non-empty
        for entry in SECURITY_FIX_PATTERNS:
            assert isinstance(entry, tuple) and len(entry) == 2
            pattern, category = entry
            assert isinstance(pattern, str) and isinstance(category, str)
            re.compile(pattern, re.IGNORECASE)  # every regex compiles

    def test_categories_are_unique(self):
        cats = [c for _p, c in SECURITY_FIX_PATTERNS]
        assert len(cats) == len(set(cats))

    def test_grep_union_covers_every_pattern(self):
        """The union string drives `git log --grep -i -E` prefilters —
        a dropped alternative would silently hide commits from every
        consumer's subprocess-side pass."""
        for pattern, _category in SECURITY_FIX_PATTERNS:
            assert pattern in GREP_UNION
        assert GREP_UNION.count("|") >= len(SECURITY_FIX_PATTERNS) - 1


class TestIsSecurityFix:
    def test_positives(self):
        for msg in (
            "Fix buffer overflow in parser (CVE-2021-1234)",
            "sanitize input length to close a use-after-free window",
            "prevent SQL injection via prepared statements",
            "fix out-of-bounds read in decoder",
            "harden against double free",
            "Security: reject oversized frames",
            "fix TOCTOU in temp file handling",
            "guard against integer underflow",
            "fix null pointer dereference on error path",
            "initialize buffer to avoid uninitialised read",
            "add missing bounds check",
            "fix memory corruption in resize",
            "this bug is remotely exploitable",
            "patch vulnerability in session handling",
        ):
            assert is_security_fix(msg), msg

    def test_negatives(self):
        for msg in (
            "cleanup whitespace",
            "unrelated refactor",
            "bump version to 1.2.3",
            "add feature flag for dark mode",
            "",
        ):
            assert not is_security_fix(msg), msg

    def test_case_insensitive(self):
        assert is_security_fix("FIX BUFFER OVERFLOW")
        assert is_security_fix("Use After Free in x")


class TestClassify:
    def test_first_matching_category_in_declaration_order(self):
        # 'cve' is declared before 'overflow'; a message matching both
        # classifies as the earlier (more specific) category.
        assert classify("Fix overflow (CVE-2024-1)") == "cve"
        assert classify("fix heap overflow") == "overflow"

    def test_none_when_no_match(self):
        assert classify("cleanup whitespace") is None
        assert classify("") is None

    def test_category_values_come_from_the_data(self):
        cats = {c for _p, c in SECURITY_FIX_PATTERNS}
        assert classify("sanitize header length") in cats


class TestMatchCategories:
    def test_all_matches_in_declaration_order(self):
        got = match_categories(
            "Fix overflow (CVE-2024-1)\nbody mentions sanitize",
        )
        assert got == ("cve", "overflow", "sanitize")

    def test_empty_on_no_match(self):
        assert match_categories("unrelated refactor") == ()
        assert match_categories("") == ()

    def test_variant_spellings(self):
        assert "use_after_free" in match_categories("fix use-after-free")
        assert "use_after_free" in match_categories("Use after free in x")
        assert "sanitize" in match_categories("Sanitise input")
        assert "race_condition" in match_categories("fix race condition")
        assert "race_condition" in match_categories("TOCTOU window closed")


class TestOracleConsumesSharedData:
    def test_git_oracle_reexports_shared_patterns(self):
        """Dedup pin: the audit oracle's pattern set IS the shared one —
        no drift possible between the two."""
        from core.audit import git_oracle
        assert git_oracle.SECURITY_FIX_PATTERNS is SECURITY_FIX_PATTERNS
