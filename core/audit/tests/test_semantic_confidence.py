"""Tests for core.audit.semantic_confidence."""

from __future__ import annotations

from core.audit.semantic_confidence import (
    classify_semantic_confidence,
    source_confirms_correction,
)


class TestClassifySemanticConfidence:

    def test_uses_instead_of_pattern(self):
        hyp = "line 10 uses `=` instead of `==` in a conditional"
        src = "if (uid = 0) {\n    grant_access();\n}\n"
        assert classify_semantic_confidence(hyp, src, line_start=9) == "high"

    def test_should_be_pattern(self):
        hyp = "`<` should be `<=` at line 5"
        src = "x = 0\nfor i in range(n):\n    if a < b:\n        x += 1\nif x < n:\n    fail()\n"
        assert classify_semantic_confidence(hyp, src, line_start=1) == "high"

    def test_should_use_instead_of_pattern(self):
        hyp = "should use `>=` instead of `>` on line 3"
        src = "int check(int x) {\n    if (x > 0)\n        return 1;\n    return 0;\n}\n"
        assert classify_semantic_confidence(hyp, src, line_start=1) == "high"

    def test_wrong_value_not_in_source(self):
        hyp = "line 10 uses `=` instead of `==`"
        src = "if (uid == 0) {\n    grant_access();\n}\n"
        assert classify_semantic_confidence(hyp, src, line_start=9) == "low"

    def test_no_correction_pattern(self):
        hyp = "buffer overflow when copying user data"
        src = "memcpy(dst, src, len);\n"
        assert classify_semantic_confidence(hyp, src) == "low"

    def test_empty_hypothesis(self):
        assert classify_semantic_confidence("", "x = 1\n") == "low"

    def test_empty_source(self):
        hyp = "uses `=` instead of `==`"
        assert classify_semantic_confidence(hyp, "") == "low"

    def test_line_reference_with_offset(self):
        hyp = "line 105 uses `*` instead of `**`"
        src = "def f():\n    return x * y\n"
        assert classify_semantic_confidence(hyp, src, line_start=104) == "high"

    def test_line_reference_out_of_window(self):
        hyp = "line 500 uses `=` instead of `==`"
        src = "if (x = 0) {\n}\n"
        assert classify_semantic_confidence(hyp, src, line_start=1) == "low"

    def test_no_line_reference_searches_all(self):
        hyp = "uses `=` instead of `==` in the conditional"
        src = "int f(int x) {\n    if (x = 0)\n        return 1;\n    return 0;\n}\n"
        assert classify_semantic_confidence(hyp, src) == "high"

    def test_same_wrong_and_correct_value(self):
        hyp = "`==` should be `==`"
        src = "if (x == 0) {}\n"
        assert classify_semantic_confidence(hyp, src) == "low"

    def test_double_quote_delimiters(self):
        hyp = 'uses "=" instead of "=="'
        src = "if (x = 0) {}\n"
        assert classify_semantic_confidence(hyp, src) == "high"

    def test_single_quote_delimiters(self):
        hyp = "uses '=' instead of '=='"
        src = "if (x = 0) {}\n"
        assert classify_semantic_confidence(hyp, src) == "high"

    def test_must_be_variant(self):
        hyp = "`&` must be `&&` at line 3"
        src = "int f() {\n    int x = 1;\n    if (a & b)\n        return 0;\n}\n"
        assert classify_semantic_confidence(hyp, src, line_start=1) == "high"

    def test_needs_to_be_variant(self):
        hyp = "`||` needs to be `&&`"
        src = "if (a || b) { return; }\n"
        assert classify_semantic_confidence(hyp, src) == "high"

    def test_case_insensitive(self):
        hyp = "Uses `=` Instead Of `==`"
        src = "if (x = 0) {}\n"
        assert classify_semantic_confidence(hyp, src) == "high"

    def test_multi_word_value_in_backticks(self):
        hyp = "uses `unsigned int` instead of `size_t`"
        src = "unsigned int len = get_length();\n"
        assert classify_semantic_confidence(hyp, src) == "high"

    def test_rather_than_variant(self):
        hyp = "uses `=` rather than `==`"
        src = "if (x = 0) {}\n"
        assert classify_semantic_confidence(hyp, src) == "high"

    def test_window_around_claimed_line(self):
        hyp = "line 12 uses `=` instead of `==`"
        lines = ["// line %d\n" % i for i in range(1, 20)]
        lines[10] = "if (x = 0)\n"  # line 11 in 1-indexed, 2 lines before claimed
        src = "".join(lines)
        assert classify_semantic_confidence(hyp, src, line_start=1) == "high"


class TestSourceConfirmsCorrection:

    def test_returns_details_on_high(self):
        hyp = "line 5 uses `=` instead of `==`"
        src = "int f() {\n    int x;\n    int y;\n    if (x = 0)\n        return;\n}\n"
        result = source_confirms_correction(hyp, src, line_start=1)
        assert result is not None
        assert result["wrong_value"] == "="
        assert result["correct_value"] == "=="
        assert result["claimed_line"] == 5

    def test_returns_none_on_low(self):
        hyp = "buffer overflow possible"
        src = "memcpy(dst, src, n);\n"
        assert source_confirms_correction(hyp, src) is None

    def test_returns_none_when_source_disagrees(self):
        hyp = "line 1 uses `=` instead of `==`"
        src = "if (x == 0) {}\n"
        assert source_confirms_correction(hyp, src, line_start=1) is None

    def test_no_line_ref_returns_none_for_claimed_line(self):
        hyp = "uses `=` instead of `==`"
        src = "if (x = 0) {}\n"
        result = source_confirms_correction(hyp, src)
        assert result is not None
        assert result["claimed_line"] is None
