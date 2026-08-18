"""Tests for core.analysis.test_discovery summary truthfulness.

The midpoint-audit receipt: on a C target with a very large native
test suite the summary read ``found 0 test cases for 0 functions in 7
files`` — the 7 were the only supported-language files in the test
tree, and the thousands of C test files were silently invisible. The
summary must attribute a zero to the language-support boundary.
"""

from __future__ import annotations

import logging

from core.analysis.test_discovery import _find_test_files, discover_tests


def _make_c_suite(tmp_path, n_c_files=5):
    tests = tmp_path / "test"
    tests.mkdir()
    for i in range(n_c_files):
        (tests / f"test_area_{i}.c").write_text(
            "static int test_main(void) { return 0; }\n",
        )
    return tests


class TestSkippedUnsupportedCounting:
    def test_c_suite_counted_as_skipped(self, tmp_path):
        _make_c_suite(tmp_path, 5)
        files, skipped = _find_test_files(tmp_path)
        assert files == []
        assert skipped == 5

    def test_supported_files_not_counted_as_skipped(self, tmp_path):
        tests = _make_c_suite(tmp_path, 3)
        (tests / "test_helper.py").write_text(
            "def test_alpha():\n    assert alpha(1) == 2\n",
        )
        files, skipped = _find_test_files(tmp_path)
        assert len(files) == 1
        assert skipped == 3

    def test_non_test_files_outside_test_dirs_ignored(self, tmp_path):
        (tmp_path / "impl.c").write_text("int impl(void) { return 0; }\n")
        files, skipped = _find_test_files(tmp_path)
        assert files == []
        assert skipped == 0


class TestSummaryMessage:
    def test_zero_on_native_suite_names_language_boundary(
        self, tmp_path, caplog,
    ):
        _make_c_suite(tmp_path, 4)
        with caplog.at_level(logging.INFO, "core.analysis.test_discovery"):
            result = discover_tests(tmp_path)
        assert result == {}
        text = caplog.text
        assert "4 test-tree files skipped" in text
        assert ".py" in text
        assert "found 0 test cases for 0 functions" not in text

    def test_zero_matches_in_supported_files_says_so(self, tmp_path, caplog):
        tests = tmp_path / "tests"
        tests.mkdir()
        (tests / "helper.py").write_text("x = 1\n")  # no test functions
        with caplog.at_level(logging.INFO, "core.analysis.test_discovery"):
            result = discover_tests(tmp_path)
        assert result == {}
        assert "no test cases matched" in caplog.text
        assert "1 scanned test files" in caplog.text

    def test_found_summary_reports_scanned_and_skipped(
        self, tmp_path, caplog,
    ):
        tests = _make_c_suite(tmp_path, 2)
        (tests / "test_beta.py").write_text(
            "def test_beta():\n    assert beta(0) == 1\n",
        )
        with caplog.at_level(logging.INFO, "core.analysis.test_discovery"):
            result = discover_tests(tmp_path)
        assert "beta" in result
        assert "1 scanned test files" in caplog.text
        assert "2 test-tree files skipped" in caplog.text
