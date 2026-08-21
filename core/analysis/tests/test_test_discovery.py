"""Tests for core.analysis.test_discovery.

Two receipt classes:

* Summary truthfulness (midpoint-audit receipt): on a target whose
  test tree is in an unsupported language the summary read ``found 0
  test cases for 0 functions in 7 files`` — the zero must be
  attributed to the language-support boundary, not look like a
  discovery bug.

* C/C++ support (openssh-audit receipt): discovery read only
  .py/.js/.ts/.go/.rs/.rb/.java, so openssh's 205-file ``regress/``
  tree was invisible. C test conventions (``regress/`` and ``tests/``
  dirs, ``test_*.c`` / ``*_test.c`` files, ``ASSERT_*``-style macros)
  are now first-class.
"""

from __future__ import annotations

import logging

from core.analysis.test_discovery import _find_test_files, discover_tests


def _make_unsupported_suite(tmp_path, n_files=5):
    """A test tree in a language discovery does not read (.sh)."""
    tests = tmp_path / "test"
    tests.mkdir()
    for i in range(n_files):
        (tests / f"test_area_{i}.sh").write_text(
            "#!/bin/sh\nexit 0\n",
        )
    return tests


class TestSkippedUnsupportedCounting:
    def test_unsupported_suite_counted_as_skipped(self, tmp_path):
        _make_unsupported_suite(tmp_path, 5)
        files, skipped = _find_test_files(tmp_path)
        assert files == []
        assert skipped == 5

    def test_supported_files_not_counted_as_skipped(self, tmp_path):
        tests = _make_unsupported_suite(tmp_path, 3)
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


class TestCFamilySupport:
    def test_regress_tree_is_a_test_dir(self, tmp_path):
        """openssh convention: regress/unittests/<area>/test_<area>.c."""
        suite = tmp_path / "regress" / "unittests" / "sshkey"
        suite.mkdir(parents=True)
        (suite / "test_sshkey.c").write_text(
            "static void\n"
            "test_sshkey_parse(void)\n"
            "{\n"
            "\tint r;\n"
            "\tr = sshkey_parse(blob, &key);\n"
            "\tASSERT_INT_EQ(r, 0);\n"
            "\tASSERT_PTR_NE(key, NULL);\n"
            "}\n",
        )
        files, skipped = _find_test_files(tmp_path)
        assert len(files) == 1
        assert skipped == 0

        result = discover_tests(tmp_path)
        assert "sshkey_parse" in result
        tc = result["sshkey_parse"][0]
        assert tc.test_function == "test_sshkey_parse"
        assert any("ASSERT_INT_EQ" in a for a in tc.assertions)

    def test_c_suffix_convention_and_libc_assert(self, tmp_path):
        """*_test.c files and bare assert() are read; the *_tests
        driver name maps via call references, not its own name."""
        tests = tmp_path / "tests"
        tests.mkdir()
        (tests / "kex_test.c").write_text(
            "void\n"
            "kex_tests(void)\n"
            "{\n"
            "\tstruct kex *k = kex_setup(fd);\n"
            "\tassert(k != NULL);\n"
            "}\n",
        )
        result = discover_tests(tmp_path)
        assert "kex_setup" in result
        # The driver's own name is not fabricated as a target.
        assert "kex_tests" not in result
        assert any(
            "assert(" in a for a in result["kex_setup"][0].assertions
        )

    def test_cpp_gtest_conventions(self, tmp_path):
        tests = tmp_path / "tests"
        tests.mkdir()
        (tests / "codec_test.cpp").write_text(
            "static bool test_decode_frame() {\n"
            "  auto out = decode_frame(buf);\n"
            "  EXPECT_EQ(out.size(), 4u);\n"
            "  return true;\n"
            "}\n",
        )
        result = discover_tests(tmp_path)
        assert "decode_frame" in result
        assert any(
            "EXPECT_EQ" in a for a in result["decode_frame"][0].assertions
        )

    def test_c_keywords_not_inferred_as_targets(self, tmp_path):
        tests = tmp_path / "tests"
        tests.mkdir()
        (tests / "test_buf.c").write_text(
            "static int test_buf_grow(void) {\n"
            "\tif (buf_grow(b, 16) != 0)\n"
            "\t\treturn 1;\n"
            "\tfor (i = 0; i < 4; i++)\n"
            "\t\tmemset(p, 0, sizeof(*p));\n"
            "\tassert(b->len == 16);\n"
            "\treturn 0;\n"
            "}\n",
        )
        result = discover_tests(tmp_path)
        assert "buf_grow" in result
        for noise in ("if", "for", "memset", "sizeof", "return"):
            assert noise not in result


class TestSummaryMessage:
    def test_zero_on_unsupported_suite_names_language_boundary(
        self, tmp_path, caplog,
    ):
        _make_unsupported_suite(tmp_path, 4)
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
        tests = _make_unsupported_suite(tmp_path, 2)
        (tests / "test_beta.py").write_text(
            "def test_beta():\n    assert beta(0) == 1\n",
        )
        with caplog.at_level(logging.INFO, "core.analysis.test_discovery"):
            result = discover_tests(tmp_path)
        assert "beta" in result
        assert "1 scanned test files" in caplog.text
        assert "2 test-tree files skipped" in caplog.text
