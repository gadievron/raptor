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


class TestPhpSupport:
    def test_phpunit_class_convention(self, tmp_path):
        """tests/<Name>Test.php with camelCase test methods and
        $this->assert* assertions."""
        tests = tmp_path / "tests"
        tests.mkdir()
        (tests / "UserStoreTest.php").write_text(
            "<?php\n"
            "class UserStoreTest extends TestCase {\n"
            "    public function testFindUser(): void {\n"
            "        $store = new UserStore();\n"
            "        $user = $store->findUser(7);\n"
            "        $this->assertSame(7, $user['id']);\n"
            "    }\n"
            "}\n",
        )
        files, skipped = _find_test_files(tmp_path)
        assert len(files) == 1
        assert skipped == 0

        result = discover_tests(tmp_path)
        assert "findUser" in result
        tc = result["findUser"][0]
        assert tc.test_function == "testFindUser"
        assert any("assertSame" in a for a in tc.assertions)

    def test_suffix_convention_outside_test_dirs(self, tmp_path):
        """A *Test.php beside the source it tests (no tests/ dir) is
        still discovered via the file-name convention."""
        src = tmp_path / "src"
        src.mkdir()
        (src / "ValidatorTest.php").write_text(
            "<?php\n"
            "class ValidatorTest extends TestCase {\n"
            "    public function testSanitize(): void {\n"
            "        static::assertTrue(sanitize('<b>x</b>') === 'x');\n"
            "    }\n"
            "}\n",
        )
        result = discover_tests(tmp_path)
        assert "sanitize" in result
        assert any(
            "assertTrue" in a for a in result["sanitize"][0].assertions
        )

    def test_snake_case_function_and_bare_assert(self, tmp_path):
        tests = tmp_path / "tests"
        tests.mkdir()
        (tests / "helpers.php").write_text(
            "<?php\n"
            "function test_render_widget() {\n"
            "    $out = render_widget(['id' => 3]);\n"
            "    assert($out !== '');\n"
            "}\n",
        )
        result = discover_tests(tmp_path)
        assert "render_widget" in result
        assert any(
            "assert(" in a for a in result["render_widget"][0].assertions
        )

    def test_php_constructs_not_inferred_as_targets(self, tmp_path):
        tests = tmp_path / "tests"
        tests.mkdir()
        (tests / "EdgeTest.php").write_text(
            "<?php\n"
            "class EdgeTest extends TestCase {\n"
            "    public function testParseHeader(): void {\n"
            "        $h = parse_header($raw);\n"
            "        if (isset($h['len']) && !empty($h)) {\n"
            "            $n = count($h);\n"
            "        }\n"
            "        $this->assertGreaterThan(0, count($h));\n"
            "    }\n"
            "}\n",
        )
        result = discover_tests(tmp_path)
        assert "parse_header" in result
        for noise in ("isset", "empty", "count"):
            assert noise not in result

    def test_helper_named_tester_is_not_a_test(self, tmp_path):
        """Only test_ / test[A-Z] openers count — a lowercase
        continuation (tester, testify) is a helper, not a test."""
        tests = tmp_path / "tests"
        tests.mkdir()
        (tests / "MiscTest.php").write_text(
            "<?php\n"
            "function tester($x) {\n"
            "    return frobnicate($x);\n"
            "}\n",
        )
        result = discover_tests(tmp_path)
        assert result == {}

    def test_expectation_setup_not_a_target(self, tmp_path):
        tests = tmp_path / "tests"
        tests.mkdir()
        (tests / "FailTest.php").write_text(
            "<?php\n"
            "class FailTest extends TestCase {\n"
            "    public function testRejectsBadKey(): void {\n"
            "        $this->expectException(ValueError::class);\n"
            "        decode_key('bogus');\n"
            "    }\n"
            "}\n",
        )
        result = discover_tests(tmp_path)
        assert "decode_key" in result
        assert "expectException" not in result

    def test_php_files_not_counted_as_skipped(self, tmp_path):
        tests = _make_unsupported_suite(tmp_path, 2)
        (tests / "AlphaTest.php").write_text(
            "<?php\n"
            "class AlphaTest extends TestCase {\n"
            "    public function testAlpha(): void {\n"
            "        $this->assertSame(2, alpha(1));\n"
            "    }\n"
            "}\n",
        )
        files, skipped = _find_test_files(tmp_path)
        assert [f.name for f in files] == ["AlphaTest.php"]
        assert skipped == 2


class TestCamelAndNoiseAreSuffixScoped:
    """The PHPUnit camel opener and the PHP builtin stoplist apply to
    .php files only — other ecosystems use lowercase-test camel names
    for HELPERS (Go acceptance testAccCheck*, JS testSetup), and the
    PHP builtin names are legitimate project functions elsewhere."""

    def test_go_acceptance_helper_is_not_a_test(self, tmp_path):
        tests = tmp_path / "tests"
        tests.mkdir()
        (tests / "widget_test.go").write_text(
            "package widget\n"
            "\n"
            "func testAccCheckWidgetExists(n string) error {\n"
            "\treturn errors.New(n)\n"
            "}\n",
        )
        result = discover_tests(tmp_path)
        assert result == {}

    def test_python_project_count_function_kept(self, tmp_path):
        tests = tmp_path / "tests"
        tests.mkdir()
        (tests / "test_stats.py").write_text(
            "def test_totals():\n"
            "    assert count(items) == 3\n"
            "    assert sprintf(fmt, 1) == 'x'\n",
        )
        result = discover_tests(tmp_path)
        assert "count" in result
        assert "sprintf" in result

    def test_php_still_gets_camel_and_noise_scoping(self, tmp_path):
        tests = tmp_path / "tests"
        tests.mkdir()
        (tests / "SumTest.php").write_text(
            "<?php\n"
            "class SumTest extends TestCase {\n"
            "    public function testSumRows(): void {\n"
            "        $this->assertSame(3, sum_rows(count($rows)));\n"
            "    }\n"
            "}\n",
        )
        result = discover_tests(tmp_path)
        assert "sum_rows" in result
        assert "count" not in result


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


class TestTestDiscoveryPrepCache:
    """Resume wall cost: test discovery is a pure function of the
    test-tree files but re-ran the extraction/inference pass on every
    resumed audit segment. The prep cache reloads the mapping when the
    test-tree fingerprint matches and re-scans when it does not."""

    def _make_suite(self, tmp_path):
        target = tmp_path / "target"
        tests = target / "tests"
        tests.mkdir(parents=True)
        (tests / "test_mod.py").write_text(
            "def test_alpha():\n"
            "    r = alpha(1)\n"
            "    assert r == 2\n"
            "\n"
            "def test_beta_empty():\n"
            "    assert beta('') is None\n",
        )
        return target

    def test_second_run_reloads_and_skips_the_scan(
        self, tmp_path, monkeypatch,
    ):
        import core.analysis.test_discovery as td

        target = self._make_suite(tmp_path)
        out = tmp_path / "out"
        out.mkdir()
        first = td.discover_tests_cached(target, out)
        assert "alpha" in first
        assert (
            out / "prep-cache" / "test-discovery-cache.json"
        ).is_file()

        calls = []
        real = td.discover_tests

        def spy(*a, **kw):
            calls.append(1)
            return real(*a, **kw)

        monkeypatch.setattr(td, "discover_tests", spy)
        second = td.discover_tests_cached(target, out)
        assert calls == [], "cache hit must skip the extraction pass"
        assert set(second) == set(first)
        for fn, cases in first.items():
            assert [
                (c.test_file, c.test_function, c.target_function,
                 c.assertions)
                for c in cases
            ] == [
                (c.test_file, c.test_function, c.target_function,
                 c.assertions)
                for c in second[fn]
            ]

    def test_changed_test_tree_rebuilds(self, tmp_path, monkeypatch):
        import core.analysis.test_discovery as td

        target = self._make_suite(tmp_path)
        out = tmp_path / "out"
        out.mkdir()
        td.discover_tests_cached(target, out)

        calls = []
        real = td.discover_tests

        def spy(*a, **kw):
            calls.append(1)
            return real(*a, **kw)

        monkeypatch.setattr(td, "discover_tests", spy)
        (target / "tests" / "test_more.py").write_text(
            "def test_gamma():\n    assert gamma() == 3\n",
        )
        rebuilt = td.discover_tests_cached(target, out)
        assert calls == [1], "fingerprint mismatch must re-scan"
        assert "gamma" in rebuilt

    def test_corrupt_cache_rebuilds(self, tmp_path):
        import core.analysis.test_discovery as td

        target = self._make_suite(tmp_path)
        out = tmp_path / "out"
        (out / "prep-cache").mkdir(parents=True)
        (out / "prep-cache" / "test-discovery-cache.json").write_text(
            "{nope",
        )
        result = td.discover_tests_cached(target, out)
        assert "alpha" in result

    def test_no_out_dir_means_no_cache(self, tmp_path):
        import core.analysis.test_discovery as td

        target = self._make_suite(tmp_path)
        result = td.discover_tests_cached(target, None)
        assert "alpha" in result

    def test_empty_result_is_cached_too(self, tmp_path, monkeypatch):
        import core.analysis.test_discovery as td

        target = tmp_path / "target"
        (target / "tests").mkdir(parents=True)
        (target / "tests" / "test_x.sh").write_text("exit 0\n")
        out = tmp_path / "out"
        out.mkdir()
        assert td.discover_tests_cached(target, out) == {}

        calls = []
        real = td.discover_tests

        def spy(*a, **kw):
            calls.append(1)
            return real(*a, **kw)

        monkeypatch.setattr(td, "discover_tests", spy)
        assert td.discover_tests_cached(target, out) == {}
        assert calls == [], "an empty mapping is a valid cached result"

    def test_broken_shape_cache_rebuilds(self, tmp_path):
        import json as _json

        import core.analysis.test_discovery as td

        target = self._make_suite(tmp_path)
        out = tmp_path / "out"
        (out / "prep-cache").mkdir(parents=True)
        fp = td._test_tree_fingerprint(target.resolve())
        # json-valid, fingerprint-matching, but a shape the reload
        # chokes on — must degrade to the re-scan, not raise.
        (out / "prep-cache" / "test-discovery-cache.json").write_text(
            _json.dumps({
                "fingerprint": fp,
                "payload": {"alpha": [{"assertions": 42}]},
            }),
        )
        result = td.discover_tests_cached(target, out)
        assert "alpha" in result
        assert result["alpha"][0].assertions


class TestHostileTreeRobustness:
    def test_dangling_symlink_does_not_abort_discovery(self, tmp_path):
        """os.walk lists a dangling symlink as a file; the unguarded
        stat() used to raise OSError and abort the whole discovery
        pass — ALL test evidence for the target lost over one entry."""
        tests = tmp_path / "tests"
        tests.mkdir()
        (tests / "test_real.py").write_text(
            "def test_alpha():\n    assert alpha(1) == 2\n",
        )
        (tests / "test_dangling.py").symlink_to(tmp_path / "nowhere.py")
        files, _skipped = _find_test_files(tmp_path)
        assert [f.name for f in files] == ["test_real.py"]

    def test_vendored_trees_are_pruned_not_walked(self, tmp_path, monkeypatch):
        """node_modules/.git subtrees must be pruned in place — the
        old `continue` still descended them."""
        import os as _os

        deep = tmp_path / "node_modules" / "a" / "b" / "c"
        deep.mkdir(parents=True)
        (deep / "test_x.py").write_text("def test_x():\n    pass\n")
        visited = []
        real_walk = _os.walk

        def spy_walk(top, *a, **k):
            for root, dirs, files in real_walk(top, *a, **k):
                visited.append(root)
                yield root, dirs, files

        monkeypatch.setattr(_os, "walk", spy_walk)
        files, _ = _find_test_files(tmp_path)
        assert files == []
        assert not any("node_modules" in v and v != str(tmp_path)
                       for v in visited if "node_modules" in v.split(_os.sep)[1:])


class TestDirPatternBoundaries:
    def test_lookalike_dirs_are_not_test_trees(self):
        from core.analysis.test_discovery import _dir_matches_test_pattern
        for part in ("special", "testimonials", "spectrum",
                     "testament"):
            assert not _dir_matches_test_pattern(part), part

    def test_real_test_dirs_still_match(self):
        from core.analysis.test_discovery import _dir_matches_test_pattern
        for part in ("tests", "test", "testing", "test_unit",
                     "tests-integration", "spec", "specs", "regress"):
            assert _dir_matches_test_pattern(part), part
