"""Tests for core.audit.test_discovery."""

from __future__ import annotations

from core.analysis.test_discovery import (
    TestCase,
    _extract_assertions,
    _extract_test_functions,
    _find_test_files,
    _infer_target_functions,
    discover_tests,
    format_tests_for_context,
)


class TestDiscoverTests:
    def test_empty_dir(self, tmp_path):
        result = discover_tests(tmp_path)
        assert result == {}

    def test_nonexistent_dir(self, tmp_path):
        result = discover_tests(tmp_path / "nope")
        assert result == {}

    def test_finds_test_by_naming_convention(self, tmp_path):
        test_dir = tmp_path / "tests"
        test_dir.mkdir()
        (test_dir / "test_auth.py").write_text(
            "def test_validate_token():\n"
            "    result = validate_token('abc')\n"
            "    assert result is True\n"
        )
        result = discover_tests(tmp_path)
        assert "validate_token" in result
        assert result["validate_token"][0].test_function == "test_validate_token"

    def test_finds_assertions(self, tmp_path):
        test_dir = tmp_path / "tests"
        test_dir.mkdir()
        (test_dir / "test_parser.py").write_text(
            "def test_parse_header():\n"
            "    h = parse_header(raw)\n"
            "    assert h.status == 200\n"
            "    assert h.body is not None\n"
        )
        result = discover_tests(tmp_path)
        assert "parse_header" in result
        tc = result["parse_header"][0]
        assert len(tc.assertions) >= 2

    def test_skips_hidden_dirs(self, tmp_path):
        hidden = tmp_path / ".hidden" / "tests"
        hidden.mkdir(parents=True)
        (hidden / "test_x.py").write_text("def test_x():\n    assert True\n")
        result = discover_tests(tmp_path)
        assert result == {}

    def test_skips_node_modules(self, tmp_path):
        nm = tmp_path / "node_modules" / "tests"
        nm.mkdir(parents=True)
        (nm / "test_x.py").write_text("def test_x():\n    assert True\n")
        result = discover_tests(tmp_path)
        assert result == {}


class TestFindTestFiles:
    def test_finds_files_in_test_dir(self, tmp_path):
        td = tmp_path / "test"
        td.mkdir()
        (td / "test_foo.py").write_text("pass")
        (td / "helper.py").write_text("pass")
        files, skipped = _find_test_files(tmp_path)
        names = [f.name for f in files]
        assert "test_foo.py" in names
        assert "helper.py" in names
        assert skipped == 0

    def test_finds_test_file_pattern(self, tmp_path):
        (tmp_path / "test_bar.py").write_text("pass")
        files, _skipped = _find_test_files(tmp_path)
        assert any(f.name == "test_bar.py" for f in files)

    def test_respects_extension_filter(self, tmp_path):
        td = tmp_path / "tests"
        td.mkdir()
        (td / "test_x.txt").write_text("pass")
        files, skipped = _find_test_files(tmp_path)
        assert not any(f.name == "test_x.txt" for f in files)
        # the unsupported-language file is counted, not silently lost
        assert skipped == 1


class TestExtractTestFunctions:
    def test_basic_extraction(self):
        source = (
            "def test_foo():\n"
            "    assert True\n"
            "\n"
            "def test_bar():\n"
            "    x = bar()\n"
            "    assert x == 1\n"
        )
        funcs = _extract_test_functions(source)
        names = [n for n, _ in funcs]
        assert "test_foo" in names
        assert "test_bar" in names

    def test_no_test_functions(self):
        source = "def helper():\n    pass\n"
        assert _extract_test_functions(source) == []


class TestInferTargetFunctions:
    def test_naming_convention(self):
        targets = _infer_target_functions(
            "test_validate_input", "validate_input('x')",
        )
        assert "validate_input" in targets

    def test_strips_suffix(self):
        targets = _infer_target_functions(
            "test_parse_header_error", "parse_header(bad)",
        )
        assert "parse_header" in targets

    def test_call_references(self):
        targets = _infer_target_functions(
            "test_something", "result = process_data(buf)\nassert result",
        )
        assert "process_data" in targets

    def test_filters_builtins(self):
        targets = _infer_target_functions(
            "test_something",
            "x = len(list(range(10)))\nassert isinstance(x, int)",
        )
        for builtin in ("len", "list", "range", "isinstance", "int"):
            assert builtin not in targets


class TestExtractAssertions:
    def test_python_asserts(self):
        body = (
            "def test_foo():\n"
            "    assert x == 1\n"
            "    assert y is not None\n"
        )
        assertions = _extract_assertions(body)
        assert len(assertions) == 2

    def test_limits_count(self):
        lines = "\n".join(f"    assert x == {i}" for i in range(20))
        body = f"def test_many():\n{lines}"
        assertions = _extract_assertions(body)
        assert len(assertions) <= 10


class TestFormatTestsForContext:
    def test_oneline(self):
        tests = [
            TestCase("tests/test_a.py", "test_foo", "foo", ["assert x"]),
            TestCase("tests/test_a.py", "test_bar", "bar", ["assert y", "assert z"]),
        ]
        text = format_tests_for_context(tests, depth="oneline")
        assert "2 test(s)" in text
        assert "3 assertions" in text

    def test_full(self):
        tests = [
            TestCase("tests/test_a.py", "test_foo", "foo", ["assert x == 1"]),
        ]
        text = format_tests_for_context(tests, depth="full")
        assert "test_foo" in text
        assert "assert: assert x == 1" in text

    def test_empty(self):
        assert format_tests_for_context([]) == ""
