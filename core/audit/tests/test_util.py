"""Tests for core.audit._util — shared low-level helpers."""

from __future__ import annotations

from pathlib import Path

from core.audit._util import (
    extract_context_map_set,
    find_function_in_checklist,
    find_function_line,
    find_function_lines,
    is_valid_identifier,
    safe_join,
    safe_joern_name_lenient,
)


class TestSafeJoin:
    def test_normal_path(self, tmp_path: Path):
        result = safe_join(tmp_path, "src/main.c")
        assert result == tmp_path / "src/main.c"

    def test_dotdot_rejected(self, tmp_path: Path):
        assert safe_join(tmp_path, "../etc/passwd") is None

    def test_deep_dotdot_rejected(self, tmp_path: Path):
        assert safe_join(tmp_path, "src/../../etc/passwd") is None

    def test_bare_filename(self, tmp_path: Path):
        result = safe_join(tmp_path, "file.c")
        assert result == tmp_path / "file.c"

    def test_empty_string(self, tmp_path: Path):
        result = safe_join(tmp_path, "")
        assert result is not None


class TestIsValidIdentifier:
    def test_normal_name(self):
        assert is_valid_identifier("parse_header")

    def test_underscore_start(self):
        assert is_valid_identifier("_private")

    def test_digit_start(self):
        assert not is_valid_identifier("3bad")

    def test_injection(self):
        assert not is_valid_identifier("foo; rm -rf /")

    def test_empty(self):
        assert not is_valid_identifier("")

    def test_dotted(self):
        assert not is_valid_identifier("module.func")


class TestFindFunctionInChecklist:
    def test_found(self):
        checklist = {
            "files": [
                {"path": "src/a.c", "items": [
                    {"name": "foo", "line_start": 10, "line_end": 20},
                    {"name": "bar", "line_start": 30, "line_end": 40},
                ]},
            ],
        }
        item = find_function_in_checklist(checklist, "src/a.c", "bar")
        assert item is not None
        assert item["line_start"] == 30

    def test_not_found(self):
        checklist = {"files": [
            {"path": "src/a.c", "items": [{"name": "foo"}]},
        ]}
        assert find_function_in_checklist(checklist, "src/a.c", "baz") is None

    def test_file_not_in_checklist(self):
        assert find_function_in_checklist({"files": []}, "x.c", "f") is None

    def test_empty_checklist(self):
        assert find_function_in_checklist({}, "x.c", "f") is None


class TestFindFunctionLine:
    def test_found(self):
        cl = {"files": [
            {"path": "a.c", "items": [{"name": "f", "line_start": 42}]},
        ]}
        assert find_function_line(cl, "a.c", "f") == 42

    def test_not_found(self):
        assert find_function_line({"files": []}, "a.c", "f") == 0


class TestFindFunctionLines:
    def test_found(self):
        cl = {"files": [
            {"path": "a.c", "items": [
                {"name": "f", "line_start": 10, "line_end": 20},
            ]},
        ]}
        assert find_function_lines(cl, "a.c", "f") == (10, 20)

    def test_not_found(self):
        assert find_function_lines({"files": []}, "a.c", "f") == (0, 0)


class TestExtractContextMapSet:
    def test_entry_points(self):
        cmap = {
            "entry_points": [
                {"file": "src/main.c", "name": "main"},
                {"file": "src/http.c", "name": "handle_request"},
            ],
        }
        result = extract_context_map_set(cmap, "entry_points")
        assert result == {
            "src/main.c:main",
            "src/http.c:handle_request",
        }

    def test_sinks(self):
        cmap = {
            "sinks": [
                {"file": "lib/exec.c", "name": "system"},
            ],
        }
        result = extract_context_map_set(cmap, "sinks")
        assert result == {"lib/exec.c:system"}

    def test_trust_boundaries_nested(self):
        cmap = {
            "trust_boundaries": [
                {
                    "name": "kernel",
                    "functions": [
                        {"file": "kern/sys.c", "name": "syscall_entry"},
                    ],
                },
            ],
        }
        result = extract_context_map_set(
            cmap, "trust_boundaries", nested_key="functions",
        )
        assert result == {"kern/sys.c:syscall_entry"}

    def test_empty_section(self):
        assert extract_context_map_set({"entry_points": []}, "entry_points") == set()

    def test_none_context_map(self):
        assert extract_context_map_set(None, "entry_points") == set()

    def test_missing_section(self):
        assert extract_context_map_set({}, "entry_points") == set()

    def test_skips_empty_keys(self):
        cmap = {
            "entry_points": [
                {"file": "", "name": ""},
                {"file": "a.c", "name": "f"},
            ],
        }
        result = extract_context_map_set(cmap, "entry_points")
        assert result == {"a.c:f"}


class TestSafeJoernNameLenient:
    """Contract for the shared lenient Joern-name escaper."""

    def test_plain_and_qualified_names_pass(self):
        assert safe_joern_name_lenient("process_input") == "process_input"
        assert safe_joern_name_lenient("pkg.MyClass.method") == "pkg.MyClass.method"

    def test_injection_rejected(self):
        assert safe_joern_name_lenient('foo"); sys.exit(1); //') is None

    def test_empty_rejected(self):
        assert safe_joern_name_lenient("") is None

    def _force_fallback(self, monkeypatch):
        import sys
        monkeypatch.setitem(sys.modules, "packages.joern.runner", None)

    def test_fallback_accepts_dotted_and_underscored(self, monkeypatch):
        self._force_fallback(monkeypatch)
        assert safe_joern_name_lenient("a.b_c.d9") == "a.b_c.d9"

    def test_fallback_rejects_control_chars_and_separators(self, monkeypatch):
        self._force_fallback(monkeypatch)
        assert safe_joern_name_lenient("tab\tname") is None
        assert safe_joern_name_lenient("foo-bar") is None
        assert safe_joern_name_lenient("foo bar") is None

    def test_fallback_escapes_backslash_and_quote(self, monkeypatch):
        # Escaping only matters for values that survive validation;
        # isalnum() lets unicode letters through unescaped, while a
        # backslash or quote never reaches the escape (not alnum).
        self._force_fallback(monkeypatch)
        assert safe_joern_name_lenient("λfunc") == "λfunc"
        assert safe_joern_name_lenient('na"me') is None
