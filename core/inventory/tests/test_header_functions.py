"""Tests for header_functions — function definition index from C/C++ headers."""

import pytest

from core.inventory.header_functions import (
    build_header_function_index,
    lookup_header_function,
    _extract_function_body,
    _cache,
)


@pytest.fixture(autouse=True)
def _clear_cache():
    _cache.clear()


class TestBuildIndex:
    def test_static_inline(self, tmp_path):
        (tmp_path / "util.h").write_text(
            "static inline int max(int a, int b) {\n"
            "    return a > b ? a : b;\n"
            "}\n"
        )
        idx = build_header_function_index(tmp_path)
        assert "max" in idx
        assert idx["max"][0] == "util.h"
        assert "return a > b" in idx["max"][1]

    def test_skips_declarations(self, tmp_path):
        (tmp_path / "api.h").write_text(
            "int compute(int x);\n"
            "void process(const char *data);\n"
        )
        idx = build_header_function_index(tmp_path)
        assert len(idx) == 0

    def test_skips_c_files(self, tmp_path):
        (tmp_path / "impl.c").write_text(
            "int foo(void) {\n"
            "    return 42;\n"
            "}\n"
        )
        idx = build_header_function_index(tmp_path)
        assert len(idx) == 0

    def test_multiple_functions(self, tmp_path):
        (tmp_path / "helpers.h").write_text(
            "static inline int min(int a, int b) {\n"
            "    return a < b ? a : b;\n"
            "}\n"
            "\n"
            "static inline int clamp(int v, int lo, int hi) {\n"
            "    if (v < lo) return lo;\n"
            "    if (v > hi) return hi;\n"
            "    return v;\n"
            "}\n"
        )
        idx = build_header_function_index(tmp_path)
        assert "min" in idx
        assert "clamp" in idx

    def test_skips_long_functions(self, tmp_path):
        body_lines = "\n".join(f"    line{i}();" for i in range(35))
        (tmp_path / "big.h").write_text(
            f"static void big(void) {{\n{body_lines}\n}}\n"
        )
        idx = build_header_function_index(tmp_path)
        assert "big" not in idx

    def test_cached(self, tmp_path):
        (tmp_path / "a.h").write_text(
            "static inline void noop(void) {}\n"
        )
        i1 = build_header_function_index(tmp_path)
        i2 = build_header_function_index(tmp_path)
        assert i1 is i2

    def test_attribute_always_inline(self, tmp_path):
        (tmp_path / "fast.h").write_text(
            "__attribute__((always_inline)) static inline int sq(int x) {\n"
            "    return x * x;\n"
            "}\n"
        )
        idx = build_header_function_index(tmp_path)
        assert "sq" in idx

    def test_nested_braces(self, tmp_path):
        (tmp_path / "ctrl.h").write_text(
            "static inline int abs_val(int x) {\n"
            "    if (x < 0) {\n"
            "        return -x;\n"
            "    }\n"
            "    return x;\n"
            "}\n"
        )
        idx = build_header_function_index(tmp_path)
        assert "abs_val" in idx
        assert "return -x" in idx["abs_val"][1]

    def test_subdirectory_headers(self, tmp_path):
        sub = tmp_path / "include" / "mylib"
        sub.mkdir(parents=True)
        (sub / "math.h").write_text(
            "static inline int double_it(int x) { return x * 2; }\n"
        )
        idx = build_header_function_index(tmp_path)
        assert "double_it" in idx
        assert "include/mylib/math.h" in idx["double_it"][0]

    def test_skips_keywords(self, tmp_path):
        (tmp_path / "bad.h").write_text(
            "if (x) {\n    foo();\n}\n"
        )
        idx = build_header_function_index(tmp_path)
        assert "if" not in idx


class TestLookup:
    def test_found(self, tmp_path):
        (tmp_path / "u.h").write_text(
            "static inline void noop(void) {}\n"
        )
        result = lookup_header_function(tmp_path, "noop")
        assert result is not None
        assert result[0] == "u.h"

    def test_not_found(self, tmp_path):
        (tmp_path / "u.h").write_text(
            "static inline void noop(void) {}\n"
        )
        assert lookup_header_function(tmp_path, "missing") is None


class TestExtractFunctionBody:
    def test_single_line(self):
        lines = ["int f(void) { return 1; }"]
        result = _extract_function_body(lines, 0)
        assert result is not None
        assert "return 1" in result

    def test_multi_line(self):
        lines = [
            "int f(void) {",
            "    return 1;",
            "}",
        ]
        result = _extract_function_body(lines, 0)
        assert result is not None
        assert "return 1" in result

    def test_unclosed(self):
        lines = ["int f(void) {", "    x++;"]
        assert _extract_function_body(lines, 0) is None
