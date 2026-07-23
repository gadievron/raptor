"""Tests for macro_resolve — C #define and Rust macro_rules! resolution."""

import pytest

from core.inventory.macro_resolve import (
    build_macro_table,
    build_rust_macro_table,
    resolve_macros,
    resolve_rust_macros,
    _extract_braced_body,
    _table_cache,
    _rust_table_cache,
)


@pytest.fixture(autouse=True)
def _clear_caches():
    _table_cache.clear()
    _rust_table_cache.clear()


class TestBuildMacroTable:
    def test_simple_define(self, tmp_path):
        (tmp_path / "foo.h").write_text("#define FOO 42\n")
        table = build_macro_table(tmp_path)
        assert "FOO" in table
        assert table["FOO"] == ("", "42")

    def test_function_like_macro(self, tmp_path):
        (tmp_path / "foo.h").write_text("#define MAX(a, b) ((a) > (b) ? (a) : (b))\n")
        table = build_macro_table(tmp_path)
        assert "MAX" in table
        params, body = table["MAX"]
        assert params == "(a, b)"
        assert "(a)" in body

    def test_skips_non_c_files(self, tmp_path):
        (tmp_path / "foo.py").write_text("#define NOT_C 1\n")
        table = build_macro_table(tmp_path)
        assert len(table) == 0

    def test_continuation_lines(self, tmp_path):
        (tmp_path / "foo.h").write_text(
            "#define MULTI(x) do { \\\n"
            "    something(x); \\\n"
            "} while(0)\n"
        )
        table = build_macro_table(tmp_path)
        assert "MULTI" in table

    def test_cached(self, tmp_path):
        (tmp_path / "foo.h").write_text("#define A 1\n")
        t1 = build_macro_table(tmp_path)
        t2 = build_macro_table(tmp_path)
        assert t1 is t2


    def test_anonymous_enum_constants(self, tmp_path):
        (tmp_path / "defs.h").write_text(
            "enum { MAX_BUF = 256, MAX_HEADERS = 64 };\n"
        )
        table = build_macro_table(tmp_path)
        assert table["MAX_BUF"] == ("", "256")
        assert table["MAX_HEADERS"] == ("", "64")

    def test_named_enum_constants(self, tmp_path):
        (tmp_path / "err.h").write_text(
            "enum errors { ERR_NONE = 0, ERR_FAIL = -1 };\n"
        )
        table = build_macro_table(tmp_path)
        assert table["ERR_NONE"] == ("", "0")
        assert table["ERR_FAIL"] == ("", "-1")

    def test_enum_does_not_override_define(self, tmp_path):
        (tmp_path / "defs.h").write_text(
            "#define MAX_BUF 512\n"
            "enum { MAX_BUF = 256 };\n"
        )
        table = build_macro_table(tmp_path)
        assert table["MAX_BUF"] == ("", "512")

    def test_enum_skips_c_keywords(self, tmp_path):
        (tmp_path / "defs.h").write_text(
            "enum { int = 1 };\n"  # pathological, shouldn't happen
        )
        table = build_macro_table(tmp_path)
        assert "int" not in table

    def test_enum_expression_values(self, tmp_path):
        (tmp_path / "defs.h").write_text(
            "enum { BUF_SIZE = (4 * 1024) };\n"
        )
        table = build_macro_table(tmp_path)
        assert table["BUF_SIZE"] == ("", "(4 * 1024)")


class TestResolveMacros:
    def test_direct_match(self, tmp_path):
        (tmp_path / "foo.h").write_text("#define PUP(a) *(a)++\n")
        result = resolve_macros(tmp_path, "x = PUP(ptr);")
        names = [name for name, _ in result]
        assert any("PUP" in n for n in names)

    def test_transitive_resolution(self, tmp_path):
        (tmp_path / "foo.h").write_text(
            "#define INNER(x) *(x)\n"
            "#define OUTER(x) INNER(x) + 1\n"
        )
        result = resolve_macros(tmp_path, "val = OUTER(p);")
        names = [name for name, _ in result]
        assert any("OUTER" in n for n in names)
        assert any("INNER" in n for n in names)

    def test_leaf_first_ordering(self, tmp_path):
        (tmp_path / "foo.h").write_text(
            "#define LEAF 42\n"
            "#define MID LEAF + 1\n"
            "#define TOP MID + 2\n"
        )
        result = resolve_macros(tmp_path, "x = TOP;")
        names = [name for name, _ in result]
        assert names.index("LEAF") < names.index("MID")
        assert names.index("MID") < names.index("TOP")

    def test_empty_source(self, tmp_path):
        (tmp_path / "foo.h").write_text("#define A 1\n")
        assert resolve_macros(tmp_path, "") == []

    def test_no_matches(self, tmp_path):
        (tmp_path / "foo.h").write_text("#define UNUSED 1\n")
        assert resolve_macros(tmp_path, "x = regular_func();") == []

    def test_depth_limit(self, tmp_path):
        (tmp_path / "foo.h").write_text(
            "#define D0 D1\n"
            "#define D1 D2\n"
            "#define D2 D3\n"
            "#define D3 D4\n"
            "#define D4 999\n"
        )
        result = resolve_macros(tmp_path, "x = D0;", max_depth=2)
        names = {name for name, _ in result}
        assert "D0" in names
        assert "D1" in names
        assert "D2" in names
        assert "D4" not in names


class TestExtractBracedBody:
    def test_simple(self):
        assert _extract_braced_body("{ body }", 0) == "body"

    def test_nested(self):
        result = _extract_braced_body("{ outer { inner } end }", 0)
        assert "inner" in result
        assert "outer" in result

    def test_no_open_brace(self):
        assert _extract_braced_body("no braces", 0) is None

    def test_unmatched(self):
        assert _extract_braced_body("{ open", 0) is None


class TestBuildRustMacroTable:
    def test_simple_macro_rules(self, tmp_path):
        (tmp_path / "lib.rs").write_text(
            "macro_rules! my_macro {\n"
            "    ($x:expr) => { $x + 1 };\n"
            "}\n"
        )
        table = build_rust_macro_table(tmp_path)
        assert "my_macro" in table
        assert "$x + 1" in table["my_macro"]

    def test_multi_arm(self, tmp_path):
        (tmp_path / "lib.rs").write_text(
            "macro_rules! vec_like {\n"
            "    () => { Vec::new() };\n"
            "    ($($x:expr),+) => { { let mut v = Vec::new(); $(v.push($x);)+ v } };\n"
            "}\n"
        )
        table = build_rust_macro_table(tmp_path)
        assert "vec_like" in table
        assert "Vec::new()" in table["vec_like"]

    def test_skips_non_rs(self, tmp_path):
        (tmp_path / "foo.c").write_text("macro_rules! not_rust { () => {} }")
        table = build_rust_macro_table(tmp_path)
        assert len(table) == 0

    def test_cached(self, tmp_path):
        (tmp_path / "lib.rs").write_text("macro_rules! a { () => { 1 }; }\n")
        t1 = build_rust_macro_table(tmp_path)
        t2 = build_rust_macro_table(tmp_path)
        assert t1 is t2


class TestResolveRustMacros:
    def test_direct(self, tmp_path):
        (tmp_path / "lib.rs").write_text(
            "macro_rules! deref_raw {\n"
            "    ($p:expr) => { unsafe { *$p } };\n"
            "}\n"
        )
        result = resolve_rust_macros(tmp_path, "let v = deref_raw!(ptr);")
        assert len(result) == 1
        assert result[0][0] == "deref_raw"

    def test_transitive(self, tmp_path):
        (tmp_path / "lib.rs").write_text(
            "macro_rules! inner { ($x:expr) => { $x }; }\n"
            "macro_rules! outer { ($x:expr) => { inner!($x) + 1 }; }\n"
        )
        result = resolve_rust_macros(tmp_path, "outer!(42)")
        names = [n for n, _ in result]
        assert "inner" in names
        assert "outer" in names
        assert names.index("inner") < names.index("outer")

    def test_empty(self, tmp_path):
        (tmp_path / "lib.rs").write_text("macro_rules! a { () => {}; }\n")
        assert resolve_rust_macros(tmp_path, "") == []

    def test_skips_std_macros(self, tmp_path):
        (tmp_path / "lib.rs").write_text("")
        result = resolve_rust_macros(tmp_path, "println!(\"hello\"); vec![1,2,3];")
        assert result == []
