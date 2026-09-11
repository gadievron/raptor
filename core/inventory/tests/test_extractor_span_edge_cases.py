"""Span/lexer edge cases in the regex extractors and repair passes.

Each class covers one lexing hazard in both directions: the input that
previously corrupted extraction, and the neighbouring legitimate input
that must keep working.
"""

from __future__ import annotations

import pytest

from core.inventory.extractors import (
    AsmExtractor,
    CExtractor,
    JavaExtractor,
    JavaScriptExtractor,
    LuaExtractor,
    PerlExtractor,
    ShellExtractor,
    _count_comment_lines_regex,
    extract_functions,
    extract_items,
)


# ---------------------------------------------------------------------------
# C — K&R heuristic phantoms
# ---------------------------------------------------------------------------


class TestKnRPhantoms:
    """Multi-line calls under a bare ``else`` (or after a goto label)
    matched the K&R name-open-paren heuristic and minted phantom
    functions — internal 'definitions' of libc names that reached even
    pristine tree-sitter parses through the repair pass."""

    ELSE_SRC = (
        "int real(int x)\n"
        "{\n"
        "    if (x)\n"
        "        y();\n"
        "    else\n"
        "        memset(buf,\n"
        "               0, len);\n"
        "    return 0;\n"
        "}\n"
        "struct s tbl[] = {\n"
        "    {1},\n"
        "};\n"
    )

    def test_no_phantom_under_bare_else(self):
        names = [f.name for f in CExtractor().extract("t.c", self.ELSE_SRC)]
        assert "memset" not in names
        assert "real" in names

    def test_no_phantom_after_goto_label(self):
        src = (
            "void g(void)\n"
            "{\n"
            "out:\n"
            "    memcpy(dst,\n"
            "           src, n);\n"
            "}\n"
            "int tab[] = {1};\n"
        )
        names = [f.name for f in CExtractor().extract("t.c", src)]
        assert "memcpy" not in names
        assert "g" in names

    def test_repair_pass_appends_no_phantom_on_pristine_parse(self):
        pytest.importorskip("tree_sitter_c")
        items = extract_items("t.c", "c", self.ELSE_SRC)
        assert not any(i.name == "memset" for i in items)
        assert any(i.name == "real" for i in items)

    def test_real_knr_definition_still_extracted(self):
        src = (
            "static int\n"
            "knr_fn(a, b)\n"
            "    int a;\n"
            "    int b;\n"
            "{\n"
            "    return a + b;\n"
            "}\n"
        )
        names = [f.name for f in CExtractor().extract("t.c", src)]
        assert "knr_fn" in names


# ---------------------------------------------------------------------------
# C — digit separators vs char literals
# ---------------------------------------------------------------------------


class TestDigitSeparators:
    def test_digit_separator_does_not_poison_spans(self):
        src = (
            "void first(void)\n"
            "{\n"
            "    long big = 1'000;\n"
            "    use(big);\n"
            "}\n"
            "void second(void)\n"
            "{\n"
            "    x();\n"
            "}\n"
        )
        by = {f.name: (f.line_start, f.line_end)
              for f in CExtractor().extract("t.c", src)}
        assert by["first"] == (1, 5)
        assert by["second"] == (6, 9)

    def test_brace_char_literal_still_skipped(self):
        src = "void f(void)\n{\n    char c = '}';\n    x();\n}\n"
        assert CExtractor().extract("t.c", src)[0].line_end == 5


# ---------------------------------------------------------------------------
# C — metadata prefix extraction
# ---------------------------------------------------------------------------


def test_static_visibility_survives_short_function_names():
    # `static int s(void)`: the first 's' is inside 'static'; a plain
    # substring split lost the internal-linkage marker.
    m = CExtractor()._c_metadata("static int s(void)", "s")
    assert m is not None and m.visibility == "static"
    m = CExtractor()._c_metadata("extern int in_fn(void)", "in_fn")
    assert m is not None and m.visibility == "extern"


# ---------------------------------------------------------------------------
# JavaScript — brace-less arrow functions
# ---------------------------------------------------------------------------


class TestArrowFunctionSpans:
    def test_expression_arrow_does_not_swallow_next_function(self):
        src = (
            "const add = (a, b) => a + b;\n"
            "\n"
            "function real(a) {\n"
            "  return a;\n"
            "}\n"
        )
        by = {f.name: (f.line_start, f.line_end)
              for f in JavaScriptExtractor().extract("t.js", src)}
        assert by["add"] == (1, 1)
        assert by["real"] == (3, 5)

    def test_braced_functions_unchanged(self):
        src = "function f(a) {\n  if (a) {\n    g();\n  }\n}\n"
        assert JavaScriptExtractor().extract("t.js", src)[0].line_end == 5


# ---------------------------------------------------------------------------
# Java — anonymous classes, comment braces
# ---------------------------------------------------------------------------


class TestJavaExtractor:
    def test_anonymous_class_is_not_a_method(self):
        src = (
            "class B {\n"
            "    Runnable r = new Runnable() {\n"
            "        public void run() { }\n"
            "    };\n"
            "}\n"
        )
        names = [f.name for f in JavaExtractor().extract("T.java", src)]
        assert "Runnable" not in names
        assert "run" in names

    def test_commented_brace_keeps_class_attribution(self):
        src = (
            "class B {\n"
            "    // helper for the parser: matches '}'\n"
            "    void m1() { }\n"
            "    void m2() { }\n"
            "}\n"
        )
        by = {f.name: f.metadata.class_name
              for f in JavaExtractor().extract("T.java", src)}
        assert by == {"m1": "B", "m2": "B"}

    def test_trailing_comment_brace_ignored(self):
        src = (
            "class B {\n"
            "    void m1() { } // closes with '}'\n"
            "    void m2() { }\n"
            "}\n"
        )
        by = {f.name: f.metadata.class_name
              for f in JavaExtractor().extract("T.java", src)}
        assert by.get("m2") == "B"


# ---------------------------------------------------------------------------
# Shell / Perl — hash inside expansions
# ---------------------------------------------------------------------------


class TestHashBraceLexing:
    def test_shell_length_expansion_keeps_span(self):
        src = (
            "foo() {\n"
            "  if (( ${#args[@]} > 0 )); then\n"
            "    echo hi\n"
            "  fi\n"
            "}\n"
            "bar() {\n"
            "  echo b\n"
            "}\n"
        )
        by = {f.name: (f.line_start, f.line_end)
              for f in ShellExtractor().extract("t.sh", src)}
        assert by["foo"] == (1, 5)
        assert by["bar"] == (6, 8)

    def test_shell_dollar_hash_keeps_span(self):
        src = "g() {\n  if [ $# -gt 0 ]; then\n    echo y\n  fi\n}\n"
        assert ShellExtractor().extract("t.sh", src)[0].line_end == 5

    def test_shell_comments_still_stripped(self):
        src = "f() {\n  # closing } in comment\n  echo x\n}\n"
        assert ShellExtractor().extract("t.sh", src)[0].line_end == 4

    def test_perl_array_last_index_keeps_span(self):
        src = (
            "sub last_idx {\n"
            "    my $n = $#list;\n"
            "    return $n;\n"
            "}\n"
        )
        assert PerlExtractor().extract("t.pl", src)[0].line_end == 4


# ---------------------------------------------------------------------------
# Lua — long comments across lines
# ---------------------------------------------------------------------------


class TestLuaLongComments:
    def test_end_inside_long_comment_does_not_truncate(self):
        src = (
            "function safe()\n"
            "  --[[ this block mentions\n"
            "  end\n"
            "  ]]\n"
            "  dangerous()\n"
            "end\n"
            "function tail()\n"
            "  return 1\n"
            "end\n"
        )
        by = {f.name: (f.line_start, f.line_end)
              for f in LuaExtractor().extract("t.lua", src)}
        assert by["safe"] == (1, 6)
        assert by["tail"] == (7, 9)

    def test_levelled_long_comment(self):
        src = (
            "function f()\n"
            "  --[=[ contains ]] and\n"
            "  end\n"
            "  ]=]\n"
            "  return 1\n"
            "end\n"
        )
        assert LuaExtractor().extract("t.lua", src)[0].line_end == 6

    def test_short_comments_unchanged(self):
        src = "function f()\n  -- end\n  return 1\nend\n"
        assert LuaExtractor().extract("t.lua", src)[0].line_end == 4


# ---------------------------------------------------------------------------
# Asm — .type is not an export marker
# ---------------------------------------------------------------------------


def test_asm_type_directive_does_not_export():
    src = (
        ".globl public_fn\n"
        ".type public_fn, @function\n"
        "public_fn:\n"
        "  ret\n"
        ".type helper_local, @function\n"
        "helper_local:\n"
        "  ret\n"
    )
    by = {f.name: f.metadata.visibility
          for f in AsmExtractor().extract("t.s", src)}
    assert by["public_fn"] == "exported"
    assert by["helper_local"] is None


# ---------------------------------------------------------------------------
# Comment counting — language coverage
# ---------------------------------------------------------------------------


class TestCommentCountCoverage:
    def test_slash_family_languages_counted(self):
        src = "// a\nlet x = 1;\n/* b */\n"
        for lang in ("rust", "scala", "kotlin", "swift", "csharp"):
            assert _count_comment_lines_regex(src, lang) == 2, lang

    def test_lua_dashes_counted(self):
        assert _count_comment_lines_regex("-- a\nlocal x = 1\n", "lua") == 1

    def test_asm_leaders_counted(self):
        assert _count_comment_lines_regex(
            "; a\n# b\n// c\nmov r0, r1\n", "asm") == 3

    def test_php_hash_and_slash_counted(self):
        assert _count_comment_lines_regex(
            "# a\n// b\n$x = 1;\n", "php") == 2


# ---------------------------------------------------------------------------
# Deep trees — extraction survives the recursion limit
# ---------------------------------------------------------------------------


def test_deep_expression_keeps_tree_sitter_extraction():
    """A deeply nested parse blew the recursive walk's recursion
    limit; the RecursionError (a RuntimeError subclass) then read as
    'grammar not installed' and rich extraction was silently lost."""
    pytest.importorskip("tree_sitter_c")
    depth = 3000
    src = (
        "int f(void) { int x = " + "(" * depth + "1" + ")" * depth
        + "; return x; }\n"
        "int g2(void) { return 2; }\n"
    )
    names = {f.name for f in extract_functions("t.c", "c", src)}
    assert {"f", "g2"} <= names
