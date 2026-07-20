"""Tests for core.source.strip — string-literal-aware comment stripping."""

from __future__ import annotations

from core.source.strip import (
    strip_c_comments,
    strip_comments,
    strip_python_comments,
    strip_shell_comments,
)


# -------------------------------------------------------------------
# C-family
# -------------------------------------------------------------------

class TestStripCComments:
    def test_line_comment(self):
        assert strip_c_comments("int x = 1; // init\n").strip() == "int x = 1;"

    def test_block_comment(self):
        result = strip_c_comments("int x = 1;\n/* multi\n   line */\nreturn x;\n")
        assert "multi" not in result
        assert "int x = 1;" in result
        assert "return x;" in result

    def test_preserves_string_with_double_slash(self):
        src = 'char *url = "https://example.com";\n'
        result = strip_c_comments(src)
        assert '"https://example.com"' in result

    def test_preserves_string_with_block_marker(self):
        src = 'char *s = "/* not a comment */";\n'
        result = strip_c_comments(src)
        assert '"/* not a comment */"' in result

    def test_preserves_char_literal(self):
        src = "char c = '/';\nint x; // comment\n"
        result = strip_c_comments(src)
        assert "'/'" in result
        assert "comment" not in result

    def test_escape_in_string(self):
        src = 'char *s = "he said \\"hi\\""; // comment\n'
        result = strip_c_comments(src)
        assert "comment" not in result
        assert '\\"hi\\"' in result

    def test_inline_after_string(self):
        src = 'printf("hello"); // greeting\n'
        result = strip_c_comments(src)
        assert '"hello"' in result
        assert "greeting" not in result

    def test_multiline_block_comment(self):
        src = "int a;\n/*\n * doc\n */\nint b;\n"
        result = strip_c_comments(src)
        assert "int a;" in result
        assert "int b;" in result
        assert "doc" not in result

    def test_empty_string(self):
        assert strip_c_comments("") == ""

    def test_no_comments(self):
        src = "int x = 1;\nreturn x;\n"
        assert strip_c_comments(src) == src

    def test_url_in_string_not_stripped(self):
        """The critical bug: // inside string must NOT be treated as comment."""
        src = 'char *cmd = "echo hello //safe";\n'
        result = strip_c_comments(src)
        assert '"echo hello //safe"' in result

    def test_changed_url_in_string_detected(self):
        """Two different strings with // must produce different results."""
        src1 = 'exec("cmd //flag1");'
        src2 = 'exec("cmd //flag2");'
        r1 = strip_c_comments(src1)
        r2 = strip_c_comments(src2)
        assert r1 != r2
        assert "flag1" in r1
        assert "flag2" in r2


# -------------------------------------------------------------------
# Python
# -------------------------------------------------------------------

class TestStripPythonComments:
    def test_full_line_comment(self):
        src = "# comment\ndef foo():\n    return 1\n"
        result = strip_python_comments(src)
        assert "comment" not in result
        assert "def foo():" in result

    def test_inline_comment(self):
        src = "x = 1  # assign\n"
        result = strip_python_comments(src)
        assert "x = 1  " in result
        assert "assign" not in result

    def test_preserves_hash_in_single_string(self):
        src = "x = 'color #ff0000'\n"
        result = strip_python_comments(src)
        assert "'color #ff0000'" in result

    def test_preserves_hash_in_double_string(self):
        src = 'x = "color #ff0000"\n'
        result = strip_python_comments(src)
        assert '"color #ff0000"' in result

    def test_preserves_hash_in_triple_string(self):
        """The critical bug: # inside triple-quoted string must survive."""
        src = 'x = """\n# not a comment\n"""\n'
        result = strip_python_comments(src)
        assert "# not a comment" in result

    def test_changed_triple_string_content_detected(self):
        """Two different triple-quoted strings with # lines must differ."""
        src1 = 'x = """\n# old doc\n"""\n'
        src2 = 'x = """\n# new doc\n"""\n'
        r1 = strip_python_comments(src1)
        r2 = strip_python_comments(src2)
        assert r1 != r2

    def test_triple_single_quotes(self):
        src = "x = '''\n# preserved\n'''\n"
        result = strip_python_comments(src)
        assert "# preserved" in result

    def test_escape_in_string(self):
        src = 'x = "he said \\"fine\\"" # comment\n'
        result = strip_python_comments(src)
        assert "comment" not in result

    def test_fstring_hash_format_preserved(self):
        src = 'x = f"{val:#04x}"\n'
        result = strip_python_comments(src)
        assert ":#04x" in result

    def test_comment_after_triple_string(self):
        src = '"""\ndoc\n"""\nx = 1 # comment\n'
        result = strip_python_comments(src)
        assert "doc" in result
        assert "comment" not in result
        assert "x = 1" in result

    def test_empty_string(self):
        assert strip_python_comments("") == ""

    def test_no_comments(self):
        src = "x = 1\ny = 2\n"
        assert strip_python_comments(src) == src

    def test_raw_string_with_hash(self):
        src = 'x = r"#not_comment"\n'
        result = strip_python_comments(src)
        assert "#not_comment" in result


# -------------------------------------------------------------------
# Shell
# -------------------------------------------------------------------

class TestStripShellComments:
    def test_full_line_comment(self):
        src = "# comment\necho hello\n"
        result = strip_shell_comments(src)
        assert "comment" not in result
        assert "echo hello" in result

    def test_inline_comment(self):
        src = "echo hello # greeting\n"
        result = strip_shell_comments(src)
        assert "echo hello" in result
        assert "greeting" not in result

    def test_preserves_hash_in_double_string(self):
        src = 'echo "color #ff0000"\n'
        result = strip_shell_comments(src)
        assert '"color #ff0000"' in result

    def test_preserves_hash_in_single_string(self):
        src = "echo 'color #ff0000'\n"
        result = strip_shell_comments(src)
        assert "'color #ff0000'" in result

    def test_hash_in_url_not_stripped(self):
        src = "curl https://example.com/path#frag\n"
        result = strip_shell_comments(src)
        assert "#frag" in result

    def test_escape_in_double_string(self):
        src = 'echo "he said \\"hi\\"" # comment\n'
        result = strip_shell_comments(src)
        assert "comment" not in result

    def test_no_escape_in_single_string(self):
        src = "echo 'it\\'s fine'\n"
        result = strip_shell_comments(src)
        assert "fine" in result


# -------------------------------------------------------------------
# Dispatch
# -------------------------------------------------------------------

class TestStripComments:
    def test_c_file(self):
        src = 'char *s = "//safe"; // comment\n'
        result = strip_comments(src, "foo.c")
        assert "//safe" in result
        assert "comment" not in result

    def test_cpp_file(self):
        result = strip_comments("int x; // comment\n", "foo.cpp")
        assert "comment" not in result

    def test_hpp_file(self):
        result = strip_comments("int x; // comment\n", "foo.hpp")
        assert "comment" not in result

    def test_tsx_file(self):
        result = strip_comments("const x = 1; // comment\n", "app.tsx")
        assert "comment" not in result

    def test_kotlin_file(self):
        result = strip_comments("fun f() {} // comment\n", "Main.kt")
        assert "comment" not in result

    def test_swift_file(self):
        result = strip_comments("func f() {} // comment\n", "main.swift")
        assert "comment" not in result

    def test_python_file(self):
        src = '"""\n# doc\n"""\nx = 1 # comment\n'
        result = strip_comments(src, "foo.py")
        assert "# doc" in result
        assert "comment" not in result

    def test_shell_file(self):
        src = 'echo "hello #world" # comment\n'
        result = strip_comments(src, "foo.sh")
        assert "#world" in result
        assert "comment" not in result

    def test_unknown_extension_unchanged(self):
        src = "hello // world # foo\n"
        assert strip_comments(src, "foo.xyz") == src
