"""Tests for prompt_output_sanitise."""

from __future__ import annotations

from core.security.prompt_output_sanitise import sanitise_code, sanitise_string


def test_passes_plain_text_unchanged():
    assert sanitise_string("hello world") == "hello world"


def test_escapes_ansi_escape_sequences():
    s = sanitise_string("\x1b[31mred\x1b[0m text")
    assert "\x1b" not in s
    assert "\\x1b" in s


def test_escapes_null_and_bell():
    s = sanitise_string("a\x00b\x07c")
    assert "\x00" not in s
    assert "\x07" not in s


def test_strips_line_leading_markdown_heading():
    s = sanitise_string("# heading\nbody")
    assert s == " heading\nbody"


def test_strips_line_leading_bullet_markers():
    s = sanitise_string("* one\n* two")
    assert s == " one\n two"


def test_strips_line_leading_emphasis_markers():
    s = sanitise_string("_em_ word\n*bold* word")
    assert s == "em_ word\nbold* word"


def test_strips_line_leading_code_fence():
    s = sanitise_string("```python\ncode\n```")
    assert "```" not in s


def test_keeps_mid_line_markdown_chars():
    s = sanitise_string("the * char is mid-string")
    assert s == "the * char is mid-string"


def test_preserves_leading_indent_when_stripping():
    s = sanitise_string("    # heading\n  * bullet")
    assert s == "     heading\n   bullet"


def test_length_caps_with_ellipsis():
    s = sanitise_string("x" * 1000, max_chars=10)
    assert len(s) == 10
    assert s.endswith("…")


def test_under_max_chars_returns_unchanged_length():
    s = sanitise_string("short", max_chars=100)
    assert s == "short"


def test_default_max_chars_is_500():
    s = sanitise_string("x" * 600)
    assert len(s) == 500
    assert s.endswith("…")


def test_handles_empty_string():
    assert sanitise_string("") == ""


def test_pipeline_order_escape_then_strip_then_cap():
    raw = "# \x1b[31mhead\x1b[0m" + ("x" * 100)
    s = sanitise_string(raw, max_chars=20)
    assert "\x1b" not in s
    assert not s.startswith("# ") and not s.startswith("#")
    assert len(s) == 20
    assert s.endswith("…")


# --- sanitise_code ---

def test_code_preserves_hash_include():
    assert sanitise_code("#include <stdio.h>") == "#include <stdio.h>"


def test_code_preserves_pointer_deref():
    assert sanitise_code("*ptr = value;") == "*ptr = value;"


def test_code_preserves_python_comment():
    assert sanitise_code("# comment\nx = 1") == "# comment\nx = 1"


def test_code_escapes_ansi():
    s = sanitise_code("int x\x1b[31m = 0;")
    assert "\x1b" not in s
    assert "\\x1b" in s


def test_code_preserves_newlines_and_tabs():
    s = sanitise_code("void f() {\n\treturn;\n}")
    assert "\n\treturn;" in s


def test_code_caps_length():
    s = sanitise_code("x" * 20000, max_chars=100)
    assert len(s) == 100
    assert s.endswith("…")


def test_code_default_cap_is_generous():
    s = sanitise_code("x" * 5000)
    assert len(s) == 5000
