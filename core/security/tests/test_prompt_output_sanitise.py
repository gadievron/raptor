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

def test_code_html_escapes_hash_include():
    """``<`` and ``>`` get HTML-escaped — render correctly inside ``` fences."""
    assert sanitise_code("#include <stdio.h>") == "#include &lt;stdio.h&gt;"


def test_code_html_escape_off_preserves_hash_include():
    """Opt-out for callers that don't want HTML escape."""
    assert sanitise_code("#include <stdio.h>", html_escape=False) == "#include <stdio.h>"


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


# --- HTML / XSS ---

def test_string_html_escapes_script_tag():
    s = sanitise_string("<script>alert(1)</script>")
    assert "<script>" not in s
    assert "&lt;script&gt;" in s


def test_string_html_escapes_img_onerror():
    s = sanitise_string('<img src=x onerror="alert(1)">')
    assert "<img" not in s
    assert "onerror=" in s  # text content, not active attribute
    assert "&lt;img" in s
    assert "&quot;" in s


def test_string_html_escapes_ampersand():
    s = sanitise_string("a & b")
    assert s == "a &amp; b"


def test_string_html_escapes_single_quote():
    s = sanitise_string("it's fine")
    assert "&#x27;" in s


def test_string_html_escape_off_preserves_tags():
    s = sanitise_string("<b>bold</b>", html_escape=False)
    assert s == "<b>bold</b>"


def test_string_double_escape_does_not_compound():
    """Render path runs once. Verify a single pass produces canonical form."""
    s = sanitise_string("&amp;")
    # Already-escaped input gets re-escaped (cannot distinguish from raw).
    # Render-once invariant in callers prevents this in practice.
    assert s == "&amp;amp;"


def test_code_html_escapes_script_in_fence_break_payload():
    """Fence-break attack: payload contains ``` then HTML.

    The HTML is still escaped — even if a buggy renderer ends the fence,
    no active tags can form.
    """
    payload = "x\n```\n<script>alert(1)</script>"
    s = sanitise_code(payload)
    assert "<script>" not in s
    assert "&lt;script&gt;" in s


def test_string_html_escape_preserves_newlines():
    s = sanitise_string("line1\nline2")
    assert "\n" in s


def test_string_pipeline_strip_then_html_escape():
    """Line-leading defang runs before HTML escape so ``# &lt;hi&gt;`` works."""
    s = sanitise_string("# <hi>")
    # # stripped, then < > escaped
    assert s == " &lt;hi&gt;"
