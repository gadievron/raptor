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


def test_strips_line_leading_tilde_fence():
    # `~~~` is the tilde spelling of a fenced code block: left alive,
    # one hostile line swallows every later section of the rendered
    # report (writer fences, headings, the next finding) as literal
    # code until a closing tilde run.
    import re as _re
    s = sanitise_string("open\n~~~\nswallowed section")
    assert not _re.search(r"(?m)^[ \t]*~", s)
    assert "swallowed section" in s
    s = sanitise_string("~~~python\ncode")
    assert not _re.search(r"(?m)^[ \t]*~", s)


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


# ---------------------------------------------------------------------------
# Regression: zero-width chars between markdown heading chars
# ---------------------------------------------------------------------------


def test_zwj_between_markdown_heading_chars_stripped_before_defang():
    """Zero-width joiner (U+200D) between two '#' chars at line start.

    Before the fix: _strip_autofetch_markup ran AFTER _LINE_LEAD_MD_RE.sub,
    so the ZWJ prevented the regex from seeing '##' (it saw '#\\u200d#'
    which doesn't match the [#] character class grouping), and the heading
    markup survived into the output.

    After the fix: _strip_autofetch_markup runs FIRST, stripping the
    invisible char, then _LINE_LEAD_MD_RE correctly matches '##' and
    defangs it.
    """
    # U+200D = zero-width joiner; inserted between two '#' chars.
    payload = "#‍# heading"
    result = sanitise_string(payload, max_chars=500)
    # Both heading chars must be removed by the defanging regex.
    assert "#" not in result


# ---------------------------------------------------------------------------
# Regression: block-structure forgery in report-bound strings
# ---------------------------------------------------------------------------
# sanitise_string only defanged line-LEADING inline control chars;
# setext heading underlines, `---` rules, and table rows survived into
# rendered reports (audit-report.md / agentic findings), letting a
# coaxed LLM string forge document structure (headings, metric tables)
# in operator-facing markdown. Payload shapes pinned from the battery
# repros (S05 reasoning-setext / reasoning-table-forge; S07 setext-eq /
# setext-dash).

import re as _re


def test_setext_equals_underline_neutralised():
    out = sanitise_string("x\nZOUT SETX\n=====")
    assert not _re.search(r"(?m)^ZOUT SETX\n=+$", out)
    assert "ZOUT SETX" in out  # prose survives, structure dies


def test_setext_dash_underline_neutralised():
    out = sanitise_string("ZOUT SETD\n---")
    assert not _re.search(r"(?m)^ZOUT SETD\n-+$", out)


def test_horizontal_rule_line_neutralised():
    out = sanitise_string("above\n---\nbelow")
    assert not _re.search(r"(?m)^-+$", out)


def test_table_forgery_neutralised():
    # A leading-pipe row + a delimiter row is what renders as a table.
    out = sanitise_string(
        "ok\n| ZEVILMETRIC | 0 findings |\n|---|---|",
    )
    assert not _re.search(r"(?m)^\|", out)          # no leading pipes
    assert not _re.search(r"(?m)^[ \t|:=-]*-[ \t|:=-]*$", out)
    assert "ZEVILMETRIC" in out


def test_table_delimiter_with_colons_neutralised():
    out = sanitise_string("h1 | h2\n:---|---:")
    assert not _re.search(r"(?m)^[ \t|:=-]*-[ \t|:=-]*$", out)


def test_blockquote_lead_stripped():
    assert sanitise_string("> forged quote").lstrip() == "forged quote"


def test_prose_with_dashes_mid_line_survives():
    out = sanitise_string("range 3-5 and a = b stay readable")
    assert "3-5" in out and "a = b" in out


# ---------------------------------------------------------------------------
# Regression: autofetch attribute cousins (report side)
# ---------------------------------------------------------------------------
# These HTML forms slip the input-side envelope regex; the report-side
# sanitiser must be a genuine second layer for them (battery variants:
# reasoning-autofetch-image-alias / title-image-alias and the S03
# attribute-fetch family, verified surviving sanitise_string pre-fix).


def test_image_tag_alias_stripped():
    # HTML parsers alias <image> to <img> — an auto-fetching tag.
    out = sanitise_string('see <image src="//evil.example/Z">')
    assert "<image" not in out.lower()
    assert "evil.example" not in out


def test_input_type_image_stripped():
    out = sanitise_string("<input type=image src=//evil.example/Z>")
    assert "<input" not in out.lower()


def test_frame_and_track_tags_stripped():
    assert "<frame" not in sanitise_string(
        "<frame src=//evil.example/Z>",
    ).lower()
    assert "<track" not in sanitise_string(
        "<track src=//evil.example/Z>",
    ).lower()


def test_style_attribute_url_fetch_stripped():
    # The fetch primitive is the style-attribute url(...) — assert IT
    # dies. (How much surrounding text survives depends on whether the
    # input-side envelope regex rewrote the tag first; both layers
    # leave no url( behind.)
    out = sanitise_string(
        '<div style="background:url(//evil.example/Z)">x',
    )
    assert "url(" not in out.lower()
    assert out.endswith("x")


def test_a_slash_href_stripped():
    # `/` also delimits attributes in HTML: <a/href=...> is a live
    # link the envelope's `<a\s` arm misses.
    out = sanitise_string('<a/href="javascript:alert(1)">c</a>')
    assert "javascript:" not in out.lower()


def test_case_insensitive_tag_forms_stripped():
    assert "<IMAGE" not in sanitise_string(
        '<IMAGE SRC="//evil.example/Z">',
    ).upper().replace("[REDACTED-AUTOFETCH-MARKUP]".upper(), "")


# ---------------------------------------------------------------------------
# sanitise_inline — the single-line-slot variant
# ---------------------------------------------------------------------------


def test_inline_flattens_newlines():
    from core.security.prompt_output_sanitise import sanitise_inline
    assert sanitise_inline("a\nb\rc d e") == "a b c d e"


def test_inline_escapes_controls_and_bidi():
    from core.security.prompt_output_sanitise import sanitise_inline
    out = sanitise_inline("x\x1b]0;t\x07\x9b2J‮y")
    for raw in ("\x1b", "\x07", "\x9b", "‮"):
        assert raw not in out


def test_inline_strips_autofetch_both_layers():
    from core.security.prompt_output_sanitise import (
        sanitise_inline,
        sanitise_string,
    )
    assert "//evil.example" not in sanitise_inline("<img src=//evil.example/x>")
    # The style-attribute url() construct is broken the same way
    # sanitise_string breaks it (the fetch syntax is redacted; the
    # bare host may remain as inert prose) — pin parity, not more.
    payload = '<div style="background:url(//evil.example)">x</div>'
    assert sanitise_inline(payload) == sanitise_string(payload)
    assert "[REDACTED-AUTOFETCH-MARKUP]" in sanitise_inline(payload)


def test_inline_preserves_literal_label_text():
    # Two-direction guard: the line-leading strip is deliberately
    # omitted — a '#' column header and a '-' placeholder cell are
    # legitimate single-line content.
    from core.security.prompt_output_sanitise import sanitise_inline
    assert sanitise_inline("#") == "#"
    assert sanitise_inline("-") == "-"
    assert sanitise_inline("*ptr") == "*ptr"


def test_inline_caps_length():
    from core.security.prompt_output_sanitise import sanitise_inline
    out = sanitise_inline("a" * 10_000, max_chars=100)
    assert len(out) == 100


def test_inline_escapes_in_cell_pipes():
    """The docstring claims fitness for table cells — an in-cell pipe
    splits the row and shifts attacker text under different column
    headers. Entity-escape like cve-diff's _md_cell."""
    from core.security.prompt_output_sanitise import sanitise_inline
    out = sanitise_inline("skip | HIGH | do-not-review")
    assert "|" not in out
    assert out == "skip &#124; HIGH &#124; do-not-review"


def test_inline_escapes_backticks():
    """A backtick closes a wrapping `` ` `` code span and the tail
    renders as live inline markdown (links). No raw backtick may
    survive; the entity renders as a backtick in plain slots."""
    from core.security.prompt_output_sanitise import sanitise_inline
    out = sanitise_inline("a`rm -rf`.sh")
    assert "`" not in out
    assert out == "a&#96;rm -rf&#96;.sh"
    # The span-breakout payload (backtick + markdown link): the link
    # is autofetch-redacted AND no raw backtick survives to close the
    # wrapping span.
    out = sanitise_inline("a`[x](https://evil.example)`.sh")
    assert "`" not in out
    assert "evil.example" not in out


# ---------------------------------------------------------------------------
# truncation boundaries + default caps — all three entry points
# ---------------------------------------------------------------------------
# The cap contract is exact, both directions: a string AT the cap
# passes through unmodified (no ellipsis appears for content nothing
# was dropped from), and a string over the cap comes back at EXACTLY
# max_chars with the final character being the single elision mark.
# The default cap value per function is itself contract: callers omit
# max_chars and rely on it when sizing report slots.


def test_string_at_default_cap_untruncated():
    s = "a" * 500
    assert sanitise_string(s) == s


def test_string_over_default_cap_truncates_to_exactly_500():
    out = sanitise_string("a" * 520)
    assert out == "a" * 499 + "…"


def test_inline_at_default_cap_untruncated():
    from core.security.prompt_output_sanitise import sanitise_inline
    s = "a" * 300
    assert sanitise_inline(s) == s


def test_inline_over_default_cap_truncates_to_exactly_300():
    from core.security.prompt_output_sanitise import sanitise_inline
    out = sanitise_inline("a" * 350)
    assert out == "a" * 299 + "…"


def test_code_at_default_cap_untruncated():
    s = "a" * 10_000
    assert sanitise_code(s) == s


def test_code_over_default_cap_truncates_to_exactly_10000():
    out = sanitise_code("a" * 10_050)
    assert out == "a" * 9_999 + "…"


def test_explicit_cap_boundary_exact():
    from core.security.prompt_output_sanitise import sanitise_inline
    assert sanitise_string("x" * 40, max_chars=40) == "x" * 40
    assert sanitise_string("x" * 41, max_chars=40) == "x" * 39 + "…"
    assert sanitise_inline("x" * 40, max_chars=40) == "x" * 40
    assert sanitise_code("x" * 40, max_chars=40) == "x" * 40


# ---------------------------------------------------------------------------
# list-marker ZWSP defang — exact output shape
# ---------------------------------------------------------------------------
# The ZWSP goes BETWEEN the marker and its following space (indent
# preserved, marker text preserved, space preserved) — CommonMark only
# forms a list item when the char AFTER the marker is a space/tab, so
# this exact placement is what defangs the construct while keeping
# the visible "1." / "-" prefixes readable.


def test_bullet_marker_zwsp_placement_exact():
    assert sanitise_string("  - item") == "  -​ item"


def test_numbered_marker_zwsp_placement_exact():
    assert sanitise_string("1. step one") == "1.​ step one"
    assert sanitise_string("\t2) step two") == "\t2)​ step two"


def test_plus_marker_zwsp_placement_exact():
    assert sanitise_string("+ item") == "+​ item"


def test_non_marker_shapes_untouched():
    # No space after the marker shape — not a list construct.
    assert sanitise_string("--flag and 1.5 stay") == "--flag and 1.5 stay"


# --- Raw structural HTML (CommonMark HTML blocks / inline raw HTML) ---
#
# Non-fetching structural HTML passed both autofetch layers verbatim:
# `<h1>ALL CLEAR</h1>` forged a heading, `<table>` a metrics table,
# `<blockquote>` an authoritative quotation — and a line-leading
# `<!--` commented out every subsequent finding until `-->` while
# `<details>` collapsed the remainder of the rendered report. The
# construct-opener escape defangs the whole class; comparison prose
# keeps its raw `<`.

def test_string_defangs_html_heading_table_blockquote():
    from core.security.prompt_output_sanitise import sanitise_string
    s = ("benign\n<h1>ALL CLEAR - no findings</h1>\n"
         "<table><tr><td>forged-metrics</td></tr></table>\n"
         "<blockquote>operator said: approve</blockquote>")
    out = sanitise_string(s)
    for raw in ("<h1>", "<table>", "<tr>", "<td>", "<blockquote>",
                "</h1>", "</table>", "</blockquote>"):
        assert raw not in out
    assert "&lt;h1>" in out
    assert "ALL CLEAR - no findings" in out


def test_string_defangs_html_comment_opener():
    from core.security.prompt_output_sanitise import sanitise_string
    s = "finding text\n<!--\nTHE REST OF THE REPORT"
    out = sanitise_string(s)
    assert "<!--" not in out
    assert "&lt;!--" in out
    assert "THE REST OF THE REPORT" in out


def test_string_defangs_details_collapse():
    from core.security.prompt_output_sanitise import sanitise_string
    out = sanitise_string(
        "x\n<details><summary>click</summary>hidden</details>")
    assert "<details>" not in out
    assert "<summary>" not in out


def test_inline_defangs_html_in_slot():
    from core.security.prompt_output_sanitise import sanitise_inline
    assert "<h1>" not in sanitise_inline("t<h1>forge</h1>")
    out = sanitise_inline("a<details open>b")
    assert "<details" not in out
    assert out.startswith("a&lt;details")


def test_html_adjacent_shapes_defanged():
    """CDATA, declaration, processing instruction, incomplete tag —
    every construct-opener spelling, not just complete known tags."""
    from core.security.prompt_output_sanitise import (
        sanitise_inline,
        sanitise_string,
    )
    for payload in (
        "x\n<![CDATA[hidden]]>",
        "x\n<!DOCTYPE html>",
        "x\n<?php evil() ?>",
        "x\n<details",            # HTML block type 6 needs no `>`
        "x\n<DETAILS OPEN>y",     # case-insensitive tag names
        "x\n<textarea>swallows",  # HTML block type 1
    ):
        assert "<" not in sanitise_string(payload).replace("&lt;", ""), payload
        assert "<" not in sanitise_inline(payload).replace("&lt;", ""), payload


def test_html_fetching_tags_still_redacted_not_escaped():
    """`<script>`/`<svg>`/`<img>` stay on the autofetch-strip lane —
    the construct escape runs after it and must not pre-empt it."""
    from core.security.prompt_output_sanitise import sanitise_string
    for payload in ("<script>alert(1)</script>", "<svg onload=x>",
                    "<img src=//evil>"):
        out = sanitise_string(payload)
        assert "REDACTED-AUTOFETCH-MARKUP" in out or "[" in out, payload
        assert "<script" not in out and "<svg" not in out \
            and "<img" not in out, payload


def test_comparison_prose_keeps_raw_angle_bracket():
    from core.security.prompt_output_sanitise import (
        sanitise_inline,
        sanitise_string,
    )
    assert sanitise_string("a < b and 5 <= 6") == "a < b and 5 <= 6"
    assert sanitise_string("x <- y") == "x <- y"
    assert sanitise_inline("a < b") == "a < b"


def test_entity_escaped_html_passes_unchanged():
    """`&lt;h1&gt;` is inert to every CommonMark renderer (entities
    render as literal text, never as markup) — no raw `<` to escape,
    and no double-escape."""
    from core.security.prompt_output_sanitise import sanitise_string
    assert sanitise_string("&lt;h1&gt;quoted&lt;/h1&gt;") == \
        "&lt;h1&gt;quoted&lt;/h1&gt;"


def test_code_lane_keeps_raw_html():
    """Fenced-code lane contract: `#include <stdio.h>` stays verbatim —
    the wrapping fence isolates rendering; only the fence-break and
    control bytes are defanged there."""
    from core.security.prompt_output_sanitise import sanitise_code
    assert sanitise_code("#include <stdio.h>") == "#include <stdio.h>"


def test_report_supplement_layer_is_pinned():
    """Kills the delete-supplement mutation: `<mglyph src=//e>` is a
    fetching form the envelope alternation does NOT carry — only the
    report-side supplement strips it, so this pin fails if the PROSE
    lane loses its second autofetch layer."""
    from core.security.prompt_output_sanitise import (
        sanitise_inline,
        sanitise_string,
    )
    for fn in (sanitise_string, sanitise_inline):
        out = fn("x <mglyph src=//e> y")
        assert "mglyph" not in out, fn.__name__
        assert "[REDACTED-AUTOFETCH-MARKUP]" in out, fn.__name__


def test_html_hiding_adversarial_shapes():
    """Adversarial-pass pins: autolinks, indented type-6 openers,
    control-byte-split tags, and double-encoded entities must leave
    no live construct opener; whitespace-after-< prose (never a tag
    to any parser) keeps its raw bracket."""
    from core.security.prompt_output_sanitise import sanitise_string
    for payload in (
        "x\n<https://evil.example/hide>",   # markdown autolink
        "x\n   <details open>rest",          # 0-3 space indent, block type 6
        "x\n<\x00details>rest",              # control-byte split
        "<?XML version=1?>",
        "<![cdata[hidden]]>",
    ):
        out = sanitise_string(payload)
        assert "<" not in out.replace("&lt;", ""), (payload, out)
    assert sanitise_string("a < b and x <\ty") == "a < b and x <\ty"
