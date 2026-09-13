"""Tests for markdown_render.render."""

from __future__ import annotations

import pytest

pytest.importorskip("markdown")

from packages.studio.services import markdown_render  # noqa: E402
from packages.studio.services.markdown_render import render  # noqa: E402

# Without nh3, render() fails closed to an escaped <pre> block, so every
# assertion about rich output structure only holds when nh3 is present.
requires_nh3 = pytest.mark.skipif(
    markdown_render.nh3 is None,
    reason="nh3 not installed - render falls back to escaped <pre>",
)


def test_empty_input_returns_empty():
    assert render("") == ""
    assert render(None) == ""


@requires_nh3
def test_heading_rendered():
    html = render("# Hello")
    assert "<h1>" in html
    assert "Hello" in html


@requires_nh3
def test_fenced_code_block_rendered():
    html = render("```python\nprint('x')\n```")
    assert "<pre>" in html
    assert "<code" in html
    assert "print" in html


@requires_nh3
def test_bullet_list_rendered():
    html = render("- a\n- b\n- c\n")
    assert "<ul>" in html
    assert html.count("<li>") == 3


@requires_nh3
def test_table_rendered_via_extra_extension():
    src = "| Col A | Col B |\n|-------|-------|\n| v1 | v2 |\n"
    html = render(src)
    assert "<table>" in html
    assert "<th>" in html
    assert "v1" in html and "v2" in html


@requires_nh3
def test_link_rendered():
    html = render("[click](https://example.com)")
    assert 'href="https://example.com"' in html


@requires_nh3
def test_sequential_renders_are_independent():
    # Footnotes / toc state should not leak across calls.
    a = render("# First\n\nBody A.")
    b = render("# Second\n\nBody B.")
    assert "First" in a and "Second" not in a
    assert "Second" in b and "First" not in b


# --- sanitisation: report content is untrusted ------------------------------

@requires_nh3
def test_script_tag_stripped():
    html = render("before\n\n<script>alert(1)</script>\n\nafter")
    assert "<script" not in html
    assert "alert(1)" not in html
    assert "before" in html and "after" in html


@requires_nh3
def test_event_handler_stripped():
    html = render('<img src="x" onerror="alert(1)">')
    assert "onerror" not in html


@requires_nh3
def test_javascript_url_stripped():
    html = render('[click](javascript:alert(1))')
    assert "javascript:" not in html


@requires_nh3
def test_iframe_and_form_stripped():
    html = render('<iframe src="https://evil.example"></iframe>\n\n<form action="/settings"></form>')
    assert "<iframe" not in html
    assert "<form" not in html


@requires_nh3
def test_script_inside_fenced_code_stays_escaped_text():
    html = render("```html\n<script>alert(1)</script>\n```")
    assert "<script>" not in html
    assert "&lt;script&gt;" in html  # visible as text inside the code block


@requires_nh3
def test_structure_survives_sanitisation():
    src = (
        "# Report\n\n"
        "| Col A | Col B |\n|-------|-------|\n| v1 | v2 |\n\n"
        "```python\nprint('x')\n```\n\n"
        "[link](https://example.com)\n"
    )
    html = render(src)
    assert "<h1>" in html
    assert "<table>" in html
    assert "<pre>" in html and "<code" in html
    assert 'href="https://example.com"' in html


def test_missing_sanitiser_fails_closed(monkeypatch):
    # Without nh3, render must never emit markup — escaped <pre> only.
    monkeypatch.setattr(markdown_render, "nh3", None)
    html = render("# Heading\n\n<script>alert(1)</script>")
    assert html.startswith("<pre>")
    assert "<script" not in html
    assert "&lt;script&gt;" in html
