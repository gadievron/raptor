"""Tests for markdown_render.render."""

from __future__ import annotations

from packages.studio.services.markdown_render import render


def test_empty_input_returns_empty():
    assert render("") == ""
    assert render(None) == ""


def test_heading_rendered():
    html = render("# Hello")
    assert "<h1>" in html
    assert "Hello" in html


def test_fenced_code_block_rendered():
    html = render("```python\nprint('x')\n```")
    assert "<pre>" in html
    assert "<code" in html
    assert "print" in html


def test_bullet_list_rendered():
    html = render("- a\n- b\n- c\n")
    assert "<ul>" in html
    assert html.count("<li>") == 3


def test_table_rendered_via_extra_extension():
    src = "| Col A | Col B |\n|-------|-------|\n| v1 | v2 |\n"
    html = render(src)
    assert "<table>" in html
    assert "<th>" in html
    assert "v1" in html and "v2" in html


def test_link_rendered():
    html = render("[click](https://example.com)")
    assert 'href="https://example.com"' in html


def test_sequential_renders_are_independent():
    # Footnotes / toc state should not leak across calls.
    a = render("# First\n\nBody A.")
    b = render("# Second\n\nBody B.")
    assert "First" in a and "Second" not in a
    assert "Second" in b and "First" not in b
