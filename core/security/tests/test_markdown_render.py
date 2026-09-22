"""Tests for core.security.markdown_render — the one-home markdown
writer helpers (fence / inline / prose) and their recognition by the
report-writer audit."""

from __future__ import annotations

import textwrap

from core.security.markdown_render import md_fence, md_inline, md_prose
from core.security.report_writer_audit import audit_source


# ---------------------------------------------------------------------------
# md_fence — fence-break defang
# ---------------------------------------------------------------------------

def test_md_fence_defuses_embedded_fence_terminator():
    hostile = "int main() {}\n```\n# INJECTED HEADING\n<img src=//evil>"
    out = md_fence(hostile)
    # No parse-relevant fence terminator survives: every 3+ backtick
    # run carries a ZWSP after the second backtick.
    assert "```" not in out
    # The visible content survives for the reader.
    assert "int main() {}" in out


def test_md_fence_escapes_control_bytes():
    out = md_fence("safe\x1b[31mANSI\x9bC1")
    assert "\x1b" not in out
    assert "\x9b" not in out


def test_md_fence_caps_length():
    assert len(md_fence("A" * 50_000)) <= 10_000


# ---------------------------------------------------------------------------
# md_inline — single-line slots
# ---------------------------------------------------------------------------

def test_md_inline_flattens_newlines_and_escapes_structure():
    out = md_inline("evil\n# forged | cell `span`")
    assert "\n" not in out
    assert "|" not in out
    assert "`" not in out


def test_md_inline_strips_autofetch_markup():
    out = md_inline('CWE-78 <img src="//attacker/x">')
    assert "<img" not in out.lower()


def test_md_inline_accepts_non_string_values():
    assert md_inline(None) == "None"
    assert md_inline(42) == "42"


# ---------------------------------------------------------------------------
# md_prose — multi-line free text
# ---------------------------------------------------------------------------

def test_md_prose_preserves_newlines_defangs_structure():
    out = md_prose("para one\n# forged heading\npara two")
    assert "para one\n" in out
    assert "\n# " not in out


def test_md_prose_strips_autofetch_markup():
    assert "![" not in md_prose("look ![x](https://evil/beacon)")


# ---------------------------------------------------------------------------
# Writer-audit recognition — the helpers ARE the recognised sanitisers
# ---------------------------------------------------------------------------

def test_writer_audit_recognises_md_helpers():
    src = textwrap.dedent(
        """
        lines = []
        for f in findings:
            lines.append(f"### {md_inline(f.get('title'))}")
            lines.append(md_prose(f.get('description')))
            lines.append(md_fence(f.get('details')))
        """
    )
    assert audit_source(src, "snippet.py") == []


def test_writer_audit_still_fires_without_md_helpers():
    src = textwrap.dedent(
        """
        lines = []
        for f in findings:
            lines.append(f"### {f.get('title')}")
        """
    )
    assert any(v.detail == "title" for v in audit_source(src, "snippet.py"))
