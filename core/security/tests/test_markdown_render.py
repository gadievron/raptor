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


def test_md_prose_defuses_tilde_fence():
    # A line-leading `~~~` opens a tilde fence (the ``` twin): left
    # alive in a finding message it renders the writer's OWN following
    # sections — snippet fence, next finding's heading — as literal
    # code, hiding them from the report reader.
    import re
    out = md_prose("open\n~~~\nswallow the rest of the report")
    assert not re.search(r"(?m)^[ \t]*~", out)
    assert "swallow the rest of the report" in out


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


def test_md_prose_defangs_structural_html():
    from core.security.markdown_render import md_prose
    out = md_prose("ok\n<h1>ALL CLEAR</h1>\n<!--\nhidden findings")
    assert "<h1>" not in out and "<!--" not in out
    assert "hidden findings" in out


def test_md_inline_defangs_structural_html():
    from core.security.markdown_render import md_inline
    assert "<h1>" not in md_inline("t<h1>forge</h1>")


def test_md_inline_default_cap_is_300():
    """Kills the cap mutation (300 → 300000 survived the battery):
    the default md_inline cap is a load-bearing bound for heading /
    label / cell slots."""
    from core.security.markdown_render import md_inline
    assert len(md_inline("A" * 1000)) <= 300


def test_md_fence_preserves_code_verbatim():
    """Kills the body-swap mutation (md_fence → sanitise_string
    survived): md_fence's distinguishing contract is that it does NOT
    strip or escape markdown/code characters — `#include`, `*ptr`,
    and raw `<...>` are legitimate code the wrapping fence isolates."""
    from core.security.markdown_render import md_fence
    assert md_fence("#include <a>\n*ptr") == "#include <a>\n*ptr"


def test_no_registered_writer_opens_tilde_fences():
    """md_fence's fence-break defang covers backtick runs only; a
    ~~~-wrapped fence gets no protection (and in-value tilde runs
    are legitimate code, so they are deliberately not defanged).
    Writers must fence with backticks — pinned across the registry."""
    from pathlib import Path
    from core.security.report_writer_audit import (
        _MERMAID_FENCE_FILES,
        _REPORT_WRITER_FILES,
    )
    repo = Path(__file__).resolve().parents[3]
    offenders = []
    for rel in _REPORT_WRITER_FILES + _MERMAID_FENCE_FILES:
        p = repo / rel
        if not p.exists():
            continue
        if "~~~" in p.read_text(encoding="utf-8"):
            offenders.append(rel)
    assert not offenders, (
        f"tilde fences in registered writers {offenders} — md_fence "
        "protects backtick fences only; use ``` wrappers"
    )
