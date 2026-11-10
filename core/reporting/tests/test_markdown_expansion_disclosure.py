"""Presentation loss is measured after sanitisation, not only on raw input."""
from copy import deepcopy

from core.reporting.document import Block, ReportDocument
from core.reporting.renderers import render_document
from core.security.markdown_render import md_inline


def test_escape_expansion_truncation_is_disclosed_without_changing_cell_content():
    value = "|" * 1000
    document = ReportDocument("Owned captured report", "fixture", "owned", blocks=[
        Block("table", columns=["Value"], rows=[[value]]),
    ])
    before = deepcopy(document.to_dict())
    rendered = render_document(document)
    expected = md_inline(value, max_chars=4000)
    assert len(value) < 4000 and len(expected) == 4000 and expected.endswith("…")
    assert ("| " + expected + " |").encode() in rendered.content
    assert any("truncated" in note for note in rendered.diagnostics)
    assert document.to_dict() == before


def test_removed_markup_does_not_claim_length_truncation():
    value = "![image](https://example.invalid/" + "x" * 6000 + ")"
    document = ReportDocument("Owned captured report", "fixture", "owned", blocks=[
        Block("table", columns=["Value"], rows=[[value]]),
    ])
    rendered = render_document(document)
    assert len(value) > 4000 and len(md_inline(value, max_chars=4000)) < 4000
    assert not any("truncated" in note for note in rendered.diagnostics)
    assert b"https://example.invalid" not in rendered.content


def test_exact_presentation_limit_is_not_reported_as_truncated():
    value = "a" * 3999 + "…"
    rendered = render_document(ReportDocument(value, "fixture", "owned"))
    assert ("# " + value).encode() in rendered.content
    assert not any("truncated" in note for note in rendered.diagnostics)
