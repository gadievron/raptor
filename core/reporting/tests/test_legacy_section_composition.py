"""Legacy fallback and explicit portable sections keep their capture contract."""
from copy import deepcopy
from dataclasses import asdict
import json

import pytest

from core.reporting.builders import document_from_spec
from core.reporting.document import Block, ReportContext
from core.reporting.options import ReportOptions
from core.reporting.spec import ReportSection, ReportSpec
from core.reporting.writer import load_committed_report, publish_report


@pytest.mark.parametrize("legacy", [False, True], ids=["portable-only", "mixed"])
def test_section_precedence_survives_committed_json_and_markdown(tmp_path, legacy):
    details = [ReportSection("Portable detail", "ignored-detail-fallback", blocks=[
        Block("paragraph", text="portable-detail-sentinel")])]
    sections = [ReportSection("Portable extra", "ignored-extra-fallback", blocks=[
        Block("paragraph", text="portable-extra-sentinel")]),
        ReportSection("Explicit empty", "ignored-empty-fallback", blocks=[])]
    if legacy:
        sections.append(ReportSection("Legacy extra", "retained-legacy-sentinel"))
    spec = ReportSpec(title="Captured composition", summary={"Count": 0, "Available": False,
                                                            "Recorded": {"items": [None, "nested-sentinel"]}},
                      detail_sections=details, sections=sections)
    original_spec = deepcopy(asdict(spec))
    context = ReportContext("fixture", "saved", state="unknown")
    original_context = context.to_dict()
    document = document_from_spec(spec, context)
    original_document = document.to_dict()
    publication = publish_report(context, document, tmp_path,
                                 options=ReportOptions(formats=("json", "markdown")))
    assert publication.committed and not publication.failed_formats
    restored, captured, manifest = load_committed_report(tmp_path)
    assert restored.to_dict() == original_context == context.to_dict()
    assert captured.to_dict() == original_document == document.to_dict()
    assert asdict(spec) == original_spec
    assert captured.extensions["raptor.legacy_sections"] is legacy
    assert captured.summary == {"Count": 0, "Available": False}
    structured = next(block for block in captured.blocks if block.title == "Structured legacy summary")
    assert json.loads(structured.text) == {"Recorded": original_spec["summary"]["Recorded"]}
    empty = next(block for block in captured.blocks if block.title == "Explicit empty")
    assert empty.kind == "section" and empty.children == [] and empty.text == ""
    generation = tmp_path / ".reporting" / manifest["generation"]
    assert json.loads((generation / "report.json").read_bytes()) == original_document
    markdown = (generation / "report.md").read_text(encoding="utf-8")
    assert "portable-detail-sentinel" in markdown and "portable-extra-sentinel" in markdown
    assert "nested-sentinel" in markdown
    assert all(value not in markdown for value in ("ignored-detail-fallback", "ignored-extra-fallback", "ignored-empty-fallback"))
    assert ("retained-legacy-sentinel" in markdown) is legacy
    assert ("Legacy Markdown displayed as literal text" in markdown) is legacy
    if legacy:
        assert "```text\nretained-legacy-sentinel\n```" in markdown
