"""Offline exports use the committed document rather than mutable mirrors."""
import json

import pytest

from core.reporting.builders import build_document
from core.reporting.document import Block, ReportContext
from core.reporting.options import ReportOptions
from core.reporting.writer import load_committed_report, publish_report, regenerate


def _tree(directory):
    return {path.relative_to(directory): None if path.is_dir() else path.read_bytes()
            for path in directory.rglob("*")}


@pytest.mark.parametrize("format", ["json", "markdown"])
def test_committed_regeneration_ignores_stale_mirrors_and_retains_notes(tmp_path, format):
    source = tmp_path / "captured-evidence.json"
    source.write_bytes(b'{"fixture":"unchanged source"}')
    context = ReportContext("fixture", "saved", artifacts=[{"path": str(source)}],
                            extensions={"fixture.raw": {"zero": 0, "available": False, "unknown": None}})
    document = build_document(context, blocks=[Block("legacy_markdown", text="captured literal sentinel")])
    directory = tmp_path / "report"
    publication = publish_report(context, document, directory,
                                 options=ReportOptions(formats=("json", "markdown")))
    assert publication.committed and not publication.failed_formats
    generation = directory / ".reporting" / publication.generation
    expected_export = (generation / ("report.json" if format == "json" else "report.md")).read_bytes()
    for filename in ("report-context.json", "report-document.json", "report.json", "report.md"):
        (directory / filename).write_bytes(b"stale unreadable compatibility fixture")
    before = _tree(directory)
    source_bytes = source.read_bytes()
    destination = tmp_path / ("regenerated.json" if format == "json" else "regenerated.md")
    diagnostics = regenerate(directory, destination, format=format)
    assert destination.read_bytes() == expected_export
    if format == "json":
        assert json.loads(destination.read_bytes()) == document.to_dict()
        assert diagnostics == []
    else:
        assert b"```text\ncaptured literal sentinel\n```" in destination.read_bytes()
        assert diagnostics == ["Legacy Markdown displayed as literal text; portable blocks are required for formatted presentation"]
        assert diagnostics[0].encode() in destination.read_bytes()
    restored, saved_document, manifest = load_committed_report(directory)
    assert restored.to_dict() == context.to_dict()
    assert saved_document.to_dict() == document.to_dict()
    assert manifest["generation"] == publication.generation
    assert _tree(directory) == before and source.read_bytes() == source_bytes
