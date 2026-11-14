"""Document-declared sources survive publication and summary fallback writes."""
from io import StringIO
import json

import pytest

from core.reporting.document import Block, ReportContext, ReportDocument
from core.reporting.options import ReportOptions
from core.reporting.service import complete_reporting
from core.reporting.writer import load_committed_report, publish_report


def _tree(directory):
    return {str(p.relative_to(directory)): p.read_bytes() for p in directory.rglob("*") if p.is_file()}


def _custom(source, *, uri=False, context_source=None):
    context = ReportContext("fixture", "saved", artifacts=[{"path": str(context_source)}] if context_source else [],
                            extensions={"raptor.findings_available": False})
    reference = {"uri": source.as_uri()} if uri else {"path": str(source)}
    document = ReportDocument("Saved custom view", "fixture", context.snapshot_id,
                              blocks=[Block("paragraph", text="Recorded custom content")],
                              extensions={"raptor.artifacts": [reference]})
    return context, document


@pytest.mark.parametrize("uri", [False, True], ids=["path", "local-uri"])
def test_publication_preserves_sources_declared_in_either_payload(tmp_path, uri):
    source = tmp_path / "document source.json"
    context_source = tmp_path / "context source.json"
    for path in (source, context_source):
        path.write_bytes(b'{"owned":"source"}\n')
    context, document = _custom(source, uri=uri, context_source=context_source)
    originals = context.to_dict(), document.to_dict()
    output = tmp_path / "capture"
    initial = publish_report(context, document, output, options=ReportOptions(formats=("json",)))
    assert initial.committed
    prior_tree = _tree(output)
    for destination in (source, context_source):
        original = destination.read_bytes()
        with pytest.raises(ValueError, match="input artifact"):
            publish_report(context, document, output, options=ReportOptions(formats=("json",), output=destination))
        assert destination.read_bytes() == original and _tree(output) == prior_tree
    assert (context.to_dict(), document.to_dict()) == originals


@pytest.mark.parametrize("enabled", [False, True], ids=["disabled-export", "enabled-export"])
@pytest.mark.parametrize("filename", ["summary.json", "summary.md"])
def test_document_summary_source_survives_initial_and_diagnostic_refresh(tmp_path, enabled, filename):
    output = tmp_path / "capture"
    output.mkdir()
    source = output / filename
    original = b"owned original source\n"
    source.write_bytes(original)
    context, document = _custom(source)
    originals = context.to_dict(), document.to_dict()
    stream = StringIO()
    result = complete_reporting(context, output, document=document,
                                options=ReportOptions(formats=("json",), enabled=enabled), stream=stream)
    assert result.errors
    assert source.read_bytes() == original
    counterpart = output / ("summary.md" if filename == "summary.json" else "summary.json")
    assert not counterpart.exists()
    assert "Structured command result captured" in stream.getvalue()
    assert (context.to_dict(), document.to_dict()) == originals
    if enabled:
        assert result.publication.committed and "summary" in result.publication.failed_formats
        assert any("input artifact preserved" in note for note in result.diagnostics)
        assert load_committed_report(output)[1].to_dict() == document.to_dict()
    else:
        assert result.publication is None and not (output / "reporting-manifest.json").exists()


def test_separate_publication_keeps_document_refs_without_mutating_context(tmp_path):
    source = tmp_path / "source.json"
    source.write_bytes(b'{"owned":"captured"}\n')
    original = source.read_bytes()
    context, document = _custom(source)
    originals = context.to_dict(), document.to_dict()
    output = tmp_path / "capture"
    result = complete_reporting(context, output, document=document,
                                options=ReportOptions(formats=("json", "markdown")), stream=StringIO())
    assert not result.errors and result.publication.committed
    saved_context, saved_document, manifest = load_committed_report(output)
    assert saved_context.artifacts == []
    assert saved_document.extensions["raptor.artifacts"] == document.extensions["raptor.artifacts"]
    assert (context.to_dict(), document.to_dict()) == originals
    generation = output / ".reporting" / manifest["generation"]
    assert json.loads((generation / "report.json").read_bytes()) == document.to_dict()
    assert source.read_bytes() == original
