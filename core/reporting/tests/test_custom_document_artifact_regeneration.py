"""Committed custom views protect sources retained by their paired context."""
from io import StringIO
import json

import pytest

from core.reporting.document import Block, ReportContext, ReportDocument
from core.reporting.options import ReportOptions
from core.reporting.service import complete_reporting
from core.reporting.writer import load_committed_report, regenerate


def _tree(directory):
    return {str(p.relative_to(directory)): p.read_bytes() for p in directory.rglob("*") if p.is_file()}


def _capture(tmp_path, *, uri=False, extra=False):
    output = tmp_path / "capture"
    output.mkdir()
    source = output / "owned source.json"
    source.write_bytes(b'{"captured":"source"}\n')
    additional = tmp_path / "extra.json"
    additional.write_bytes(b'{"extra":"source"}\n')
    reference = {"uri": source.as_uri()} if uri else {"path": source.name}
    context = ReportContext("fixture", "saved", artifacts=[reference])
    extensions = {"raptor.artifacts": [{"path": str(additional)}]} if extra else {}
    document = ReportDocument("Custom saved view", "fixture", context.snapshot_id,
                              blocks=[Block("paragraph", text="Recorded custom content")], extensions=extensions)
    document_before = document.to_dict()
    result = complete_reporting(context, output, document=document,
                                options=ReportOptions(formats=("json", "markdown")), stream=StringIO())
    assert not result.errors and result.publication.committed
    saved_context, saved_document, manifest = load_committed_report(output)
    assert saved_context.artifacts == [reference]
    assert saved_document.to_dict() == document_before == document.to_dict()
    return output, source, additional, saved_document, manifest


@pytest.mark.parametrize("role", ["context-relative", "context-uri", "document-extra"])
def test_directory_regeneration_preserves_context_and_document_sources(tmp_path, role):
    output, source, additional, _, _ = _capture(tmp_path, uri=role == "context-uri", extra=role == "document-extra")
    destination = additional if role == "document-extra" else source
    before = destination.read_bytes()
    captured_tree = _tree(output)
    with pytest.raises(ValueError, match="source artifact"):
        regenerate(output, destination, format="json")
    assert destination.read_bytes() == before
    assert _tree(output) == captured_tree


@pytest.mark.parametrize("format,filename", [("json", "report.json"), ("markdown", "report.md")])
def test_custom_document_regenerates_elsewhere_without_rewriting_capture(tmp_path, format, filename):
    output, _, additional, document, manifest = _capture(tmp_path, extra=True)
    captured_tree = _tree(output)
    additional_before = additional.read_bytes()
    expected = (output / ".reporting" / manifest["generation"] / filename).read_bytes()
    destination = tmp_path / ("regenerated" + (".json" if format == "json" else ".md"))
    assert regenerate(output, destination, format=format) == []
    assert destination.read_bytes() == expected
    assert _tree(output) == captured_tree and additional.read_bytes() == additional_before
    assert load_committed_report(output)[1].to_dict() == document.to_dict()


def test_explicit_document_keeps_its_declared_source_protection(tmp_path):
    output, _, additional, document, _ = _capture(tmp_path, extra=True)
    standalone = tmp_path / "standalone.json"
    standalone.write_text(json.dumps(document.to_dict()))
    original = additional.read_bytes()
    captured_tree = _tree(output)
    with pytest.raises(ValueError, match="source artifact"):
        regenerate(standalone, additional, format="json")
    assert additional.read_bytes() == original and _tree(output) == captured_tree
