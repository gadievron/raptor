"""Distinct filename overrides preserve formats sharing a renderer extension."""
import hashlib
import json

import pytest

from core.reporting import renderers
from core.reporting.builders import build_document
from core.reporting.document import ReportContext
from core.reporting.options import ReportOptions
from core.reporting.writer import load_committed_report, publish_report


@pytest.mark.parametrize("custom_first", [False, True], ids=["builtin-first", "custom-first"])
def test_same_extension_formats_publish_distinct_overridden_files(tmp_path, monkeypatch, custom_first):
    source = tmp_path / "source.json"
    source.write_text(json.dumps({"label": "retained capture"}), encoding="utf-8")
    source_bytes = source.read_bytes()
    context = ReportContext("fixture", "saved", artifacts=[{"path": str(source)}],
                            extensions={"fixture.raw": json.loads(source_bytes), "raptor.findings_available": False})
    document = build_document(context)
    original_context, original_document = context.to_dict(), document.to_dict()
    builtin_bytes = renderers.render_document(document, "markdown").content
    custom_bytes = b"# Inert alternate representation\n"
    registry = renderers._RENDERERS
    name = "owned-alternate-md"
    assert name not in registry
    calls = []

    def alternate(captured):
        assert captured.to_dict() == original_document
        calls.append(captured.snapshot_id)
        return renderers.RenderedReport(custom_bytes)

    formats = (name, "md") if custom_first else ("md", name)
    output = tmp_path / "report"
    with monkeypatch.context() as scoped:
        scoped.setattr(renderers, "_RENDERERS", dict(registry))
        renderers.register_renderer(renderers.Renderer(name, ".md", "text/markdown", alternate))
        publication = publish_report(context, document, output, options=ReportOptions(
            formats=formats, filenames=(("md", "portable.md"), (name, "alternate.md"))))
    assert renderers._RENDERERS is registry and calls == [context.snapshot_id]
    assert publication.committed and publication.failed_formats == []
    expected_paths = {"markdown": str(output / "portable.md"), name: str(output / "alternate.md")}
    assert publication.outputs == expected_paths
    restored, captured_document, manifest = load_committed_report(output)
    assert restored.to_dict() == original_context == context.to_dict()
    assert captured_document.to_dict() == original_document == document.to_dict()
    assert manifest["formats"] == ([name, "markdown"] if custom_first else ["markdown", name])
    assert manifest["outputs"] == expected_paths
    generation = output / ".reporting" / manifest["generation"]
    for filename, content in (("portable.md", builtin_bytes), ("alternate.md", custom_bytes)):
        assert (output / filename).read_bytes() == content
        assert (generation / filename).read_bytes() == content
        assert manifest["files"][filename] == {"size": len(content), "sha256": hashlib.sha256(content).hexdigest()}
    assert not (output / "report.md").exists()
    assert source.read_bytes() == source_bytes
