"""Partial-format publications remain readable without the optional renderer."""
import hashlib
from io import StringIO
import json

import pytest

from core.reporting import renderers
from core.reporting.builders import build_document
from core.reporting.document import ReportContext
from core.reporting.options import ReportOptions
from core.reporting.service import complete_reporting
from core.reporting.writer import load_committed_report, load_context, regenerate


@pytest.mark.parametrize("invalid_first", [False, True], ids=["json-first", "invalid-first"])
def test_partial_publication_reloads_and_regenerates_after_renderer_removed(tmp_path, monkeypatch, invalid_first):
    source = tmp_path / "context.json"
    context = ReportContext("fixture", "saved", state="unknown", artifacts=[{"path": str(source)}],
                            extensions={"fixture.raw": {"zero": 0, "available": False, "unknown": None},
                                        "raptor.findings_available": False})
    source.write_text(json.dumps(context.to_dict()))
    source_bytes = source.read_bytes()
    context = load_context(source)
    original = context.to_dict()
    document = build_document(context)
    original_document = document.to_dict()
    registry = renderers._RENDERERS
    name = "owned-invalid"
    assert name not in registry
    calls = []
    def invalid(captured):
        assert captured.to_dict() == original_document
        calls.append(captured.snapshot_id)
        return None
    formats = (name, "json") if invalid_first else ("json", name)
    output = tmp_path / "report"
    with monkeypatch.context() as scoped:
        scoped.setattr(renderers, "_RENDERERS", dict(registry))
        renderers.register_renderer(renderers.Renderer(name, ".invalid", "application/test", invalid))
        result = complete_reporting(context, output, document=document,
                                    options=ReportOptions(formats), stream=StringIO())
    assert renderers._RENDERERS is registry and calls == [context.snapshot_id]
    assert result.errors == [name]
    assert result.publication and result.publication.committed
    assert result.publication.failed_formats == [name]
    assert set(result.publication.outputs) == {"json"}
    restored, captured, manifest = load_committed_report(output)
    assert restored.to_dict() == original == context.to_dict()
    assert captured.to_dict() == original_document == document.to_dict()
    assert manifest["status"] == "partial" and manifest["formats"] == list(formats)
    assert manifest["render_failures"] == [name] and manifest["failed_formats"] == [name]
    assert f"{name} report failed (ValueError)" in manifest["diagnostics"]
    generation = output / ".reporting" / manifest["generation"]
    content = (generation / "report.json").read_bytes()
    assert json.loads(content) == captured.to_dict()
    assert (output / "report.json").read_bytes() == content
    assert manifest["files"]["report.json"] == {"size": len(content), "sha256": hashlib.sha256(content).hexdigest()}
    assert "report.invalid" not in manifest["files"]
    assert not (generation / "report.invalid").exists() and not (output / "report.invalid").exists()
    previous_files = {str(path.relative_to(output)): path.read_bytes() for path in output.rglob("*") if path.is_file()}
    regenerated = tmp_path / "regenerated.json"
    assert regenerate(output, regenerated, format="json") == []
    assert regenerated.read_bytes() == content
    assert {str(path.relative_to(output)): path.read_bytes() for path in output.rglob("*") if path.is_file()} == previous_files
    assert source.read_bytes() == source_bytes
