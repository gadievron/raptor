"""Cancellation during rendering preserves the previously committed report."""
from io import StringIO

import pytest

from core.reporting import renderers, writer
from core.reporting.adapters import native_findings
from core.reporting.document import ReportContext, encode
from core.reporting.options import ReportOptions
from core.reporting.service import complete_reporting


def _context(label):
    return ReportContext("fixture", label, target=label, state="completed", findings=native_findings(
        [{"id": "F1", "rule_id": f"rule-{label}", "file": "a.c", "line": 1}],
        run_id=label, producer="fixture", triage=True))


def _tree(directory):
    return {path.relative_to(directory): None if path.is_dir() else path.read_bytes()
            for path in directory.rglob("*")}


@pytest.mark.parametrize("exception_type", [KeyboardInterrupt, SystemExit], ids=["keyboard", "system-exit"])
def test_renderer_cancellation_after_json_keeps_prior_generation(tmp_path, monkeypatch, exception_type):
    output = tmp_path / "report"
    before = _context("before")
    result = complete_reporting(before, output, options=ReportOptions(formats=("json", "markdown")),
                                stream=StringIO())
    assert not result.errors and result.publication.committed
    prior_context, prior_document, prior_manifest = writer.load_committed_report(output)
    prior_tree = _tree(output)
    source = tmp_path / "current-context.json"
    current = _context("after")
    current.artifacts = [{"path": str(source)}]
    source.write_bytes(encode({**current.to_dict(), "snapshot_id": current.snapshot_id}))
    original = source.read_bytes()
    current = writer.load_context(source)
    primary = exception_type("fixture cancellation")
    calls = []
    successful_renders = []
    registry = renderers._RENDERERS
    actual_render = writer.render_document
    format_name = "owned-cancel-fixture"
    assert format_name not in registry

    def cancel(document):
        assert document.snapshot_id == current.snapshot_id
        calls.append(document.snapshot_id)
        raise primary

    def observe(document, format="markdown"):
        rendered = actual_render(document, format)
        successful_renders.append(format)
        return rendered

    console = StringIO()
    with monkeypatch.context() as scoped:
        scoped.setattr(renderers, "_RENDERERS", dict(registry))
        scoped.setattr(writer, "render_document", observe)
        renderers.register_renderer(renderers.Renderer(format_name, ".cancel", "application/x-inert", cancel))
        with pytest.raises(exception_type) as caught:
            complete_reporting(current, output, options=ReportOptions(formats=("json", format_name)),
                               expected_generation=prior_manifest["generation"], stream=console)
        assert caught.value is primary
    assert renderers._RENDERERS is registry and writer.render_document is actual_render
    assert successful_renders == ["json"] and calls == [current.snapshot_id]
    assert "rule-after" in console.getvalue()
    assert _tree(output) == prior_tree and source.read_bytes() == original
    restored, document, manifest = writer.load_committed_report(output)
    assert restored.to_dict() == prior_context.to_dict()
    assert document.to_dict() == prior_document.to_dict()
    assert manifest["generation"] == prior_manifest["generation"]
