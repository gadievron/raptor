"""Renderer-local mutations cannot rewrite other formats or captured inputs."""
import json

import pytest

from core.reporting import renderers
from core.reporting.builders import build_document
from core.reporting.document import Block, Inline, ReportContext, encode
from core.reporting.options import ReportOptions
from core.reporting.writer import load_committed_report, load_context, publish_report


@pytest.mark.parametrize("fail", [False, True], ids=["returned", "refused"])
def test_renderer_receives_an_independent_nested_document(tmp_path, monkeypatch, fail):
    source = tmp_path / "saved-context.json"
    context = ReportContext("fixture", "saved", extensions={"fixture.raw": {"values": [0, False, None]}})
    source.write_bytes(encode({**context.to_dict(), "snapshot_id": context.snapshot_id}))
    source_bytes = source.read_bytes()
    context = load_context(source)
    block = Block("section", title="Original section", extensions={"fixture.nested": {"items": ["original"]}},
                  children=[Block("paragraph", text="Original prose", inline=[Inline("strong", "Original inline")])])
    document = build_document(context, blocks=[block])
    original_context, original_document = context.to_dict(), document.to_dict()
    original_markdown = renderers.render_document(document).content
    registry = renderers._RENDERERS
    name = "owned-copy-fixture"
    assert name not in registry
    calls = []

    def mutate(local):
        assert local is not document and local.to_dict() == original_document
        calls.append(local.snapshot_id)
        local.title = "mutated-callback-sentinel"
        local.metadata["fixture"] = "mutated-callback-sentinel"
        local.diagnostics.append("mutated-callback-sentinel")
        section = next(b for b in local.blocks if b.title == "Original section")
        section.extensions["fixture.nested"]["items"].append("mutated-callback-sentinel")
        section.children[0].text = "mutated-callback-sentinel"
        section.children[0].inline[0].text = "mutated-callback-sentinel"
        if fail:
            raise ValueError("inert callback refusal")
        return renderers.RenderedReport(b"inert callback output")

    output = tmp_path / "report"
    with monkeypatch.context() as scoped:
        scoped.setattr(renderers, "_RENDERERS", dict(registry))
        renderers.register_renderer(renderers.Renderer(name, ".owned", "application/x-inert", mutate))
        publication = publish_report(context, document, output,
                                     options=ReportOptions(formats=(name, "json", "markdown")))
    assert renderers._RENDERERS is registry and calls == [context.snapshot_id]
    assert publication.committed and publication.failed_formats == ([name] if fail else [])
    restored, saved_document, manifest = load_committed_report(output)
    assert restored.to_dict() == original_context == context.to_dict()
    assert saved_document.to_dict() == original_document == document.to_dict()
    generation = output / ".reporting" / manifest["generation"]
    assert json.loads((generation / "report.json").read_bytes()) == original_document
    assert (generation / "report.md").read_bytes() == original_markdown
    assert (generation / "report.owned").exists() is not fail
    if not fail:
        assert (generation / "report.owned").read_bytes() == b"inert callback output"
    assert source.read_bytes() == source_bytes
