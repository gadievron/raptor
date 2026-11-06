"""Security boundaries exercised with local, inert reporting fixtures."""
from xml.etree import ElementTree
from pathlib import Path

import pytest

from core.reporting.builders import build_document
from core.reporting.document import Block, Inline, ReportContext
from core.reporting.lifecycle import apply_input_selection
from core.reporting.options import ReportOptions
from core.reporting.renderers import render_document
from core.reporting.writer import load_committed_report, publish_report, regenerate


def sample():
    context = ReportContext("scan", "fixture", state="completed")
    return context, build_document(context)


@pytest.mark.parametrize("label", ["x] ![unexpected image", "x\\] ![unexpected image", "[nested] ![image"])
def test_link_label_cannot_turn_link_into_an_autofetch_image(label):
    MarkdownIt = pytest.importorskip("markdown_it").MarkdownIt
    _, document = sample()
    document.blocks = [Block("paragraph", inline=[Inline("link", label, "https://example.invalid/reference")])]
    rendered = render_document(document).content.decode()
    html = MarkdownIt().render(rendered)
    assert "<img" not in html
    assert '<a href="https://example.invalid/reference">' in html


@pytest.mark.parametrize("body,parts", [
    ("!", [Inline("link", "reference", "https://example.invalid/reference")]),
    ("![split", [Inline("text", "](https://example.invalid/image)")]),
    ("", [Inline("text", "![split"), Inline("text", "](https://example.invalid/image)")]),
])
def test_separately_sanitised_fragments_cannot_compose_autofetch_markup(body, parts):
    MarkdownIt = pytest.importorskip("markdown_it").MarkdownIt
    _, document = sample()
    document.blocks = [Block("paragraph", text=body, inline=parts)]
    html = MarkdownIt().render(render_document(document).content.decode())
    assert "<img" not in html


@pytest.mark.parametrize("key", ["key\x00with\x1bcontrols", "key\ud800", "key\ufffe", 'key\"/><script>'])
def test_xml_keys_and_values_remain_parseable_inert_data(key):
    _, document = sample()
    document.metadata[key] = key
    document.extensions[key] = {key: key}
    root = ElementTree.fromstring(render_document(document, "xml").content)
    assert root.tag == "raptor-report"
    assert not root.findall(".//script")


@pytest.mark.parametrize("filename", ["manifest.json", "report-context.json", "report-document.json", "summary.json", "reporting-input.json", "findings-import.json"])
def test_payload_filename_overrides_cannot_replace_persistence_even_with_external_mirror(tmp_path, filename):
    context, document = sample()
    directory = tmp_path / "run"
    external = tmp_path / "external.json"
    options = ReportOptions(formats=("json",), filenames=(("json", filename),), output=external)
    with pytest.raises(ValueError, match="reserved"):
        publish_report(context, document, directory, options=options)
    assert not directory.exists() and not external.exists()


@pytest.mark.parametrize("filename", ["reporting-input.json", "findings-import.json"])
def test_publication_and_regeneration_preserve_lineage_state(tmp_path, filename):
    context, document = sample()
    publish_report(context, document, tmp_path)
    protected = tmp_path / filename
    protected.write_bytes(b"existing lineage state")
    with pytest.raises(ValueError, match="reserved"):
        publish_report(context, document, tmp_path, options=ReportOptions(formats=("json",), output=protected))
    with pytest.raises(ValueError, match="reserved"):
        regenerate(tmp_path, protected, format="json")
    assert protected.read_bytes() == b"existing lineage state"


def test_destination_alias_cannot_bypass_reserved_state_guard(tmp_path):
    context, document = sample()
    protected = tmp_path / "reporting-input.json"
    protected.write_bytes(b"retained")
    alias = tmp_path / "innocuous.json"
    alias.symlink_to(protected)
    with pytest.raises(ValueError, match="reserved"):
        publish_report(context, document, tmp_path, options=ReportOptions(formats=("json",), output=alias))
    assert protected.read_bytes() == b"retained" and alias.is_symlink()


def test_implicit_manifest_cannot_follow_a_symlink(tmp_path):
    context, document = sample()
    publish_report(context, document, tmp_path)
    pointer = tmp_path / "reporting-manifest.json"
    external = tmp_path / "other.json"
    pointer.rename(external)
    pointer.symlink_to(external)
    with pytest.raises(OSError):
        load_committed_report(tmp_path)


@pytest.mark.parametrize("name", ["reporting-manifest.json", "generation-manifest"])
def test_deep_json_manifest_is_a_typed_refusal(tmp_path, name):
    context, document = sample()
    published = publish_report(context, document, tmp_path)
    target = tmp_path / "reporting-manifest.json" if name == "reporting-manifest.json" else tmp_path / ".reporting" / published.generation / "manifest.json"
    target.write_text("[" * 2000 + "0" + "]" * 2000)
    with pytest.raises(ValueError):
        load_committed_report(tmp_path)


def test_input_selection_cannot_read_an_external_symlink(tmp_path):
    from core.json import save_json
    external = tmp_path / "external.json"
    save_json(external, {"schema_version": 1, "mode": "selected-findings", "owner": None,
                         "identity_policy": "exact-input-content-and-recorded-occurrence/v1",
                         "source_snapshot": "a" * 64, "selection": [], "private_note": "must not be captured"})
    (tmp_path / "reporting-input.json").symlink_to(external)
    context = ReportContext("validate", "fixture")
    apply_input_selection(context, tmp_path)
    assert "raptor.input_selection" not in context.extensions and not context.parents


@pytest.mark.parametrize("artifact", [{"path": []}, {"uri": {}}, {"canonical_digest": False}])
def test_malformed_artifact_references_are_rejected_before_path_operations(artifact):
    context = ReportContext("scan", "fixture", artifacts=[artifact])
    with pytest.raises(ValueError, match="artifact"):
        context.to_dict()


@pytest.mark.parametrize("field,value", [("source_id", {}), ("source_id", True), ("source_occurrence_ref", [])])
def test_malformed_identity_fields_are_typed_refusals(field, value):
    context = ReportContext("validate", "fixture", findings=[{"occurrence_ref": "fixture", field: value}])
    with pytest.raises(ValueError, match="normalized finding"):
        context.to_dict()


@pytest.mark.parametrize("source", [
    '---\nconfig:\n  securityLevel: loose\n---\nflowchart LR\nA-->B',
    'flowchart LR\nA@{img: "/private-image"}',
    'flowchart LR\nA["&#60;img src=/private-image&#62;"]',
])
def test_unsupported_mermaid_configuration_and_resources_use_text_fallback(source):
    _, document = sample()
    document.blocks = [Block("diagram", text="Recorded graph", extensions={"mermaid": source})]
    rendered = render_document(document)
    assert b"```mermaid" not in rendered.content
    assert b"Recorded graph" in rendered.content
    assert rendered.diagnostics


@pytest.mark.parametrize("authority", ["", "localhost", "LOCALHOST"])
def test_file_uri_artifact_is_protected_from_publication_and_regeneration(tmp_path, authority):
    source = tmp_path / "source evidence.json"
    source.write_bytes(b"retained source")
    uri = source.as_uri().replace("file://", "file://" + authority, 1)
    context = ReportContext("scan", "fixture", artifacts=[{"uri": uri}])
    document = build_document(context)
    publish_report(context, document, tmp_path)
    with pytest.raises(ValueError, match="input artifact"):
        publish_report(context, document, tmp_path, options=ReportOptions(formats=("json",), output=source))
    with pytest.raises(ValueError, match="source artifact"):
        regenerate(tmp_path, source, format="json")
    assert source.read_bytes() == b"retained source"


def test_format_diagnostics_are_sanitised_at_terminal_boundary(tmp_path, monkeypatch, capsys):
    from core.reporting.renderers import RenderedReport
    from core.reporting.service import complete_reporting
    import sys
    original = render_document
    def render(document, format="markdown"):
        content = original(document, format)
        return RenderedReport(content.content, ("fixture\x1b[31m\nFORGED",))
    monkeypatch.setattr("core.reporting.writer.render_document", render)
    context, document = sample()
    complete_reporting(context, tmp_path, document=document, stream=sys.stdout)
    text = capsys.readouterr().out
    assert "\x1b" not in text and "\\x1b" in text and "\nFORGED" not in text


def test_accounting_quick_view_is_bounded():
    from core.reporting.summary import build_operator_summary, render_operator_summary
    context = ReportContext("scan", "fixture", extensions={"raptor.accounting": {f"metric{i}": i for i in range(1000)}})
    text = render_operator_summary(build_operator_summary(context))
    assert "980 additional accounting fields" in text
    assert "metric999=" not in text


def test_reporting_generation_reader_refuses_intermediate_directory_swap(tmp_path, monkeypatch):
    import core.reporting.writer as writer
    context, document = sample()
    publish_report(context, document, tmp_path)
    external = tmp_path / "outside"
    external.mkdir()
    original = writer.open_regular_beneath
    swapped = False
    def swap(root, relative, **kwargs):
        nonlocal swapped
        if not swapped:
            (tmp_path / ".reporting").rename(tmp_path / "held")
            (tmp_path / ".reporting").symlink_to(external, target_is_directory=True)
            swapped = True
        return original(root, relative, **kwargs)
    monkeypatch.setattr(writer, "open_regular_beneath", swap)
    with pytest.raises(ValueError):
        load_committed_report(tmp_path)
    assert not list(external.iterdir())


def test_publication_refuses_reporting_directory_swap_after_preflight(tmp_path, monkeypatch):
    import core.reporting.writer as writer
    directory = tmp_path / "run"
    outside = tmp_path / "outside"
    outside.mkdir()
    original = writer._owned_dir
    def swap(path, root):
        result = original(path, root)
        if root.name == ".reporting":
            (directory / ".reporting").rename(tmp_path / "held")
            (directory / ".reporting").symlink_to(outside, target_is_directory=True)
        return result
    monkeypatch.setattr(writer, "_owned_dir", swap)
    context, document = sample()
    with pytest.raises(OSError):
        publish_report(context, document, directory)
    assert not list(outside.iterdir())
    assert not (directory / "reporting-manifest.json").exists()


def test_absolute_mirror_inside_relative_output_keeps_the_output_root_anchor(tmp_path, monkeypatch):
    import core.reporting.writer as writer
    monkeypatch.chdir(tmp_path)
    mirror = tmp_path / "run/nested/custom.md"
    observed = []
    original = writer.write_bytes_atomically
    def observe(path, content, **kwargs):
        if Path(path) == mirror:
            observed.append(kwargs.get("root"))
        return original(path, content, **kwargs)
    monkeypatch.setattr(writer, "write_bytes_atomically", observe)
    context, document = sample()
    publish_report(context, document, Path("run"), options=ReportOptions(output=mirror))
    assert observed == [tmp_path / "run"]


def test_unexpected_renderer_failure_cannot_abort_other_formats(tmp_path, monkeypatch):
    import core.reporting.renderers as renderers
    from core.reporting.service import complete_reporting
    def fail(document):
        raise RuntimeError("fixture\x1b[31m\nFORGED")
    monkeypatch.setitem(renderers._RENDERERS, "failure", renderers.Renderer("failure", ".fail", "application/test", fail))
    context, document = sample()
    result = complete_reporting(context, tmp_path, document=document, options=ReportOptions(formats=("failure", "json")))
    assert result.publication.committed
    assert result.publication.failed_formats == ["failure"]
    assert (tmp_path / "report.json").is_file()
    assert all("\x1b" not in note for note in result.diagnostics)


def test_validation_enrichment_cannot_capture_a_private_json_symlink(tmp_path):
    import json
    from core.json import save_json
    from packages.exploitability_validation.report import build_validation_spec
    directory = tmp_path / "run"
    directory.mkdir()
    private = tmp_path / "private.json"
    save_json(private, {"private_token": "PRIVATE_SENTINEL"})
    (directory / "capability-preflight.json").symlink_to(private)
    payload = {"findings": [{"id": "F1", "file": "a.c", "line": 1, "status": "not_disproven"}]}
    spec = build_validation_spec(str(directory), findings_data=payload, checklist={})
    assert spec.source_data["enrichment"]["Capability Preflight"] is None
    assert "PRIVATE_SENTINEL" not in json.dumps(spec.source_data)


def test_diagram_capture_cannot_follow_a_private_artifact_symlink(tmp_path):
    import json
    from dataclasses import asdict
    from core.json import save_json
    from packages.diagram.reporting import capture_directory_blocks
    directory = tmp_path / "run"
    directory.mkdir()
    private = tmp_path / "private.json"
    save_json(private, {"entry_points": [{"name": "PRIVATE_SENTINEL", "file": "a.c", "line": 1}], "sinks": []})
    (directory / "context-map.json").symlink_to(private)
    blocks = capture_directory_blocks(directory)
    assert "PRIVATE_SENTINEL" not in json.dumps([asdict(block) for block in blocks])
    assert any("unsafe" in block.text for block in blocks)


def test_frozen_diagrams_do_not_fall_back_to_a_live_graph_store(tmp_path, monkeypatch):
    from packages.diagram.reporting import capture_directory_blocks
    monkeypatch.setattr("packages.diagram.renderer._derive_directory_target",
                        lambda *args: pytest.fail("frozen capture must not query a live graph store"))
    capture_directory_blocks(tmp_path)
