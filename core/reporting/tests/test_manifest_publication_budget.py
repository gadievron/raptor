"""Publication must not select control records larger than its reader accepts."""
import io
import json
from types import SimpleNamespace

import pytest

from core.reporting import renderers, writer
from core.reporting.builders import build_document
from core.reporting.document import ReportContext
from core.reporting.options import ReportOptions
from core.reporting.renderers import RenderedReport, Renderer, register_renderer
from core.reporting.service import complete_reporting


@pytest.fixture
def captured_report(tmp_path, monkeypatch):
    monkeypatch.setattr(renderers, "_RENDERERS", dict(renderers._RENDERERS))
    state = SimpleNamespace(output=tmp_path / "report", note="", calls=0)

    def render(document):
        state.calls += 1
        return RenderedReport(b"captured renderer output\n", (state.note,))

    register_renderer(Renderer("budget-fixture", ".txt", "text/plain", render))
    state.context = ReportContext("scan", "captured")
    state.document = build_document(state.context)
    state.previous = writer.publish_report(state.context, state.document, state.output,
                                           options=ReportOptions(formats=("json",)))
    state.before = {name: (state.output / name).read_bytes() for name in
                    ("reporting-manifest.json", "report-context.json", "report-document.json", "report.json")}
    state.options = ReportOptions(formats=("budget-fixture",))
    return state


def _assert_previous_retained(state):
    assert all((state.output / name).read_bytes() == data for name, data in state.before.items())
    context, document, manifest = writer.load_committed_report(state.output)
    assert manifest["generation"] == state.previous.generation
    assert context.snapshot_id == document.snapshot_id == state.context.snapshot_id
    historical, _, _ = writer.load_report_generation(state.output, state.previous.generation, state.context.snapshot_id)
    assert historical.to_dict() == state.context.to_dict()


def test_oversized_diagnostics_cannot_replace_readable_report(captured_report):
    state = captured_report
    state.note = "x" * (1024 * 1024 + 1)
    with pytest.raises(ValueError, match="manifest.*limit"):
        writer.publish_report(state.context, state.document, state.output, options=state.options)
    assert state.calls == 1
    _assert_previous_retained(state)


def test_current_record_budget_preserves_pointer_when_immutable_record_fits(captured_report):
    state = captured_report
    probe = writer.publish_report(state.context, state.document, state.output, options=state.options)
    probe_path = state.output / ".reporting" / probe.generation / "manifest.json"
    base_size = probe_path.stat().st_size
    pointer = state.output / "reporting-manifest.json"
    assert pointer.stat().st_size > base_size
    before = pointer.read_bytes()
    prior_directories = set((state.output / ".reporting").iterdir())
    # ASCII notes change encoded size one byte at a time; all identity hashes
    # have fixed length. Calibrate against actual publisher output, not a
    # second implementation of its control-record format.
    state.note = "x" * (1024 * 1024 - base_size)
    with pytest.raises(ValueError, match="manifest.*limit"):
        writer.publish_report(state.context, state.document, state.output, options=state.options)
    assert state.calls == 2
    assert pointer.read_bytes() == before
    staged = set((state.output / ".reporting").iterdir()) - prior_directories
    assert len(staged) == 1
    generation = staged.pop()
    assert (generation / "manifest.json").stat().st_size == 1024 * 1024
    assert writer.load_committed_report(state.output)[2]["generation"] == probe.generation
    assert writer.load_report_generation(state.output, generation.name, state.context.snapshot_id)[0].to_dict() == state.context.to_dict()
    # Compatibility mirrors are nontransactional; only the committed pointer
    # is required to remain selected after this final-record refusal.


def test_ordinary_diagnostics_roundtrip_without_truncation(captured_report):
    state = captured_report
    state.note = "Captured renderer limitation"
    publication = writer.publish_report(state.context, state.document, state.output, options=state.options)
    assert publication.committed and publication.diagnostics == [state.note]
    context, document, manifest = writer.load_committed_report(state.output)
    assert context.snapshot_id == document.snapshot_id == state.context.snapshot_id
    assert manifest["diagnostics"] == [state.note]
    immutable = state.output / ".reporting" / publication.generation / "manifest.json"
    assert json.loads(immutable.read_bytes())["diagnostics"] == [state.note]


def test_completion_reports_budget_failure_and_keeps_previous_report(captured_report):
    state = captured_report
    state.note = "private-note" + "x" * (1024 * 1024)
    stream = io.StringIO()
    result = complete_reporting(state.context, state.output, document=state.document,
                                options=state.options, stream=stream)
    assert result.errors and result.publication is None
    assert "persistence failed" in stream.getvalue()
    assert "private-note" not in stream.getvalue()
    assert state.calls == 1
    _assert_previous_retained(state)


def test_mirror_failure_keeps_partial_selection_when_metadata_fits(captured_report, monkeypatch):
    state = captured_report
    state.note = "Captured renderer limitation"
    original = writer.write_bytes_atomically
    refused = []

    def write(path, content, **kwargs):
        if path == state.output / "report.txt":
            refused.append(path)
            raise OSError("owned mirror unavailable")
        return original(path, content, **kwargs)

    monkeypatch.setattr(writer, "write_bytes_atomically", write)
    publication = writer.publish_report(state.context, state.document, state.output, options=state.options)
    assert publication.committed and publication.failed_formats == ["budget-fixture"]
    assert refused == [state.output / "report.txt"]
    context, document, manifest = writer.load_committed_report(state.output)
    assert context.snapshot_id == document.snapshot_id == state.context.snapshot_id
    assert manifest["status"] == "partial" and manifest["outputs"] == {}
    assert state.note in manifest["diagnostics"]
