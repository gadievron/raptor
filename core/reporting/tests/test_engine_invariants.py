"""Adversarial correctness checks for snapshots, retries, and reporting IO."""
from __future__ import annotations

import io
import json

import pytest

from core.reporting.adapters import native_findings
from core.reporting.builders import build_document
from core.reporting.document import Block, ReportContext, ReportDocument, StageEnvelope
from core.reporting.options import ReportOptions
from core.reporting.service import complete_reporting
from core.reporting.writer import load_committed_report, publish_report


def sample(message="first"):
    context = ReportContext("validate", "same-run", target="source", state="completed")
    context.findings = native_findings([{"id": "F1", "message": message, "file": "a.c", "line": 2}],
                                       run_id=context.run_id, producer="validate")
    return context


@pytest.mark.parametrize("key", ["path", "uri"])
def test_native_artifacts_cannot_be_overwritten_by_report_destinations(tmp_path, key):
    source = tmp_path / "source.json"
    source.write_text('{"evidence":true}')
    context = sample()
    context.artifacts = [{key: str(source)}]
    result = complete_reporting(context, tmp_path, options=ReportOptions(formats=("json",), output=source))
    assert result.errors
    assert source.read_text() == '{"evidence":true}'


@pytest.mark.parametrize("state", ["failed", "cancelled"])
def test_failed_or_cancelled_run_is_not_downgraded_to_partial(state):
    from core.reporting.summary import build_operator_summary
    context = sample()
    context.state = state
    context.stages = [StageEnvelope("scan", "failed")]
    assert build_operator_summary(context).state == state


def test_domain_builder_failure_cannot_hide_completed_finding_summary(tmp_path):
    output = io.StringIO()
    def fail(context):
        raise ValueError("domain document cannot be captured")
    result = complete_reporting(sample(), tmp_path, document_factory=fail, stream=output)
    assert result.errors
    assert "Captured findings: 1" in output.getvalue()
    assert json.loads((tmp_path / "summary.json").read_text())["total"] == 1


def test_generation_identity_includes_filenames(tmp_path):
    c = sample()
    d = build_document(c)
    first = publish_report(c, d, tmp_path, stem="one")
    before = (tmp_path / ".reporting" / first.generation / "manifest.json").read_bytes()
    second = publish_report(c, d, tmp_path, stem="two")
    assert first.generation != second.generation
    assert (tmp_path / ".reporting" / first.generation / "manifest.json").read_bytes() == before


def test_external_destination_does_not_mutate_immutable_generation(tmp_path):
    c = sample()
    d = build_document(c)
    first = publish_report(c, d, tmp_path, options=ReportOptions(output=tmp_path / "first.md"))
    manifest = tmp_path / ".reporting" / first.generation / "manifest.json"
    before = manifest.read_bytes()
    publish_report(c, d, tmp_path, options=ReportOptions(output=tmp_path / "second.md"))
    assert manifest.read_bytes() == before


def test_rejected_publication_cannot_replace_current_summary(tmp_path):
    c = sample()
    first = complete_reporting(c, tmp_path)
    generation = first.publication.generation
    newer = sample("newer")
    complete_reporting(newer, tmp_path, expected_generation=generation)
    before = (tmp_path / "summary.json").read_bytes()
    stale = sample("stale")
    result = complete_reporting(stale, tmp_path, expected_generation=generation)
    assert result.errors
    assert (tmp_path / "summary.json").read_bytes() == before


def test_native_occurrences_do_not_alias_different_pass_contents():
    first = sample("first")
    second = sample("different observation")
    assert first.findings[0]["occurrence_ref"] != second.findings[0]["occurrence_ref"]


def test_string_false_does_not_hide_a_native_finding():
    findings = native_findings([{"suppressed": "false"}], run_id="r", producer="p")
    assert findings[0]["suppressed"] is False


def test_no_full_render_success_keeps_last_committed_generation(tmp_path, monkeypatch):
    c = sample()
    first = publish_report(c, build_document(c), tmp_path)
    before = (tmp_path / "reporting-manifest.json").read_bytes()
    def fail(*args, **kwargs):
        raise ValueError("renderer failed")
    monkeypatch.setattr("core.reporting.writer.render_document", fail)
    d = build_document(sample("second"))
    result = publish_report(sample("second"), d, tmp_path)
    assert result.failed_formats
    assert (tmp_path / "reporting-manifest.json").read_bytes() == before
    assert (tmp_path / ".reporting" / first.generation / "report-document.json").exists()


def test_summary_failure_does_not_prevent_other_report_outputs(tmp_path, monkeypatch):
    def fail(*args, **kwargs):
        raise OSError("summary destination unavailable")
    monkeypatch.setattr("core.reporting.service.write_summary", fail)
    c = sample()
    result = complete_reporting(c, tmp_path, stream=io.StringIO())
    assert (tmp_path / "report.md").exists()
    assert result.publication is not None


@pytest.mark.parametrize("data", [
    {"kind": [], "title": "x"},
    {"kind": "table", "columns": ["one"], "rows": [[1, 2]]},
])
def test_malformed_blocks_have_typed_errors(data):
    with pytest.raises(ValueError):
        Block.from_dict(data)


@pytest.mark.parametrize("field,value", [("diagnostics", "not a list"), ("duration_seconds", -1), ("scope", []), ("stage_id", 3)])
def test_stage_envelopes_validate_wire_types(field, value):
    with pytest.raises(ValueError):
        StageEnvelope(**{"stage_id": "A", field: value})


def test_invalid_manifest_is_reported_without_crashing_completion(tmp_path):
    (tmp_path / "reporting-manifest.json").write_text("[]")
    result = complete_reporting(sample(), tmp_path, stream=io.StringIO(), expected_generation="old")
    assert result.errors


def test_context_loader_rejects_duplicate_occurrences():
    c = sample()
    payload = c.to_dict()
    payload["findings"].append(dict(payload["findings"][0]))
    with pytest.raises(ValueError, match="occurrence"):
        ReportContext.from_dict(payload)


def test_document_loader_rejects_non_scalar_metadata():
    data = build_document(sample()).to_dict()
    data["metadata"]["target"] = {"nested": "object"}
    with pytest.raises(ValueError):
        ReportDocument.from_dict(data)


def test_summary_input_artifact_is_never_overwritten(tmp_path):
    source = tmp_path / "summary.json"
    source.write_text(json.dumps({"source": "evidence"}))
    before = source.read_bytes()
    c = sample()
    c.artifacts = [{"path": str(source)}]
    result = complete_reporting(c, tmp_path, stream=io.StringIO())
    assert source.read_bytes() == before
    assert result.diagnostics


def test_committed_reader_ignores_stale_compatibility_mirrors(tmp_path):
    c = sample()
    publish_report(c, build_document(c), tmp_path)
    (tmp_path / "report-context.json").write_text("corrupted mirror")
    actual, document, manifest = load_committed_report(tmp_path)
    assert actual.snapshot_id == document.snapshot_id == manifest["snapshot_id"] == c.snapshot_id


def test_committed_reader_rejects_modified_capture(tmp_path):
    c = sample()
    result = publish_report(c, build_document(c), tmp_path)
    (tmp_path / ".reporting" / result.generation / "report-document.json").write_text("{}")
    with pytest.raises(ValueError, match="digest mismatch"):
        load_committed_report(tmp_path)


def test_render_failure_then_retry_creates_a_new_immutable_generation(tmp_path, monkeypatch):
    import core.reporting.writer as writer
    real = writer.render_document
    c = sample()
    def fail(*args, **kwargs):
        raise ValueError("transient renderer failure")
    monkeypatch.setattr(writer, "render_document", fail)
    failed = writer.publish_report(c, build_document(c), tmp_path)
    failed_manifest = tmp_path / ".reporting" / failed.generation / "manifest.json"
    before = failed_manifest.read_bytes()
    monkeypatch.setattr(writer, "render_document", real)
    success = writer.publish_report(c, build_document(c), tmp_path)
    assert success.generation != failed.generation
    assert failed_manifest.read_bytes() == before
