"""Structured captures remain readable when formatted exports are disabled."""
import pytest

from core.reporting.adapters import native_findings
from core.reporting.builders import build_document
from core.reporting.document import Block, ReportContext
from core.reporting.options import ReportOptions
from core.reporting.writer import load_committed_report, publish_report


def _context(label):
    return ReportContext("fixture", label, findings=native_findings(
        [{"id": "F1", "file": "a.c", "line": 1, "message": label}],
        run_id=label, producer="fixture", triage=True))


def _tree(directory):
    return {path.relative_to(directory): None if path.is_dir() else path.read_bytes()
            for path in directory.rglob("*")}


@pytest.mark.parametrize("invalid,expected_error", [
    ("schema", "Unsupported report document schema version"),
    ("metadata", "Report metadata and summary values must be scalar"),
    ("table", "Table rows must match columns and contain scalar values"),
])
def test_disabled_writer_cannot_select_an_unreadable_document(tmp_path, invalid, expected_error):
    output = tmp_path / "report"
    prior = _context("before")
    publication = publish_report(prior, build_document(prior), output, options=ReportOptions(formats=("json",)))
    assert publication.committed
    before = _tree(output)
    context = _context("after")
    document = build_document(context)
    if invalid == "schema":
        document.schema_version = True
    elif invalid == "metadata":
        document.metadata["nested"] = {"not": "scalar"}
    else:
        document.blocks.append(Block("table", columns=["one"], rows=[["extra", "cell"]]))
    captured = context.to_dict()
    malformed = document.to_dict()
    refusal = None
    try:
        publish_report(context, document, output, options=ReportOptions(enabled=False))
    except ValueError as exc:
        refusal = exc
    # Check the actual selected reader as well as the admission refusal.
    restored, _, manifest = load_committed_report(output)
    assert refusal is not None and expected_error in str(refusal)
    assert restored.to_dict() == prior.to_dict()
    assert manifest["generation"] == publication.generation
    assert _tree(output) == before
    assert document.to_dict() == malformed and context.to_dict() == captured


def test_valid_disabled_writer_still_captures_structured_inputs(tmp_path):
    context = _context("captured")
    document = build_document(context)
    document.metadata.update({"zero": 0, "available": False, "unknown": None})
    output = tmp_path / "report"
    publication = publish_report(context, document, output, options=ReportOptions(enabled=False))
    assert publication.committed and publication.outputs == {} and publication.failed_formats == []
    restored, captured_document, _ = load_committed_report(output)
    assert restored.to_dict() == context.to_dict() and captured_document.to_dict() == document.to_dict()
    assert not (output / "report.md").exists() and not (output / "report.json").exists()
    assert restored.findings[0]["status"] == "Unconfirmed"
