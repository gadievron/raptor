"""Saved stage evidence keeps zero, unknown and unavailable values distinct."""
import hashlib

from core.reporting.builders import build_document
from core.reporting.document import ReportContext, StageEnvelope
from core.reporting.options import ReportOptions
from core.reporting.writer import load_committed_report, publish_report, regenerate


def test_stage_payload_survives_saved_readback_and_regeneration(tmp_path):
    source = tmp_path / "stage-evidence.json"
    original = b'{"marker":"supplied stage evidence"}'
    source.write_bytes(original)
    source_digest = hashlib.sha256(original).hexdigest()
    coverage = [{"unit": "function", "completed": 0, "total": None, "available": False,
                 "scope": "supplied partial inventory"}]
    artifacts = [{"uri": source.as_uri(), "digest": source_digest, "role": "recorded stage evidence"}]
    stage = StageEnvelope("saved stage", "partial", duration_seconds=0,
                          scope={"population": "supplied", "complete": False},
                          coverage=coverage, artifacts=artifacts,
                          diagnostics=["Population denominator was not recorded"])
    context = ReportContext("fixture", "saved", state="partial", stages=[stage],
                            expected_stages=["saved stage"])
    document = build_document(context)
    output = tmp_path / "report"
    publication = publish_report(context, document, output,
                                 options=ReportOptions(formats=("json", "markdown")))
    assert publication.committed and not publication.failed_formats
    generation = output / ".reporting" / publication.generation
    # The consistent reader must retain the stage payload despite damaged mirrors.
    for name in ("report-context.json", "report-document.json"):
        (output / name).write_bytes(b"stale compatibility mirror")

    restored, saved_document, _ = load_committed_report(output)
    recorded = restored.stages[0]
    assert restored.snapshot_id == saved_document.snapshot_id == context.snapshot_id
    assert recorded.coverage == coverage and recorded.artifacts == artifacts
    assert recorded.coverage[0]["completed"] == 0
    assert recorded.coverage[0]["total"] is None
    assert recorded.coverage[0]["available"] is False
    assert recorded.scope == stage.scope and recorded.duration_seconds == 0
    assert recorded.diagnostics == stage.diagnostics
    assert restored.completion_state == "partial"
    for format_name, filename in (("json", "report.json"), ("markdown", "report.md")):
        destination = tmp_path / ("regenerated-" + filename)
        assert regenerate(output, destination, format=format_name) == []
        assert destination.read_bytes() == (generation / filename).read_bytes()
    assert source.read_bytes() == original
