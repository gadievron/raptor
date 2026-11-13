"""Publication must not select stage state that changes during snapshot reload."""
import io

from core.reporting.builders import build_document
from core.reporting.document import ReportContext, StageEnvelope
from core.reporting.options import ReportOptions
from core.reporting.service import complete_reporting
from core.reporting.writer import load_committed_report, publish_report


def test_mutated_unknown_state_cannot_replace_committed_snapshot(tmp_path):
    output = tmp_path / "output"
    options = ReportOptions(formats=("json",))
    previous = ReportContext("scan", "previous", state="completed", stages=[StageEnvelope("scanner", "completed")])
    publish_report(previous, build_document(previous), output, options=options)
    before = {name: (output / name).read_bytes() for name in
              ("reporting-manifest.json", "report-context.json", "report-document.json", "report.json")}
    stage = StageEnvelope("scanner", "completed")
    stage.state = "producer_future"
    context = ReportContext("scan", "next", state="completed", stages=[stage])
    result = complete_reporting(context, output, options=options, stream=io.StringIO())
    assert result.errors
    assert stage.state == "producer_future"
    assert all((output / name).read_bytes() == data for name, data in before.items())
    restored, _, _ = load_committed_report(output)
    assert restored.snapshot_id == previous.snapshot_id
    assert restored.stages[0].state == "completed"


def test_unknown_constructor_state_keeps_canonical_unknown_roundtrip(tmp_path):
    stage = StageEnvelope("scanner", "producer_future")
    assert stage.state == "unknown" and stage.original_state == "producer_future"
    context = ReportContext("scan", "saved", state="completed", stages=[stage])
    publish_report(context, build_document(context), tmp_path, options=ReportOptions(formats=("json",)))
    restored, _, _ = load_committed_report(tmp_path)
    assert restored.snapshot_id == context.snapshot_id
    assert restored.stages[0].state == "unknown"
    assert restored.stages[0].original_state == "producer_future"
    assert restored.stages[0].diagnostics == stage.diagnostics
    assert restored.completion_state == "partial"


def test_known_state_mutation_remains_roundtrippable(tmp_path):
    stage = StageEnvelope("scanner", "running")
    stage.state = "failed"
    context = ReportContext("scan", "saved", state="completed", stages=[stage])
    publish_report(context, build_document(context), tmp_path, options=ReportOptions(formats=("json",)))
    restored, _, _ = load_committed_report(tmp_path)
    assert restored.snapshot_id == context.snapshot_id
    assert restored.stages[0].state == "failed"
    assert restored.completion_state == "partial"
