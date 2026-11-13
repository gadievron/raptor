"""Quick-view stage and diagnostic caps retain the complete saved capture."""
from io import StringIO
import json

import pytest

from core.reporting.document import ReportContext, StageEnvelope, encode
from core.reporting.options import ReportOptions
from core.reporting.service import complete_reporting
from core.reporting.writer import load_committed_report, load_context


@pytest.mark.parametrize("count", [30, 32], ids=["boundary", "overflow"])
def test_stage_and_diagnostic_caps_keep_committed_records(tmp_path, count):
    notes = [f"captured-note-{index:02d}" for index in range(count)]
    context = ReportContext("fixture", "saved", state="partial", diagnostics=list(notes),
                            stages=[StageEnvelope(f"captured-stage-{index:02d}", "unknown",
                                                  diagnostics=[notes[index]]) for index in range(count)],
                            extensions={"raptor.findings_available": False})
    source = tmp_path / "saved-context.json"
    source.write_bytes(encode({**context.to_dict(), "snapshot_id": context.snapshot_id}))
    source_bytes = source.read_bytes()
    context = load_context(source)
    original = context.to_dict()
    stream = StringIO()
    output = tmp_path / "report"
    result = complete_reporting(context, output, options=ReportOptions(formats=("json", "markdown")),
                                stream=stream)
    assert not result.errors and result.publication.committed
    restored, document, manifest = load_committed_report(output)
    assert restored.to_dict() == original == context.to_dict()
    assert source.read_bytes() == source_bytes
    summary = result.summary
    assert summary.stage_total == count and len(summary.stages) == 30
    assert summary.diagnostic_total == count
    assert summary.diagnostics[:30] == notes[:30]
    assert len(summary.diagnostics) == (31 if count > 30 else 30)
    assert summary.state == "partial" and not summary.findings_available
    assert summary.total == 0 and summary.counts == {} and summary.rows == []
    generation = output / ".reporting" / manifest["generation"]
    for home in (output, generation):
        saved = json.loads((home / "summary.json").read_bytes())
        assert saved == summary.to_dict() == document.extensions["raptor.summary"]
        markdown = (home / "summary.md").read_text(encoding="utf-8")
        for rendered in (stream.getvalue(), markdown):
            assert "captured-stage-29" in rendered and "captured-note-29" in rendered
            assert ("additional stages retained in report context" in rendered) is (count > 30)
            assert ("additional diagnostics retained in report context" in rendered) is (count > 30)
            if count > 30:
                assert "2 additional stages" in rendered and "2 additional diagnostics" in rendered
                assert "captured-stage-31" not in rendered and "captured-note-31" not in rendered
    assert [stage.stage_id for stage in restored.stages] == [f"captured-stage-{index:02d}" for index in range(count)]
    assert restored.diagnostics == notes
    assert [stage.diagnostics for stage in restored.stages] == [[note] for note in notes]
