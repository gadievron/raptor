"""Unavailable engagement overlays stay unavailable in captured presentation."""
from copy import deepcopy
import json

import pytest

from core.engagement import report as engagement
from core.reporting.options import ReportOptions
from core.reporting.tests.test_audit_engagement_documents import engagement_report
from core.reporting.writer import load_committed_report


@pytest.mark.parametrize("consumed", [False, True], ids=["unavailable", "consumed"])
def test_prebuilt_overlay_readback_preserves_raw_values_without_earned_credit(tmp_path, monkeypatch, consumed):
    report = engagement_report()
    values = [12345, 23456, 34567, 45678]
    overlay = dict(zip(("checklist_items", "reviewed_analysed_depth", "no_lane_residual",
                        "advisory_llm_extent_including_reads"), values))
    overlay["consumed"] = consumed
    if not consumed:
        overlay["reason"] = "unavailable"
    report["coverage"]["per_artifact"][0]["overlay"] = overlay
    source = tmp_path / "saved-engagement.json"
    source.write_text(json.dumps(report), encoding="utf-8")
    source_bytes = source.read_bytes()
    captured = json.loads(source_bytes)
    original = deepcopy(captured)
    output = tmp_path / "report"
    output.mkdir()
    sink = []
    actual_builder = engagement.build_report

    def forbidden(*args, **kwargs):
        pytest.fail("prebuilt reporting must not synthesize engagement state")

    with monkeypatch.context() as scoped:
        scoped.setattr(engagement, "build_report", forbidden)
        native_json, markdown_path = engagement.write_report(
            output, report=captured, report_options=ReportOptions(formats=("json", "markdown")), reporting_sink=sink)
    assert engagement.build_report is actual_builder
    assert len(sink) == 1 and not sink[0].errors and sink[0].publication.committed
    context, document, manifest = load_committed_report(output)
    assert context.extensions["raptor.engagement"] == original == captured
    assert json.loads(native_json.read_bytes()) == original
    assert context.findings == [] and sink[0].summary.findings_available is False
    assert context.completion_state == "unknown"
    coverage = context.extensions["raptor.engagement"]["coverage"]
    assert coverage["earned_journal_rows_total"] == {"clean": 2}
    assert coverage["at_verdict_time_rows_total"] == {"clean": 1}
    assert coverage["per_artifact"][0]["overlay"] == overlay
    section = next(block for block in document.blocks if block.title == "Coverage Synthesis")
    table = next(block for block in section.children if block.kind == "table")
    assert table.rows[0][2:] == (values if consumed else ["—", "—", "Unavailable", "—"])
    assert table.rows[0][1] == "2 (partial load) (rows absent since verdict)"
    generation = output / ".reporting" / manifest["generation"]
    assert json.loads((generation / "engagement-summary.json").read_bytes()) == document.to_dict()
    markdown = markdown_path.read_text(encoding="utf-8")
    assert markdown_path.read_bytes() == (generation / "engagement-report.md").read_bytes()
    assert "never count as earned coverage" in markdown
    for value in values:
        assert (str(value) in markdown) is consumed
    if not consumed:
        assert "Unavailable" in markdown
    assert source.read_bytes() == source_bytes
