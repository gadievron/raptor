"""Known dispatch deferrals survive report rendering without review credit."""
import json

from core.audit.report import generate_report, write_report, write_markdown_report
from core.audit.tests.test_report_completeness import TestCompleteRunReport as _CompleteRun


def test_current_binary_deferral_does_not_poison_a_later_complete_report(tmp_path):
    out = _CompleteRun()._complete_run(tmp_path)
    label = "No implementation view was available for this binary unit; review deferred"
    baseline = generate_report(out, final_status="completed")
    report = generate_report(out, final_status="completed", processing_limitations=[label, label])
    assert report["completeness"]["partial"] is True
    assert report["completeness"]["missing"] == [label]
    assert report["stats"] == baseline["stats"]
    assert report["findings"] == baseline["findings"]
    write_report(report, out)
    saved = json.loads((out / "audit-report.json").read_text())
    assert saved["completeness"]["missing"] == [label]
    assert label in write_markdown_report(report, out).read_text()
    # Unlike an irretrievably lost assessment, a deferred dispatch can be
    # repaired. A later complete projection must not inherit a sticky failure.
    assert not (out / "processing-completeness.json").exists()
    recovered = generate_report(out, final_status="completed", processing_limitations=[])
    assert recovered["completeness"]["partial"] is False
    assert recovered["completeness"]["missing"] == []
    assert recovered["stats"] == baseline["stats"]
    assert recovered["findings"] == baseline["findings"]
