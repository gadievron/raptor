"""Explicit retention limitations affect completeness, never prior assessments."""
import json

import pytest

from core.audit.report import generate_report, write_markdown_report
from core.audit.report_document import build_audit_document
from core.audit.tests.test_report_completeness import TestCompleteRunReport as _CompleteRun
from core.reporting.renderers import get_renderer

DARK = "new dark verification pass results (persistence failed)"
DIFFERENTIAL = "new differential verification pass results (persistence failed)"


@pytest.mark.parametrize("label", [DARK, DIFFERENTIAL])
def test_known_retention_failure_reaches_persisted_report(tmp_path, label):
    out = _CompleteRun()._complete_run(tmp_path)
    before_bytes = {p.name: p.read_bytes() for p in out.iterdir() if p.is_file()}
    baseline = generate_report(out, final_status="completed")
    limitations = [label, label]
    report = generate_report(out, final_status="completed", processing_limitations=limitations)
    assert report["completeness"]["partial"] is True
    assert report["completeness"]["missing"] == [label]
    assert report["completeness"]["run_status"] == "completed"
    assert report["completeness"]["resumable"] is False
    assert report["stats"] == baseline["stats"]
    assert report["findings"] == baseline["findings"]
    assert report["stats"]["clean"] == 1 and report["stats"]["error"] == 0
    assert limitations == [label, label]
    context, document = build_audit_document(report, out)
    assert context.state == "partial"
    for fmt in ("json", "markdown"):
        content = get_renderer(fmt).render(document).content
        (out / ("processing-report." + fmt)).write_bytes(content)
        assert label in content.decode()
    (out / "audit-report.json").write_text(json.dumps(report), encoding="utf-8")
    assert json.loads((out / "audit-report.json").read_text())["completeness"]["missing"] == [label]
    assert label in write_markdown_report(report, out).read_text()
    for name, contents in before_bytes.items():
        assert (out / name).read_bytes() == contents


@pytest.mark.parametrize("limitations", [None, [], ["ordinary pass error: private detail"], [DARK.upper()]])
def test_absent_or_unrecognised_signal_does_not_invent_persistence_failure(tmp_path, limitations):
    out = _CompleteRun()._complete_run(tmp_path)
    baseline = generate_report(out, final_status="completed")
    report = generate_report(out, final_status="completed", processing_limitations=limitations)
    assert report == baseline
    assert report["completeness"]["partial"] is False
    assert "private detail" not in json.dumps(report)


def test_two_fixed_signals_are_bounded_and_ordered(tmp_path):
    out = _CompleteRun()._complete_run(tmp_path)
    report = generate_report(out, final_status="completed",
                             processing_limitations=[DIFFERENTIAL, DARK] * 30)
    assert report["completeness"]["missing"] == [DARK, DIFFERENTIAL]
