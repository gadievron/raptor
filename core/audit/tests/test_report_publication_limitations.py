"""Explicit publication loss changes completeness, not durable assessments."""
import json

import pytest

from core.audit.report import (
    UNACKNOWLEDGED_ASSESSMENTS_LIMITATION,
    generate_report,
    write_markdown_report,
    write_report,
)
from core.audit.tests.test_report_completeness import TestCompleteRunReport as _CompleteRun


def test_unacknowledged_assessment_is_disclosed_without_replacing_prior(tmp_path):
    out = _CompleteRun()._complete_run(tmp_path)
    prior = {p.name: p.read_bytes() for p in out.iterdir() if p.is_file()}
    baseline = generate_report(out, final_status="completed")
    report = generate_report(
        out, final_status="completed", unacknowledged_assessments=True,
    )
    completeness = report["completeness"]
    assert completeness["partial"] is True
    assert completeness["missing"] == [UNACKNOWLEDGED_ASSESSMENTS_LIMITATION]
    assert completeness["run_status"] == "completed"
    assert completeness["resumable"] is False
    assert report["stats"] == baseline["stats"]
    assert report["findings"] == baseline["findings"]
    assert report["stats"]["clean"] == 1 and report["stats"]["error"] == 0
    saved = json.loads(write_report(report, out).read_text())
    assert saved["completeness"] == completeness
    assert UNACKNOWLEDGED_ASSESSMENTS_LIMITATION in write_markdown_report(report, out).read_text()
    for name, content in prior.items():
        assert (out / name).read_bytes() == content


@pytest.mark.parametrize("signal", [False, None, 1, "true", {"body": "private proposal"}])
def test_only_explicit_boolean_signal_changes_completeness(tmp_path, signal):
    out = _CompleteRun()._complete_run(tmp_path)
    baseline = generate_report(out, final_status="completed")
    report = generate_report(
        out, final_status="completed", unacknowledged_assessments=signal,
    )
    assert report == baseline
    assert report["completeness"]["partial"] is False
    assert "private proposal" not in json.dumps(report)


def test_publication_and_retention_limitations_remain_distinct(tmp_path):
    out = _CompleteRun()._complete_run(tmp_path)
    dark = "new dark verification pass results (persistence failed)"
    report = generate_report(
        out, final_status="completed", processing_limitations=[dark, dark],
        unacknowledged_assessments=True,
    )
    assert report["completeness"]["missing"] == [dark, UNACKNOWLEDGED_ASSESSMENTS_LIMITATION]
    assert report["stats"]["clean"] == 1 and report["stats"]["error"] == 0
