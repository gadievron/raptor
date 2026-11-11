"""Explicit publication loss changes completeness, not durable assessments."""
import copy
import json

import pytest

from core.audit.report import (
    UNACKNOWLEDGED_ASSESSMENTS_LIMITATION,
    generate_report,
    write_markdown_report,
    write_report,
)
from core.audit.tests.test_report_completeness import TestCompleteRunReport as _CompleteRun
from core.audit.tests.test_report_completeness import _journal
from core.audit.report_document import build_audit_document
from core.reporting.renderers import get_renderer


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


LABEL = "new review assessments (journal acknowledgement unavailable)"


REASON = "initial_journal_acknowledgement_unavailable"


PRIVATE = "PRIVATE_UNPUBLISHED_REVIEW_ERROR_591"


def test_unacknowledged_assessment_reaches_saved_completeness_only(tmp_path):
    out = _CompleteRun()._complete_run(tmp_path)
    _journal(out, "prior_supported", "finding")
    inputs = {p.name: p.read_bytes() for p in out.iterdir() if p.is_file()}
    baseline = generate_report(out, final_status="completed")
    failures = [{"reason": REASON, "adjudication": "unverified",
                 "unpublished_assessment": {"status": "finding", "body": PRIVATE},
                 "error": PRIVATE}] * 30
    before = copy.deepcopy(failures)
    report = generate_report(out, final_status="completed", publication_failures=failures)
    assert report["completeness"]["missing"] == [LABEL]
    assert report["completeness"]["partial"] is True
    assert report["completeness"]["run_status"] == "completed"
    assert report["completeness"]["resumable"] is False
    assert report["stats"] == baseline["stats"]
    assert report["stats"]["finding"] == 1 and report["stats"]["clean"] == 1
    assert report["findings"] == baseline["findings"]
    assert report["findings_count"] == baseline["findings_count"]
    assert failures == before
    context, document = build_audit_document(report, out)
    assert context.state == "partial"
    (out / "audit-report.json").write_text(json.dumps(report), encoding="utf-8")
    for fmt in ("json", "markdown"):
        content = get_renderer(fmt).render(document).content
        (out / ("publication-report." + fmt)).write_bytes(content)
        assert LABEL in content.decode() and PRIVATE not in content.decode()
        assert "persistence failed" not in content.decode()
    assert PRIVATE not in json.dumps(report)
    assert LABEL in write_markdown_report(report, out).read_text()
    for name, contents in inputs.items():
        assert (out / name).read_bytes() == contents


@pytest.mark.parametrize("failures", [None, [], [{}], [{"reason": "ordinary_pass_error", "adjudication": "unverified"}],
                                      [{"reason": REASON, "adjudication": "verified"}],
                                      [{"reason": REASON + " private", "adjudication": "unverified"}]])
def test_unrelated_or_missing_publication_signal_is_not_relabelled(tmp_path, failures):
    out = _CompleteRun()._complete_run(tmp_path)
    baseline = generate_report(out, final_status="completed")
    assert generate_report(out, final_status="completed", publication_failures=failures) == baseline


def test_publication_list_and_retention_limitations_remain_distinct(tmp_path):
    out = _CompleteRun()._complete_run(tmp_path)
    persistence = "new dark verification pass results (persistence failed)"
    report = generate_report(out, final_status="completed", processing_limitations=[persistence],
                             publication_failures=[{"reason": REASON, "adjudication": "unverified"}])
    assert report["completeness"]["missing"] == [persistence, LABEL]
