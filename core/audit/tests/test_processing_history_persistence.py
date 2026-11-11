"""Report rebuilds retain explicit processing-history loss, never new verdicts."""
import json

import pytest

from core.audit import report as reports
from core.audit.orchestrator import OrchestratorResult
from core.audit.tests.test_processing_finalization_integration import _finalize
from core.audit.tests.test_report_completeness import TestCompleteRunReport as _CompleteRun

FILE = "processing-completeness.json"
DARK = "new dark verification pass results (persistence failed)"
DIFFERENTIAL = "new differential verification pass results (persistence failed)"
PUBLICATION = reports.UNACKNOWLEDGED_ASSESSMENTS_LIMITATION
INVALID = "processing completeness record (unreadable or invalid)"


@pytest.mark.parametrize("label", [DARK, DIFFERENTIAL, PUBLICATION])
def test_finalized_loss_survives_report_rebuild(label, tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("_RAPTOR_TRUSTED", "1")
    out = _CompleteRun()._complete_run(tmp_path)
    prior = {p.name: p.read_bytes() for p in out.iterdir() if p.is_file()}
    result = OrchestratorResult()
    if label == PUBLICATION:
        result.publication_failures = [{"reason": "initial_journal_acknowledgement_unavailable",
                                       "adjudication": "unverified"}]
    else:
        result.processing_limitations = [label]
    _finalize(out, result, monkeypatch)
    assert json.loads((out / FILE).read_text()) == {"schema_version": 1, "limitations": [label]}
    rebuilt = reports.generate_report(out, final_status="completed")
    assert rebuilt["completeness"]["missing"] == [label]
    assert rebuilt["completeness"]["partial"] is True
    assert rebuilt["completeness"]["resumable"] is False
    assert rebuilt["stats"]["clean"] == 1 and rebuilt["stats"]["error"] == 0
    assert label in reports.write_markdown_report(rebuilt, out).read_text()
    # An ordinary later render cannot reconstruct the earlier lost history.
    reports.write_report(rebuilt, out)
    assert label in reports.generate_report(out)["completeness"]["missing"]
    for name, content in prior.items():
        assert (out / name).read_bytes() == content


def test_healthy_report_does_not_create_failure_record(tmp_path):
    out = _CompleteRun()._complete_run(tmp_path)
    reports.write_report(reports.generate_report(out), out)
    assert not (out / FILE).exists()
    assert reports.generate_report(out)["completeness"]["partial"] is False


@pytest.mark.parametrize("payload", ["{", "x" * 4097,
    json.dumps({"schema_version": True, "limitations": [DARK]}),
    json.dumps({"schema_version": 2, "limitations": [DARK]}),
    json.dumps({"schema_version": 1, "limitations": [{"body": "private-content"}]}),
    json.dumps({"schema_version": 1, "limitations": ["private-content"]}),
])
def test_invalid_explicit_record_is_incomplete_without_disclosing_contents(tmp_path, payload):
    out = _CompleteRun()._complete_run(tmp_path)
    (out / FILE).write_text(payload)
    report = reports.generate_report(out, final_status="completed")
    assert report["completeness"]["missing"] == [INVALID]
    assert report["completeness"]["partial"] is True
    assert report["stats"]["clean"] == 1
    assert "private-content" not in json.dumps(report)


def test_projection_write_failure_preserves_previous_report(tmp_path, monkeypatch):
    out = _CompleteRun()._complete_run(tmp_path)
    saved = reports.write_report(reports.generate_report(out), out)
    before = saved.read_bytes()
    report = reports.generate_report(out, processing_limitations=[DARK])
    failure = OSError("private write failure")
    save = reports.save_json
    def refuse(path, data, **kwargs):
        if path.name == FILE:
            raise failure
        return save(path, data, **kwargs)
    monkeypatch.setattr(reports, "save_json", refuse)
    with pytest.raises(OSError) as caught:
        reports.write_report(report, out)
    assert caught.value is failure
    assert saved.read_bytes() == before


def test_multiple_history_signals_union_in_fixed_order(tmp_path):
    out = _CompleteRun()._complete_run(tmp_path)
    reports.write_report(reports.generate_report(out, unacknowledged_assessments=True), out)
    reports.write_report(reports.generate_report(out, processing_limitations=[DIFFERENTIAL, DARK]), out)
    report = reports.generate_report(out, final_status="completed", unacknowledged_assessments=False)
    assert report["completeness"]["missing"] == [DARK, DIFFERENTIAL, PUBLICATION]
