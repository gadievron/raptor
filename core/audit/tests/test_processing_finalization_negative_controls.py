"""Ordinary adapter EIO is not a retained-result write failure."""
import errno
import json

import pytest

from core.audit import dark_verify
from core.audit.report import generate_report
from core.audit.tests.test_processing_finalization_integration import _finalize
from core.audit.tests.test_processing_limitations import MESSAGES, _setup, _snapshot
from core.audit.tests.test_report_completeness import TestCompleteRunReport as _CompleteRun
from core.coverage.journal import ReviewJournalEntry, append_entry, load_entries, now_iso


@pytest.mark.parametrize("kind", ["dark", "differential"])
def test_actual_ordinary_adapter_eio_does_not_publish_retention_failure(
    kind, tmp_path, monkeypatch, capsys,
):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("_RAPTOR_TRUSTED", "1")
    out = _CompleteRun()._complete_run(tmp_path)
    append_entry(out, ReviewJournalEntry(
        ts=now_iso(), run_id=out.name, file="a.c", function="prior_concern",
        verdict="suspicious", source_hash="abc123def456", line_start=1,
        body="Retained prior reasoning", confidence=.65,
    ))
    findings = [{"id": "prior-concern", "file": "a.c", "function": "prior_concern",
                 "line": 1, "status": "suspicious", "confidence": .65,
                 "title": "Retained prior concern", "body": "Retained prior reasoning"}]
    findings_path = out / "findings.json"
    findings_path.write_text(json.dumps(findings), encoding="utf-8")
    prior_findings = findings_path.read_bytes()
    journal_path = out / "review-journal.jsonl"
    prior_journal = journal_path.read_bytes()
    prior_entries = [(e.file, e.function, e.verdict, e.body, e.confidence)
                     for e in load_entries(out)]
    # An independent coverage gap makes partial=False an invalid negative oracle.
    (out / "cost-breakdown.json").unlink()
    op = _setup(kind, tmp_path, monkeypatch, confirms=False)
    op.config.out_dir = out
    fault = OSError(errno.EIO, "ordinary-adapter-EIO-706")
    calls = []

    def fail(*args, **kwargs):
        calls.append("ordinary adapter reached")
        raise fault

    monkeypatch.setattr(dark_verify, "execute_witness", fail)
    try:
        op.run()
    except OSError as caught:
        assert caught is fault
    assert calls
    assert op.result.processing_limitations == []
    # Preserve whichever ordinary-error policy the real producer applied.
    after_producer = _snapshot(op.result)
    baseline = generate_report(out, final_status="completed")
    _finalize(out, op.result, monkeypatch)
    console = capsys.readouterr().out
    (out / "captured-console.txt").write_text(console, encoding="utf-8")
    report = json.loads((out / "audit-report.json").read_text())
    assert report["stats"] == baseline["stats"]
    assert report["findings"] == baseline["findings"]
    assert report["completeness"]["partial"] is True
    assert any("cost-breakdown.json" in item for item in report["completeness"]["missing"])
    assert not set(MESSAGES.values()).intersection(report["completeness"]["missing"])
    assert not (out / "processing-completeness.json").exists()
    public = console
    for name in ("audit-report.json", "audit-report.md", "audit-summary.json", "report-context.json"):
        public += (out / name).read_text()
    assert all(label not in public for label in MESSAGES.values())
    assert _snapshot(op.result) == after_producer
    assert journal_path.read_bytes().startswith(prior_journal)
    assert findings_path.read_bytes() == prior_findings
    assert prior_entries == [(e.file, e.function, e.verdict, e.body, e.confidence)
                             for e in load_entries(out)][:len(prior_entries)]
