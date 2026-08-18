"""Salvage reporting: the report generator against partial run dirs.

Completeness is reported, not assumed — missing sections are stated,
verdict tables come from whatever the journal holds, and segment
provenance from resumed runs is surfaced.
"""

from __future__ import annotations

import json
from pathlib import Path

from core.audit.report import generate_report, write_markdown_report
from core.coverage.journal import ReviewJournalEntry, append_entry, now_iso


def _journal(out_dir: Path, function: str, verdict: str) -> None:
    append_entry(out_dir, ReviewJournalEntry(
        ts=now_iso(), run_id=out_dir.name, file="a.c",
        function=function, verdict=verdict, source_hash="abc123def456",
        line_start=1, line_end=5,
    ))


def _meta(out_dir: Path, status: str, resumes: list | None = None) -> None:
    extra = {"resumes": resumes} if resumes else {}
    (out_dir / ".raptor-run.json").write_text(json.dumps({
        "version": 2, "command": "audit", "status": status,
        "timestamp": "2026-08-18T00:00:00+00:00", "extra": extra,
    }))


def _truncated_run(tmp_path: Path) -> Path:
    """A run killed mid-loop: metadata + checklist + journal only —
    no gaps.json, no graded export, no cost ledger."""
    out = tmp_path / "audit-run"
    out.mkdir()
    _meta(out, "interrupted")
    (out / "checklist.json").write_text(json.dumps({
        "target_path": str(tmp_path), "files": [],
    }))
    _journal(out, "f1", "clean")
    _journal(out, "f2", "suspicious")
    _journal(out, "f3", "finding")
    return out


class TestPartialRunReport:

    def test_verdict_table_from_journal_and_missing_stated(self, tmp_path):
        out = _truncated_run(tmp_path)
        report = generate_report(out)

        # Verdicts render from whatever the journal holds.
        assert report["stats"]["reviewed"] == 3
        assert report["stats"]["clean"] == 1
        assert report["stats"]["suspicious"] == 1
        assert report["stats"]["finding"] == 1

        comp = report["completeness"]
        assert comp["partial"] is True
        assert comp["run_status"] == "interrupted"
        assert comp["resumable"] is True
        assert comp["no_verdicts"] is False
        missing = " / ".join(comp["missing"])
        assert "gaps.json" in missing
        assert "findings-graded.json" in missing
        assert "cost-breakdown.json" in missing
        assert "checklist.json" not in missing

    def test_summary_states_partial_and_resume_hint(self, tmp_path):
        out = _truncated_run(tmp_path)
        report = generate_report(out)
        summary = report["summary"]
        assert "Partial run" in summary
        assert "Interrupted" in summary
        assert "Missing:" in summary
        assert "raptor-audit resume" in summary

    def test_markdown_report_has_completeness_section(self, tmp_path):
        out = _truncated_run(tmp_path)
        report = generate_report(out)
        path = write_markdown_report(report, out)
        md = path.read_text()
        assert "## Run completeness" in md
        assert "Partial run" in md
        assert "Missing: gap schedule (gaps.json)" in md

    def test_empty_dir_states_no_verdicts(self, tmp_path):
        out = tmp_path / "dead-run"
        out.mkdir()
        _meta(out, "failed")
        report = generate_report(out)
        comp = report["completeness"]
        assert comp["partial"] is True
        assert comp["no_verdicts"] is True
        assert "No review journal" in report["summary"]

    def test_run_without_metadata_is_partial_unknown(self, tmp_path):
        out = tmp_path / "bare"
        out.mkdir()
        _journal(out, "f1", "clean")
        report = generate_report(out)
        comp = report["completeness"]
        assert comp["partial"] is True
        assert comp["run_status"] is None
        assert comp["resumable"] is False


class TestCompleteRunReport:

    def _complete_run(self, tmp_path: Path) -> Path:
        out = tmp_path / "audit-run"
        out.mkdir()
        _meta(out, "completed")
        (out / "checklist.json").write_text(json.dumps({
            "target_path": str(tmp_path), "files": [],
        }))
        (out / "gaps.json").write_text(json.dumps({"count": 0, "gaps": []}))
        (out / "findings-graded.json").write_text(
            json.dumps({"findings": [], "stats": {}}),
        )
        (out / "cost-breakdown.json").write_text(
            json.dumps({"phases": {}, "totals": {}}),
        )
        _journal(out, "f1", "clean")
        return out

    def test_complete_run_not_partial_no_noise(self, tmp_path):
        out = self._complete_run(tmp_path)
        report = generate_report(out)
        comp = report["completeness"]
        assert comp["partial"] is False
        assert comp["missing"] == []
        assert "Partial run" not in report["summary"]
        md = write_markdown_report(report, out).read_text()
        assert "## Run completeness" not in md

    def test_completed_run_with_missing_export_is_stated(self, tmp_path):
        out = self._complete_run(tmp_path)
        (out / "findings-graded.json").unlink()
        report = generate_report(out)
        comp = report["completeness"]
        assert comp["partial"] is True
        assert comp["resumable"] is False, (
            "completed runs are never resumable, even when an export "
            "artifact is missing"
        )
        assert "raptor-audit resume" not in report["summary"]

    def test_segments_surface_on_resumed_completed_run(self, tmp_path):
        out = self._complete_run(tmp_path)
        _meta(out, "completed", resumes=[
            {"ts": "2026-08-18T01:00:00+00:00", "prior_status": "running",
             "segment": 2},
        ])
        report = generate_report(out)
        assert report["segments"]["count"] == 2
        assert report["segments"]["resumes"][0]["segment"] == 2
        assert "Run segments: 2" in report["summary"]
        md = write_markdown_report(report, out).read_text()
        assert "Run segments: 2" in md
