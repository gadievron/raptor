"""Budget-truncation-as-exclusion reporting.

``gaps[:budget]`` used to drop the tail silently: nothing recorded
those functions as "not attempted", so run summaries conflated them
with reviewed code. The truncation now records the dropped tail in
``not-attempted.json`` and the report surfaces it in both the run
summary and the coverage accounting (gaps_remaining / functions-
reviewed denominator). The dropped functions stay gap-eligible.
"""

from __future__ import annotations

import json

from core.audit.gaps import compute_gaps, truncate_gaps_to_budget
from core.audit.report import generate_report, write_markdown_report


def _checklist(n=6):
    return {
        "target_path": "/tmp/proj",
        "files": [{
            "path": "m.c",
            "items": [
                {"name": f"fn{i}", "kind": "function",
                 "line_start": 1 + i * 10, "line_end": 8 + i * 10}
                for i in range(n)
            ],
        }],
    }


class TestTruncationRecording:
    def test_compute_gaps_budget_records_dropped_tail(self, tmp_path):
        gaps = compute_gaps(_checklist(6), [], budget=2, out_dir=tmp_path)
        assert len(gaps) == 2

        payload = json.loads((tmp_path / "not-attempted.json").read_text())
        assert payload["reason"] == "budget"
        assert payload["count"] == 4
        dropped_names = {f["name"] for f in payload["functions"]}
        scheduled_names = {g["name"] for g in gaps}
        assert len(dropped_names) == 4
        assert not dropped_names & scheduled_names

    def test_under_budget_writes_nothing(self, tmp_path):
        gaps = compute_gaps(_checklist(2), [], budget=5, out_dir=tmp_path)
        assert len(gaps) == 2
        assert not (tmp_path / "not-attempted.json").exists()

    def test_helper_is_reusable_on_scored_lists(self, tmp_path):
        gaps = [{"file": "a.c", "name": f"f{i}", "priority": 1,
                 "line_start": i + 1, "line_end": i + 5} for i in range(5)]
        kept = truncate_gaps_to_budget(gaps, 3, tmp_path)
        assert [g["name"] for g in kept] == ["f0", "f1", "f2"]
        payload = json.loads((tmp_path / "not-attempted.json").read_text())
        assert {f["name"] for f in payload["functions"]} == {"f3", "f4"}

    def test_dropped_functions_stay_gap_eligible(self, tmp_path):
        # Nothing about the recording marks the tail covered: a
        # recomputation without budget surfaces every function again.
        compute_gaps(_checklist(6), [], budget=2, out_dir=tmp_path)
        gaps = compute_gaps(_checklist(6), [], out_dir=tmp_path)
        assert len(gaps) == 6


class TestReportAccounting:
    def _run_dir(self, tmp_path):
        # Scheduled gaps: 2; journal reviews: 1; truncated tail: 4.
        (tmp_path / "gaps.json").write_text(json.dumps({
            "count": 2,
            "gaps": [{"file": "m.c", "name": "fn0"},
                     {"file": "m.c", "name": "fn1"}],
        }))
        (tmp_path / "review-journal.jsonl").write_text(json.dumps({
            "file": "m.c", "function": "fn0", "verdict": "clean",
            "ts": "2026-01-01T00:00:00Z", "run_id": "run-1",
        }) + "\n")
        (tmp_path / "not-attempted.json").write_text(json.dumps({
            "reason": "budget", "count": 4,
            "functions": [{"file": "m.c", "name": f"fn{i}"}
                          for i in range(2, 6)],
        }))
        return tmp_path

    def test_summary_reports_not_attempted_line(self, tmp_path):
        report = generate_report(self._run_dir(tmp_path))
        assert report["not_attempted"] == {"reason": "budget", "count": 4}
        assert "Not attempted (budget): 4 functions" in report["summary"]

    def test_gaps_remaining_includes_truncated_tail(self, tmp_path):
        report = generate_report(self._run_dir(tmp_path))
        # 2 scheduled - 1 reviewed = 1, plus the 4 never-scheduled.
        assert report["gaps_remaining"] == 5

    def test_markdown_report_carries_the_accounting(self, tmp_path):
        run_dir = self._run_dir(tmp_path)
        report = generate_report(run_dir)
        write_markdown_report(report, run_dir)
        md = (run_dir / "audit-report.md").read_text()
        assert "Not attempted (budget):" in md
        # Coverage denominator counts the truncated tail.
        assert "of 6" in md

    def test_no_truncation_no_noise(self, tmp_path):
        (tmp_path / "gaps.json").write_text(json.dumps({
            "count": 1, "gaps": [{"file": "m.c", "name": "fn0"}],
        }))
        report = generate_report(tmp_path)
        assert "not_attempted" not in report
        assert "Not attempted" not in report["summary"]
