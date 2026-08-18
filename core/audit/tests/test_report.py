"""Tests for core.audit.report — summary report generation."""

from __future__ import annotations

import json
from pathlib import Path

from core.audit.report import (
    _compute_stats,
    _count_remaining_gaps,
    _evidence_distribution,
    _find_unrecorded_reads,
    _format_summary,
    format_summary,
    generate_report,
    write_markdown_report,
    write_report,
)


class TestComputeStats:
    def test_counts_statuses(self):
        audit_data = {
            "files": {
                "a.c": {
                    "functions": {
                        "f1": {"status": "clean"},
                        "f2": {"status": "suspicious"},
                        "f3": {"status": "finding"},
                    },
                },
                "b.c": {
                    "functions": {
                        "g1": {"status": "clean"},
                        "g2": {"status": "error"},
                    },
                },
            },
        }
        stats = _compute_stats(audit_data)
        assert stats["reviewed"] == 5
        assert stats["clean"] == 2
        assert stats["suspicious"] == 1
        assert stats["finding"] == 1
        assert stats["error"] == 1

    def test_empty(self):
        stats = _compute_stats({"files": {}})
        assert stats["reviewed"] == 0

    def test_mechanical_entries_counted_separately(self):
        # The observed contradiction: report said 14 reviewed /
        # 8 suspicious, console said 9 / 3 — five post-loop mechanical
        # journal entries were silently counted as LLM reviews. One
        # rule now: reviewed = LLM reviews; mechanical stated apart.
        audit_data = {
            "functions_analysed": (
                [
                    {"file": "a.c", "function": f"f{i}", "status": "clean"}
                    for i in range(6)
                ]
                + [
                    {"file": "a.c", "function": f"s{i}",
                     "status": "suspicious"}
                    for i in range(3)
                ]
                + [
                    {"file": "b.c", "function": f"m{i}",
                     "status": "suspicious", "mechanical": True}
                    for i in range(5)
                ]
            ),
        }
        stats = _compute_stats(audit_data)
        assert stats["reviewed"] == 9
        assert stats["suspicious"] == 3
        assert stats["mechanical"] == 5

    def test_mechanical_share_stated_in_summary(self):
        report = {
            "stats": {
                "reviewed": 9, "clean": 6, "suspicious": 3,
                "finding": 0, "error": 0, "mechanical": 5,
            },
            "findings_count": 0,
            "gaps_remaining": 0,
            "findings": [],
        }
        summary = _format_summary(report)
        assert "Functions LLM-reviewed: 9 (+5 mechanical post-loop)" in summary
        assert "Suspicious: 3" in summary

    def test_load_review_state_marks_mechanical_entries(self, monkeypatch):
        from types import SimpleNamespace

        from core.audit import journal as journal_mod
        from core.audit.report import _load_review_state

        def _entry(func, *, strategies=(), body=""):
            return SimpleNamespace(
                file="a.c", function=func, verdict="suspicious",
                source_hash="h", strategies=list(strategies), body=body,
            )

        entries = {
            "a.c:llm": _entry("llm", strategies=["taint"], body="deep dive"),
            "a.c:mech": _entry(
                "mech",
                strategies=["post-loop-mechanical"],
                body="[mechanical] resource exhaustion",
            ),
        }
        monkeypatch.setattr(
            journal_mod, "latest_entries", lambda out_dir: entries,
        )
        state = _load_review_state(Path("/nonexistent"))
        by_name = {
            f["function"]: f for f in state["functions_analysed"]
        }
        assert by_name["llm"]["mechanical"] is False
        assert by_name["mech"]["mechanical"] is True

    def test_functions_analysed_format(self):
        audit_data = {
            "functions_analysed": [
                {"file": "a.c", "function": "f1", "status": "clean"},
                {"file": "a.c", "function": "f2", "status": "finding"},
                {"file": "b.c", "function": "g1", "status": "suspicious"},
            ],
        }
        stats = _compute_stats(audit_data)
        assert stats["reviewed"] == 3
        assert stats["clean"] == 1
        assert stats["finding"] == 1
        assert stats["suspicious"] == 1


class TestCountRemainingGaps:
    def test_basic(self):
        gaps_data = {"count": 10}
        audit_data = {
            "files": {
                "a.c": {"functions": {"f1": {}, "f2": {}, "f3": {}}},
            },
        }
        remaining = _count_remaining_gaps(gaps_data, audit_data)
        assert remaining == 7

    def test_all_covered(self):
        gaps_data = {"count": 3}
        audit_data = {
            "files": {
                "a.c": {"functions": {"f1": {}, "f2": {}, "f3": {}}},
            },
        }
        remaining = _count_remaining_gaps(gaps_data, audit_data)
        assert remaining == 0

    def test_empty_gaps(self):
        remaining = _count_remaining_gaps({}, {"files": {}})
        assert remaining == 0

    def test_functions_analysed_format(self):
        gaps_data = {"count": 10}
        audit_data = {
            "functions_analysed": [
                {"file": "a.c", "function": "f1", "status": "clean"},
                {"file": "a.c", "function": "f2", "status": "finding"},
            ],
        }
        remaining = _count_remaining_gaps(gaps_data, audit_data)
        assert remaining == 8


class TestFormatSummary:
    def test_basic_summary(self):
        report = {
            "stats": {"reviewed": 10, "clean": 7, "suspicious": 2, "finding": 1, "error": 0},
            "findings_count": 1,
            "gaps_remaining": 5,
            "findings": [
                {"title": "Buffer overflow", "file": "a.c", "line": 42, "severity": "high"},
            ],
        }
        summary = _format_summary(report)
        assert "Functions LLM-reviewed: 10" in summary
        assert "Clean: 7" in summary
        assert "Suspicious: 2" in summary
        assert "Finding: 1" in summary
        assert "Buffer overflow" in summary
        assert "Gaps remaining: 5" in summary

    def test_no_findings(self):
        report = {
            "stats": {"reviewed": 5, "clean": 5, "suspicious": 0, "finding": 0, "error": 0},
            "findings_count": 0,
            "gaps_remaining": 0,
            "findings": [],
        }
        summary = _format_summary(report)
        assert "Finding: 0" in summary
        assert "Findings" not in summary.split("Tool-confirmed")[0]


class TestGenerateReport:
    def test_basic_report(self, tmp_path: Path):
        # Post-migration: review state comes from the review journal,
        # not coverage-audit.json. Seed two entries and verify the
        # report reads them via ``_load_review_state``.
        from core.coverage.journal import (
            ReviewJournalEntry,
            append_entry,
            now_iso,
        )
        append_entry(tmp_path, ReviewJournalEntry(
            ts=now_iso(), run_id="test", file="a.c", function="f1",
            verdict="clean", source_hash="",
        ))
        append_entry(tmp_path, ReviewJournalEntry(
            ts=now_iso(), run_id="test", file="a.c", function="f2",
            verdict="finding", source_hash="",
        ))
        (tmp_path / "findings.json").write_text(json.dumps([
            {"title": "UAF", "file": "a.c", "line": 10, "severity": "high"},
        ]))
        (tmp_path / "gaps.json").write_text(json.dumps({"count": 5, "gaps": []}))

        report = generate_report(tmp_path)
        assert report["stats"]["reviewed"] == 2
        assert report["findings_count"] == 1
        assert report["gaps_remaining"] == 3
        assert "summary" in report

    def test_empty_run(self, tmp_path: Path):
        report = generate_report(tmp_path)
        assert report["stats"]["reviewed"] == 0
        assert report["findings_count"] == 0


class TestUnrecordedReads:
    def test_finds_unrecorded_functions(self, tmp_path: Path):
        target = tmp_path / "target"
        target.mkdir()
        (target / "a.c").write_text("int f1() {} int f2() {} int f3() {}")

        (tmp_path / "coverage-audit.json").write_text(json.dumps({
            "files": {
                "a.c": {"functions": {"f1": {"status": "clean"}}},
            },
        }))
        (tmp_path / "checklist.json").write_text(json.dumps({
            "files": [
                {
                    "path": "a.c",
                    "items": [
                        {"name": "f1", "kind": "function", "line_start": 1},
                        {"name": "f2", "kind": "function", "line_start": 2},
                        {"name": "f3", "kind": "function", "line_start": 3},
                    ],
                },
            ],
        }))
        (tmp_path / ".reads-manifest").write_text(
            str(target / "a.c") + "\n"
        )

        audit_data = json.loads(
            (tmp_path / "coverage-audit.json").read_text()
        )
        result = _find_unrecorded_reads(tmp_path, audit_data, target)
        assert len(result) == 1
        assert result[0]["file"] == "a.c"
        assert "f2" in result[0]["functions"]
        assert "f3" in result[0]["functions"]
        assert "f1" not in result[0]["functions"]

    def test_no_manifest(self, tmp_path: Path):
        result = _find_unrecorded_reads(tmp_path, {"files": {}}, None)
        assert result == []

    def test_all_recorded(self, tmp_path: Path):
        target = tmp_path / "target"
        target.mkdir()
        (target / "a.c").write_text("int f1() {}")

        (tmp_path / "coverage-audit.json").write_text(json.dumps({
            "files": {
                "a.c": {"functions": {"f1": {"status": "clean"}}},
            },
        }))
        (tmp_path / "checklist.json").write_text(json.dumps({
            "files": [
                {
                    "path": "a.c",
                    "items": [
                        {"name": "f1", "kind": "function", "line_start": 1},
                    ],
                },
            ],
        }))
        (tmp_path / ".reads-manifest").write_text(
            str(target / "a.c") + "\n"
        )

        audit_data = json.loads(
            (tmp_path / "coverage-audit.json").read_text()
        )
        result = _find_unrecorded_reads(tmp_path, audit_data, target)
        assert result == []

    def test_file_not_in_checklist(self, tmp_path: Path):
        target = tmp_path / "target"
        target.mkdir()
        (target / "b.c").write_text("int g1() {}")

        (tmp_path / "coverage-audit.json").write_text(json.dumps({
            "files": {},
        }))
        (tmp_path / "checklist.json").write_text(json.dumps({
            "files": [
                {
                    "path": "a.c",
                    "items": [
                        {"name": "f1", "kind": "function", "line_start": 1},
                    ],
                },
            ],
        }))
        (tmp_path / ".reads-manifest").write_text(
            str(target / "b.c") + "\n"
        )

        result = _find_unrecorded_reads(tmp_path, {"files": {}}, target)
        assert result == []

    def test_summary_includes_unrecorded(self):
        report = {
            "stats": {"reviewed": 1, "clean": 1, "suspicious": 0,
                      "finding": 0, "dormant": 0, "error": 0},
            "findings_count": 0,
            "gaps_remaining": 10,
            "findings": [],
            "unrecorded_reads": [
                {"file": "a.c", "functions": ["f2", "f3"]},
            ],
        }
        summary = _format_summary(report)
        assert "Unrecorded reads" in summary
        assert "2 functions" in summary
        assert "a.c" in summary
        assert "--related-to" in summary


class TestWriteReport:
    def test_writes_json(self, tmp_path: Path):
        report = {
            "stats": {"reviewed": 1, "clean": 1},
            "findings_count": 0,
            "gaps_remaining": 0,
            "findings": [],
            "summary": "All clean.",
        }
        path = write_report(report, tmp_path)
        assert path.exists()

        with open(path) as f:
            data = json.load(f)
        assert data["stats"]["reviewed"] == 1
        assert "summary" not in data


class TestFormatSummaryPublic:
    def test_uses_precomputed_summary(self):
        report = {"summary": "All clean."}
        assert format_summary(report) == "All clean."

    def test_delegates_to_format_summary_when_missing(self):
        report = {
            "stats": {
                "reviewed": 5, "clean": 3, "suspicious": 1,
                "finding": 1, "dormant": 0, "error": 0,
            },
            "findings_count": 1,
            "gaps_remaining": 10,
            "findings": [{"severity": "high", "title": "test"}],
        }
        result = format_summary(report)
        assert "5" in result
        assert isinstance(result, str)

    def test_empty_report_returns_string(self):
        result = format_summary({})
        assert isinstance(result, str)


class TestEvidenceDistribution:
    def test_counts_tiers(self):
        findings = [
            {"evidence_tier": "OBSERVED_RUNTIME"},
            {"evidence_tier": "XREF_BACKED"},
            {"evidence_tier": "XREF_BACKED"},
            {"evidence_tier": "HEURISTIC"},
        ]
        dist = _evidence_distribution(findings)
        assert dist["OBSERVED_RUNTIME"] == 1
        assert dist["XREF_BACKED"] == 2
        assert dist["HEURISTIC"] == 1

    def test_empty(self):
        assert _evidence_distribution([]) == {}

    def test_missing_tier_defaults_to_heuristic(self):
        findings = [{"title": "no tier field"}]
        dist = _evidence_distribution(findings)
        assert dist["HEURISTIC"] == 1


class TestWriteMarkdownReport:
    def test_writes_file(self, tmp_path):
        report = {
            "stats": {"reviewed": 100, "clean": 90, "finding": 5,
                       "suspicious": 3, "dormant": 1, "error": 1},
            "findings_count": 5,
            "gaps_remaining": 400,
            "findings": [
                {
                    "id": "FIND-001",
                    "title": "Stack buffer overflow in parse_header",
                    "file": "src/http.c",
                    "line": 87,
                    "depth": "L2",
                    "evidence_tier": "OBSERVED_RUNTIME",
                    "severity": "high",
                },
                {
                    "id": "FIND-002",
                    "title": "SQL injection in query_user",
                    "file": "src/db.c",
                    "line": 42,
                    "depth": "L1",
                    "evidence_tier": "XREF_BACKED",
                    "severity": "high",
                },
            ],
        }
        path = write_markdown_report(
            report, tmp_path,
            target_path=Path("/src/project"),
            model="claude-opus-4-6",
            duration_minutes=47,
            cost_usd=412.30,
            capabilities={"joern": True, "frida": False, "r2": True},
            suppressions_count=12,
        )
        assert path.exists()
        content = path.read_text()

        assert "# Audit Report" in content
        assert "/src/project" in content
        assert "claude-opus-4-6" in content
        assert "47 minutes" in content
        assert "$412.30" in content
        assert "100 of 500" in content
        assert "FIND-001" in content
        assert "FIND-002" in content
        assert "OBSERVED_RUNTIME" in content
        assert "XREF_BACKED" in content
        assert "| joern | Yes |" in content
        assert "| frida | No |" in content
        assert "12 findings suppressed" in content

    def test_no_findings(self, tmp_path):
        report = {
            "stats": {"reviewed": 50},
            "findings_count": 0,
            "gaps_remaining": 0,
            "findings": [],
        }
        path = write_markdown_report(report, tmp_path)
        content = path.read_text()
        assert "No findings" in content

    def test_evidence_table(self, tmp_path):
        report = {
            "stats": {},
            "findings": [
                {"evidence_tier": "HEURISTIC", "id": "F1", "title": "a",
                 "file": "a.c", "line": 1, "depth": "L0", "severity": "low"},
                {"evidence_tier": "HEURISTIC", "id": "F2", "title": "b",
                 "file": "b.c", "line": 2, "depth": "L0", "severity": "low"},
            ],
        }
        path = write_markdown_report(report, tmp_path)
        content = path.read_text()
        assert "| HEURISTIC | 2 |" in content


class TestDarkSurfacing:
    """Dark outcomes must reach the operator: stats, summary, and a
    dedicated report section (previously tallied invisibly)."""

    def test_compute_stats_counts_dark(self):
        audit_data = {
            "functions_analysed": [
                {"file": "a.c", "function": "f1", "status": "dark"},
                {"file": "a.c", "function": "f2", "status": "clean"},
            ],
        }
        stats = _compute_stats(audit_data)
        assert stats["dark"] == 1

    def test_summary_lists_dark_findings(self):
        report = {
            "stats": {"reviewed": 2, "dark": 1},
            "findings_count": 0,
            "gaps_remaining": 0,
            "findings": [],
            "dark_findings": [
                {"title": "auth bypass in role check",
                 "file": "auth.py", "line": 12},
            ],
        }
        text = _format_summary(report)
        assert "Dark: 1" in text
        assert "need concrete verification" in text
        assert "auth bypass in role check" in text
        assert "/validate" in text

    def test_markdown_report_dark_section(self, tmp_path):
        report = {
            "stats": {},
            "findings": [],
            "dark_findings": [
                {"title": "auth bypass in role check",
                 "file": "auth.py", "line": 12},
            ],
        }
        path = write_markdown_report(report, tmp_path)
        content = path.read_text()
        assert "## Dark findings (1)" in content
        assert "needs_validation" in content
        assert "auth bypass in role check" in content

    def test_generate_report_loads_dark_from_graded_export(self, tmp_path):
        graded = {
            "findings": [
                {"status": "dark", "title": "idor in order lookup",
                 "file": "orders.py", "line": 4},
                {"status": "finding", "title": "overflow",
                 "file": "a.c", "line": 9},
            ],
            "stats": {"total": 2},
        }
        (tmp_path / "findings-graded.json").write_text(json.dumps(graded))
        report = generate_report(tmp_path)
        dark = report.get("dark_findings", [])
        assert len(dark) == 1
        assert dark[0]["title"] == "idor in order lookup"
