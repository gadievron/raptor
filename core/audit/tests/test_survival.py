"""Tests for core.audit.survival — per-channel /validate survival."""

from __future__ import annotations

from pathlib import Path

from core.audit.journal import ReviewJournalEntry, append_entry, now_iso
from core.audit.survival import (
    NO_CHANNEL,
    aggregate_survival,
    format_survival,
)


def _entry(
    file: str,
    function: str,
    verdict: str,
    *,
    evidence_tools: list[str] | None = None,
    prior_review: str | None = None,
    validate_verdict: str | None = None,
) -> ReviewJournalEntry:
    return ReviewJournalEntry(
        ts=now_iso(),
        run_id="test-run",
        file=file,
        function=function,
        verdict=verdict,
        source_hash="",
        evidence_tools=list(evidence_tools or []),
        prior_review=prior_review,
        validate_verdict=validate_verdict,
    )


def _write(out_dir: Path, *entries: ReviewJournalEntry) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    for e in entries:
        append_entry(out_dir, e)


class TestAggregateSurvival:
    def test_empty_journal(self, tmp_path: Path):
        assert aggregate_survival(tmp_path) == {}

    def test_no_corrections(self, tmp_path: Path):
        _write(tmp_path, _entry(
            "a.c", "f", "finding", evidence_tools=["smt:check-overflow"],
        ))
        assert aggregate_survival(tmp_path) == {}

    def test_disproven_counts_against_channel(self, tmp_path: Path):
        _write(
            tmp_path,
            _entry("a.c", "f", "finding",
                   evidence_tools=["smt:check-overflow"]),
            _entry("a.c", "f", "clean",
                   prior_review="finding", validate_verdict="disproven"),
        )
        agg = aggregate_survival(tmp_path)
        assert agg == {"smt": {"survived": 0, "disproven": 1, "unknown": 0}}

    def test_confirmed_counts_as_survived(self, tmp_path: Path):
        _write(
            tmp_path,
            _entry("b.c", "g", "finding",
                   evidence_tools=["semgrep:rule-x"]),
            _entry("b.c", "g", "finding",
                   prior_review="finding", validate_verdict="confirmed"),
        )
        agg = aggregate_survival(tmp_path)
        assert agg == {"semgrep": {"survived": 1, "disproven": 0, "unknown": 0}}

    def test_same_channel_tools_count_once(self, tmp_path: Path):
        _write(
            tmp_path,
            _entry("b.c", "g", "finding",
                   evidence_tools=["semgrep:rule-x", "semgrep:rule-y"]),
            _entry("b.c", "g", "finding",
                   prior_review="finding", validate_verdict="confirmed"),
        )
        agg = aggregate_survival(tmp_path)
        assert agg["semgrep"]["survived"] == 1

    def test_multiple_channels_each_credited(self, tmp_path: Path):
        _write(
            tmp_path,
            _entry("c.c", "h", "finding",
                   evidence_tools=["smt:check-oob", "coccinelle:rule"]),
            _entry("c.c", "h", "clean",
                   prior_review="finding", validate_verdict="disproven"),
        )
        agg = aggregate_survival(tmp_path)
        assert agg["smt"]["disproven"] == 1
        assert agg["coccinelle"]["disproven"] == 1

    def test_llm_claimed_and_prefilter_prefixes(self, tmp_path: Path):
        _write(
            tmp_path,
            _entry("d.c", "i", "suspicious",
                   evidence_tools=["llm-claimed:overflow hypothesis"]),
            _entry("d.c", "i", "clean",
                   prior_review="suspicious", validate_verdict="disproven"),
            _entry("e.c", "j", "finding",
                   evidence_tools=["prefilter:memcpy"]),
            _entry("e.c", "j", "finding",
                   prior_review="finding", validate_verdict="confirmed"),
        )
        agg = aggregate_survival(tmp_path)
        assert agg["llm-claimed"]["disproven"] == 1
        assert agg["prefilter"]["survived"] == 1

    def test_no_evidence_tools_bucketed_as_none(self, tmp_path: Path):
        _write(
            tmp_path,
            _entry("f.c", "k", "finding"),
            _entry("f.c", "k", "clean",
                   prior_review="finding", validate_verdict="disproven"),
        )
        agg = aggregate_survival(tmp_path)
        assert agg == {NO_CHANNEL: {"survived": 0, "disproven": 1,
                                    "unknown": 0}}

    def test_clean_prior_review_excluded(self, tmp_path: Path):
        # A missed vulnerability (clean upgraded by /validate) is not a
        # surviving claim — there is no evidence channel to credit.
        _write(
            tmp_path,
            _entry("g.c", "m", "clean",
                   evidence_tools=["semgrep:rule"]),
            _entry("g.c", "m", "finding",
                   prior_review="clean", validate_verdict="confirmed"),
        )
        assert aggregate_survival(tmp_path) == {}

    def test_unknown_verdict_bucketed_separately(self, tmp_path: Path):
        _write(
            tmp_path,
            _entry("h.c", "n", "finding",
                   evidence_tools=["codeql:query"]),
            _entry("h.c", "n", "finding",
                   prior_review="finding", validate_verdict="unknown"),
        )
        agg = aggregate_survival(tmp_path)
        assert agg["codeql"] == {"survived": 0, "disproven": 0, "unknown": 1}

    def test_latest_correction_wins(self, tmp_path: Path):
        _write(
            tmp_path,
            _entry("i.c", "o", "finding",
                   evidence_tools=["smt:check-null-deref"]),
            _entry("i.c", "o", "clean",
                   prior_review="finding", validate_verdict="disproven"),
            _entry("i.c", "o", "finding",
                   prior_review="finding", validate_verdict="confirmed"),
        )
        agg = aggregate_survival(tmp_path)
        assert agg["smt"] == {"survived": 1, "disproven": 0, "unknown": 0}

    def test_channel_from_latest_prior_entry(self, tmp_path: Path):
        # Evidence channel comes from the most recent tool-bearing
        # entry before the correction, not the first.
        _write(
            tmp_path,
            _entry("j.c", "p", "suspicious",
                   evidence_tools=["prefilter:memcpy"]),
            _entry("j.c", "p", "finding",
                   evidence_tools=["joern:taint"]),
            _entry("j.c", "p", "finding",
                   prior_review="finding", validate_verdict="confirmed"),
        )
        agg = aggregate_survival(tmp_path)
        assert "joern" in agg
        assert "prefilter" not in agg


class TestFormatSurvival:
    def test_empty(self):
        assert format_survival({}) == []

    def test_rates_and_ordering(self):
        agg = {
            "smt": {"survived": 1, "disproven": 3, "unknown": 0},
            "semgrep": {"survived": 2, "disproven": 0, "unknown": 1},
        }
        lines = format_survival(agg)
        assert lines[0].startswith("Finding survival")
        # smt has 4 adjudicated+unknown, semgrep 3 → smt first.
        assert "smt: 1 survived / 3 disproven (survival 25%)" in lines[1]
        assert "semgrep: 2 survived / 0 disproven" in lines[2]
        assert "1 unknown" in lines[2]

    def test_rate_na_when_all_unknown(self):
        lines = format_survival(
            {"smt": {"survived": 0, "disproven": 0, "unknown": 2}},
        )
        assert "survival n/a" in lines[1]


class TestReportWiring:
    def test_report_includes_survival_section(self, tmp_path: Path):
        from core.audit.report import generate_report
        _write(
            tmp_path,
            _entry("a.c", "f", "finding",
                   evidence_tools=["smt:check-overflow"]),
            _entry("a.c", "f", "clean",
                   prior_review="finding", validate_verdict="disproven"),
        )
        report = generate_report(tmp_path)
        assert report["survival"] == {
            "smt": {"survived": 0, "disproven": 1, "unknown": 0},
        }
        assert "Finding survival (/validate feedback)" in report["summary"]
        assert "smt: 0 survived / 1 disproven" in report["summary"]

    def test_report_omits_survival_when_no_corrections(self, tmp_path: Path):
        from core.audit.report import generate_report
        _write(tmp_path, _entry(
            "a.c", "f", "finding", evidence_tools=["smt:check-overflow"],
        ))
        report = generate_report(tmp_path)
        assert "survival" not in report
        assert "Finding survival" not in report["summary"]
