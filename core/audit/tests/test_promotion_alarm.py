"""Tests for the promotion-without-tool-evidence alarm.

The alarm is a mechanical invariant check: a ``finding`` that reaches
the journal-write or findings-export chokepoint without qualifying
tool evidence (``is_tool_evidence``) is the signature of a successful
injection or a verdict-gate bug.  It must be EMPTY on legitimate runs
(tool-evidenced findings, LLM-guess suspicious entries, clean verdicts)
and must fire — alarm-only, never blocking — on a forged promotion.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from core.audit.promotion_alarm import (
    ALARM_EVENT,
    ALARM_FILENAME,
    build_alarm_record,
    check_and_emit,
    check_outcomes,
    load_alarms,
)


@dataclass
class _FakeOutcome:
    file: str = "src/auth.py"
    function: str = "check_pw"
    status: str = "finding"
    body: str = "SQL injection in query"
    model: str = "test-model"
    cost_usd: float = 0.01
    duration_s: float = 1.5
    line: int = 10
    hypothesis: str = "unsanitised input reaches query"
    hypotheses: list[Any] = field(default_factory=list)
    evidence_tool: str = ""
    review_result: dict[str, Any] | None = None
    tools_dispatched: set | None = None


def _alarm_lines(out_dir: Path) -> list[dict[str, Any]]:
    path = out_dir / ALARM_FILENAME
    if not path.exists():
        return []
    return [
        json.loads(line)
        for line in path.read_text().splitlines() if line.strip()
    ]


# ---------------------------------------------------------------------------
# Record construction — the invariant itself
# ---------------------------------------------------------------------------


class TestBuildAlarmRecord:
    def test_finding_without_evidence_fires(self):
        rec = build_alarm_record(
            stage="journal-write", file="a.c", function="f",
            verdict="finding", evidence_tool="",
        )
        assert rec is not None
        assert rec["event"] == ALARM_EVENT
        assert rec["verdict"] == "finding"
        assert rec["stage"] == "journal-write"

    def test_llm_claimed_stamp_is_not_evidence(self):
        # ``llm-claimed:*`` is the namespaced LLM self-assertion —
        # it must never satisfy the alarm's evidence check.
        rec = build_alarm_record(
            stage="journal-write", file="a.c", function="f",
            verdict="finding", evidence_tool="llm-claimed:semgrep",
        )
        assert rec is not None

    def test_tool_evidenced_finding_is_silent(self):
        for tool in ("semgrep", "smt:check-overflow", "prefilter:oob-write",
                     "dark_verify:confirmed", "semgrep+joern"):
            rec = build_alarm_record(
                stage="journal-write", file="a.c", function="f",
                verdict="finding", evidence_tool=tool,
            )
            assert rec is None, f"alarm fired on tool evidence {tool!r}"

    def test_suspicious_is_designed_llm_guess_bucket(self):
        # Evidence-less suspicious is routine (the pipeline explicitly
        # allows LLM-guess suspicious verdicts) — never alarmed.
        rec = build_alarm_record(
            stage="journal-write", file="a.c", function="f",
            verdict="suspicious", evidence_tool="",
        )
        assert rec is None

    def test_clean_and_dormant_are_silent(self):
        for verdict in ("clean", "dormant", "error", ""):
            rec = build_alarm_record(
                stage="journal-write", file="a.c", function="f",
                verdict=verdict, evidence_tool="",
            )
            assert rec is None

    def test_g2_invariant_bypass_is_designed_exception(self):
        rec = build_alarm_record(
            stage="journal-write", file="a.c", function="f",
            verdict="finding", evidence_tool="",
            review_result={"g2_invariant_bypass": ["INV-001"]},
        )
        assert rec is None

    def test_hypothesis_is_truncated(self):
        rec = build_alarm_record(
            stage="journal-write", file="a.c", function="f",
            verdict="finding", evidence_tool="",
            hypothesis="x" * 5000,
        )
        assert rec is not None
        assert len(rec["hypothesis"]) == 500


# ---------------------------------------------------------------------------
# Emission — CRITICAL log + JSONL artifact
# ---------------------------------------------------------------------------


class TestCheckAndEmit:
    def test_forged_promotion_emits_critical_and_record(self, tmp_path, caplog):
        outcome = _FakeOutcome(status="finding", evidence_tool="")
        with caplog.at_level(logging.CRITICAL, logger="core.audit.promotion_alarm"):
            rec = check_and_emit(
                tmp_path, outcome, stage="journal-write", run_id="run-1",
            )
        assert rec is not None
        critical = [
            r for r in caplog.records if r.levelno == logging.CRITICAL
        ]
        assert critical, "no CRITICAL log emitted"
        assert ALARM_EVENT in critical[0].getMessage()

        lines = _alarm_lines(tmp_path)
        assert len(lines) == 1
        assert lines[0]["event"] == ALARM_EVENT
        assert lines[0]["file"] == "src/auth.py"
        assert lines[0]["function"] == "check_pw"
        assert lines[0]["run_id"] == "run-1"

    def test_legitimate_finding_emits_nothing(self, tmp_path):
        outcome = _FakeOutcome(
            status="finding", evidence_tool="semgrep:sql-injection",
        )
        rec = check_and_emit(tmp_path, outcome, stage="journal-write")
        assert rec is None
        assert not (tmp_path / ALARM_FILENAME).exists()

    def test_alarm_never_raises_on_hostile_outcome(self, tmp_path):
        # An object whose attribute access explodes must not break the
        # journal-write path — the alarm is best-effort by contract.
        class _Hostile:
            def __getattr__(self, name):
                raise RuntimeError("boom")

        assert check_and_emit(
            tmp_path, _Hostile(), stage="journal-write",
        ) is None

    def test_load_alarms_round_trip(self, tmp_path):
        check_and_emit(
            tmp_path,
            _FakeOutcome(status="finding", evidence_tool=""),
            stage="journal-write",
        )
        check_and_emit(
            tmp_path,
            _FakeOutcome(function="g", status="finding", evidence_tool=""),
            stage="findings-export",
        )
        records = load_alarms(tmp_path)
        assert len(records) == 2
        assert {r["stage"] for r in records} == {
            "journal-write", "findings-export",
        }


# ---------------------------------------------------------------------------
# Chokepoint integration — journal write + findings export
# ---------------------------------------------------------------------------


class TestJournalChokepoint:
    def test_forged_promotion_at_journal_write_fires(self, tmp_path):
        from core.audit.collector import append_journal_for_outcome

        outcome = _FakeOutcome(status="finding", evidence_tool="")
        append_journal_for_outcome(
            out_dir=tmp_path,
            target_path=tmp_path,
            run_id="run-x",
            outcome=outcome,
            gap={"file": outcome.file, "name": outcome.function,
                 "line_start": 10, "line_end": 30},
            checked_by=["audit"],
        )
        lines = _alarm_lines(tmp_path)
        assert len(lines) == 1
        assert lines[0]["stage"] == "journal-write"
        # The journal entry itself is still written — alarm never blocks.
        from core.coverage.journal import load_entries
        entries = load_entries(tmp_path)
        assert len(entries) == 1
        assert entries[0].verdict == "finding"

    def test_legitimate_run_shape_is_alarm_free(self, tmp_path):
        # A representative legitimate run: tool-evidenced finding,
        # LLM-guess suspicious, clean, dormant.  Zero alarms.
        from core.audit.collector import append_journal_for_outcome

        outcomes = [
            _FakeOutcome(function="a", status="finding",
                         evidence_tool="smt:check-overflow"),
            _FakeOutcome(function="b", status="suspicious",
                         evidence_tool=""),
            _FakeOutcome(function="c", status="clean", evidence_tool=""),
            _FakeOutcome(function="d", status="dormant", evidence_tool=""),
        ]
        for o in outcomes:
            append_journal_for_outcome(
                out_dir=tmp_path,
                target_path=tmp_path,
                run_id="run-x",
                outcome=o,
                gap={"file": o.file, "name": o.function,
                     "line_start": 1, "line_end": 2},
                checked_by=["audit"],
            )
        assert _alarm_lines(tmp_path) == []

    def test_g2_bypass_marker_suppresses_journal_alarm(self, tmp_path):
        from core.audit.collector import append_journal_for_outcome

        outcome = _FakeOutcome(
            status="finding", evidence_tool="",
            review_result={"g2_invariant_bypass": ["INV-042"]},
        )
        append_journal_for_outcome(
            out_dir=tmp_path,
            target_path=tmp_path,
            run_id="run-x",
            outcome=outcome,
            gap={"file": outcome.file, "name": outcome.function,
                 "line_start": 10, "line_end": 30},
            checked_by=["audit"],
        )
        assert _alarm_lines(tmp_path) == []


class TestExportChokepoint:
    def test_export_sweep_catches_post_loop_forgery(self, tmp_path):
        from core.audit.findings_export import export_findings

        outcomes = [
            _FakeOutcome(function="ok", status="finding",
                         evidence_tool="coccinelle:rule-1"),
            _FakeOutcome(function="forged", status="finding",
                         evidence_tool=""),
            _FakeOutcome(function="guess", status="suspicious",
                         evidence_tool=""),
        ]
        export = export_findings(outcomes, out_dir=tmp_path, run_id="run-y")
        # Export output unchanged: all three claims exported
        # (finding, finding, suspicious) — the alarm never drops.
        assert export["stats"]["total"] == 3
        lines = _alarm_lines(tmp_path)
        assert len(lines) == 1
        assert lines[0]["function"] == "forged"
        assert lines[0]["stage"] == "findings-export"

    def test_export_without_out_dir_skips_sweep(self, tmp_path):
        from core.audit.findings_export import export_findings

        outcomes = [
            _FakeOutcome(function="forged", status="finding",
                         evidence_tool=""),
        ]
        export_findings(outcomes)
        assert _alarm_lines(tmp_path) == []

    def test_check_outcomes_returns_emitted_records(self, tmp_path):
        outcomes = [
            _FakeOutcome(function="x", status="finding", evidence_tool=""),
            _FakeOutcome(function="y", status="finding",
                         evidence_tool="semgrep"),
        ]
        emitted = check_outcomes(
            tmp_path, outcomes, stage="findings-export",
        )
        assert len(emitted) == 1
        assert emitted[0]["function"] == "x"


# ---------------------------------------------------------------------------
# Report surface
# ---------------------------------------------------------------------------


class TestReportSurface:
    def test_alarms_appear_in_report_summary(self, tmp_path):
        check_and_emit(
            tmp_path,
            _FakeOutcome(status="finding", evidence_tool=""),
            stage="journal-write",
        )
        from core.audit.report import generate_report

        report = generate_report(tmp_path)
        alarms = report.get("promotion_alarms")
        assert alarms and alarms[0]["event"] == ALARM_EVENT
        assert "Promotion alarms" in report["summary"]

    def test_clean_run_report_has_no_alarm_section(self, tmp_path):
        from core.audit.report import generate_report

        report = generate_report(tmp_path)
        assert "promotion_alarms" not in report
        assert "Promotion alarms" not in report["summary"]
