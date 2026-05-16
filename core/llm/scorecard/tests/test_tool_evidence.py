"""Tests for the tool-evidence producer.

Covers the single-record primitive
(``record_tool_evidence_outcome``), the bulk variant, and the CLI
``tool-evidence`` subcommand that joins orchestrated + validation
reports.
"""

from __future__ import annotations

import io
import json
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from types import SimpleNamespace

import pytest

from core.llm.scorecard import cli as cli_mod
from core.llm.scorecard.scorecard import EventType, ModelScorecard
from core.llm.scorecard.tool_evidence import (
    record_tool_evidence_outcome,
    record_tool_evidence_outcomes,
)


@pytest.fixture
def scorecard(tmp_path: Path) -> ModelScorecard:
    return ModelScorecard(tmp_path / "sc.json", shadow_rate=0.0)


def _stat(sc: ModelScorecard, dc: str, model: str, ev: str = EventType.TOOL_EVIDENCE):
    s = sc.get_stat(dc, model)
    if s is None:
        return (0, 0)
    return s.events[ev].correct, s.events[ev].incorrect


# ---------------------------------------------------------------------------
# Single-record primitive
# ---------------------------------------------------------------------------


class TestSingleRecord:
    def test_agree_records_correct(self, scorecard):
        ok = record_tool_evidence_outcome(
            scorecard,
            model="claude-opus", rule_id="py/sql-injection",
            analysis_verdict=True, validation_verdict=True,
        )
        assert ok is True
        assert _stat(scorecard, "agentic:py/sql-injection", "claude-opus") == (1, 0)

    def test_disagree_records_incorrect(self, scorecard):
        ok = record_tool_evidence_outcome(
            scorecard,
            model="claude-opus", rule_id="py/sql-injection",
            analysis_verdict=True, validation_verdict=False,
        )
        assert ok is True
        assert _stat(scorecard, "agentic:py/sql-injection", "claude-opus") == (0, 1)

    def test_inconclusive_skipped(self, scorecard):
        ok = record_tool_evidence_outcome(
            scorecard,
            model="claude-opus", rule_id="py/sql-injection",
            analysis_verdict=True, validation_verdict=None,
        )
        assert ok is False
        assert scorecard.get_stat("agentic:py/sql-injection", "claude-opus") is None

    def test_none_scorecard_no_op(self):
        ok = record_tool_evidence_outcome(
            None,
            model="m", rule_id="r",
            analysis_verdict=True, validation_verdict=True,
        )
        assert ok is False

    def test_missing_model_skipped(self, scorecard):
        ok = record_tool_evidence_outcome(
            scorecard,
            model="", rule_id="py/x",
            analysis_verdict=True, validation_verdict=False,
        )
        assert ok is False

    def test_missing_rule_id_skipped(self, scorecard):
        ok = record_tool_evidence_outcome(
            scorecard,
            model="m", rule_id="",
            analysis_verdict=True, validation_verdict=False,
        )
        assert ok is False

    def test_finding_id_appears_in_sample(self, scorecard):
        record_tool_evidence_outcome(
            scorecard,
            model="claude-opus", rule_id="py/sql-injection",
            analysis_verdict=True, validation_verdict=False,
            finding_id="f-001",
            analysis_reasoning="model said tainted via request.GET",
        )
        s = scorecard.get_stat("agentic:py/sql-injection", "claude-opus")
        samples = [
            samp for samp in s.disagreement_samples
            if samp.get("event_type") == EventType.TOOL_EVIDENCE
        ]
        assert len(samples) == 1
        assert "request.GET" in samples[0]["this_reasoning"]
        assert "f-001" in samples[0]["other_reasoning"]
        assert "not exploitable" in samples[0]["other_reasoning"]


# ---------------------------------------------------------------------------
# Bulk variant
# ---------------------------------------------------------------------------


class TestBulkRecord:
    def test_writes_one_per_record(self, scorecard):
        records = [
            {"model": "opus", "rule_id": "py/sql-injection",
             "analysis_verdict": True, "validation_verdict": True},
            {"model": "opus", "rule_id": "py/path-traversal",
             "analysis_verdict": True, "validation_verdict": False},
            {"model": "haiku", "rule_id": "py/sql-injection",
             "analysis_verdict": False, "validation_verdict": False},
        ]
        n = record_tool_evidence_outcomes(scorecard, records=records)
        assert n == 3
        assert _stat(scorecard, "agentic:py/sql-injection", "opus") == (1, 0)
        assert _stat(scorecard, "agentic:py/path-traversal", "opus") == (0, 1)
        assert _stat(scorecard, "agentic:py/sql-injection", "haiku") == (1, 0)

    def test_inconclusive_records_skipped(self, scorecard):
        records = [
            {"model": "opus", "rule_id": "py/x",
             "analysis_verdict": True, "validation_verdict": None},
            {"model": "opus", "rule_id": "py/x",
             "analysis_verdict": True, "validation_verdict": True},
        ]
        n = record_tool_evidence_outcomes(scorecard, records=records)
        assert n == 1
        assert _stat(scorecard, "agentic:py/x", "opus") == (1, 0)

    def test_malformed_records_skipped_not_aborting(self, scorecard):
        records = [
            "garbage",
            None,
            {"model": "opus", "rule_id": "py/x",
             "analysis_verdict": True, "validation_verdict": True},
        ]
        n = record_tool_evidence_outcomes(scorecard, records=records)  # type: ignore[arg-type]
        assert n == 1


# ---------------------------------------------------------------------------
# CLI tool-evidence subcommand: join orchestrated + validation reports
# ---------------------------------------------------------------------------


def _capture(handler, args):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        rc = handler(args)
    return rc, out.getvalue(), err.getvalue()


class TestCLIToolEvidence:
    def test_joins_reports_and_records(self, tmp_path):
        analysis_path = tmp_path / "orchestrated.json"
        validation_path = tmp_path / "validation.json"
        sc_path = tmp_path / "sc.json"

        analysis_path.write_text(json.dumps({
            "results": [
                {"finding_id": "f1", "rule_id": "py/sql-injection",
                 "analysed_by": "claude-opus", "is_exploitable": True,
                 "reasoning": "tainted"},
                {"finding_id": "f2", "rule_id": "py/path-traversal",
                 "analysed_by": "claude-opus", "is_exploitable": True},
                # f3 absent from validation → skip
                {"finding_id": "f3", "rule_id": "py/x",
                 "analysed_by": "claude-opus", "is_exploitable": True},
            ],
        }))
        validation_path.write_text(json.dumps({
            "findings": [
                {"finding_id": "f1", "is_exploitable": True},
                {"finding_id": "f2", "is_exploitable": False},
                # f4 unknown to analysis → skip
                {"finding_id": "f4", "is_exploitable": True},
                # f5 inconclusive → skip
                {"finding_id": "f5", "is_exploitable": None},
            ],
        }))

        args = SimpleNamespace(
            path=sc_path,
            analysis=analysis_path,
            validation=validation_path,
            prefix="agentic",
        )
        rc, _, err = _capture(cli_mod.cmd_tool_evidence, args)
        assert rc == 0
        assert "tool_evidence event(s)" in err
        sc = ModelScorecard(sc_path)
        # f1: agreed → correct
        assert _stat(sc, "agentic:py/sql-injection", "claude-opus") == (1, 0)
        # f2: disagreed → incorrect
        assert _stat(sc, "agentic:py/path-traversal", "claude-opus") == (0, 1)
        # f3 / f4 / f5: skipped (no join / inconclusive)
        assert sc.get_stat("agentic:py/x", "claude-opus") is None

    def test_missing_analysis_file_returns_error(self, tmp_path):
        args = SimpleNamespace(
            path=tmp_path / "sc.json",
            analysis=tmp_path / "missing.json",
            validation=tmp_path / "validation.json",
            prefix="agentic",
        )
        # Validation file also missing — but analysis fail is checked
        # first; either way the command returns non-zero.
        rc, _, err = _capture(cli_mod.cmd_tool_evidence, args)
        assert rc == 2
        assert "cannot read" in err

    def test_malformed_json_returns_error(self, tmp_path):
        analysis_path = tmp_path / "orchestrated.json"
        validation_path = tmp_path / "validation.json"
        analysis_path.write_text("{not json")
        validation_path.write_text("{}")
        args = SimpleNamespace(
            path=tmp_path / "sc.json",
            analysis=analysis_path,
            validation=validation_path,
            prefix="agentic",
        )
        rc, _, err = _capture(cli_mod.cmd_tool_evidence, args)
        assert rc == 2

    def test_skips_records_without_analysed_by(self, tmp_path):
        """Adversarial: an analysis record missing ``analysed_by``
        would otherwise get a fake ``"?"`` model and silently land
        on a no-one's cell. Skip + emit a notice instead."""
        analysis_path = tmp_path / "orchestrated.json"
        validation_path = tmp_path / "validation.json"
        sc_path = tmp_path / "sc.json"
        analysis_path.write_text(json.dumps({
            "results": [
                {"finding_id": "f1", "rule_id": "py/x",
                 "is_exploitable": True},  # no analysed_by
                {"finding_id": "f2", "rule_id": "py/x",
                 "analysed_by": "claude-opus", "is_exploitable": True},
            ],
        }))
        validation_path.write_text(json.dumps({
            "findings": [
                {"finding_id": "f1", "is_exploitable": True},
                {"finding_id": "f2", "is_exploitable": False},
            ],
        }))
        args = SimpleNamespace(
            path=sc_path, analysis=analysis_path, validation=validation_path,
            prefix="agentic",
        )
        rc, _, err = _capture(cli_mod.cmd_tool_evidence, args)
        assert rc == 0
        assert "skipped" in err
        sc = ModelScorecard(sc_path)
        # Only f2 recorded.
        assert _stat(sc, "agentic:py/x", "claude-opus") == (0, 1)
        # No "?"-keyed cell.
        assert sc.get_stat("agentic:py/x", "?") is None

    def test_prefix_flag_routes_to_codeql_namespace(self, tmp_path):
        """``--prefix codeql`` routes events to ``codeql:<rule_id>``
        cells matching the existing prefilter producer's convention
        for /codeql consumers."""
        analysis_path = tmp_path / "orchestrated.json"
        validation_path = tmp_path / "validation.json"
        sc_path = tmp_path / "sc.json"
        analysis_path.write_text(json.dumps({
            "results": [
                {"finding_id": "f1", "rule_id": "py/sql-injection",
                 "analysed_by": "claude-opus", "is_exploitable": True},
            ],
        }))
        validation_path.write_text(json.dumps({
            "findings": [{"finding_id": "f1", "is_exploitable": True}],
        }))
        args = SimpleNamespace(
            path=sc_path, analysis=analysis_path, validation=validation_path,
            prefix="codeql",
        )
        rc, _, _ = _capture(cli_mod.cmd_tool_evidence, args)
        assert rc == 0
        sc = ModelScorecard(sc_path)
        # Cell under codeql:..., not agentic:...
        assert _stat(sc, "codeql:py/sql-injection", "claude-opus") == (1, 0)
        assert sc.get_stat("agentic:py/sql-injection", "claude-opus") is None

    def test_idempotency_reminder_in_output(self, tmp_path):
        """Operator should see the 'don't double-run' contract every
        time. Documented in stderr rather than tracked as state."""
        analysis_path = tmp_path / "orchestrated.json"
        validation_path = tmp_path / "validation.json"
        sc_path = tmp_path / "sc.json"
        analysis_path.write_text(json.dumps({"results": []}))
        validation_path.write_text(json.dumps({"findings": []}))
        args = SimpleNamespace(
            path=sc_path, analysis=analysis_path, validation=validation_path,
            prefix="agentic",
        )
        _, _, err = _capture(cli_mod.cmd_tool_evidence, args)
        assert "double-records" in err

    def test_isolation_from_cheap_short_circuit(self, tmp_path):
        """tool-evidence events go to TOOL_EVIDENCE slot only;
        cheap-tier counters that drive the auto-policy gate are
        untouched."""
        sc_path = tmp_path / "sc.json"
        sc = ModelScorecard(sc_path, shadow_rate=0.0)
        for _ in range(20):
            sc.record_event(
                "agentic:py/x", "claude-opus",
                EventType.CHEAP_SHORT_CIRCUIT, "correct",
            )
        before = sc.get_stat("agentic:py/x", "claude-opus").events[
            EventType.CHEAP_SHORT_CIRCUIT
        ]

        analysis_path = tmp_path / "orchestrated.json"
        validation_path = tmp_path / "validation.json"
        analysis_path.write_text(json.dumps({
            "results": [
                {"finding_id": "f1", "rule_id": "py/x",
                 "analysed_by": "claude-opus", "is_exploitable": True},
            ],
        }))
        validation_path.write_text(json.dumps({
            "findings": [
                {"finding_id": "f1", "is_exploitable": False},
            ],
        }))
        args = SimpleNamespace(
            path=sc_path,
            analysis=analysis_path,
            validation=validation_path,
            prefix="agentic",
        )
        _capture(cli_mod.cmd_tool_evidence, args)
        after = sc.get_stat("agentic:py/x", "claude-opus").events[
            EventType.CHEAP_SHORT_CIRCUIT
        ]
        assert (before.correct, before.incorrect) == (after.correct, after.incorrect)
