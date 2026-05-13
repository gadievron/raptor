"""Regression tests for F088.

`record_tool_evidence_outcome` is NOT idempotent: re-invoking the
producer with the same (model, rule_id, finding_id) doubles the
event counts and duplicates the disagreement-sample entry. The CLI
shim acknowledges this with a printed "double-records" reminder,
making the gap explicit-but-still-present.

Per F088 dossier guidance, mirrors `ec7c14bf` (dict-lock TOCTOU
dedup-by-key pattern) — gate `record_event` on first-seen of
(rule_id, model, finding_id). The atomic check-and-mark lives on
ModelScorecard so the persisted JSON gets the dedup state across
process restarts (operators running the CLI twice across days
should still see only one event per finding).

When finding_id is None, idempotency cannot apply (no key) — the
function falls back to its pre-fix behaviour so callers that lack
finding_id still record (the only known caller, cli.cmd_tool_evidence,
always provides finding_id).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.llm.scorecard.scorecard import EventType, ModelScorecard
from core.llm.scorecard.tool_evidence import (
    record_tool_evidence_outcome,
    record_tool_evidence_outcomes,
)


@pytest.fixture
def scorecard(tmp_path: Path) -> ModelScorecard:
    """Per-test scorecard backed by a fresh JSON file."""
    return ModelScorecard(tmp_path / "scorecard.json")


def _stat(sc, dc, model):
    s = sc.get_stat(dc, model)
    if s is None:
        return (0, 0)
    ev = s.events.get(EventType.TOOL_EVIDENCE)
    if ev is None:
        return (0, 0)
    return (int(ev.correct), int(ev.incorrect))


class TestIdempotency:
    """Re-invoking with the same (model, rule_id, finding_id) must
    record at most one event in the scorecard."""

    def test_second_invocation_with_same_finding_id_no_op(self, scorecard):
        ok1 = record_tool_evidence_outcome(
            scorecard,
            model="claude-opus", rule_id="py/sql",
            analysis_verdict=True, validation_verdict=True,
            finding_id="f-001",
        )
        ok2 = record_tool_evidence_outcome(
            scorecard,
            model="claude-opus", rule_id="py/sql",
            analysis_verdict=True, validation_verdict=True,
            finding_id="f-001",
        )
        assert ok1 is True, "first call must record"
        assert ok2 is False, "second call (same finding_id) must skip"
        assert _stat(scorecard, "agentic:py/sql", "claude-opus") == (1, 0), (
            "must be exactly 1 correct, not 2"
        )

    def test_disagreement_sample_not_duplicated(self, scorecard):
        record_tool_evidence_outcome(
            scorecard,
            model="claude-opus", rule_id="py/xss",
            analysis_verdict=True, validation_verdict=False,
            finding_id="f-007",
            analysis_reasoning="taint via request.GET",
        )
        record_tool_evidence_outcome(
            scorecard,
            model="claude-opus", rule_id="py/xss",
            analysis_verdict=True, validation_verdict=False,
            finding_id="f-007",
            analysis_reasoning="taint via request.GET",
        )
        s = scorecard.get_stat("agentic:py/xss", "claude-opus")
        samples = [
            samp for samp in s.disagreement_samples
            if samp.get("event_type") == EventType.TOOL_EVIDENCE
        ]
        # Without dedup, this is 2. With dedup, this is 1.
        assert len(samples) == 1, (
            f"expected 1 disagreement sample post-dedup, got {len(samples)}"
        )

    def test_different_finding_id_same_cell_records_both(self, scorecard):
        ok1 = record_tool_evidence_outcome(
            scorecard,
            model="claude-opus", rule_id="py/sql",
            analysis_verdict=True, validation_verdict=True,
            finding_id="f-001",
        )
        ok2 = record_tool_evidence_outcome(
            scorecard,
            model="claude-opus", rule_id="py/sql",
            analysis_verdict=True, validation_verdict=True,
            finding_id="f-002",
        )
        assert ok1 is True
        assert ok2 is True
        assert _stat(scorecard, "agentic:py/sql", "claude-opus") == (2, 0)

    def test_different_model_same_finding_id_records_both(self, scorecard):
        ok1 = record_tool_evidence_outcome(
            scorecard,
            model="claude-opus", rule_id="py/sql",
            analysis_verdict=True, validation_verdict=True,
            finding_id="f-001",
        )
        ok2 = record_tool_evidence_outcome(
            scorecard,
            model="gpt-4o", rule_id="py/sql",
            analysis_verdict=True, validation_verdict=True,
            finding_id="f-001",
        )
        assert ok1 is True
        assert ok2 is True
        assert _stat(scorecard, "agentic:py/sql", "claude-opus") == (1, 0)
        assert _stat(scorecard, "agentic:py/sql", "gpt-4o") == (1, 0)

    def test_different_rule_id_same_finding_id_records_both(self, scorecard):
        ok1 = record_tool_evidence_outcome(
            scorecard,
            model="claude-opus", rule_id="py/sql",
            analysis_verdict=True, validation_verdict=True,
            finding_id="f-001",
        )
        ok2 = record_tool_evidence_outcome(
            scorecard,
            model="claude-opus", rule_id="py/xss",
            analysis_verdict=True, validation_verdict=True,
            finding_id="f-001",
        )
        assert ok1 is True
        assert ok2 is True

    def test_no_finding_id_falls_back_to_old_behaviour(self, scorecard):
        """When finding_id is None there is no key to dedup on; the
        producer must still record (legacy callers may not have
        finding_id available)."""
        ok1 = record_tool_evidence_outcome(
            scorecard,
            model="claude-opus", rule_id="py/sql",
            analysis_verdict=True, validation_verdict=True,
            finding_id=None,
        )
        ok2 = record_tool_evidence_outcome(
            scorecard,
            model="claude-opus", rule_id="py/sql",
            analysis_verdict=True, validation_verdict=True,
            finding_id=None,
        )
        assert ok1 is True
        assert ok2 is True
        # Without finding_id, we cannot dedup; both record.
        assert _stat(scorecard, "agentic:py/sql", "claude-opus") == (2, 0)

    def test_idempotency_persists_across_scorecard_reload(self, tmp_path):
        """Operators running the CLI twice across processes must
        still see dedup. The dedup state lives in the scorecard JSON
        (alongside event counts), not just in-memory."""
        path = tmp_path / "scorecard.json"
        sc1 = ModelScorecard(path)
        ok1 = record_tool_evidence_outcome(
            sc1,
            model="claude-opus", rule_id="py/sql",
            analysis_verdict=True, validation_verdict=True,
            finding_id="f-100",
        )
        # Fresh scorecard reading from same file — simulates a new
        # CLI invocation re-loading the persisted state.
        sc2 = ModelScorecard(path)
        ok2 = record_tool_evidence_outcome(
            sc2,
            model="claude-opus", rule_id="py/sql",
            analysis_verdict=True, validation_verdict=True,
            finding_id="f-100",
        )
        assert ok1 is True
        assert ok2 is False
        assert _stat(sc2, "agentic:py/sql", "claude-opus") == (1, 0)


class TestBulkIdempotency:
    """The bulk variant must inherit idempotency via the single-record
    path it delegates to."""

    def test_bulk_dedups_repeated_finding_id(self, scorecard):
        records = [
            {
                "model": "claude-opus", "rule_id": "py/sql",
                "analysis_verdict": True, "validation_verdict": True,
                "finding_id": "f-1",
            },
            {
                "model": "claude-opus", "rule_id": "py/sql",
                "analysis_verdict": True, "validation_verdict": True,
                "finding_id": "f-1",  # dupe
            },
            {
                "model": "claude-opus", "rule_id": "py/sql",
                "analysis_verdict": True, "validation_verdict": True,
                "finding_id": "f-2",
            },
        ]
        n = record_tool_evidence_outcomes(scorecard, records=records)
        # Bulk returns count of *recorded* events — 2, not 3.
        assert n == 2
        assert _stat(scorecard, "agentic:py/sql", "claude-opus") == (2, 0)
