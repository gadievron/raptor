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


class TestAtomicClaimAndRecord:
    # Bugbot PR #515: the prior split-call sequence (claim → record_event)
    # used TWO separate _with_lock cycles. Between them, a process kill
    # or I/O error could leave finding_id persisted in the seen-set with
    # zero events recorded — the finding_id was then permanently "seen"
    # so retries returned False without ever recording.
    #
    # The fix introduces claim_and_record_tool_evidence, which does both
    # operations under a single lock-and-persist cycle. The tests below
    # exercise the atomicity guarantee directly on the substrate.

    def test_claim_and_record_persists_both_seen_set_and_event(
        self, scorecard,
    ):
        # Single call records both the seen-set claim and the event.
        ok = scorecard.claim_and_record_tool_evidence(
            decision_class="agentic:py/sql",
            model="claude-opus",
            finding_id="f-200",
            outcome="correct",
        )
        assert ok is True
        # Event landed.
        assert _stat(scorecard, "agentic:py/sql", "claude-opus") == (1, 0)
        # Seen-set persisted.
        raw = json.loads(scorecard.path.read_text())
        cell = raw["models"]["claude-opus"]["agentic:py/sql"]
        assert "f-200" in cell["tool_evidence_finding_ids"]

    def test_claim_and_record_returns_false_on_duplicate_no_event(
        self, scorecard,
    ):
        # First call records.
        first = scorecard.claim_and_record_tool_evidence(
            decision_class="agentic:py/sql",
            model="claude-opus",
            finding_id="f-201",
            outcome="correct",
        )
        # Second call with same finding_id is a no-op; event count
        # stays at 1.
        second = scorecard.claim_and_record_tool_evidence(
            decision_class="agentic:py/sql",
            model="claude-opus",
            finding_id="f-201",
            outcome="correct",
        )
        assert first is True
        assert second is False
        assert _stat(scorecard, "agentic:py/sql", "claude-opus") == (1, 0)

    def test_claim_and_record_persist_failure_rolls_back_both(
        self, tmp_path, monkeypatch,
    ):
        # If save_json fails (e.g. disk full mid-persist), the
        # _with_lock context exits via exception → the context does NOT
        # persist. Both the seen-set claim AND the event increment must
        # roll back: on retry the next claim_and_record_tool_evidence
        # call must succeed (NOT find finding_id already in seen-set).
        from core.llm.scorecard import scorecard as scorecard_mod

        path = tmp_path / "scorecard.json"
        sc = ModelScorecard(path)

        # Make the first attempt's persist fail.
        original_save_json = scorecard_mod.save_json
        attempts = {"n": 0}

        def flaky_save_json(p, data):
            attempts["n"] += 1
            if attempts["n"] == 1:
                raise OSError("simulated disk failure")
            return original_save_json(p, data)

        monkeypatch.setattr(scorecard_mod, "save_json", flaky_save_json)

        # First call: raises (the failure propagates out of _with_lock).
        with pytest.raises(OSError, match="simulated disk failure"):
            sc.claim_and_record_tool_evidence(
                decision_class="agentic:py/sql",
                model="claude-opus",
                finding_id="f-202",
                outcome="correct",
            )

        # Second call (with save_json now working): MUST succeed
        # — the seen-set + event from the failed first attempt MUST
        # have been rolled back by the _with_lock exception path.
        # Fresh ModelScorecard reads from disk to prove persistence.
        sc2 = ModelScorecard(path)
        ok = sc2.claim_and_record_tool_evidence(
            decision_class="agentic:py/sql",
            model="claude-opus",
            finding_id="f-202",
            outcome="correct",
        )
        assert ok is True, (
            "first call's persist failed; finding_id must NOT be in "
            "seen-set on retry (else the F088 atomicity bug recurs)"
        )
        assert _stat(sc2, "agentic:py/sql", "claude-opus") == (1, 0)

    def test_record_tool_evidence_outcome_uses_atomic_path(
        self, scorecard, monkeypatch,
    ):
        # Verify the user-facing record_tool_evidence_outcome now
        # routes through claim_and_record_tool_evidence (one lock)
        # and not through the two-call sequence (two locks).
        calls = {"claim_and_record": 0, "record_event": 0, "claim": 0}

        original_claim_and_record = scorecard.claim_and_record_tool_evidence

        def counting_claim_and_record(*a, **kw):
            calls["claim_and_record"] += 1
            return original_claim_and_record(*a, **kw)

        def counting_record_event(*a, **kw):
            calls["record_event"] += 1

        def counting_claim(*a, **kw):
            calls["claim"] += 1
            return True

        monkeypatch.setattr(
            scorecard, "claim_and_record_tool_evidence",
            counting_claim_and_record,
        )
        monkeypatch.setattr(
            scorecard, "record_event", counting_record_event,
        )
        monkeypatch.setattr(
            scorecard, "claim_tool_evidence_finding", counting_claim,
        )

        record_tool_evidence_outcome(
            scorecard,
            model="claude-opus", rule_id="py/sql",
            analysis_verdict=True, validation_verdict=True,
            finding_id="f-203",
        )

        assert calls["claim_and_record"] == 1, (
            "atomic path should fire exactly once when finding_id given"
        )
        assert calls["record_event"] == 0, (
            "separate record_event must NOT be called on the atomic path"
        )
        assert calls["claim"] == 0, (
            "separate claim must NOT be called on the atomic path"
        )


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
