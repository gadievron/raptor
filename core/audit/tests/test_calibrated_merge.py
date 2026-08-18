"""Tests for the calibrated cross-model merge decision.

Previously the merge was prefer-positive with one heuristic, and that
heuristic counted ``status="error"`` results in the panel: one finding
plus two content-filter errors downgraded although no model disagreed.
Reliability data from the scorecard store sat unused at decision time.

These tests pin: error votes excluded from the dissent denominator,
reliability-weighted posteriors (a reliable model's lone finding in
its strong class survives two weak negatives), priors applied, ties
broken by calibrated confidence not list order, conservative cold-start
fallback, the tool-evidence preservation guard, and merge telemetry.
No LLM calls anywhere.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import pytest

from core.audit.calibrated_merge import (
    MIN_RELIABILITY_EVENTS,
    calibrated_decision,
    decision_class_for,
    model_reliability,
    priors_from_journal,
)
from core.audit.multi_review import AuditVerdictAdapter

# ---------------------------------------------------------------------------
# Scorecard stub
# ---------------------------------------------------------------------------

@dataclass
class _Counts:
    correct: int = 0
    incorrect: int = 0


@dataclass
class _Stats:
    events: dict = field(default_factory=dict)


class _Scorecard:
    """Minimal ModelScorecard stand-in: (decision_class, model) → events."""

    def __init__(self, cells: dict | None = None):
        # cells: {(decision_class, model): {event_type: (correct, incorrect)}}
        self._cells = cells or {}

    def get_stat(self, decision_class: str, model: str):
        cell = self._cells.get((decision_class, model))
        if cell is None:
            return None
        return _Stats(events={
            et: _Counts(correct=c, incorrect=i)
            for et, (c, i) in cell.items()
        })


def _v(status: str, model: str, **extra) -> dict:
    return {"file": "a.c", "function": "f", "status": status,
            "_model": model, **extra}


def _reliable(correct: int = 18, incorrect: int = 2) -> dict:
    return {"tool_evidence": (correct, incorrect)}


def _weak(correct: int = 3, incorrect: int = 7) -> dict:
    return {"tool_evidence": (correct, incorrect)}


# ---------------------------------------------------------------------------
# P20(a): error votes must not count as dissent
# ---------------------------------------------------------------------------

class TestErrorVotesExcluded:
    def test_finding_plus_two_errors_not_downgraded(self):
        adapter = AuditVerdictAdapter()
        results = [
            _v("finding", "model-a"),
            _v("error", "model-b"),
            _v("error", "model-c"),
        ]
        primary = adapter.select_primary(results)
        assert primary["status"] == "finding", (
            "content-filter errors are not dissenting votes"
        )

    def test_true_lone_dissent_still_downgraded(self):
        adapter = AuditVerdictAdapter()
        results = [
            _v("finding", "model-a"),
            _v("clean", "model-b"),
            _v("clean", "model-c"),
        ]
        primary = adapter.select_primary(results)
        assert primary["status"] == "suspicious"

    def test_all_errors_still_returns_something(self):
        adapter = AuditVerdictAdapter()
        results = [_v("error", "model-a"), _v("error", "model-b")]
        primary = adapter.select_primary(results)
        assert primary["status"] == "error"


# ---------------------------------------------------------------------------
# Decision class + reliability
# ---------------------------------------------------------------------------

class TestDecisionClass:
    def test_cwe_from_variant(self):
        variants = [_v("finding", "m", cwe="CWE-190"), _v("clean", "m2")]
        assert decision_class_for(variants) == "audit:CWE-190"

    def test_fallback_class(self):
        assert decision_class_for([_v("clean", "m")]) == "audit:review"


class TestModelReliability:
    def test_informative_cell(self):
        sc = _Scorecard({("audit:CWE-190", "model-a"): _reliable(18, 2)})
        r = model_reliability(sc, "audit:CWE-190", "model-a")
        assert r is not None and r > 0.8

    def test_sparse_cell_uninformative(self):
        sc = _Scorecard({
            ("audit:CWE-190", "model-a"): {
                "tool_evidence": (MIN_RELIABILITY_EVENTS - 3, 0),
            },
        })
        assert model_reliability(sc, "audit:CWE-190", "model-a") is None

    def test_missing_cell_uninformative(self):
        assert model_reliability(_Scorecard(), "audit:CWE-190", "m") is None

    def test_schema_valid_events_ignored(self):
        sc = _Scorecard({
            ("audit:CWE-190", "model-a"): {"schema_valid": (100, 0)},
        })
        assert model_reliability(sc, "audit:CWE-190", "model-a") is None


# ---------------------------------------------------------------------------
# Calibrated decision
# ---------------------------------------------------------------------------

class TestCalibratedDecision:
    def test_reliable_lone_finding_survives_weak_majority(self):
        """The P20 headline: a reliable model's finding in its strong
        class is no longer outvoted by two weak models."""
        sc = _Scorecard({
            ("audit:CWE-190", "model-a"): _reliable(),
            ("audit:CWE-190", "model-b"): _weak(),
            ("audit:CWE-190", "model-c"): _weak(),
        })
        variants = [
            _v("finding", "model-a", cwe="CWE-190"),
            _v("clean", "model-b"),
            _v("clean", "model-c"),
        ]
        decision = calibrated_decision(variants, scorecard=sc)
        assert decision is not None
        assert decision.primary["status"] == "finding"
        assert decision.telemetry["method"] == "calibrated"
        assert decision.telemetry["posterior_positive"] > 0.5

    def test_cold_start_returns_none(self):
        decision = calibrated_decision(
            [_v("finding", "m1"), _v("clean", "m2")],
            scorecard=_Scorecard(),
        )
        assert decision is None

    def test_prior_alone_can_decide(self):
        from core.llm.scorecard.priors import weak_informative_prior
        priors = {"audit:CWE-190": weak_informative_prior(0.9, 20)}
        variants = [
            _v("finding", "m1", cwe="CWE-190"),
            _v("clean", "m2"),
        ]
        decision = calibrated_decision(
            variants, scorecard=_Scorecard(), priors_by_class=priors,
        )
        assert decision is not None
        assert decision.primary["status"] == "finding"
        assert decision.telemetry["prior"] == pytest.approx(0.9, abs=0.01)

    def test_tie_broken_by_reliability_not_order(self):
        """Among same-side candidates, the most reliable model's
        variant is primary even when it appears later in the list."""
        sc = _Scorecard({
            ("audit:review", "model-lo"): {"tool_evidence": (6, 4)},
            ("audit:review", "model-hi"): _reliable(),
        })
        variants = [
            _v("suspicious", "model-lo", body="low-reliability body"),
            _v("suspicious", "model-hi", body="high-reliability body"),
        ]
        decision = calibrated_decision(variants, scorecard=sc)
        assert decision is not None
        assert decision.primary["_model"] == "model-hi"

    def test_negative_decision_preserves_tool_backed_positive(self):
        """A calibrated negative never silently drops a mechanical
        tool receipt — demote to suspicious with the guard recorded."""
        sc = _Scorecard({
            ("audit:review", "model-b"): _reliable(),
            ("audit:review", "model-c"): _reliable(),
        })
        variants = [
            _v("finding", "model-a",
               evidence_tool="smt:check-overflow"),
            _v("clean", "model-b"),
            _v("clean", "model-c"),
        ]
        decision = calibrated_decision(variants, scorecard=sc)
        assert decision is not None
        assert decision.telemetry["posterior_positive"] < 0.5
        assert decision.primary["status"] == "suspicious"
        assert decision.primary["calibrated_downgrade"] is True
        assert decision.telemetry["guard"] == "tool_evidence_preserved"

    def test_negative_decision_llm_only_positive_dropped(self):
        sc = _Scorecard({
            ("audit:review", "model-b"): _reliable(),
            ("audit:review", "model-c"): _reliable(),
        })
        variants = [
            _v("finding", "model-a"),
            _v("clean", "model-b"),
            _v("clean", "model-c"),
        ]
        decision = calibrated_decision(variants, scorecard=sc)
        assert decision is not None
        assert decision.primary["status"] == "clean"


# ---------------------------------------------------------------------------
# Adapter integration + telemetry
# ---------------------------------------------------------------------------

class TestAdapterIntegration:
    def test_calibrated_path_annotates_telemetry(self):
        sc = _Scorecard({
            ("audit:CWE-190", "model-a"): _reliable(),
            ("audit:CWE-190", "model-b"): _weak(),
            ("audit:CWE-190", "model-c"): _weak(),
        })
        adapter = AuditVerdictAdapter(scorecard=sc)
        results = [
            _v("finding", "model-a", cwe="CWE-190"),
            _v("clean", "model-b"),
            _v("clean", "model-c"),
        ]
        primary = adapter.select_primary(results)
        assert primary["status"] == "finding"
        assert primary["merge_decision"]["method"] == "calibrated"
        weights = primary["merge_decision"]["weights"]
        assert len(weights) == 3
        assert any(w["informative"] for w in weights)

    def test_fallback_telemetry_without_scorecard(self):
        adapter = AuditVerdictAdapter()
        primary = adapter.select_primary(
            [_v("clean", "m1"), _v("clean", "m2")],
        )
        assert primary["merge_decision"]["method"] == "prefer_positive"
        assert primary["merge_decision"]["fallback_reason"] == "no_scorecard"

    def test_fallback_telemetry_cold_start(self):
        adapter = AuditVerdictAdapter(scorecard=_Scorecard())
        primary = adapter.select_primary(
            [_v("finding", "m1"), _v("clean", "m2")],
        )
        # prefer-positive keeps the finding, telemetry names the path
        assert primary["status"] == "finding"
        assert primary["merge_decision"]["method"] == "prefer_positive"
        assert (primary["merge_decision"]["fallback_reason"]
                == "cold_start_or_tie")

    def test_merge_end_to_end_through_adapter(self):
        sc = _Scorecard({
            ("audit:CWE-190", "model-a"): _reliable(),
            ("audit:CWE-190", "model-b"): _weak(),
            ("audit:CWE-190", "model-c"): _weak(),
        })
        adapter = AuditVerdictAdapter(scorecard=sc)
        per_model = {
            "model-a": [_v("finding", "model-a", cwe="CWE-190")],
            "model-b": [_v("clean", "model-b")],
            "model-c": [_v("clean", "model-c")],
        }
        # merge() attaches _model itself; strip our injected copies
        for results in per_model.values():
            for r in results:
                r.pop("_model", None)
        merged = adapter.merge(per_model)
        assert len(merged) == 1
        assert merged[0]["status"] == "finding"
        assert merged[0]["merge_decision"]["method"] == "calibrated"
        assert len(merged[0]["multi_model_analyses"]) == 3


# ---------------------------------------------------------------------------
# Priors from the journal
# ---------------------------------------------------------------------------

class TestPriorsFromJournal:
    def test_priors_built_from_validate_corrections(self, tmp_path: Path):
        from core.coverage.journal import ReviewJournalEntry, append_entry

        out = tmp_path / "run1"
        out.mkdir()
        for i, (verdict, cwe) in enumerate([
            ("confirmed", "CWE-190"),
            ("confirmed", "CWE-190"),
            ("disproven", "CWE-190"),
            ("disproven", "CWE-416"),
        ]):
            append_entry(out, ReviewJournalEntry(
                ts=f"2026-08-0{i + 1}T00:00:00Z",
                run_id="r1",
                file=f"src/f{i}.c",
                function=f"fn{i}",
                verdict="finding",
                source_hash="h",
                cwe=cwe,
                prior_review="finding",
                validate_verdict=verdict,
            ))

        priors = priors_from_journal(out)
        assert "audit:CWE-190" in priors
        assert "audit:CWE-416" in priors
        # 2 confirmed / 1 disproven → mean above 0.5
        assert priors["audit:CWE-190"].mean > 0.5
        assert priors["audit:CWE-416"].mean < 0.5

    def test_missing_journal_returns_empty(self, tmp_path: Path):
        empty = tmp_path / "nothing"
        empty.mkdir()
        assert priors_from_journal(empty) == {}

    def test_none_out_dir(self):
        assert priors_from_journal(None) == {}
