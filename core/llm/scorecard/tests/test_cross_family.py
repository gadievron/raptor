"""Tests for cross-family check scorecard producer."""

from __future__ import annotations

from pathlib import Path

from core.llm.scorecard.cross_family import record_cross_family_outcomes
from core.llm.scorecard.scorecard import EventType, ModelScorecard


def _make_result(finding_id, *, rule_id="test-rule", model="gemini-2.5-pro",
                 cf_check=None, cf_agreed=False, cf_disputed=False):
    r = {
        "finding_id": finding_id,
        "rule_id": rule_id,
        "analysed_by": model,
        "resolved_model": model,
        "is_exploitable": True,
        "reasoning": "some reasoning",
    }
    if cf_check is not None:
        r["cross_family_check"] = cf_check
    if cf_agreed:
        r["cross_family_agreed"] = True
    if cf_disputed:
        r["cross_family_disputed"] = True
    return r


class TestRecordCrossFamilyOutcomes:
    def test_none_scorecard_returns_zero(self):
        assert record_cross_family_outcomes(None, results_by_id={}) == 0

    def test_no_cross_family_findings(self, tmp_path: Path):
        sc = ModelScorecard(path=tmp_path / "sc.json")
        results = {"F-001": _make_result("F-001")}
        assert record_cross_family_outcomes(sc, results_by_id=results) == 0

    def test_agreed_records_correct(self, tmp_path: Path):
        sc = ModelScorecard(path=tmp_path / "sc.json")
        results = {"F-001": _make_result(
            "F-001",
            cf_check={"checker_model": "gpt-5", "verdict": "agreed"},
            cf_agreed=True,
        )}
        n = record_cross_family_outcomes(sc, results_by_id=results)
        assert n == 1
        stats = sc.get_stats()
        cell = next(s for s in stats if s.model == "gpt-5")
        ec = cell.events.get(EventType.CROSS_FAMILY_CONSISTENCY)
        assert ec is not None
        assert ec.correct == 1

    def test_model_version_never_the_checker_alias(self, tmp_path: Path):
        """Family convention (see consensus.py): model_version is the
        concrete served snapshot, None when unavailable so the cell
        stays alias-keyed — the check record carries no
        resolved_model, and stamping the alias made the cell lie
        about its snapshot."""
        sc = ModelScorecard(path=tmp_path / "sc.json")
        results = {"F-001": _make_result(
            "F-001",
            cf_check={"checker_model": "gpt-5", "verdict": "agreed"},
        )}
        assert record_cross_family_outcomes(sc, results_by_id=results) == 1
        dc = "agentic:test-rule"
        assert sc.get_stat(dc, "gpt-5").model_version in ("", None)

    def test_future_disagreed_verdict_is_not_agreement(
            self, tmp_path: Path):
        """Prefix-anchored grammar: a verdict string outside the
        producer's known set must record nothing — the bare substring
        test read a hypothetical "disagreed" as agreement."""
        sc = ModelScorecard(path=tmp_path / "sc.json")
        results = {"F-001": _make_result(
            "F-001",
            cf_check={"checker_model": "gpt-5", "verdict": "disagreed"},
        )}
        assert record_cross_family_outcomes(sc, results_by_id=results) == 0

    def test_disputed_records_incorrect(self, tmp_path: Path):
        sc = ModelScorecard(path=tmp_path / "sc.json")
        results = {"F-001": _make_result(
            "F-001",
            cf_check={
                "checker_model": "gpt-5",
                "verdict": "disputed — conservative override",
                "checker_ruling": "This is a false positive because...",
                "trigger": "nonce_leaked",
            },
            cf_disputed=True,
        )}
        n = record_cross_family_outcomes(sc, results_by_id=results)
        assert n == 1
        stats = sc.get_stats()
        cell = next(s for s in stats if s.model == "gpt-5")
        ec = cell.events.get(EventType.CROSS_FAMILY_CONSISTENCY)
        assert ec is not None
        assert ec.incorrect == 1

    def test_disputed_captures_sample(self, tmp_path: Path):
        sc = ModelScorecard(path=tmp_path / "sc.json")
        sc.retain_samples = True
        results = {"F-001": _make_result(
            "F-001",
            cf_check={
                "checker_model": "gpt-5",
                "verdict": "disputed — conservative override",
                "checker_ruling": "Actually safe due to bounds check",
                "trigger": "low_quality",
            },
            cf_disputed=True,
        )}
        record_cross_family_outcomes(sc, results_by_id=results)
        stats = sc.get_stats()
        cell = next(s for s in stats if s.model == "gpt-5")
        assert len(cell.disagreement_samples) == 1
        assert cell.disagreement_samples[0]["trigger"] == "low_quality"
        assert "bounds check" in cell.disagreement_samples[0]["checker_ruling"]

    def test_skips_same_family_fallback(self, tmp_path: Path):
        sc = ModelScorecard(path=tmp_path / "sc.json")
        results = {"F-001": _make_result(
            "F-001",
            cf_check={
                "checker_model": "gemini-2.5-flash",
                "intended_model": "gpt-5",
                "verdict": "skipped — checker fell back to same family",
                "trigger": "nonce_leaked",
            },
        )}
        assert record_cross_family_outcomes(sc, results_by_id=results) == 0

    def test_decision_class_format(self, tmp_path: Path):
        sc = ModelScorecard(path=tmp_path / "sc.json")
        results = {"F-001": _make_result(
            "F-001",
            rule_id="py/sql-injection",
            cf_check={"checker_model": "gpt-5", "verdict": "agreed"},
            cf_agreed=True,
        )}
        record_cross_family_outcomes(sc, results_by_id=results)
        classes = {s.decision_class for s in sc.get_stats()}
        assert "agentic:py/sql-injection" in classes

    def test_multiple_findings_mixed(self, tmp_path: Path):
        sc = ModelScorecard(path=tmp_path / "sc.json")
        results = {
            "F-001": _make_result(
                "F-001",
                cf_check={"checker_model": "gpt-5", "verdict": "agreed"},
                cf_agreed=True,
            ),
            "F-002": _make_result(
                "F-002",
                cf_check={
                    "checker_model": "gpt-5",
                    "verdict": "disputed — conservative override",
                },
                cf_disputed=True,
            ),
            "F-003": _make_result("F-003"),
        }
        n = record_cross_family_outcomes(sc, results_by_id=results)
        assert n == 2
        stats = sc.get_stats()
        cell = next(s for s in stats if s.model == "gpt-5")
        ec = cell.events[EventType.CROSS_FAMILY_CONSISTENCY]
        assert ec.correct == 1
        assert ec.incorrect == 1

    def test_disputed_derived_from_verdict_string(self, tmp_path: Path):
        """Verdict-string drives outcome even without top-level boolean."""
        sc = ModelScorecard(path=tmp_path / "sc.json")
        results = {"F-001": _make_result(
            "F-001",
            cf_check={
                "checker_model": "gpt-5",
                "verdict": "disputed — conservative override",
            },
        )}
        n = record_cross_family_outcomes(sc, results_by_id=results)
        assert n == 1
        cell = next(s for s in sc.get_stats() if s.model == "gpt-5")
        assert cell.events[EventType.CROSS_FAMILY_CONSISTENCY].incorrect == 1

    def test_skips_empty_checker_model(self, tmp_path: Path):
        sc = ModelScorecard(path=tmp_path / "sc.json")
        results = {"F-001": _make_result(
            "F-001",
            cf_check={"checker_model": "", "verdict": "agreed"},
            cf_agreed=True,
        )}
        assert record_cross_family_outcomes(sc, results_by_id=results) == 0

    def test_skips_none_checker_model(self, tmp_path: Path):
        sc = ModelScorecard(path=tmp_path / "sc.json")
        results = {"F-001": _make_result(
            "F-001",
            cf_check={"checker_model": None, "verdict": "agreed"},
            cf_agreed=True,
        )}
        assert record_cross_family_outcomes(sc, results_by_id=results) == 0


class TestConsistencyNotReliabilityGraded:
    """A 1-vs-1 primary/checker pair carries no ground truth, so both
    outcomes must land on the consistency slot — which the calibrated
    merge's reliability pool excludes — and never on a
    correctness-graded slot."""

    def test_consistency_slot_excluded_from_reliability_pool(self):
        from core.audit.calibrated_merge import RELIABILITY_EVENT_TYPES

        assert (EventType.CROSS_FAMILY_CONSISTENCY
                not in RELIABILITY_EVENT_TYPES)

    def test_dispute_records_neutral_event_only(self, tmp_path: Path):
        from core.audit.calibrated_merge import RELIABILITY_EVENT_TYPES

        sc = ModelScorecard(path=tmp_path / "sc.json")
        results = {"F-001": _make_result(
            "F-001",
            cf_check={
                "checker_model": "gpt-5",
                "verdict": "disputed — conservative override",
                "checker_ruling": "primary overstated reachability",
                "trigger": "low_quality",
            },
            cf_disputed=True,
        )}
        n = record_cross_family_outcomes(sc, results_by_id=results)
        assert n == 1
        cell = next(s for s in sc.get_stats() if s.model == "gpt-5")
        # Neutral shape present.
        cons = cell.events[EventType.CROSS_FAMILY_CONSISTENCY]
        assert (cons.correct, cons.incorrect) == (0, 1)
        # No reliability-pooled slot gained an attribution.
        for event_type, counts in cell.events.items():
            if event_type in RELIABILITY_EVENT_TYPES:
                assert counts.correct == 0
                assert counts.incorrect == 0

    def test_agreement_records_neutral_event_only(self, tmp_path: Path):
        from core.audit.calibrated_merge import RELIABILITY_EVENT_TYPES

        sc = ModelScorecard(path=tmp_path / "sc.json")
        results = {"F-001": _make_result(
            "F-001",
            cf_check={"checker_model": "gpt-5", "verdict": "agreed"},
            cf_agreed=True,
        )}
        n = record_cross_family_outcomes(sc, results_by_id=results)
        assert n == 1
        cell = next(s for s in sc.get_stats() if s.model == "gpt-5")
        cons = cell.events[EventType.CROSS_FAMILY_CONSISTENCY]
        assert (cons.correct, cons.incorrect) == (1, 0)
        for event_type, counts in cell.events.items():
            if event_type in RELIABILITY_EVENT_TYPES:
                assert counts.correct == 0
                assert counts.incorrect == 0


class TestMalformedVerdict:
    def test_none_verdict_skips_without_aborting_walk(self, tmp_path: Path):
        """A present-but-None verdict (checker errored upstream) must
        degrade to a skip — pre-fix it raised AttributeError outside
        the per-event try, dropping every remaining finding's event."""
        sc = ModelScorecard(path=tmp_path / "sc.json")
        results = {
            "F-001": _make_result("F-001", cf_check={
                "verdict": None,
                "checker_model": "gpt-5.2",
            }),
            "F-002": _make_result("F-002", cf_check={
                "verdict": "disputed",
                "checker_model": "gpt-5.2",
                "trigger": "verdict-flip",
                "checker_ruling": "disagree",
            }),
        }
        n = record_cross_family_outcomes(sc, results_by_id=results)
        assert n == 1


class TestVerdictStringIsAuthoritative:
    """The verdict string is the producer's grammar; the top-level
    boolean flags are set by a different code path and can fall out
    of sync. An out-of-sync True flag must never mint ``correct``
    past a present-but-unknown verdict; the flag serves only as the
    backstop for legacy records that carry no verdict string."""

    def test_unknown_verdict_with_true_flag_mints_nothing(self, tmp_path):
        sc = ModelScorecard(tmp_path / "sc.json")
        n = record_cross_family_outcomes(
            sc,
            results_by_id={"f1": {
                "rule_id": "r",
                "cross_family_agreed": True,  # out-of-sync flag
                "cross_family_check": {
                    "verdict": "someday-a-new-verdict",
                    "checker_model": "gemini-pro",
                },
            }},
        )
        assert n == 0

    def test_flag_backstops_verdictless_legacy_record(self, tmp_path):
        sc = ModelScorecard(tmp_path / "sc.json")
        n = record_cross_family_outcomes(
            sc,
            results_by_id={"f1": {
                "rule_id": "r",
                "cross_family_agreed": True,
                "cross_family_check": {
                    # legacy record: no verdict string at all
                    "checker_model": "gemini-pro",
                },
            }},
        )
        assert n == 1
        stat = sc.get_stat("agentic:r", "gemini-pro")
        assert stat.events["cross_family_consistency"].correct == 1
