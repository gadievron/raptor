"""Tests for the VALIDATE_FEEDBACK producer — the live writer of
audit:<CWE> reliability cells."""

from pathlib import Path

from core.llm.scorecard.scorecard import (
    ALL_EVENT_TYPES,
    EventType,
    ModelScorecard,
)
from core.llm.scorecard.validate_feedback import (
    classify_outcome,
    record_validate_feedback_outcome,
    record_validate_feedback_outcomes,
)


class TestEventTypeRegistration:
    def test_validate_feedback_registered(self):
        assert EventType.VALIDATE_FEEDBACK in ALL_EVENT_TYPES

    def test_corpus_ground_truth_registered(self):
        # The offline corpus harness referenced this constant before it
        # existed; its AttributeError was swallowed by the harness's
        # best-effort catch, so corpus runs silently recorded nothing.
        assert EventType.CORPUS_GROUND_TRUTH in ALL_EVENT_TYPES

    def test_reliability_set_includes_audit_producers(self):
        from core.audit.calibrated_merge import RELIABILITY_EVENT_TYPES
        assert EventType.VALIDATE_FEEDBACK in RELIABILITY_EVENT_TYPES
        assert EventType.CORPUS_GROUND_TRUTH in RELIABILITY_EVENT_TYPES


class TestClassifyOutcome:
    def test_positive_confirmed_is_correct(self):
        assert classify_outcome("finding", "confirmed") == "correct"
        assert classify_outcome("suspicious", "confirmed") == "correct"

    def test_positive_disproven_is_incorrect(self):
        assert classify_outcome("finding", "disproven") == "incorrect"
        assert classify_outcome("suspicious", "disproven") == "incorrect"

    def test_clean_confirmed_is_incorrect(self):
        # The model called it clean; /validate proved a finding — miss.
        assert classify_outcome("clean", "confirmed") == "incorrect"

    def test_clean_disproven_is_correct(self):
        assert classify_outcome("clean", "disproven") == "correct"

    def test_inconclusive_is_no_signal(self):
        assert classify_outcome("finding", "unknown") is None
        assert classify_outcome("finding", "") is None
        assert classify_outcome("error", "confirmed") is None
        assert classify_outcome("", "confirmed") is None


class TestRecording:
    def _scorecard(self, tmp_path: Path) -> ModelScorecard:
        return ModelScorecard(tmp_path / "scorecard.json")

    def test_records_into_cwe_cell(self, tmp_path: Path):
        sc = self._scorecard(tmp_path)
        ok = record_validate_feedback_outcome(
            sc, model="m1", cwe="CWE-787",
            prior_verdict="finding", validate_verdict="confirmed",
        )
        assert ok is True
        stats = sc.get_stat("audit:CWE-787", "m1")
        assert stats is not None

    def test_default_decision_class_without_cwe(self, tmp_path: Path):
        sc = self._scorecard(tmp_path)
        record_validate_feedback_outcome(
            sc, model="m1", cwe=None,
            prior_verdict="finding", validate_verdict="disproven",
        )
        assert sc.get_stat("audit:review", "m1") is not None

    def test_no_signal_records_nothing(self, tmp_path: Path):
        sc = self._scorecard(tmp_path)
        assert record_validate_feedback_outcome(
            sc, model="m1", cwe="CWE-787",
            prior_verdict="finding", validate_verdict="unknown",
        ) is False

    def test_missing_model_records_nothing(self, tmp_path: Path):
        sc = self._scorecard(tmp_path)
        assert record_validate_feedback_outcome(
            sc, model="", cwe="CWE-787",
            prior_verdict="finding", validate_verdict="confirmed",
        ) is False

    def test_batch(self, tmp_path: Path):
        sc = self._scorecard(tmp_path)
        n = record_validate_feedback_outcomes(
            [
                {"model": "m1", "cwe": "CWE-787",
                 "prior_verdict": "finding",
                 "validate_verdict": "confirmed",
                 "file": "a.c", "function": "f"},
                {"model": "m1", "cwe": "CWE-787",
                 "prior_verdict": "suspicious",
                 "validate_verdict": "disproven",
                 "file": "a.c", "function": "g", "reason": "dead path"},
                {"model": "m1", "cwe": "CWE-787",
                 "prior_verdict": "finding",
                 "validate_verdict": "unknown",
                 "file": "a.c", "function": "h"},
            ],
            scorecard=sc,
        )
        assert n == 2

    def test_empty_batch(self, tmp_path: Path):
        assert record_validate_feedback_outcomes(
            [], scorecard=self._scorecard(tmp_path)) == 0

    def test_feeds_calibrated_reliability(self, tmp_path: Path):
        # End-to-end into the calibrated-merge weight: enough
        # VALIDATE_FEEDBACK events move the model's reliability off
        # the cold-start 0.5.
        from core.audit.calibrated_merge import model_reliability
        sc = self._scorecard(tmp_path)
        for _ in range(8):
            record_validate_feedback_outcome(
                sc, model="m1", cwe="CWE-787",
                prior_verdict="finding", validate_verdict="confirmed",
            )
        weight = model_reliability(sc, "audit:CWE-787", "m1")
        assert weight is not None
        assert weight > 0.5


class TestCorpusProducerRecordsAgain:
    def test_record_scorecard_writes_events(self, tmp_path: Path,
                                            monkeypatch):
        # Regression for the silent corpus-producer breakage: the
        # harness recorded against EventType.CORPUS_GROUND_TRUTH,
        # which didn't exist — AttributeError was swallowed and no
        # audit:<bug_class> cell was ever written.
        monkeypatch.setenv("RAPTOR_DIR", str(tmp_path))
        from core.audit.corpus.run_corpus import _record_scorecard
        _record_scorecard(
            [{
                "bug_class": "CWE-190",
                "function_id": "a.c:f",
                "expected": "finding",
                "actual": "clean",
                "match": False,
                "hypothesis": "overflow",
            }],
            model="m1",
        )
        sc = ModelScorecard(tmp_path / "out" / "llm_scorecard.json")
        assert sc.get_stat("audit:CWE-190", "m1") is not None
