"""Tests for core.orchestration.funnel — bucket classification (gh #549).

Regression coverage for the silent-success bug where every per-finding
LLM dispatch returning ``is_true_positive: None`` (q<0.5 from
cc_dispatch) was counted as a confirmed true positive, masking total
dispatch failure behind a successful-looking report.
"""

from __future__ import annotations

from core.orchestration.funnel import bucket_orchestration_results


class TestVerdictBucketing:
    """True / False / None on ``is_true_positive`` route correctly."""

    def test_true_verdict_counts_as_true_positive(self):
        results = [{"is_true_positive": True}]
        b = bucket_orchestration_results(results)
        assert b["true_positives"] == 1
        assert b["false_positives"] == 0
        assert b["unverdicted"] == 0

    def test_false_verdict_counts_as_false_positive(self):
        results = [{"is_true_positive": False}]
        b = bucket_orchestration_results(results)
        assert b["false_positives"] == 1
        assert b["true_positives"] == 0
        assert b["unverdicted"] == 0

    def test_none_verdict_is_unverdicted_not_true_positive(self):
        # THE bug: pre-fix the `else` branch counted this as a true
        # positive. Three None verdicts must show as 3 unverdicted, 0
        # true_positives.
        results = [
            {"is_true_positive": None},
            {"is_true_positive": None},
            {"is_true_positive": None},
        ]
        b = bucket_orchestration_results(results)
        assert b["unverdicted"] == 3
        assert b["true_positives"] == 0
        assert b["false_positives"] == 0

    def test_missing_key_is_not_counted(self):
        # Pre-existing semantics: results without the ``is_true_positive``
        # key are treated as "not analysed" and contribute to none of
        # the three buckets.
        results = [{"file_path": "x.py"}]
        b = bucket_orchestration_results(results)
        assert b["true_positives"] == 0
        assert b["false_positives"] == 0
        assert b["unverdicted"] == 0


class TestErrorAndBlockedBucketing:
    """Errored / blocked items skip the verdict path entirely."""

    def test_error_increments_failed(self):
        results = [{"error": "exit code 1: boom"}]
        b = bucket_orchestration_results(results)
        assert b["failed"] == 1
        assert b["blocked"] == 0

    def test_blocked_error_type_increments_blocked(self):
        results = [{"error": "policy block", "error_type": "blocked"}]
        b = bucket_orchestration_results(results)
        assert b["blocked"] == 1
        assert b["failed"] == 0

    def test_error_does_not_count_verdict_or_exploitable(self):
        # Even if the dict happens to carry is_true_positive / is_exploitable,
        # an error short-circuits to the failed/blocked bucket only.
        results = [{
            "error": "timeout",
            "is_true_positive": True,
            "is_exploitable": True,
        }]
        b = bucket_orchestration_results(results)
        assert b["failed"] == 1
        assert b["true_positives"] == 0
        assert b["exploitable"] == 0


class TestExploitableTracking:
    """``is_exploitable`` truthy increments the exploitable count."""

    def test_true_positive_exploitable_counts_both(self):
        results = [{"is_true_positive": True, "is_exploitable": True}]
        b = bucket_orchestration_results(results)
        assert b["true_positives"] == 1
        assert b["exploitable"] == 1

    def test_unverdicted_with_none_exploitable_is_not_counted(self):
        # Defensive: a q<0.5 empty response has BOTH verdicts as None.
        # Unverdicted bucket fires; exploitable does NOT (None is falsy).
        results = [{"is_true_positive": None, "is_exploitable": None}]
        b = bucket_orchestration_results(results)
        assert b["unverdicted"] == 1
        assert b["exploitable"] == 0


class TestSeverityMismatch:
    """False-positive verdict on a scanner-flagged ``error`` finding lands
    in ``severity_mismatches`` for operator review.
    """

    def test_false_positive_with_error_level_flagged(self):
        finding = {"is_true_positive": False, "level": "error", "file_path": "x.c"}
        b = bucket_orchestration_results([finding])
        assert b["false_positives"] == 1
        assert b["severity_mismatches"] == [finding]

    def test_false_positive_without_error_level_not_flagged(self):
        finding = {"is_true_positive": False, "level": "warning"}
        b = bucket_orchestration_results([finding])
        assert b["false_positives"] == 1
        assert b["severity_mismatches"] == []

    def test_unverdicted_does_not_land_in_severity_mismatches(self):
        # gh #549 inverse: a None verdict on an error-level scanner
        # finding must NOT be treated as a "scanner said error but
        # LLM said FP" mismatch — the LLM didn't say anything.
        finding = {"is_true_positive": None, "level": "error"}
        b = bucket_orchestration_results([finding])
        assert b["unverdicted"] == 1
        assert b["severity_mismatches"] == []


class TestRealWorldShape:
    """End-to-end shapes mirroring the gh #549 repro."""

    def test_zephrfish_repro_three_empty_verdicts(self):
        # All three findings came back with empty verdicts (q=0.08).
        # Pre-fix: reported "True positives: 3" (silent success).
        # Post-fix: 0 TP, 3 unverdicted, 0 exploitable.
        results = [
            {"is_true_positive": None, "is_exploitable": None, "file_path": "a.mjs"},
            {"is_true_positive": None, "is_exploitable": None, "file_path": "b.mjs"},
            {"is_true_positive": None, "is_exploitable": None, "file_path": "c.mjs"},
        ]
        b = bucket_orchestration_results(results)
        assert b["true_positives"] == 0
        assert b["false_positives"] == 0
        assert b["unverdicted"] == 3
        assert b["exploitable"] == 0
        assert b["failed"] == 0
        assert b["blocked"] == 0

    def test_mixed_run(self):
        results = [
            {"is_true_positive": True, "is_exploitable": True},
            {"is_true_positive": False, "level": "error"},
            {"is_true_positive": None},
            {"error": "timeout"},
            {"error": "policy", "error_type": "blocked"},
        ]
        b = bucket_orchestration_results(results)
        assert b["true_positives"] == 1
        assert b["false_positives"] == 1
        assert b["unverdicted"] == 1
        assert b["exploitable"] == 1
        assert b["failed"] == 1
        assert b["blocked"] == 1
        assert len(b["severity_mismatches"]) == 1

    def test_empty_results_returns_all_zeros(self):
        b = bucket_orchestration_results([])
        assert b["true_positives"] == 0
        assert b["false_positives"] == 0
        assert b["unverdicted"] == 0
        assert b["exploitable"] == 0
        assert b["failed"] == 0
        assert b["blocked"] == 0
        assert b["severity_mismatches"] == []
