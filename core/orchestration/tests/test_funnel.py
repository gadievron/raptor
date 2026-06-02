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
            "self_contradictory": True,
        }]
        b = bucket_orchestration_results(results)
        assert b["failed"] == 1
        assert b["true_positives"] == 0
        assert b["exploitable"] == 0
        assert b["inconsistent"] == 0


class TestExploitableTracking:
    """``is_exploitable`` truthy increments the exploitable count."""

    def test_true_positive_exploitable_counts_both(self):
        results = [{"is_true_positive": True, "is_exploitable": True}]
        b = bucket_orchestration_results(results)
        assert b["true_positives"] == 1
        assert b["exploitable"] == 1
        assert b["inconsistent"] == 0

    def test_unverdicted_with_none_exploitable_is_not_counted(self):
        # Defensive: a q<0.5 empty response has BOTH verdicts as None.
        # Unverdicted bucket fires; exploitable does NOT (None is falsy).
        results = [{"is_true_positive": None, "is_exploitable": None}]
        b = bucket_orchestration_results(results)
        assert b["unverdicted"] == 1
        assert b["exploitable"] == 0
        assert b["inconsistent"] == 0


class TestInconsistentSplitsOutOfExploitable:
    """``self_contradictory=True`` + ``is_exploitable=True`` lands in
    ``inconsistent``, NOT in ``exploitable``. Pre-fix the headline
    "Exploitable: N" double-counted these against the per-finding
    table's totals in the same output."""

    def test_exploitable_self_contradictory_goes_to_inconsistent(self):
        results = [{
            "is_true_positive": True,
            "is_exploitable": True,
            "self_contradictory": True,
        }]
        b = bucket_orchestration_results(results)
        assert b["exploitable"] == 0
        assert b["inconsistent"] == 1
        # ``true_positives`` is unaffected — the verdict-classification
        # path runs independently of the exploitable split.
        assert b["true_positives"] == 1
        # Full finding dict surfaces in inconsistent_findings so the
        # caller can render the per-finding list without re-filtering
        # results[*].self_contradictory itself.
        assert len(b["inconsistent_findings"]) == 1
        assert b["inconsistent_findings"][0] is results[0]

    def test_exploitable_clean_stays_in_exploitable(self):
        results = [{
            "is_true_positive": True,
            "is_exploitable": True,
            "self_contradictory": False,
        }]
        b = bucket_orchestration_results(results)
        assert b["exploitable"] == 1
        assert b["inconsistent"] == 0

    def test_self_contradictory_without_exploitable_neither_bucket(self):
        # Self-contradictory verdicts that AREN'T exploitable don't go
        # into the new ``inconsistent`` bucket — that bucket exists
        # specifically to subtract from the headline Exploitable count.
        # The pre-existing "Self-contradictory: N" line in the report
        # counts these separately (broader signal).
        results = [{
            "is_true_positive": True,
            "is_exploitable": False,
            "self_contradictory": True,
        }]
        b = bucket_orchestration_results(results)
        assert b["exploitable"] == 0
        assert b["inconsistent"] == 0

    def test_mixed_exploitable_and_inconsistent_account_arithmetic(self):
        # Pre-fix the headline "Exploitable: N" included every finding
        # with is_exploitable=True, double-counting the
        # self_contradictory subset that the per-finding table
        # reported separately. Same data, two disagreeing totals in
        # the same output. Post-fix: exploitable and inconsistent are
        # disjoint, the headline and the table agree.
        results = (
            [{"is_true_positive": True, "is_exploitable": True}] * 5
            + [{"is_true_positive": True, "is_exploitable": True,
                "self_contradictory": True}] * 3
            + [{"is_true_positive": False, "is_exploitable": False}] * 2
        )
        b = bucket_orchestration_results(results)
        assert b["exploitable"] == 5
        assert b["inconsistent"] == 3
        assert b["false_positives"] == 2
        # Headline arithmetic: exploitable + inconsistent + false_positives
        # accounts for all 10 verdicts.
        assert b["exploitable"] + b["inconsistent"] + b["false_positives"] == 10


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
        assert b["inconsistent"] == 0
        assert b["failed"] == 0
        assert b["blocked"] == 0
        assert b["severity_mismatches"] == []
        assert b["inconsistent_findings"] == []


class TestStatusAwareBucketing:
    """QoL #19 wiring: when a finding carries the explicit ``status``
    field, the funnel uses it; otherwise the legacy field-detection
    path runs. Backwards-compat for pre-#19 emit sites."""

    def test_explicit_status_wins_over_field_inference(self):
        from core.run.finding_status import ANALYSIS_INCONSISTENT
        results = [{
            "is_true_positive": True,
            "is_exploitable": True,
            "status": ANALYSIS_INCONSISTENT,
            # No self_contradictory; legacy path would route to
            # ``exploitable``; explicit status routes to inconsistent.
        }]
        b = bucket_orchestration_results(results)
        assert b["exploitable"] == 0
        assert b["inconsistent"] == 1

    def test_skipped_statuses_excluded_from_verdict_buckets(self):
        # Skipped findings don't contribute to TP/FP/exploitable/
        # inconsistent. They weren't analysed, so no verdict applies.
        from core.run.finding_status import (
            SKIPPED_DEAD_CODE, SKIPPED_DUPLICATE, SKIPPED_OVER_BUDGET,
        )
        results = [
            {"status": SKIPPED_OVER_BUDGET,
             "is_true_positive": True, "is_exploitable": True},
            {"status": SKIPPED_DEAD_CODE,
             "is_true_positive": True, "is_exploitable": True},
            {"status": SKIPPED_DUPLICATE,
             "is_true_positive": False},
            # The only actually-analysed finding.
            {"is_true_positive": True, "is_exploitable": True},
        ]
        b = bucket_orchestration_results(results)
        assert b["true_positives"] == 1
        assert b["exploitable"] == 1
        assert b["false_positives"] == 0

    def test_judge_resolved_contradiction_now_lands_in_exploitable(self):
        # Composes #11-11d (judge clears self_contradictory) with
        # the funnel: the resolved finding correctly counts as
        # exploitable, not inconsistent. Operator headline drops
        # the inconsistent count without losing the finding.
        results = [{
            "is_true_positive": True,
            "is_exploitable": True,
            "self_contradictory": False,
            "contradiction_resolved_by_judge": True,
        }]
        b = bucket_orchestration_results(results)
        assert b["exploitable"] == 1
        assert b["inconsistent"] == 0

    def test_error_field_takes_precedence_over_explicit_status(self):
        # Defensive: a finding that recorded an error AND an
        # explicit status (rare but possible if partial-state write)
        # still gets bucketed as failed/blocked. The error field is
        # the most-load-bearing signal for ''did this complete?''.
        from core.run.finding_status import ANALYSED
        results = [{
            "status": ANALYSED,
            "error": "post-status crash",
        }]
        b = bucket_orchestration_results(results)
        assert b["failed"] == 1
        assert b["true_positives"] == 0
