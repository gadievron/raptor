"""Tests for _per_model_failure_summary — operator-visibility helper
that surfaces which model failed on which finding(s)."""

from __future__ import annotations

from packages.llm_analysis.orchestrator import _per_model_failure_summary


class TestEmptyAndNoErrors:
    def test_empty_input(self):
        assert _per_model_failure_summary([]) == {}

    def test_all_successes(self):
        results = [
            {"finding_id": "f1", "analysed_by": "pro", "is_exploitable": True},
            {"finding_id": "f2", "analysed_by": "flash", "is_exploitable": False},
        ]
        assert _per_model_failure_summary(results) == {}


class TestSingleModelErrors:
    def test_one_error_one_model(self):
        results = [
            {"finding_id": "f1", "analysed_by": "pro", "error": "rate limit"},
        ]
        out = _per_model_failure_summary(results)
        assert out == {"pro": {"count": 1, "first_error": "rate limit"}}

    def test_multiple_errors_same_model(self):
        results = [
            {"finding_id": "f1", "analysed_by": "pro", "error": "first error"},
            {"finding_id": "f2", "analysed_by": "pro", "error": "second error"},
            {"finding_id": "f3", "analysed_by": "pro", "error": "third error"},
        ]
        out = _per_model_failure_summary(results)
        assert out == {"pro": {"count": 3, "first_error": "first error"}}


class TestMultiModelErrors:
    def test_per_model_attribution(self):
        results = [
            {"finding_id": "f1", "analysed_by": "pro", "error": "pro fail 1"},
            {"finding_id": "f1", "analysed_by": "flash", "error": "flash fail 1"},
            {"finding_id": "f2", "analysed_by": "pro", "error": "pro fail 2"},
        ]
        out = _per_model_failure_summary(results)
        assert out == {
            "pro": {"count": 2, "first_error": "pro fail 1"},
            "flash": {"count": 1, "first_error": "flash fail 1"},
        }


class TestMixedSuccessFailure:
    def test_only_failures_aggregated(self):
        results = [
            {"finding_id": "f1", "analysed_by": "pro", "is_exploitable": True},
            {"finding_id": "f2", "analysed_by": "pro", "error": "fail"},
            {"finding_id": "f3", "analysed_by": "flash", "is_exploitable": False},
        ]
        out = _per_model_failure_summary(results)
        assert out == {"pro": {"count": 1, "first_error": "fail"}}


class TestEdgeCases:
    def test_missing_analysed_by_grouped_under_question_mark(self):
        # Result with no analysed_by — group under "?" so operator
        # at least sees something failed unattributable.
        results = [
            {"finding_id": "f1", "error": "early failure"},
        ]
        out = _per_model_failure_summary(results)
        assert out == {"?": {"count": 1, "first_error": "early failure"}}

    def test_empty_analysed_by_grouped_under_question_mark(self):
        results = [
            {"finding_id": "f1", "analysed_by": "", "error": "x"},
        ]
        out = _per_model_failure_summary(results)
        assert out == {"?": {"count": 1, "first_error": "x"}}

    def test_long_error_truncated(self):
        long_err = "x" * 500
        results = [{"analysed_by": "pro", "error": long_err}]
        out = _per_model_failure_summary(results)
        assert len(out["pro"]["first_error"]) == 200

    def test_non_string_error_coerced_to_str(self):
        results = [{"analysed_by": "pro", "error": {"code": 401, "msg": "auth"}}]
        out = _per_model_failure_summary(results)
        # str() of dict is fine; what matters is no crash
        assert out["pro"]["count"] == 1
        assert "401" in out["pro"]["first_error"]

    def test_non_dict_entries_skipped(self):
        # Defensive: malformed entries shouldn't crash
        results = ["garbage", None, {"analysed_by": "pro", "error": "real"}]
        out = _per_model_failure_summary(results)  # type: ignore[arg-type]
        assert out == {"pro": {"count": 1, "first_error": "real"}}
