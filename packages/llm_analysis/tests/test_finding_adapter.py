"""Tests for FindingAdapter — the multi-model substrate adapter for
/agentic findings."""

from __future__ import annotations

import pytest

from packages.llm_analysis.finding_adapter import FindingAdapter


# ---------------------------------------------------------------------------
# item_id
# ---------------------------------------------------------------------------


class TestItemId:
    def test_returns_finding_id(self):
        adapter = FindingAdapter()
        assert adapter.item_id({"finding_id": "F-001"}) == "F-001"

    def test_missing_finding_id_raises(self):
        adapter = FindingAdapter()
        with pytest.raises(ValueError, match="finding_id"):
            adapter.item_id({"is_exploitable": True})

    def test_empty_finding_id_raises(self):
        adapter = FindingAdapter()
        with pytest.raises(ValueError, match="finding_id"):
            adapter.item_id({"finding_id": ""})

    def test_non_string_finding_id_raises(self):
        adapter = FindingAdapter()
        with pytest.raises(ValueError, match="finding_id"):
            adapter.item_id({"finding_id": 42})


# ---------------------------------------------------------------------------
# normalize_verdict
# ---------------------------------------------------------------------------


class TestNormalizeVerdict:
    """Mirrors legacy ``r.get("is_exploitable", False)`` truthy check:
    truthy → positive, anything else → negative. There is no "unknown"
    bucket — legacy treated missing-as-False (negative-equivalent)."""

    def test_exploitable_true_is_positive(self):
        adapter = FindingAdapter()
        assert adapter.normalize_verdict({"is_exploitable": True}) == "positive"

    def test_exploitable_false_is_negative(self):
        adapter = FindingAdapter()
        assert adapter.normalize_verdict({"is_exploitable": False}) == "negative"

    def test_missing_is_negative(self):
        # Legacy: r.get("is_exploitable", False) → False → negative.
        adapter = FindingAdapter()
        assert adapter.normalize_verdict({}) == "negative"

    def test_none_is_negative(self):
        # None is falsy.
        adapter = FindingAdapter()
        assert adapter.normalize_verdict({"is_exploitable": None}) == "negative"

    def test_truthy_non_bool_is_positive(self):
        # Legacy used truthy check, not strict True. "yes" / 1 / etc.
        # rank as positive in legacy. We preserve that.
        adapter = FindingAdapter()
        assert adapter.normalize_verdict({"is_exploitable": "yes"}) == "positive"
        assert adapter.normalize_verdict({"is_exploitable": 1}) == "positive"

    def test_falsy_non_bool_is_negative(self):
        adapter = FindingAdapter()
        assert adapter.normalize_verdict({"is_exploitable": ""}) == "negative"
        assert adapter.normalize_verdict({"is_exploitable": 0}) == "negative"
        assert adapter.normalize_verdict({"is_exploitable": []}) == "negative"


# ---------------------------------------------------------------------------
# select_primary — behaviour-preserving check vs legacy _select_primary_result
# ---------------------------------------------------------------------------


class TestSelectPrimaryBehaviour:
    """These mirror the original test_dispatch.py::TestSelectPrimaryResult
    tests but locate them with the adapter, so adapter-level behaviour
    is covered separately from orchestrator-level."""

    def test_prefers_exploitable_over_non(self):
        adapter = FindingAdapter()
        r1 = {"is_exploitable": False, "exploitability_score": 0.9, "analysed_by": "m1"}
        r2 = {"is_exploitable": True, "exploitability_score": 0.5, "analysed_by": "m2"}
        assert adapter.select_primary([r1, r2])["analysed_by"] == "m2"

    def test_prefers_higher_quality_among_exploitable(self):
        adapter = FindingAdapter()
        r1 = {"is_exploitable": True, "_quality": 0.5, "analysed_by": "m1"}
        r2 = {"is_exploitable": True, "_quality": 0.9, "analysed_by": "m2"}
        assert adapter.select_primary([r1, r2])["analysed_by"] == "m2"

    def test_prefers_higher_score_on_quality_tie(self):
        adapter = FindingAdapter()
        r1 = {"is_exploitable": True, "_quality": 1.0,
              "exploitability_score": 0.7, "analysed_by": "m1"}
        r2 = {"is_exploitable": True, "_quality": 1.0,
              "exploitability_score": 0.9, "analysed_by": "m2"}
        assert adapter.select_primary([r1, r2])["analysed_by"] == "m2"

    def test_single_result_returned_unchanged(self):
        adapter = FindingAdapter()
        r1 = {"is_exploitable": True, "analysed_by": "m1"}
        assert adapter.select_primary([r1])["analysed_by"] == "m1"

    def test_empty_list_raises(self):
        # Substrate contract — caller must filter errors and never call
        # select_primary with an empty list.
        adapter = FindingAdapter()
        with pytest.raises(ValueError):
            adapter.select_primary([])


class TestExtractAnalysisRecord:
    """Override mirrors /agentic's existing inline shape from
    orchestrator.py's manual multi_model_analyses construction:
    model + is_exploitable + exploitability_score + ruling + reasoning
    (untruncated)."""

    def test_returns_agentic_shape(self):
        adapter = FindingAdapter()
        result = {
            "is_exploitable": True,
            "exploitability_score": 0.9,
            "ruling": "exploitable",
            "reasoning": "user input reaches sink",
            # extra fields shouldn't leak into the record
            "extra": "should not appear",
        }
        record = adapter.extract_analysis_record(result, "claude-opus-4-7")
        assert record == {
            "model": "claude-opus-4-7",
            "is_exploitable": True,
            "exploitability_score": 0.9,
            "ruling": "exploitable",
            "reasoning": "user input reaches sink",
        }

    def test_missing_fields_default_to_none_or_empty(self):
        adapter = FindingAdapter()
        record = adapter.extract_analysis_record({}, "m1")
        assert record == {
            "model": "m1",
            "is_exploitable": None,
            "exploitability_score": None,
            "ruling": None,
            "reasoning": "",
        }

    def test_reasoning_not_truncated(self):
        # /agentic's legacy inline construction did NOT truncate reasoning.
        # Substrate's BaseVerdictAdapter default truncates to 600 chars
        # (REASONING_TRUNCATE). Our override preserves legacy untruncated.
        adapter = FindingAdapter()
        long_reasoning = "x" * 5000
        record = adapter.extract_analysis_record(
            {"reasoning": long_reasoning}, "m1",
        )
        assert record["reasoning"] == long_reasoning
        assert len(record["reasoning"]) == 5000

    def test_no_verdict_field(self):
        # Substrate default includes "verdict" (normalize_verdict output).
        # /agentic uses "ruling" instead; "verdict" should NOT appear.
        adapter = FindingAdapter()
        record = adapter.extract_analysis_record(
            {"is_exploitable": True, "ruling": "exploitable"}, "m1",
        )
        assert "verdict" not in record
        assert record["ruling"] == "exploitable"


class TestSelectPrimaryWithErrorFallback:
    """Wrapper that mirrors legacy _select_primary_result's error
    handling. Errors filtered out; if every result is an error,
    returns dict-copy of the first."""

    def test_filters_errors_then_picks_best(self):
        adapter = FindingAdapter()
        r1 = {"error": "model-a failed", "analysed_by": "m1"}
        r2 = {"is_exploitable": True, "analysed_by": "m2"}
        r3 = {"error": "model-c failed", "analysed_by": "m3"}
        result = adapter.select_primary_with_error_fallback([r1, r2, r3])
        assert result["analysed_by"] == "m2"

    def test_all_errors_returns_first(self):
        adapter = FindingAdapter()
        r1 = {"error": "first failure", "analysed_by": "m1"}
        r2 = {"error": "second failure", "analysed_by": "m2"}
        result = adapter.select_primary_with_error_fallback([r1, r2])
        assert result["analysed_by"] == "m1"
        # And it's a dict copy, not the same object
        assert result is not r1

    def test_no_errors_behaves_like_select_primary(self):
        adapter = FindingAdapter()
        r1 = {"is_exploitable": False, "analysed_by": "m1"}
        r2 = {"is_exploitable": True, "analysed_by": "m2"}
        with_wrapper = adapter.select_primary_with_error_fallback([r1, r2])
        without_wrapper = adapter.select_primary([r1, r2])
        assert with_wrapper == without_wrapper

    def test_empty_list_raises(self):
        adapter = FindingAdapter()
        with pytest.raises(ValueError):
            adapter.select_primary_with_error_fallback([])


class TestLegacyQuirksPreserved:
    """Lock in two legacy quirks from _select_primary_result that the
    substrate's BaseVerdictAdapter default would NOT preserve.

    Option A is a strict lift-and-shift; behaviour change of any kind
    is out of scope. Future PRs (B, C) may revisit if these quirks
    surface real bugs in production."""

    def test_missing_quality_defaults_to_one_not_zero(self):
        # Legacy _select_primary_result used `r.get("_quality", 1.0)`.
        # Substrate's BaseVerdictAdapter default would treat missing as
        # 0.0. We preserve legacy's 1.0 default so the model WITHOUT
        # the field beats one that has _quality=0.85.
        adapter = FindingAdapter()
        r1 = {"is_exploitable": True, "_quality": 0.85, "analysed_by": "m1"}
        r2 = {"is_exploitable": True, "analysed_by": "m2"}  # no _quality
        assert adapter.select_primary([r1, r2])["analysed_by"] == "m2"

    def test_missing_is_exploitable_treated_as_negative(self):
        # Legacy used `r.get("is_exploitable", False)` then `if r_expl`
        # truthy check. Missing is_exploitable was effectively False,
        # i.e. negative-equivalent. Substrate's default would have
        # mapped missing to "unknown" (rank between positive/negative).
        # Preserve legacy: missing → negative-equivalent.
        adapter = FindingAdapter()
        r1 = {"is_exploitable": False, "_quality": 0.9, "analysed_by": "m1"}
        r2 = {"analysed_by": "m2"}  # missing is_exploitable
        # Both rank as "not positive" (legacy treats both same).
        # Falls to _quality tiebreak: r1 has 0.9 explicit,
        # r2 has 1.0 default. r2 wins.
        assert adapter.select_primary([r1, r2])["analysed_by"] == "m2"

    def test_truthy_non_bool_is_exploitable_treated_as_exploitable(self):
        # Legacy: `if r_expl` is truthy for "yes", 1, [...], etc.
        # Substrate's strict ``is True`` check would have rejected
        # them. Preserve legacy's truthy behaviour.
        # batch 346 — quality floor takes precedence over verdict
        # rank, so the truthy-positive needs above-floor quality
        # to actually win the selection.
        adapter = FindingAdapter()
        r1 = {"is_exploitable": False, "_quality": 0.9, "analysed_by": "m1"}
        r2 = {"is_exploitable": "yes", "_quality": 0.5, "analysed_by": "m2"}
        # Both above floor (0.3); r2 ranks positive (truthy) and
        # wins on the verdict axis.
        assert adapter.select_primary([r1, r2])["analysed_by"] == "m2"

    def test_quality_floor_demotes_low_quality_positive(self):
        # batch 346 — a positive verdict with quality below the
        # floor (0.3) should NOT outrank a clean above-floor
        # negative. Pre-fix the malformed positive won; post-fix
        # the clean negative wins.
        adapter = FindingAdapter()
        clean_negative = {
            "is_exploitable": False, "_quality": 0.9, "analysed_by": "clean",
        }
        malformed_positive = {
            "is_exploitable": True, "_quality": 0.05, "analysed_by": "malformed",
        }
        assert adapter.select_primary(
            [malformed_positive, clean_negative]
        )["analysed_by"] == "clean"

    def test_quality_floor_only_candidate_still_wins(self):
        # If every candidate is below floor, the best one
        # (highest verdict-rank, then quality) is still selected
        # — the floor is a preference, not a hard exclusion.
        adapter = FindingAdapter()
        r1 = {"is_exploitable": False, "_quality": 0.1, "analysed_by": "m1"}
        r2 = {"is_exploitable": True, "_quality": 0.2, "analysed_by": "m2"}
        # Both below floor; verdict rank decides — r2 wins.
        assert adapter.select_primary([r1, r2])["analysed_by"] == "m2"

    def test_bool_quality_treated_as_default(self):
        # _quality=True or _quality=False is a schema error. Substrate
        # excludes bools from numeric coercion (bool is subclass of int).
        # Mirror that here: bool _quality falls back to default (0.0
        # in our override, NOT 1.0 — see select_primary code).
        adapter = FindingAdapter()
        r1 = {"is_exploitable": True, "_quality": True, "analysed_by": "m1"}
        r2 = {"is_exploitable": True, "_quality": 0.5, "analysed_by": "m2"}
        # r1's quality coerces to 0.0 (bool rejected); r2 has 0.5. r2 wins.
        assert adapter.select_primary([r1, r2])["analysed_by"] == "m2"

    def test_none_quality_does_not_crash(self):
        # Slight divergence from legacy: legacy used `r_q > b_q` directly,
        # which raises TypeError when either side is None. We coerce None
        # to 0.0 (same as missing-with-no-default) — robustness win, not
        # a regression. validation.py always sets _quality as float in
        # production so this divergence is theoretical.
        adapter = FindingAdapter()
        r1 = {"is_exploitable": True, "_quality": None, "analysed_by": "m1"}
        r2 = {"is_exploitable": True, "_quality": 0.5, "analysed_by": "m2"}
        # r1's None coerces to 0.0; r2 has 0.5. r2 wins.
        result = adapter.select_primary([r1, r2])
        assert result["analysed_by"] == "m2"
