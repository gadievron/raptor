"""Tests for BaseVerdictAdapter and BaseSetAdapter.

Uses concrete-but-minimal subclasses to exercise merge/correlate/select_primary
behaviour without coupling to any real consumer schema.
"""

import pytest

from core.llm.multi_model.adapters import BaseSetAdapter, BaseVerdictAdapter


# ---------------------------------------------------------------------------
# Test subclasses
# ---------------------------------------------------------------------------


class FindingAdapter(BaseVerdictAdapter):
    """Verdict adapter for finding-shaped items."""

    def item_id(self, item):
        return item["finding_id"]

    def normalize_verdict(self, item):
        if item.get("is_exploitable") is True:
            return "positive"
        if item.get("is_exploitable") is False:
            return "negative"
        v = item.get("verdict", "")
        if v in ("inconclusive", "uncertain"):
            return "inconclusive"
        return "unknown"


class VariantAdapter(BaseSetAdapter):
    """Set adapter for variant-shaped items."""

    def item_id(self, item):
        return f"{item['file']}:{item['line']}"

    def item_key(self, item):
        return (item["file"], item["line"])


# ---------------------------------------------------------------------------
# BaseVerdictAdapter — merge
# ---------------------------------------------------------------------------


class TestVerdictMerge:
    def test_single_model_no_multi_analyses(self):
        adapter = FindingAdapter()
        result = adapter.merge({
            "model-a": [{"finding_id": "f1", "is_exploitable": True}],
        })
        assert len(result) == 1
        assert "multi_model_analyses" not in result[0]

    def test_two_models_attaches_analyses(self):
        adapter = FindingAdapter()
        result = adapter.merge({
            "model-a": [{"finding_id": "f1", "is_exploitable": True,
                        "exploitability_score": 9, "reasoning": "A's case"}],
            "model-b": [{"finding_id": "f1", "is_exploitable": False,
                        "reasoning": "B disagrees"}],
        })
        assert len(result) == 1
        analyses = result[0]["multi_model_analyses"]
        assert len(analyses) == 2
        models = {a["model"] for a in analyses}
        assert models == {"model-a", "model-b"}

    def test_select_primary_prefers_positive(self):
        adapter = FindingAdapter()
        # B says exploitable=True, A says exploitable=False
        result = adapter.merge({
            "model-a": [{"finding_id": "f1", "is_exploitable": False}],
            "model-b": [{"finding_id": "f1", "is_exploitable": True}],
        })
        # Primary should reflect the positive verdict
        assert result[0]["is_exploitable"] is True

    def test_select_primary_quality_tiebreak_when_both_positive(self):
        adapter = FindingAdapter()
        result = adapter.merge({
            "model-a": [{"finding_id": "f1", "is_exploitable": True, "_quality": 0.8}],
            "model-b": [{"finding_id": "f1", "is_exploitable": True, "_quality": 0.95}],
        })
        # Higher quality wins among positive verdicts
        assert result[0]["_quality"] == 0.95

    def test_disjoint_findings_both_kept(self):
        adapter = FindingAdapter()
        result = adapter.merge({
            "model-a": [{"finding_id": "f1", "is_exploitable": True}],
            "model-b": [{"finding_id": "f2", "is_exploitable": False}],
        })
        assert len(result) == 2
        ids = {item["finding_id"] for item in result}
        assert ids == {"f1", "f2"}

    def test_first_seen_order_preserved(self):
        adapter = FindingAdapter()
        # f1 first via model-a, f2 first via model-b — order should reflect
        # appearance order across models
        result = adapter.merge({
            "model-a": [{"finding_id": "f1", "is_exploitable": True},
                        {"finding_id": "f2", "is_exploitable": True}],
            "model-b": [{"finding_id": "f3", "is_exploitable": True}],
        })
        ids = [item["finding_id"] for item in result]
        # Substrate sorts model dict alphabetically, so a comes first
        assert ids == ["f1", "f2", "f3"]


# ---------------------------------------------------------------------------
# BaseVerdictAdapter — correlate
# ---------------------------------------------------------------------------


class TestVerdictCorrelate:
    def test_unanimous_positive_is_high(self):
        adapter = FindingAdapter()
        per_model = {
            "model-a": [{"finding_id": "f1", "is_exploitable": True}],
            "model-b": [{"finding_id": "f1", "is_exploitable": True}],
        }
        merged = adapter.merge(per_model)
        c = adapter.correlate(merged, per_model)
        assert c["confidence_signals"]["f1"] == "high"
        assert c["summary"]["agreed"] == 1

    def test_unanimous_negative_is_high_negative(self):
        adapter = FindingAdapter()
        per_model = {
            "model-a": [{"finding_id": "f1", "is_exploitable": False}],
            "model-b": [{"finding_id": "f1", "is_exploitable": False}],
        }
        merged = adapter.merge(per_model)
        c = adapter.correlate(merged, per_model)
        assert c["confidence_signals"]["f1"] == "high-negative"

    def test_split_is_disputed(self):
        adapter = FindingAdapter()
        per_model = {
            "model-a": [{"finding_id": "f1", "is_exploitable": True,
                        "reasoning": "I see the sink"}],
            "model-b": [{"finding_id": "f1", "is_exploitable": False,
                        "reasoning": "Sink is unreachable"}],
        }
        merged = adapter.merge(per_model)
        c = adapter.correlate(merged, per_model)
        assert c["confidence_signals"]["f1"] == "disputed"
        assert c["summary"]["disputed"] == 1
        # Minority insight surfaced
        insights = c["unique_insights"]
        assert len(insights) >= 1

    def test_single_model_finding_is_single_model(self):
        adapter = FindingAdapter()
        per_model = {
            "model-a": [{"finding_id": "f1", "is_exploitable": True}],
        }
        merged = adapter.merge(per_model)
        c = adapter.correlate(merged, per_model)
        assert c["confidence_signals"]["f1"] == "single_model"
        assert c["summary"]["single_model"] == 1

    def test_unknown_verdicts_excluded_from_classification(self):
        adapter = FindingAdapter()
        # Item has unknown verdict from both models — no agreement to compute
        per_model = {
            "model-a": [{"finding_id": "f1", "verdict": "weird"}],
            "model-b": [{"finding_id": "f1", "verdict": "??"}],
        }
        merged = adapter.merge(per_model)
        c = adapter.correlate(merged, per_model)
        # Both unknowns → no classifiable verdicts → single_model
        assert c["confidence_signals"]["f1"] == "single_model"

    def test_models_listed_in_summary(self):
        adapter = FindingAdapter()
        per_model = {
            "model-a": [{"finding_id": "f1", "is_exploitable": True}],
            "model-b": [{"finding_id": "f1", "is_exploitable": True}],
        }
        merged = adapter.merge(per_model)
        c = adapter.correlate(merged, per_model)
        assert c["summary"]["models"] == ["model-a", "model-b"]

    def test_n_equals_one_correlate(self):
        # N=1 must be graceful per substrate contract
        adapter = FindingAdapter()
        per_model = {
            "only": [{"finding_id": "f1", "is_exploitable": True}],
        }
        merged = adapter.merge(per_model)
        c = adapter.correlate(merged, per_model)
        assert c["summary"]["total"] == 1

    def test_all_inconclusive_is_high_inconclusive_not_disputed(self):
        # Regression: previously bucketed as "disputed", which wasted
        # reviewer attention on findings everyone agreed were uncertain.
        adapter = FindingAdapter()
        per_model = {
            "model-a": [{"finding_id": "f1", "verdict": "inconclusive"}],
            "model-b": [{"finding_id": "f1", "verdict": "uncertain"}],
        }
        merged = adapter.merge(per_model)
        c = adapter.correlate(merged, per_model)
        assert c["confidence_signals"]["f1"] == "high-inconclusive"
        # Counted under "agreed" (mutual conclusion, even if it's mutual uncertainty)
        assert c["summary"]["agreed"] == 1
        assert c["summary"]["disputed"] == 0

    def test_positive_plus_inconclusive_is_mixed_not_disputed(self):
        # Softer disagreement than pos vs neg: one model uncertain,
        # others positive. Should be "mixed" not "disputed".
        adapter = FindingAdapter()
        per_model = {
            "model-a": [{"finding_id": "f1", "is_exploitable": True}],
            "model-b": [{"finding_id": "f1", "verdict": "inconclusive"}],
        }
        merged = adapter.merge(per_model)
        c = adapter.correlate(merged, per_model)
        assert c["confidence_signals"]["f1"] == "mixed"
        assert c["summary"]["mixed"] == 1
        assert c["summary"]["disputed"] == 0

    def test_negative_plus_inconclusive_is_mixed_not_disputed(self):
        adapter = FindingAdapter()
        per_model = {
            "model-a": [{"finding_id": "f1", "is_exploitable": False}],
            "model-b": [{"finding_id": "f1", "verdict": "inconclusive"}],
        }
        merged = adapter.merge(per_model)
        c = adapter.correlate(merged, per_model)
        assert c["confidence_signals"]["f1"] == "mixed"

    def test_disputed_still_requires_pos_and_neg(self):
        # Three-way: pos+neg+inconclusive — still disputed because pos AND neg both present
        adapter = FindingAdapter()
        per_model = {
            "model-a": [{"finding_id": "f1", "is_exploitable": True}],
            "model-b": [{"finding_id": "f1", "is_exploitable": False}],
            "model-c": [{"finding_id": "f1", "verdict": "inconclusive"}],
        }
        merged = adapter.merge(per_model)
        c = adapter.correlate(merged, per_model)
        assert c["confidence_signals"]["f1"] == "disputed"


class TestReasoningTruncation:
    def test_default_truncate_is_600(self):
        adapter = FindingAdapter()
        long_reasoning = "x" * 1000
        per_model = {
            "model-a": [{"finding_id": "f1", "is_exploitable": True,
                        "reasoning": long_reasoning}],
            "model-b": [{"finding_id": "f1", "is_exploitable": True}],
        }
        merged = adapter.merge(per_model)
        analyses = merged[0]["multi_model_analyses"]
        a_record = next(a for a in analyses if a["model"] == "model-a")
        assert len(a_record["reasoning"]) == 600

    def test_truncation_overridable_via_class_attr(self):
        class ShortReasoningAdapter(FindingAdapter):
            REASONING_TRUNCATE = 50

        adapter = ShortReasoningAdapter()
        long_reasoning = "x" * 1000
        per_model = {
            "model-a": [{"finding_id": "f1", "is_exploitable": True,
                        "reasoning": long_reasoning}],
            "model-b": [{"finding_id": "f1", "is_exploitable": True}],
        }
        merged = adapter.merge(per_model)
        analyses = merged[0]["multi_model_analyses"]
        a_record = next(a for a in analyses if a["model"] == "model-a")
        assert len(a_record["reasoning"]) == 50


# ---------------------------------------------------------------------------
# BaseVerdictAdapter — select_primary
# ---------------------------------------------------------------------------


class TestVerdictSelectPrimary:
    def test_empty_raises(self):
        adapter = FindingAdapter()
        with pytest.raises(ValueError, match="empty"):
            adapter.select_primary([])

    def test_overridable(self):
        # Subclass can override with own policy
        class FirstWinsAdapter(FindingAdapter):
            def select_primary(self, model_results):
                return dict(model_results[0])

        adapter = FirstWinsAdapter()
        result = adapter.merge({
            "model-a": [{"finding_id": "f1", "is_exploitable": False}],
            "model-b": [{"finding_id": "f1", "is_exploitable": True}],
        })
        # FirstWins picks model-a's result (False) instead of prefer-positive
        assert result[0]["is_exploitable"] is False

    def test_non_numeric_quality_doesnt_crash_sort(self):
        # Defensive: consumer's schema could put a string in _quality.
        # Substrate should coerce to 0 rather than crash with "TypeError:
        # '<' not supported between str and float".
        adapter = FindingAdapter()
        result = adapter.merge({
            "model-a": [{"finding_id": "f1", "is_exploitable": True, "_quality": "high"}],
            "model-b": [{"finding_id": "f1", "is_exploitable": True, "_quality": 0.9}],
        })
        # No crash. Both got coerced; numeric one wins on tiebreak.
        assert result[0]["_quality"] == 0.9

    def test_non_numeric_exploitability_score_doesnt_crash_sort(self):
        adapter = FindingAdapter()
        result = adapter.merge({
            "model-a": [{"finding_id": "f1", "is_exploitable": True,
                        "exploitability_score": "9/10"}],
            "model-b": [{"finding_id": "f1", "is_exploitable": True,
                        "exploitability_score": 7}],
        })
        # No crash; numeric tiebreak wins
        assert result[0]["exploitability_score"] == 7

    def test_bool_score_treated_as_zero(self):
        # bool is technically int in Python — schema error, treat as 0.
        adapter = FindingAdapter()
        result = adapter.merge({
            "model-a": [{"finding_id": "f1", "is_exploitable": True,
                        "exploitability_score": True}],  # would be 1 if not coerced
            "model-b": [{"finding_id": "f1", "is_exploitable": True,
                        "exploitability_score": 0.5}],
        })
        # bool→0; numeric 0.5 wins
        assert result[0]["exploitability_score"] == 0.5


class TestCorrelateSummaryInvariant:
    def test_bucket_counts_sum_to_total(self):
        adapter = FindingAdapter()
        per_model = {
            "model-a": [
                {"finding_id": "f1", "is_exploitable": True},
                {"finding_id": "f2", "is_exploitable": False},
                {"finding_id": "f3", "is_exploitable": True},
                {"finding_id": "f4", "verdict": "inconclusive"},
            ],
            "model-b": [
                {"finding_id": "f1", "is_exploitable": True},   # high
                {"finding_id": "f2", "is_exploitable": True},   # disputed
                {"finding_id": "f3", "verdict": "inconclusive"}, # mixed
                {"finding_id": "f4", "verdict": "inconclusive"}, # high-inconclusive
                {"finding_id": "f5", "is_exploitable": True},   # single_model (only b)
            ],
        }
        merged = adapter.merge(per_model)
        c = adapter.correlate(merged, per_model)
        s = c["summary"]
        assert s["agreed"] + s["disputed"] + s["mixed"] + s["single_model"] == s["total"]


class TestSetMergeSameModelDuplicates:
    """If a model returns the same item twice, it shouldn't double-count
    in either presence_matrix or recall_signals."""

    def test_intra_model_dupes_dont_inflate_presence(self):
        adapter = VariantAdapter()
        per_model = {
            "model-a": [
                {"file": "x.c", "line": 5},
                {"file": "x.c", "line": 5},  # same item again
            ],
        }
        merged = adapter.merge(per_model)
        c = adapter.correlate(merged, per_model)
        # presence_matrix should show model-a once, not twice
        assert c["presence_matrix"]["x.c:5"] == ["model-a"]
        # recall counts unique models — single_model
        assert c["recall_signals"]["x.c:5"] == "single_model"

    def test_intra_model_dupes_with_other_model(self):
        adapter = VariantAdapter()
        per_model = {
            "model-a": [
                {"file": "x.c", "line": 5},
                {"file": "x.c", "line": 5},  # dupe
            ],
            "model-b": [
                {"file": "x.c", "line": 5},
            ],
        }
        merged = adapter.merge(per_model)
        c = adapter.correlate(merged, per_model)
        # presence: 2 unique models
        assert c["presence_matrix"]["x.c:5"] == ["model-a", "model-b"]
        # recall: all_models (both contributed)
        assert c["recall_signals"]["x.c:5"] == "all_models"

    def test_intra_model_dupes_dont_create_fake_multi_model_finds(self):
        # Regression: previously len(finds_by_key) > 1 was the gate.
        # A single model returning the same item twice would wrongly
        # attach multi_model_finds, suggesting two models contributed.
        adapter = VariantAdapter()
        per_model = {
            "model-a": [
                {"file": "x.c", "line": 5},
                {"file": "x.c", "line": 5},  # dupe
            ],
        }
        merged = adapter.merge(per_model)
        # Only one DISTINCT model contributed; multi_model_finds absent.
        assert "multi_model_finds" not in merged[0]
        assert merged[0]["found_by_models"] == ["model-a"]

    def test_genuine_multi_model_finds_still_attached(self):
        adapter = VariantAdapter()
        per_model = {
            "model-a": [{"file": "x.c", "line": 5, "snippet": "a"}],
            "model-b": [{"file": "x.c", "line": 5, "snippet": "b"}],
        }
        merged = adapter.merge(per_model)
        # Two distinct models — multi_model_finds present
        assert "multi_model_finds" in merged[0]
        assert len(merged[0]["multi_model_finds"]) == 2


class TestVerdictMergeMultiModelAnalysesContract:
    """Single-model items have NO multi_model_analyses key (not [] or None)."""

    def test_single_model_has_no_key(self):
        adapter = FindingAdapter()
        per_model = {
            "model-a": [{"finding_id": "f1", "is_exploitable": True}],
        }
        merged = adapter.merge(per_model)
        # Key absent — consumers should test `in item`, not `.get(...)`
        assert "multi_model_analyses" not in merged[0]

    def test_intra_model_dupes_dont_create_fake_multi_model_analyses(self):
        # Regression: previously len(entries) > 1 was the gate. A single
        # model returning the same finding twice would wrongly attach
        # multi_model_analyses with two records both labelled with the
        # same model name.
        adapter = FindingAdapter()
        per_model = {
            "model-a": [
                {"finding_id": "f1", "is_exploitable": True, "_quality": 0.7},
                {"finding_id": "f1", "is_exploitable": False, "_quality": 0.9},  # dupe id, different verdict
            ],
        }
        merged = adapter.merge(per_model)
        # Only one DISTINCT model contributed — multi_model_analyses absent.
        assert "multi_model_analyses" not in merged[0]
        # select_primary still picked among the dupes (prefer-positive)
        assert merged[0]["is_exploitable"] is True

    def test_genuine_multi_model_analyses_still_attached(self):
        adapter = FindingAdapter()
        per_model = {
            "model-a": [{"finding_id": "f1", "is_exploitable": True}],
            "model-b": [{"finding_id": "f1", "is_exploitable": False}],
        }
        merged = adapter.merge(per_model)
        assert "multi_model_analyses" in merged[0]
        assert len(merged[0]["multi_model_analyses"]) == 2


# ---------------------------------------------------------------------------
# BaseSetAdapter — merge
# ---------------------------------------------------------------------------


class TestSetMerge:
    def test_single_model_no_multi_finds(self):
        adapter = VariantAdapter()
        result = adapter.merge({
            "model-a": [{"file": "x.c", "line": 5}],
        })
        assert len(result) == 1
        assert "multi_model_finds" not in result[0]
        assert result[0]["found_by_models"] == ["model-a"]

    def test_overlapping_items_unioned(self):
        adapter = VariantAdapter()
        result = adapter.merge({
            "model-a": [{"file": "x.c", "line": 5}],
            "model-b": [{"file": "x.c", "line": 5}],
        })
        # Same key → one merged item with both models
        assert len(result) == 1
        assert result[0]["found_by_models"] == ["model-a", "model-b"]

    def test_disjoint_items_both_kept(self):
        adapter = VariantAdapter()
        result = adapter.merge({
            "model-a": [{"file": "x.c", "line": 5}],
            "model-b": [{"file": "y.c", "line": 10}],
        })
        assert len(result) == 2
        for item in result:
            assert len(item["found_by_models"]) == 1

    def test_two_models_attaches_finds(self):
        adapter = VariantAdapter()
        result = adapter.merge({
            "model-a": [{"file": "x.c", "line": 5, "snippet": "a"}],
            "model-b": [{"file": "x.c", "line": 5, "snippet": "b"}],
        })
        # multi_model_finds present when 2+ models contributed
        finds = result[0]["multi_model_finds"]
        assert len(finds) == 2
        assert {f["model"] for f in finds} == {"model-a", "model-b"}

    def test_found_by_models_sorted(self):
        adapter = VariantAdapter()
        result = adapter.merge({
            "zeta": [{"file": "x.c", "line": 5}],
            "alpha": [{"file": "x.c", "line": 5}],
        })
        assert result[0]["found_by_models"] == ["alpha", "zeta"]


# ---------------------------------------------------------------------------
# BaseSetAdapter — correlate
# ---------------------------------------------------------------------------


class TestSetCorrelate:
    def test_all_models_recall(self):
        adapter = VariantAdapter()
        per_model = {
            "model-a": [{"file": "x.c", "line": 5}],
            "model-b": [{"file": "x.c", "line": 5}],
            "model-c": [{"file": "x.c", "line": 5}],
        }
        merged = adapter.merge(per_model)
        c = adapter.correlate(merged, per_model)
        assert c["recall_signals"]["x.c:5"] == "all_models"

    def test_majority_recall(self):
        adapter = VariantAdapter()
        per_model = {
            "model-a": [{"file": "x.c", "line": 5}],
            "model-b": [{"file": "x.c", "line": 5}],
            "model-c": [],
        }
        merged = adapter.merge(per_model)
        c = adapter.correlate(merged, per_model)
        assert c["recall_signals"]["x.c:5"] == "majority"

    def test_minority_recall(self):
        adapter = VariantAdapter()
        per_model = {
            "model-a": [{"file": "x.c", "line": 5}],
            "model-b": [],
            "model-c": [],
        }
        merged = adapter.merge(per_model)
        c = adapter.correlate(merged, per_model)
        assert c["recall_signals"]["x.c:5"] == "minority"

    def test_single_model_recall(self):
        adapter = VariantAdapter()
        per_model = {
            "only": [{"file": "x.c", "line": 5}],
        }
        merged = adapter.merge(per_model)
        c = adapter.correlate(merged, per_model)
        assert c["recall_signals"]["x.c:5"] == "single_model"

    def test_presence_matrix(self):
        adapter = VariantAdapter()
        per_model = {
            "model-a": [{"file": "x.c", "line": 5}],
            "model-b": [{"file": "x.c", "line": 5}, {"file": "y.c", "line": 10}],
        }
        merged = adapter.merge(per_model)
        c = adapter.correlate(merged, per_model)
        assert c["presence_matrix"]["x.c:5"] == ["model-a", "model-b"]
        assert c["presence_matrix"]["y.c:10"] == ["model-b"]

    def test_summary_buckets(self):
        adapter = VariantAdapter()
        per_model = {
            "a": [{"file": "x.c", "line": 1}, {"file": "y.c", "line": 2}],
            "b": [{"file": "x.c", "line": 1}],
        }
        merged = adapter.merge(per_model)
        c = adapter.correlate(merged, per_model)
        assert c["summary"]["all_models"] == 1   # x.c:1
        assert c["summary"]["minority"] == 1     # y.c:2
        assert c["summary"]["total"] == 2


# ---------------------------------------------------------------------------
# Substrate-protocol satisfaction
# ---------------------------------------------------------------------------


class TestProtocolSatisfaction:
    """Concrete bases must satisfy ItemAdapter (and their respective
    subprotocol) for use with run_multi_model."""

    def test_finding_adapter_is_item_adapter(self):
        from core.llm.multi_model import ItemAdapter, VerdictAdapter
        a = FindingAdapter()
        assert isinstance(a, ItemAdapter)
        assert isinstance(a, VerdictAdapter)

    def test_variant_adapter_is_item_adapter(self):
        from core.llm.multi_model import ItemAdapter, SetAdapter
        a = VariantAdapter()
        assert isinstance(a, ItemAdapter)
        assert isinstance(a, SetAdapter)


# ---------------------------------------------------------------------------
# Abstract methods enforced
# ---------------------------------------------------------------------------


class TestAbstractEnforcement:
    def test_cannot_instantiate_base_verdict_adapter(self):
        with pytest.raises(TypeError):
            BaseVerdictAdapter()  # type: ignore[abstract]

    def test_cannot_instantiate_base_set_adapter(self):
        with pytest.raises(TypeError):
            BaseSetAdapter()  # type: ignore[abstract]
