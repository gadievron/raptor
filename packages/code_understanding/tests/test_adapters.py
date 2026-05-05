"""Tests for VariantAdapter and TraceAdapter.

The substrate-level adapter behaviour (merge / correlate semantics) is
already exercised in core/llm/multi_model/tests. These tests verify the
consumer-specific bits: item_id, item_key, normalize_verdict.
"""

import pytest

from packages.code_understanding import TraceAdapter, VariantAdapter


# ---------------------------------------------------------------------------
# VariantAdapter
# ---------------------------------------------------------------------------


class TestVariantAdapterItemId:
    def test_id_includes_function_when_present(self):
        adapter = VariantAdapter()
        assert adapter.item_id({
            "file": "src/parser.c", "line": 42, "function": "parse_header",
        }) == "src/parser.c:42:parse_header"

    def test_id_omits_function_when_absent(self):
        adapter = VariantAdapter()
        assert adapter.item_id({
            "file": "src/parser.c", "line": 42,
        }) == "src/parser.c:42"

    def test_id_omits_function_when_empty(self):
        adapter = VariantAdapter()
        assert adapter.item_id({
            "file": "src/parser.c", "line": 42, "function": "",
        }) == "src/parser.c:42"


class TestVariantAdapterItemKey:
    def test_basic_key(self):
        adapter = VariantAdapter()
        assert adapter.item_key({
            "file": "src/parser.c", "line": 42, "function": "f",
        }) == ("src/parser.c", 42, "f")

    def test_strips_leading_dot_slash(self):
        # "./src/x.c" and "src/x.c" should produce equal keys
        adapter = VariantAdapter()
        a = adapter.item_key({"file": "./src/parser.c", "line": 42, "function": "f"})
        b = adapter.item_key({"file": "src/parser.c", "line": 42, "function": "f"})
        assert a == b

    def test_strips_whitespace(self):
        adapter = VariantAdapter()
        a = adapter.item_key({"file": "  src/parser.c  ", "line": 42, "function": " f "})
        b = adapter.item_key({"file": "src/parser.c", "line": 42, "function": "f"})
        assert a == b

    def test_does_not_lowercase(self):
        # File paths are case-sensitive on Linux/macOS source trees;
        # we must NOT collapse case.
        adapter = VariantAdapter()
        a = adapter.item_key({"file": "src/Parser.c", "line": 42, "function": ""})
        b = adapter.item_key({"file": "src/parser.c", "line": 42, "function": ""})
        assert a != b

    def test_does_not_strip_extra_dots_at_start(self):
        # Regression: previously used lstrip("./") which is a CHARACTER set,
        # so leading dot sequences ("...weird.c") would get over-stripped.
        # Now we use removeprefix("./") which only strips the literal prefix.
        adapter = VariantAdapter()
        # Three dots is unusual but should be preserved as-is
        weird = adapter.item_key({"file": "...weird.c", "line": 1, "function": ""})
        assert weird == ("...weird.c", 1, "")

    def test_does_not_strip_dot_only_path(self):
        adapter = VariantAdapter()
        # ".file" is a hidden file name, not "./file"
        result = adapter.item_key({"file": ".hidden", "line": 1, "function": ""})
        assert result == (".hidden", 1, "")


class TestVariantAdapterCanonicalIds:
    """Regression: item_id and item_key must agree on canonicalization
    so the same logical variant gets the same ID regardless of which
    model contributed first."""

    def test_id_normalizes_dot_slash_prefix(self):
        adapter = VariantAdapter()
        a = adapter.item_id({"file": "./src/x.c", "line": 5, "function": "f"})
        b = adapter.item_id({"file": "src/x.c", "line": 5, "function": "f"})
        assert a == b == "src/x.c:5:f"

    def test_id_normalizes_whitespace(self):
        adapter = VariantAdapter()
        a = adapter.item_id({"file": "  src/x.c  ", "line": 5, "function": " f "})
        b = adapter.item_id({"file": "src/x.c", "line": 5, "function": "f"})
        assert a == b

    def test_merged_item_has_canonical_id_regardless_of_first_model(self):
        # Whether claude or zeta contributed first, item_id should be canonical.
        adapter = VariantAdapter()
        result_a_first = adapter.merge({
            "alpha": [{"file": "./src/x.c", "line": 5, "function": "f"}],
            "zeta":  [{"file": "src/x.c",   "line": 5, "function": "f"}],
        })
        result_z_first = adapter.merge({
            "alpha": [{"file": "src/x.c",   "line": 5, "function": "f"}],
            "zeta":  [{"file": "./src/x.c", "line": 5, "function": "f"}],
        })
        # IDs must be identical in both cases
        assert adapter.item_id(result_a_first[0]) == adapter.item_id(result_z_first[0])


class TestVariantAdapterLineCoercion:
    """Models occasionally return numeric fields as strings; the adapter
    should treat "5" and 5 as the same line."""

    def test_string_line_unifies_with_int_line(self):
        adapter = VariantAdapter()
        result = adapter.merge({
            "model-a": [{"file": "src/x.c", "line": 5, "function": "f"}],
            "model-b": [{"file": "src/x.c", "line": "5", "function": "f"}],
        })
        # Same logical variant — should merge into one item
        assert len(result) == 1
        assert result[0]["found_by_models"] == ["model-a", "model-b"]

    def test_string_line_with_whitespace_unifies(self):
        adapter = VariantAdapter()
        result = adapter.merge({
            "model-a": [{"file": "src/x.c", "line": 5, "function": "f"}],
            "model-b": [{"file": "src/x.c", "line": " 5 ", "function": "f"}],
        })
        assert len(result) == 1

    def test_genuinely_different_lines_kept_separate(self):
        adapter = VariantAdapter()
        result = adapter.merge({
            "model-a": [{"file": "src/x.c", "line": 5, "function": "f"}],
            "model-b": [{"file": "src/x.c", "line": "10", "function": "f"}],
        })
        assert len(result) == 2

    def test_non_numeric_line_string_preserved(self):
        # Pathological case: model returned non-numeric line. Should
        # surface as its own bucket rather than silently coercing to 0.
        adapter = VariantAdapter()
        result = adapter.merge({
            "model-a": [{"file": "src/x.c", "line": "junk", "function": "f"}],
        })
        assert len(result) == 1
        # The id is still derivable — the canonical line stays as the original junk string
        assert "junk" in adapter.item_id(result[0])

    def test_non_numeric_line_strips_whitespace_for_dedup(self):
        # If two models return the SAME non-numeric line value but with
        # different whitespace, they should still bucket together.
        # Pre-fix: only the int-coercion path was stripped; the fallback
        # path kept original whitespace, splitting the bucket.
        adapter = VariantAdapter()
        result = adapter.merge({
            "model-a": [{"file": "src/x.c", "line": "junk", "function": "f"}],
            "model-b": [{"file": "src/x.c", "line": "junk ", "function": "f"}],
        })
        assert len(result) == 1
        assert result[0]["found_by_models"] == ["model-a", "model-b"]


class TestVariantAdapterMerge:
    def test_two_models_overlapping_finds(self):
        adapter = VariantAdapter()
        result = adapter.merge({
            "claude": [
                {"file": "src/x.c", "line": 5, "function": "f", "snippet": "claude saw"},
            ],
            "gemini": [
                {"file": "src/x.c", "line": 5, "function": "f", "snippet": "gemini saw"},
            ],
        })
        assert len(result) == 1
        assert result[0]["found_by_models"] == ["claude", "gemini"]
        # multi_model_finds preserves both views
        assert "multi_model_finds" in result[0]
        assert len(result[0]["multi_model_finds"]) == 2

    def test_normalized_paths_unify_finds(self):
        # claude returned "./src/x.c"; gemini returned "src/x.c".
        # VariantAdapter's item_key normalizes ./ — they should unify.
        adapter = VariantAdapter()
        result = adapter.merge({
            "claude": [{"file": "./src/x.c", "line": 5, "function": "f"}],
            "gemini": [{"file": "src/x.c", "line": 5, "function": "f"}],
        })
        assert len(result) == 1


# ---------------------------------------------------------------------------
# TraceAdapter
# ---------------------------------------------------------------------------


class TestTraceAdapterItemId:
    def test_uses_trace_id(self):
        adapter = TraceAdapter()
        assert adapter.item_id({"trace_id": "EP-001"}) == "EP-001"

    def test_strips_trace_id_whitespace(self):
        # Models occasionally return ids with surrounding whitespace.
        # Strip so " EP-001 " and "EP-001" don't bucket separately.
        adapter = TraceAdapter()
        assert adapter.item_id({"trace_id": "  EP-001  "}) == "EP-001"

    def test_whitespace_padded_trace_ids_unify_in_merge(self):
        adapter = TraceAdapter()
        result = adapter.merge({
            "model-a": [{"trace_id": "EP-001", "verdict": "reachable"}],
            "model-b": [{"trace_id": "  EP-001  ", "verdict": "reachable"}],
        })
        # Same trace, just whitespace differences
        assert len(result) == 1

    def test_missing_trace_id_raises_with_clear_message(self):
        # Regression: previously raised KeyError, which misleads operators
        # into thinking the adapter is buggy. Now we raise ValueError
        # naming the actual problem (model returned malformed dict).
        adapter = TraceAdapter()
        with pytest.raises(ValueError, match="missing.*trace_id"):
            adapter.item_id({"verdict": "reachable", "reasoning": "ok"})


class TestTraceAdapterDefensiveVerdict:
    """Model output occasionally has type drift; non-string verdict
    values shouldn't crash with AttributeError."""

    def test_int_verdict_is_unknown(self):
        adapter = TraceAdapter()
        # Pre-fix: `(42 or "").strip().lower()` raised AttributeError
        assert adapter.normalize_verdict({"verdict": 42}) == "unknown"

    def test_none_verdict_is_unknown(self):
        adapter = TraceAdapter()
        assert adapter.normalize_verdict({"verdict": None}) == "unknown"

    def test_list_verdict_is_unknown(self):
        adapter = TraceAdapter()
        # Some LLMs return ["reachable"] instead of "reachable"
        assert adapter.normalize_verdict({"verdict": ["reachable"]}) == "unknown"

    def test_correlate_with_typedrift_doesnt_crash(self):
        # End-to-end: a model returning a non-string verdict must not
        # crash merge or correlate. The substrate drops "unknown"
        # verdicts from agreement classification, so the remaining
        # classifiable verdict (positive) wins → high.
        adapter = TraceAdapter()
        per_model = {
            "model-a": [{"trace_id": "EP-001", "verdict": "reachable"}],
            "model-b": [{"trace_id": "EP-001", "verdict": 42}],  # type drift
        }
        merged = adapter.merge(per_model)
        c = adapter.correlate(merged, per_model)
        # Doesn't crash; classifiable verdicts = {"positive"} → "high"
        assert c["confidence_signals"]["EP-001"] == "high"


class TestTraceAdapterNormalizeVerdict:
    def test_reachable_is_positive(self):
        adapter = TraceAdapter()
        assert adapter.normalize_verdict({"verdict": "reachable"}) == "positive"

    def test_not_reachable_is_negative(self):
        adapter = TraceAdapter()
        assert adapter.normalize_verdict({"verdict": "not_reachable"}) == "negative"

    def test_uncertain_is_inconclusive(self):
        adapter = TraceAdapter()
        assert adapter.normalize_verdict({"verdict": "uncertain"}) == "inconclusive"

    def test_unknown_string_is_unknown(self):
        adapter = TraceAdapter()
        assert adapter.normalize_verdict({"verdict": "weird"}) == "unknown"

    def test_empty_is_unknown(self):
        adapter = TraceAdapter()
        assert adapter.normalize_verdict({}) == "unknown"

    def test_case_and_whitespace_insensitive(self):
        adapter = TraceAdapter()
        assert adapter.normalize_verdict({"verdict": "  REACHABLE  "}) == "positive"


class TestTraceAdapterMerge:
    def test_prefer_positive_default(self):
        # Default select_primary inherited from BaseVerdictAdapter:
        # reachable wins over not_reachable.
        adapter = TraceAdapter()
        result = adapter.merge({
            "claude": [{"trace_id": "EP-001", "verdict": "not_reachable"}],
            "gemini": [{"trace_id": "EP-001", "verdict": "reachable"}],
        })
        assert len(result) == 1
        assert result[0]["verdict"] == "reachable"
        # multi_model_analyses attached when 2+ distinct models
        assert "multi_model_analyses" in result[0]


class TestTraceAdapterReasoningTruncation:
    def test_reasoning_truncate_is_1200(self):
        # Subclass overrides REASONING_TRUNCATE — verify it sticks
        adapter = TraceAdapter()
        long_reasoning = "x" * 2000
        result = adapter.merge({
            "claude": [{"trace_id": "EP-001", "verdict": "reachable",
                        "reasoning": long_reasoning}],
            "gemini": [{"trace_id": "EP-001", "verdict": "reachable"}],
        })
        analyses = result[0]["multi_model_analyses"]
        claude_record = next(a for a in analyses if a["model"] == "claude")
        assert len(claude_record["reasoning"]) == 1200


class TestTraceAdapterCorrelate:
    def test_disputed_when_reachable_vs_not_reachable(self):
        adapter = TraceAdapter()
        per_model = {
            "claude": [{"trace_id": "EP-001", "verdict": "reachable"}],
            "gemini": [{"trace_id": "EP-001", "verdict": "not_reachable"}],
        }
        merged = adapter.merge(per_model)
        c = adapter.correlate(merged, per_model)
        assert c["confidence_signals"]["EP-001"] == "disputed"

    def test_high_when_all_reachable(self):
        adapter = TraceAdapter()
        per_model = {
            "claude": [{"trace_id": "EP-001", "verdict": "reachable"}],
            "gemini": [{"trace_id": "EP-001", "verdict": "reachable"}],
        }
        merged = adapter.merge(per_model)
        c = adapter.correlate(merged, per_model)
        assert c["confidence_signals"]["EP-001"] == "high"

    def test_mixed_when_reachable_plus_uncertain(self):
        adapter = TraceAdapter()
        per_model = {
            "claude": [{"trace_id": "EP-001", "verdict": "reachable"}],
            "gemini": [{"trace_id": "EP-001", "verdict": "uncertain"}],
        }
        merged = adapter.merge(per_model)
        c = adapter.correlate(merged, per_model)
        assert c["confidence_signals"]["EP-001"] == "mixed"
