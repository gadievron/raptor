"""Tests for ``core.llm.semantic_entropy.divergence`` and
``pairwise_distance``."""

from __future__ import annotations

import pytest

from core.llm.semantic_entropy import (
    _jaccard_distance,
    divergence,
    pairwise_distance,
)


# --- Reasoning fixtures: realistic security-analysis prose -----------

# Three models all citing the same SQL injection sink in cgi_query().
SQL_INJECTION_AGREED = {
    "model-a": (
        "User input flows from request.GET['q'] into cgi_query() "
        "without sanitisation. The sink at cgi.c:142 concatenates "
        "the query string directly into the SQL statement. Classic "
        "SQL injection with attacker-controlled input."
    ),
    "model-b": (
        "Tainted data from request.GET reaches cgi_query in cgi.c "
        "line 142. String concatenation builds the SQL with no "
        "parameterisation, so the attacker controls the query."
    ),
    "model-c": (
        "Source: request.GET['q']. Sink: cgi_query at cgi.c:142. "
        "The function builds SQL by string concatenation, exposing "
        "an injection vector to any untrusted query parameter."
    ),
}

# Same verdict (exploitable) but each model cites a different bug:
# SQL injection vs path traversal vs deserialisation.
SAME_VERDICT_DIFFERENT_REASONS = {
    "model-a": (
        "SQL injection at cgi_query in cgi.c:142. Request.GET['q'] "
        "reaches the sink unsanitised, attacker controls the SQL "
        "via the query parameter and can read arbitrary tables."
    ),
    "model-b": (
        "Path traversal in upload_file at upload.c:88. The filename "
        "from multipart form data is joined with the storage path "
        "without normalisation, so '../../etc/passwd' escapes the "
        "upload directory."
    ),
    "model-c": (
        "Insecure deserialisation in api_handler at api.py:31. The "
        "pickle.loads call on the request body trusts arbitrary "
        "attacker-supplied serialised objects, leading to remote "
        "code execution."
    ),
}


class TestPanelSizeGate:
    def test_returns_none_for_two_models(self):
        result = divergence({k: v for k, v in list(
            SQL_INJECTION_AGREED.items())[:2]})
        assert result is None

    def test_returns_none_for_one_model(self):
        result = divergence({"model-a": SQL_INJECTION_AGREED["model-a"]})
        assert result is None

    def test_returns_none_for_empty(self):
        assert divergence({}) is None


class TestReasoningLengthFilter:
    def test_drops_short_reasonings(self):
        # Two long, one short → only two valid → below min_models.
        inputs = dict(SQL_INJECTION_AGREED)
        inputs["model-c"] = "ok"
        assert divergence(inputs) is None

    def test_drops_none_and_empty(self):
        inputs = dict(SQL_INJECTION_AGREED)
        inputs["model-d"] = ""
        inputs["model-e"] = None  # type: ignore[assignment]
        result = divergence(inputs)
        assert result is not None
        assert result["n_models"] == 3

    def test_custom_min_chars(self):
        # With min_chars=10000 every reasoning is filtered out.
        result = divergence(SQL_INJECTION_AGREED, min_chars=10000)
        assert result is None


class TestAgreedReasoning:
    def test_low_distance_when_panel_aligned(self):
        result = divergence(SQL_INJECTION_AGREED)
        assert result is not None
        assert result["mean_pairwise_distance"] < 0.85
        assert result["n_models"] == 3
        assert result["outlier_model"] in SQL_INJECTION_AGREED

    def test_returns_full_shape(self):
        result = divergence(SQL_INJECTION_AGREED)
        assert result is not None
        assert set(result) == {
            "mean_pairwise_distance",
            "max_pairwise_distance",
            "outlier_model",
            "per_model_distance",
            "n_models",
        }
        assert isinstance(result["per_model_distance"], dict)
        assert set(result["per_model_distance"]) == set(
            SQL_INJECTION_AGREED)


class TestDivergentReasoning:
    def test_high_dispersion_when_models_cite_different_bugs(self):
        agreed = divergence(SQL_INJECTION_AGREED)
        divergent = divergence(SAME_VERDICT_DIFFERENT_REASONS)
        assert agreed is not None and divergent is not None
        # The divergent panel should sit visibly farther apart than
        # the aligned one. The exact gap isn't load-bearing — any
        # consumer using a fixed threshold should set it from real
        # data, not from this assertion. We just want positive
        # discrimination of at least 0.10.
        assert (divergent["mean_pairwise_distance"]
                > agreed["mean_pairwise_distance"] + 0.10)
        assert (divergent["max_pairwise_distance"]
                > agreed["max_pairwise_distance"] + 0.10)


class TestOutlierIdentification:
    def test_picks_the_one_dissimilar_model(self):
        # Two models give the same SQL-injection story; one cites
        # a totally different bug. Expect the third model as outlier.
        inputs = {
            "model-a": SQL_INJECTION_AGREED["model-a"],
            "model-b": SQL_INJECTION_AGREED["model-b"],
            "model-c": SAME_VERDICT_DIFFERENT_REASONS["model-b"],  # path traversal
        }
        result = divergence(inputs)
        assert result is not None
        assert result["outlier_model"] == "model-c"

    def test_outlier_choice_is_deterministic(self):
        # Two runs on the same input must agree on the outlier even
        # if multiple models are tied at the max distance.
        a = divergence(SAME_VERDICT_DIFFERENT_REASONS)
        b = divergence(SAME_VERDICT_DIFFERENT_REASONS)
        assert a is not None and b is not None
        assert a["outlier_model"] == b["outlier_model"]


class TestEdgeCases:
    def test_identical_reasonings_have_zero_distance(self):
        same = SQL_INJECTION_AGREED["model-a"]
        result = divergence({"a": same, "b": same, "c": same})
        assert result is not None
        # Identical token sets → Jaccard distance 0 everywhere.
        assert result["mean_pairwise_distance"] == pytest.approx(
            0.0, abs=1e-9)
        assert result["max_pairwise_distance"] == pytest.approx(
            0.0, abs=1e-9)

    def test_distances_within_unit_interval(self):
        result = divergence(SAME_VERDICT_DIFFERENT_REASONS)
        assert result is not None
        for d in result["per_model_distance"].values():
            assert 0.0 <= d <= 1.0
        assert 0.0 <= result["mean_pairwise_distance"] <= 1.0
        assert 0.0 <= result["max_pairwise_distance"] <= 1.0


# ---------------------------------------------------------------------------
# pairwise_distance — N=2 specialisation
# ---------------------------------------------------------------------------


class TestPairwiseDistance:
    def test_identical_strings_zero_distance(self):
        s = SQL_INJECTION_AGREED["model-a"]
        assert pairwise_distance(s, s) == pytest.approx(0.0, abs=1e-9)

    def test_aligned_panel_below_divergent_panel(self):
        aligned = pairwise_distance(
            SQL_INJECTION_AGREED["model-a"],
            SQL_INJECTION_AGREED["model-b"],
        )
        divergent = pairwise_distance(
            SAME_VERDICT_DIFFERENT_REASONS["model-a"],
            SAME_VERDICT_DIFFERENT_REASONS["model-b"],
        )
        assert aligned is not None and divergent is not None
        # Same gap pinned in the panel-level test: aligned < divergent
        # by at least 0.10. Cross-references the discrimination
        # contract for callers that operate at N=2 (cross-family).
        assert divergent > aligned + 0.10

    def test_within_unit_interval(self):
        d = pairwise_distance(
            SAME_VERDICT_DIFFERENT_REASONS["model-a"],
            SAME_VERDICT_DIFFERENT_REASONS["model-c"],
        )
        assert d is not None
        assert 0.0 <= d <= 1.0

    def test_short_string_returns_none(self):
        assert pairwise_distance("ok", SQL_INJECTION_AGREED["model-a"]) is None
        assert pairwise_distance(SQL_INJECTION_AGREED["model-a"], "ok") is None

    def test_non_string_inputs_return_none(self):
        assert pairwise_distance(None, "x" * 100) is None  # type: ignore[arg-type]
        assert pairwise_distance("x" * 100, 42) is None    # type: ignore[arg-type]

    def test_custom_min_chars(self):
        # With min_chars=10000 every reasoning is filtered out.
        result = pairwise_distance(
            SQL_INJECTION_AGREED["model-a"],
            SQL_INJECTION_AGREED["model-b"],
            min_chars=10000,
        )
        assert result is None

    def test_both_empty_return_none(self):
        assert pairwise_distance("", "") is None


# ---------------------------------------------------------------------------
# _jaccard_distance — direct edge-case coverage for the math primitive
# ---------------------------------------------------------------------------


class TestJaccardDistance:
    """Direct tests for ``_jaccard_distance``. The public API
    (``divergence`` / ``pairwise_distance``) covers it transitively
    on realistic inputs, but the underscore primitive's edge cases
    (empty sets, one-empty, full-overlap) deserve their own pins so
    a future refactor doesn't quietly break the contract."""

    def test_identical_sets_zero_distance(self):
        s = {"a", "b", "c"}
        assert _jaccard_distance(s, s) == pytest.approx(0.0, abs=1e-9)

    def test_disjoint_sets_distance_one(self):
        assert _jaccard_distance({"a", "b"}, {"c", "d"}) == pytest.approx(
            1.0, abs=1e-9)

    def test_both_empty_treated_as_identical(self):
        # Convention: two zero-information inputs are "the same" for
        # downstream consumers (no signal either way).
        assert _jaccard_distance(set(), set()) == 0.0

    def test_one_empty_one_nonempty_orthogonal(self):
        # Convention: one-empty plus one-nonempty is "completely
        # different" — anything is dissimilar from nothing.
        assert _jaccard_distance(set(), {"a"}) == 1.0
        assert _jaccard_distance({"a"}, set()) == 1.0

    def test_partial_overlap_proportional(self):
        # |A ∩ B| / |A ∪ B| = 1/3 → distance = 2/3
        d = _jaccard_distance({"a", "b"}, {"b", "c"})
        assert d == pytest.approx(2 / 3, abs=1e-9)


# ---------------------------------------------------------------------------
# Verbosity-bias regression — pin the known length sensitivity
# ---------------------------------------------------------------------------


class TestVerbosityBiasRegression:
    """Document and pin the known verbosity bias so a future "fix"
    has to consciously update the test rather than silently change
    the metric profile.

    The bias: same diagnosis but different verbosity produces
    elevated distance, with the LONG-form model selected as outlier
    rather than the substantively-different one. Confirmed in the
    2026-05-09 Gemini run (flash-lite consistently the outlier
    because it writes terser reasoning, not because it diagnoses
    differently). See ``project_semantic_entropy`` memory.

    If you implement a tokens-per-doc / length-normalisation fix
    for the bias, update these expectations to match the new
    behavior — don't just delete the tests.
    """

    SAME_DIAGNOSIS_DIFFERENT_LENGTHS = {
        "terse": (
            "SQL injection at cgi_query in cgi.c:142. "
            "Query parameter is unsafe."
        ),
        "medium": (
            "SQL injection at cgi_query in cgi.c:142. The query "
            "parameter from request.GET is concatenated into the "
            "SQL string without parameterisation, exposing injection."
        ),
        "verbose": (
            "User input flows from the request.GET['q'] parameter "
            "into cgi_query at cgi.c line 142, where the SQL string "
            "is built by concatenation of the query string into the "
            "SELECT statement. The function does not parameterise "
            "input. This is a classic SQL injection vector. The "
            "attacker can read arbitrary tables and exfiltrate data."
        ),
    }

    def test_same_diagnosis_at_different_lengths_still_diverges(self):
        # All three reasonings diagnose the same bug at the same
        # location. A length-aware metric would return ~0 distance.
        # The current Jaccard-on-token-sets metric does NOT — terse
        # vs verbose share <50% of their tokens.
        result = divergence(self.SAME_DIAGNOSIS_DIFFERENT_LENGTHS)
        assert result is not None
        # The bias: even on identical substance, distance is high.
        # If you fix the bias, this assertion needs to flip to <0.3.
        assert result["mean_pairwise_distance"] > 0.5

    def test_verbose_model_is_outlier_under_length_bias(self):
        # The longest reasoning has the largest token-set, which
        # makes its asymmetric overlap with smaller token-sets large
        # in absolute terms. By Jaccard's |A ∩ B| / |A ∪ B|
        # construction the long one ends up farthest from the rest.
        # Same pattern observed in the 2026-05-09 Gemini run with
        # flash-lite as the *short* outlier — shorter token sets
        # also score as outliers because they're asymmetric in the
        # other direction. Either extreme is selected; only the
        # middle isn't.
        result = divergence(self.SAME_DIAGNOSIS_DIFFERENT_LENGTHS)
        assert result is not None
        assert result["outlier_model"] in {"terse", "verbose"}
        assert result["outlier_model"] != "medium"
