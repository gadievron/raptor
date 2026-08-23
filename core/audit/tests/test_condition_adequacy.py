"""Tests for condition_adequacy — per-sink-API guard sufficiency specs."""


import core.audit.condition_adequacy as ca
from core.audit.condition_adequacy import (
    Adequacy,
    assess_file_guards,
    assess_guard_adequacy,
    compare_sink_guards,
)
from core.audit.condition_extraction import GuardCondition, SinkGuard

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _guard(text: str, category: str, **kw) -> GuardCondition:
    return GuardCondition(text=text, category=category, polarity="required", line=1, **kw)


def _sg(sink_api: str, guards: list, line: int = 10, func: str = "f") -> SinkGuard:
    return SinkGuard(
        sink_file="test.c",
        sink_line=line,
        sink_function=func,
        sink_api=sink_api,
        guards=guards,
        unconditional=(len(guards) == 0),
    )


# ---------------------------------------------------------------------------
# Adequacy assessment tests
# ---------------------------------------------------------------------------


class TestAssessGuardAdequacy:
    def test_memcpy_with_bounds_referencing_size(self):
        g = _guard("len < sizeof(buf)", "bounds")
        result = assess_guard_adequacy("memcpy", [g])
        assert result.verdict == Adequacy.SUFFICIENT
        assert not result.missing_categories

    def test_memcpy_with_bounds_no_size_reference(self):
        g = _guard("x > 0", "bounds")
        result = assess_guard_adequacy("memcpy", [g])
        assert result.verdict == Adequacy.PARTIAL
        assert "text pattern unmatched" in result.notes[-1]

    def test_memcpy_with_only_auth_guard(self):
        g = _guard("is_admin(user)", "auth")
        result = assess_guard_adequacy("memcpy", [g])
        assert result.verdict == Adequacy.IRRELEVANT

    def test_memcpy_no_guards(self):
        result = assess_guard_adequacy("memcpy", [])
        assert result.verdict == Adequacy.INSUFFICIENT
        assert "no guards present" in result.notes

    def test_system_with_auth(self):
        # Soundness: an auth-LOOKING identifier proves nothing about
        # what it authorises — category/text match caps at PARTIAL so
        # the guard-clean skip path cannot fire on it.
        g = _guard("user.is_authenticated", "auth")
        result = assess_guard_adequacy("system", [g])
        assert result.verdict == Adequacy.PARTIAL

    def test_system_with_only_bounds(self):
        g = _guard("len < 256", "bounds")
        result = assess_guard_adequacy("system", [g])
        assert result.verdict == Adequacy.IRRELEVANT

    def test_system_no_guards(self):
        result = assess_guard_adequacy("system", [])
        assert result.verdict == Adequacy.INSUFFICIENT

    def test_eval_with_auth(self):
        # Same soundness cap as test_system_with_auth.
        g = _guard("request.user.is_staff", "auth")
        result = assess_guard_adequacy("eval", [g])
        assert result.verdict == Adequacy.PARTIAL

    def test_malloc_with_overflow_check(self):
        g = _guard("n < SIZE_MAX / sizeof(int)", "bounds")
        result = assess_guard_adequacy("malloc", [g])
        assert result.verdict == Adequacy.SUFFICIENT

    def test_malloc_with_simple_bound(self):
        # Soundness: ``n > 0`` is a non-emptiness check, not a bounds
        # check — nothing prevents n * elem_size from wrapping.  The
        # verdict caps at PARTIAL without an upper-bound comparison.
        g = _guard("n > 0", "bounds")
        result = assess_guard_adequacy("malloc", [g])
        assert result.verdict == Adequacy.PARTIAL

    def test_pickle_loads_needs_both(self):
        g1 = _guard("user.is_admin", "auth")
        result = assess_guard_adequacy("pickle.loads", [g1])
        assert result.verdict == Adequacy.PARTIAL
        assert "type" in result.missing_categories

    def test_pickle_loads_with_both(self):
        # Both required categories present, but auth/type category
        # matches cannot establish sufficiency mechanically (what does
        # is_admin gate? does the isinstance bind the loaded value?) —
        # capped at PARTIAL for review.
        g1 = _guard("user.is_admin", "auth")
        g2 = _guard("isinstance(data, SafeType)", "type")
        result = assess_guard_adequacy("pickle.loads", [g1, g2])
        assert result.verdict == Adequacy.PARTIAL
        assert not result.missing_categories

    def test_unknown_sink_api(self):
        g = _guard("x > 0", "bounds")
        result = assess_guard_adequacy("my_custom_function", [g])
        assert result.verdict == Adequacy.UNKNOWN
        assert "no sink spec defined" in result.notes[0]

    def test_dotted_api_suffix_match(self):
        # Suffix match still resolves the spec (verdict is not
        # UNKNOWN); the auth cap applies as for bare "system".
        g = _guard("is_admin", "auth")
        result = assess_guard_adequacy("os.system", [g])
        assert result.verdict == Adequacy.PARTIAL

    def test_sql_sink_needs_type(self):
        g = _guard("len(query) < 1000", "bounds")
        result = assess_guard_adequacy("cursor.execute", [g])
        assert result.verdict == Adequacy.INSUFFICIENT
        assert "type" in result.missing_categories

    def test_sql_with_type_check(self):
        g = _guard("isinstance(stmt, PreparedStatement)", "type")
        result = assess_guard_adequacy("cursor.execute", [g])
        assert result.verdict == Adequacy.SUFFICIENT

    def test_file_sink_with_path_check(self):
        g = _guard("'..' not in path and os.path.abspath(path)", "bounds")
        result = assess_guard_adequacy("open", [g])
        assert result.verdict == Adequacy.SUFFICIENT

    def test_to_dict(self):
        g = _guard("len < sizeof(buf)", "bounds")
        result = assess_guard_adequacy("memcpy", [g])
        d = result.to_dict()
        assert d["verdict"] == "sufficient"
        assert "bounds" in d["required_categories"]


class TestSufficientRequiresSemanticAdequacy:
    """Regression (verdict soundness): category-regex matches used to
    yield SUFFICIENT verdicts that drove whole-function guard-clean
    commits skipping LLM review.  ``len > 0`` is not a bounds check
    for memcpy; an auth-looking identifier is never sufficient for
    system/eval/deserialize."""

    def test_memcpy_len_gt_zero_not_sufficient(self):
        g = _guard("len > 0", "bounds")
        result = assess_guard_adequacy("memcpy", [g])
        assert result.verdict != Adequacy.SUFFICIENT

    def test_memcpy_len_ne_zero_not_sufficient(self):
        g = _guard("len != 0", "bounds")
        result = assess_guard_adequacy("memcpy", [g])
        assert result.verdict != Adequacy.SUFFICIENT

    def test_strcpy_size_ge_one_not_sufficient(self):
        g = _guard("size >= 1", "bounds")
        result = assess_guard_adequacy("strcpy", [g])
        assert result.verdict != Adequacy.SUFFICIENT

    def test_system_bare_auth_word_not_sufficient(self):
        g = _guard("allowed", "auth")
        result = assess_guard_adequacy("system", [g])
        assert result.verdict != Adequacy.SUFFICIENT

    def test_system_auth_field_not_sufficient(self):
        g = _guard("opts->permitted", "auth")
        result = assess_guard_adequacy("system", [g])
        assert result.verdict != Adequacy.SUFFICIENT

    def test_memcpy_upper_bound_still_sufficient(self):
        # Boost value preserved: a real upper-bound comparison keeps
        # the SUFFICIENT verdict.
        g = _guard("len < sizeof(buf)", "bounds")
        result = assess_guard_adequacy("memcpy", [g])
        assert result.verdict == Adequacy.SUFFICIENT

    def test_memcpy_reversed_upper_bound_sufficient(self):
        g = _guard("sizeof(buf) > len", "bounds")
        result = assess_guard_adequacy("memcpy", [g])
        assert result.verdict == Adequacy.SUFFICIENT

    def test_alloc_upper_bound_against_size_max(self):
        g = _guard("n < SIZE_MAX / size", "bounds")
        result = assess_guard_adequacy("malloc", [g])
        assert result.verdict == Adequacy.SUFFICIENT

    def test_memcpy_min_clamp_counts_as_upper_bound(self):
        g = _guard("len = min(len, sizeof(buf))", "bounds")
        result = assess_guard_adequacy("memcpy", [g])
        assert result.verdict == Adequacy.SUFFICIENT


# ---------------------------------------------------------------------------
# Within-function comparison tests
# ---------------------------------------------------------------------------


class TestCompareSinkGuards:
    def test_detects_asymmetry(self):
        guarded = _sg("memcpy", [_guard("len < sizeof(buf)", "bounds")], line=10)
        unguarded = _sg("memcpy", [], line=20)
        results = compare_sink_guards([guarded, unguarded])
        assert len(results) == 1
        assert results[0].guarded_line == 10
        assert results[0].unguarded_line == 20
        assert "bounds" in results[0].missing_categories

    def test_no_asymmetry_when_equal(self):
        g1 = _sg("memcpy", [_guard("len < 100", "bounds")], line=10)
        g2 = _sg("memcpy", [_guard("n < 200", "bounds")], line=20)
        results = compare_sink_guards([g1, g2])
        assert len(results) == 0

    def test_different_sinks_not_compared(self):
        g1 = _sg("memcpy", [_guard("len < 100", "bounds")], line=10)
        g2 = _sg("strcpy", [], line=20)
        results = compare_sink_guards([g1, g2])
        assert len(results) == 0

    def test_different_functions_not_compared(self):
        g1 = _sg("memcpy", [_guard("len < 100", "bounds")], line=10, func="func_a")
        g2 = _sg("memcpy", [], line=20, func="func_b")
        results = compare_sink_guards([g1, g2])
        assert len(results) == 0

    def test_confidence_auth_missing(self):
        guarded = _sg("system", [_guard("is_admin()", "auth")], line=10)
        unguarded = _sg("system", [], line=20)
        results = compare_sink_guards([guarded, unguarded])
        assert len(results) == 1
        assert results[0].confidence >= 0.7

    def test_multiple_asymmetries(self):
        best = _sg("memcpy", [
            _guard("len < sizeof(buf)", "bounds"),
            _guard("user_is_admin", "auth"),
        ], line=10)
        weak1 = _sg("memcpy", [_guard("len < 100", "bounds")], line=20)
        weak2 = _sg("memcpy", [], line=30)
        results = compare_sink_guards([best, weak1, weak2])
        assert len(results) == 2

    def test_unknown_guards_dont_win_best_selection(self):
        # 5 unknown guards should NOT beat 2 categorised guards
        many_unknown = _sg("memcpy", [
            _guard("???", "unknown"),
            _guard("???", "unknown"),
            _guard("???", "unknown"),
            _guard("???", "unknown"),
            _guard("???", "unknown"),
        ], line=10)
        fewer_categorised = _sg("memcpy", [
            _guard("len < sizeof(buf)", "bounds"),
            _guard("is_admin()", "auth"),
        ], line=20)
        bare = _sg("memcpy", [], line=30)
        results = compare_sink_guards([many_unknown, fewer_categorised, bare])
        # fewer_categorised should be selected as best; bare is missing both
        assert len(results) >= 1
        found_lines = {r.unguarded_line for r in results}
        assert 30 in found_lines

    def test_to_dict(self):
        guarded = _sg("memcpy", [_guard("len < sizeof(buf)", "bounds")], line=10)
        unguarded = _sg("memcpy", [], line=20)
        results = compare_sink_guards([guarded, unguarded])
        d = results[0].to_dict()
        assert d["sink_api"] == "memcpy"
        assert d["guarded_line"] == 10


# ---------------------------------------------------------------------------
# Batch API
# ---------------------------------------------------------------------------


class TestAssessFileGuards:
    def test_returns_both(self):
        guards = [
            _sg("memcpy", [_guard("len < sizeof(buf)", "bounds")], line=10),
            _sg("memcpy", [], line=20),
        ]
        adequacy, asymmetries = assess_file_guards(guards)
        assert len(adequacy) == 2
        assert adequacy[0].verdict == Adequacy.SUFFICIENT
        assert adequacy[1].verdict == Adequacy.INSUFFICIENT
        assert len(asymmetries) == 1


# ---------------------------------------------------------------------------
# present_categories semantics
# ---------------------------------------------------------------------------


class TestPresentCategoriesConsistency:
    """'unknown' is excluded from present_categories on both paths."""

    def test_no_spec_path_excludes_unknown(self):
        result = assess_guard_adequacy(
            "my_custom_function",
            [_guard("???", "unknown"), _guard("x > 0", "bounds")],
        )
        assert result.verdict == Adequacy.UNKNOWN
        assert result.present_categories == frozenset({"bounds"})

    def test_spec_path_excludes_unknown(self):
        result = assess_guard_adequacy(
            "memcpy",
            [_guard("???", "unknown"), _guard("len < sizeof(buf)", "bounds")],
        )
        assert result.present_categories == frozenset({"bounds"})

    def test_both_paths_report_identically(self):
        guards = [_guard("???", "unknown"), _guard("is_admin(u)", "auth")]
        no_spec = assess_guard_adequacy("my_custom_function", guards)
        with_spec = assess_guard_adequacy("system", guards)
        assert (
            no_spec.to_dict()["present_categories"]
            == with_spec.to_dict()["present_categories"]
        )

    def test_only_unknown_guards_yield_empty(self):
        result = assess_guard_adequacy(
            "my_custom_function", [_guard("???", "unknown")],
        )
        assert result.present_categories == frozenset()


class TestDerefSpecRemoved:
    """The never-registered null-deref spec is gone, not silently dead."""

    def test_constant_removed(self):
        assert not hasattr(ca, "_DEREF_SPEC")

    def test_no_registered_spec_requires_only_null(self):
        assert all(
            spec.required != frozenset({"null"})
            for spec in ca._SINK_SPECS.values()
        )


class TestPolarityHonoured:
    def test_excluded_bounds_guard_cannot_make_sufficient(self):
        # Regression PoC: if (len < sizeof(buf)) { small(); } else
        # { memcpy(buf, src, len); } — the sink runs exactly when the
        # bounds check FAILS, yet the guard's category/text made the
        # memcpy 'adequately guarded' (SUFFICIENT skips LLM review).
        g = GuardCondition(
            text="len < sizeof(buf)", category="bounds",
            polarity="excluded", line=3,
        )
        res = assess_guard_adequacy("memcpy", [g])
        assert res.verdict == Adequacy.INSUFFICIENT, res.to_dict()
        assert any("excluded polarity" in n for n in res.notes)

    def test_required_polarity_keeps_sufficiency(self):
        g = GuardCondition(
            text="len < sizeof(buf)", category="bounds",
            polarity="required", line=3,
        )
        res = assess_guard_adequacy("memcpy", [g])
        assert res.verdict == Adequacy.SUFFICIENT

    def test_excluded_null_guard_cannot_make_sufficient(self):
        # if (p != NULL) { ok(); } else { *p ... } — the 'guard'
        # guarantees the bug on the sink path.
        g = GuardCondition(
            text="p != NULL", category="null",
            polarity="excluded", line=2,
        )
        res = assess_guard_adequacy("strlen", [g])
        assert res.verdict != Adequacy.SUFFICIENT

    def test_mixed_polarities_keep_only_required(self):
        excluded = GuardCondition(
            text="len < sizeof(buf)", category="bounds",
            polarity="excluded", line=2,
        )
        required = GuardCondition(
            text="len < sizeof(buf)", category="bounds",
            polarity="required", line=5,
        )
        res = assess_guard_adequacy("memcpy", [excluded, required])
        assert res.verdict == Adequacy.SUFFICIENT
        assert any("excluded polarity" in n for n in res.notes)
