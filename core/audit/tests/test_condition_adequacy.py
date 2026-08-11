"""Tests for condition_adequacy — per-sink-API guard sufficiency specs."""


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
        g = _guard("user.is_authenticated", "auth")
        result = assess_guard_adequacy("system", [g])
        assert result.verdict == Adequacy.SUFFICIENT

    def test_system_with_only_bounds(self):
        g = _guard("len < 256", "bounds")
        result = assess_guard_adequacy("system", [g])
        assert result.verdict == Adequacy.IRRELEVANT

    def test_system_no_guards(self):
        result = assess_guard_adequacy("system", [])
        assert result.verdict == Adequacy.INSUFFICIENT

    def test_eval_with_auth(self):
        g = _guard("request.user.is_staff", "auth")
        result = assess_guard_adequacy("eval", [g])
        assert result.verdict == Adequacy.SUFFICIENT

    def test_malloc_with_overflow_check(self):
        g = _guard("n < SIZE_MAX / sizeof(int)", "bounds")
        result = assess_guard_adequacy("malloc", [g])
        assert result.verdict == Adequacy.SUFFICIENT

    def test_malloc_with_simple_bound(self):
        g = _guard("n > 0", "bounds")
        result = assess_guard_adequacy("malloc", [g])
        assert result.verdict == Adequacy.SUFFICIENT

    def test_pickle_loads_needs_both(self):
        g1 = _guard("user.is_admin", "auth")
        result = assess_guard_adequacy("pickle.loads", [g1])
        assert result.verdict == Adequacy.PARTIAL
        assert "type" in result.missing_categories

    def test_pickle_loads_with_both(self):
        g1 = _guard("user.is_admin", "auth")
        g2 = _guard("isinstance(data, SafeType)", "type")
        result = assess_guard_adequacy("pickle.loads", [g1, g2])
        assert result.verdict == Adequacy.SUFFICIENT

    def test_unknown_sink_api(self):
        g = _guard("x > 0", "bounds")
        result = assess_guard_adequacy("my_custom_function", [g])
        assert result.verdict == Adequacy.UNKNOWN
        assert "no sink spec defined" in result.notes[0]

    def test_dotted_api_suffix_match(self):
        g = _guard("is_admin", "auth")
        result = assess_guard_adequacy("os.system", [g])
        assert result.verdict == Adequacy.SUFFICIENT

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
