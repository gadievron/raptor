"""Tests for core.iris.assumptions — safety assumption data model."""

from core.evidence import EvidenceTier
from core.iris.assumptions import (
    AssumptionCategory,
    BypassFinding,
    SafetyAssumption,
    _assumption_key,
    assumption_from_dict,
    assumptions_from_list,
    evict_stale_assumptions,
    merge_assumptions,
)


def _make_assumption(
    target="modify_state",
    file="src/state.c",
    enforced_by=None,
    **kw,
):
    return SafetyAssumption(
        target=target,
        file=file,
        assumption=f"{target} requires enforcer",
        category=kw.pop("category", AssumptionCategory.ORDERING),
        enforced_by=enforced_by or ["acquire_lock"],
        **kw,
    )


class TestSafetyAssumption:
    def test_to_dict_roundtrip(self):
        a = _make_assumption(bug_class="race_condition", confidence=0.8)
        d = a.to_dict()
        b = assumption_from_dict(d)
        assert b.target == a.target
        assert b.file == a.file
        assert b.category == a.category
        assert b.enforced_by == a.enforced_by
        assert b.bug_class == a.bug_class
        assert b.confidence == a.confidence

    def test_optional_fields(self):
        a = _make_assumption(source="llm", underminer="narrow_cast")
        d = a.to_dict()
        assert d["source"] == "llm"
        assert d["underminer"] == "narrow_cast"

    def test_optional_fields_absent(self):
        a = _make_assumption()
        d = a.to_dict()
        assert "source" not in d
        assert "underminer" not in d

    def test_unknown_category_fallback(self):
        d = {"target": "f", "file": "x.c", "assumption": "test", "category": "bogus"}
        a = assumption_from_dict(d)
        assert a.category == AssumptionCategory.SANITISATION

    def test_unknown_tier_fallback(self):
        d = {"target": "f", "file": "x.c", "assumption": "test", "evidence_tier": "bogus"}
        a = assumption_from_dict(d)
        assert a.evidence_tier == EvidenceTier.HEURISTIC

    def test_params_affected_strings_coerced_to_int(self):
        d = {"target": "f", "file": "x.c", "assumption": "test",
             "params_affected": ["0", "1", "2"]}
        a = assumption_from_dict(d)
        assert a.params_affected == [0, 1, 2]
        assert all(isinstance(p, int) for p in a.params_affected)

    def test_params_affected_non_numeric_skipped(self):
        d = {"target": "f", "file": "x.c", "assumption": "test",
             "params_affected": ["0", "abc", "2"]}
        a = assumption_from_dict(d)
        assert a.params_affected == [0, 2]

    def test_params_affected_scalar_int(self):
        d = {"target": "f", "file": "x.c", "assumption": "test",
             "params_affected": 3}
        a = assumption_from_dict(d)
        assert a.params_affected == [3]


class TestBypassFinding:
    def test_to_dict(self):
        a = _make_assumption()
        f = BypassFinding(
            assumption=a,
            caller_file="src/handler.c",
            caller_function="unsafe_handler",
            missing_enforcer="acquire_lock",
            via_intermediate="do_work",
            is_transitive=True,
        )
        d = f.to_dict()
        assert d["caller_function"] == "unsafe_handler"
        assert d["via_intermediate"] == "do_work"
        assert d["is_transitive"] is True
        assert d["assumption"]["target"] == "modify_state"

    def test_to_dict_minimal(self):
        a = _make_assumption()
        f = BypassFinding(assumption=a, caller_file="x.c", caller_function="bad")
        d = f.to_dict()
        assert "via_intermediate" not in d
        assert "line_info" not in d


class TestAssumptionKey:
    def test_same_key(self):
        a1 = _make_assumption()
        a2 = _make_assumption()
        assert _assumption_key(a1) == _assumption_key(a2)

    def test_different_enforcers(self):
        a1 = _make_assumption(enforced_by=["lock"])
        a2 = _make_assumption(enforced_by=["unlock"])
        assert _assumption_key(a1) != _assumption_key(a2)

    def test_enforcer_order_independent(self):
        a1 = _make_assumption(enforced_by=["b", "a"])
        a2 = _make_assumption(enforced_by=["a", "b"])
        assert _assumption_key(a1) == _assumption_key(a2)

    def test_different_underminers(self):
        a1 = _make_assumption(underminer="narrow_cast")
        a2 = _make_assumption(underminer="type_cast")
        assert _assumption_key(a1) != _assumption_key(a2)

    def test_underminer_vs_none(self):
        a1 = _make_assumption(underminer="narrow_cast")
        a2 = _make_assumption()
        assert _assumption_key(a1) != _assumption_key(a2)


class TestAssumptionsFromList:
    def test_valid(self):
        items = [
            {"target": "f", "file": "x.c", "assumption": "t", "category": "ordering"},
            {"target": "g", "file": "y.c", "assumption": "t2"},
        ]
        result = assumptions_from_list(items)
        assert len(result) == 2
        assert result[0].target == "f"
        assert result[1].target == "g"

    def test_malformed_skipped(self):
        items = [
            {"target": "f", "file": "x.c", "assumption": "t"},
            None,
        ]
        result = assumptions_from_list(items)
        assert len(result) == 1


class TestMergeAssumptions:
    def test_no_conflict(self):
        a = _make_assumption(target="f1")
        b = _make_assumption(target="f2")
        merged = merge_assumptions([a], [b])
        assert len(merged) == 2

    def test_higher_tier_wins(self):
        old = _make_assumption(evidence_tier=EvidenceTier.HEURISTIC)
        new = _make_assumption(evidence_tier=EvidenceTier.XREF_BACKED)
        merged = merge_assumptions([old], [new])
        assert len(merged) == 1
        assert merged[0].evidence_tier == EvidenceTier.XREF_BACKED

    def test_equal_tier_new_wins(self):
        old = _make_assumption(confidence=0.3)
        new = _make_assumption(confidence=0.9)
        merged = merge_assumptions([old], [new])
        assert len(merged) == 1
        assert merged[0].confidence == 0.9


class TestEvictStale:
    def test_keeps_current_files(self):
        a = _make_assumption(file="src/auth.c")
        result = evict_stale_assumptions([a], {"src/auth.c"})
        assert len(result) == 1

    def test_evicts_missing_files(self):
        a = _make_assumption(file="src/old.c")
        result = evict_stale_assumptions([a], {"src/auth.c"})
        assert len(result) == 0

    def test_keeps_high_tier_even_if_missing(self):
        a = _make_assumption(file="src/old.c", evidence_tier=EvidenceTier.XREF_BACKED)
        result = evict_stale_assumptions([a], {"src/auth.c"})
        assert len(result) == 1
