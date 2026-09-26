"""Guard-predicate census: site extraction, the four drift kinds,
enumerated inconclusive reasons, and two-direction floor behaviour."""

from __future__ import annotations

import pytest

from core.audit.guard_predicate import (
    DIMENSION_GUARD_PREDICATE,
    KIND_MISSING_NULL_ARM,
    KIND_OFF_BY_ONE,
    KIND_SIGNEDNESS_MIX,
    KIND_WRONG_VARIABLE,
    REASON_MACRO_DIVERGENT,
    REASON_PREDICATE_DATA_DEPENDENT,
    REASON_TYPE_CONTEXT_DIFFERS,
    detect_guard_predicate_deviations,
    is_guard_predicate_hypothesis,
)
from core.testing import requires_ts

pytestmark = requires_ts("c")


def _loop_fn(name: str, cond: str, sub: str = "a[i]") -> str:
    return (
        f"int {name}(int *a, int n)\n"
        "{\n"
        "    int i, t = 0;\n"
        f"    for (i = 0; {cond}; i++)\n"
        f"        t += {sub};\n"
        "    return t;\n"
        "}\n"
    )


def _detect(src: str, **kwargs):
    return detect_guard_predicate_deviations(
        {"peers.c": src}, seed=b"pin", **kwargs,
    )


class TestOffByOne:
    def test_flipped_operator_flags_the_deviant(self):
        src = "".join(
            _loop_fn(f"sum_{c}", "i < n") for c in "abc"
        ) + _loop_fn("sum_d", "i <= n")
        devs, stats = _detect(src)
        assert len(devs) == 1
        d = devs[0]
        assert d.kind == KIND_OFF_BY_ONE
        assert d.enclosing_function == "sum_d"
        assert d.cwe == "CWE-193"
        assert (d.n, d.conforming) == (4, 3)
        assert d.relop == "<=" and d.majority_relop == "<"
        pe = d.peer_evidence
        assert pe is not None
        assert pe.dimension == DIMENSION_GUARD_PREDICATE
        assert pe.rule_id == "consistency:guard-predicate-majority"
        assert stats["groups"] >= 1
        assert stats["predicate_ops"] > 0

    def test_uniform_family_is_clean(self):
        src = "".join(
            _loop_fn(f"sum_{c}", "i < n") for c in "abcd"
        )
        devs, _stats = _detect(src)
        assert devs == []

    def test_below_min_sites_no_vote(self):
        src = _loop_fn("sum_a", "i < n") + _loop_fn("sum_b", "i <= n")
        devs, stats = _detect(src)
        assert devs == []
        assert stats["groups"] == 0

    def test_below_ratio_no_vote(self):
        # 2 vs 2: no 0.75 majority in either direction.
        src = (
            _loop_fn("sum_a", "i < n") + _loop_fn("sum_b", "i < n")
            + _loop_fn("sum_c", "i <= n") + _loop_fn("sum_d", "i <= n")
        )
        devs, _stats = _detect(src)
        assert devs == []


class TestWrongVariable:
    def test_tested_identifier_differs_from_index(self):
        src = "".join(
            _loop_fn(f"sum_{c}", "i < n") for c in "abc"
        ) + (
            "int sum_d(int *a, int n)\n"
            "{\n"
            "    int i, j = 0, t = 0;\n"
            "    for (i = 0; j < n; i++)\n"
            "        t += a[i];\n"
            "    return t;\n"
            "}\n"
        )
        devs, _stats = _detect(src)
        kinds = {d.kind for d in devs}
        assert KIND_WRONG_VARIABLE in kinds
        dev = next(d for d in devs if d.kind == KIND_WRONG_VARIABLE)
        assert dev.enclosing_function == "sum_d"
        assert dev.tested_var == "j"


class TestSignednessMix:
    def test_mixed_declared_signedness_flags_the_deviant(self):
        def fn(name: str, ntype: str) -> str:
            return (
                f"int {name}(int *a, {ntype} n)\n"
                "{\n"
                f"    {ntype} i = 0;\n"
                "    int t = 0;\n"
                "    for (i = 0; i < n; i++)\n"
                "        t += a[i];\n"
                "    return t;\n"
                "}\n"
            )
        src = (
            fn("sum_a", "size_t") + fn("sum_b", "size_t")
            + fn("sum_c", "size_t") + fn("sum_d", "int")
        )
        devs, _stats = _detect(src)
        assert [d.kind for d in devs] == [KIND_SIGNEDNESS_MIX]
        assert devs[0].enclosing_function == "sum_d"
        assert devs[0].cwe == "CWE-195"

    def test_unresolved_declarations_never_vote(self):
        # Parameters typed via an unknown alias: no signedness claim.
        def fn(name: str) -> str:
            return (
                f"int {name}(int *a, klen_t n)\n"
                "{\n"
                "    klen_t i = 0;\n"
                "    int t = 0;\n"
                "    for (i = 0; i < n; i++)\n"
                "        t += a[i];\n"
                "    return t;\n"
                "}\n"
            )
        src = "".join(fn(f"sum_{c}") for c in "abcd")
        devs, _stats = _detect(src)
        assert devs == []


class TestMissingNullArm:
    def _guard_fn(self, name: str, cond: str) -> str:
        return (
            f"int {name}(struct pkt *p, int max)\n"
            "{\n"
            f"    if ({cond})\n"
            "        return use(p);\n"
            "    return -1;\n"
            "}\n"
        )

    def test_dropped_null_arm_flags_the_deviant(self):
        src = "".join(
            self._guard_fn(f"h_{c}", "p && p->len < max")
            for c in "abc"
        ) + self._guard_fn("h_d", "p->len < max")
        devs, _stats = _detect(src)
        assert [d.kind for d in devs] == [KIND_MISSING_NULL_ARM]
        d = devs[0]
        assert d.enclosing_function == "h_d"
        assert d.cwe == "CWE-476"
        assert (d.n, d.conforming) == (4, 3)

    def test_uniformly_bare_family_is_clean(self):
        src = "".join(
            self._guard_fn(f"h_{c}", "p->len < max") for c in "abcd"
        )
        devs, _stats = _detect(src)
        assert devs == []


class TestInconclusiveReasons:
    def test_call_bound_is_predicate_data_dependent(self):
        src = "".join(
            _loop_fn(f"sum_{c}", "i < limit(n)") for c in "abc"
        ) + _loop_fn("sum_d", "i <= limit(n)")
        devs, stats = _detect(src)
        assert devs == []
        assert stats["inconclusive_reasons"].get(
            REASON_PREDICATE_DATA_DEPENDENT,
        )

    def test_macro_divergence_is_enumerated(self):
        base = "".join(
            _loop_fn(f"sum_{c}", "i < n") for c in "abc"
        )
        # The deviant's condition carries a macro token its peers'
        # conditions do not.
        deviant = (
            "int sum_d(int *a, int n)\n"
            "{\n"
            "    int i, t = 0;\n"
            "    for (i = 0; SLOW_PATH <= n; i++)\n"
            "        t += a[i];\n"
            "    return t;\n"
            "}\n"
        )
        devs, stats = _detect(base + deviant)
        assert devs == []
        assert stats["inconclusive_reasons"].get(
            REASON_MACRO_DIVERGENT,
        )

    def test_type_divergent_operator_drift_is_enumerated(self):
        def fn(name: str, ntype: str, relop: str) -> str:
            return (
                f"int {name}(int *a, {ntype} n)\n"
                "{\n"
                f"    {ntype} i = 0;\n"
                "    int t = 0;\n"
                f"    for (i = 0; i {relop} n; i++)\n"
                "        t += a[i];\n"
                "    return t;\n"
                "}\n"
            )
        src = (
            fn("sum_a", "size_t", "<") + fn("sum_b", "size_t", "<")
            + fn("sum_c", "size_t", "<") + fn("sum_d", "int", "<=")
        )
        devs, stats = _detect(src)
        assert all(d.kind != KIND_OFF_BY_ONE for d in devs)
        assert stats["inconclusive_reasons"].get(
            REASON_TYPE_CONTEXT_DIFFERS,
        )


class TestExtractionNarrowness:
    def test_compound_loop_conditions_are_skipped(self):
        src = "".join(
            _loop_fn(f"sum_{c}", "i < n && i < m") for c in "abcd"
        )
        devs, stats = _detect(src)
        assert devs == []
        assert stats["sites"] == 0

    def test_shift_operators_never_read_as_comparisons(self):
        src = "".join(
            _loop_fn(f"sum_{c}", "i < (n << 2)") for c in "abcd"
        )
        _devs, stats = _detect(src)
        # `(n << 2)` parses as a bound expression or not at all —
        # never as a `<` comparison against `<`-shifted garbage.
        assert stats["sites"] in (0, 4)

    def test_disjunctive_if_guards_are_skipped(self):
        src = (
            "int h_a(struct pkt *p, int max)\n"
            "{\n"
            "    if (p || p->len < max)\n"
            "        return use(p);\n"
            "    return -1;\n"
            "}\n"
        )
        _devs, stats = _detect(src)
        assert stats["sites"] == 0


class TestHypothesisMatcher:
    def test_predicate_shapes_match(self):
        assert is_guard_predicate_hypothesis(
            "3/4 sibling loops bound i with < n; this uses <= n",
        )
        assert is_guard_predicate_hypothesis(
            "off-by-one against the peer loops' bound",
        )

    def test_return_check_shapes_do_not(self):
        assert not is_guard_predicate_hypothesis(
            "9/10 callers check do_auth()'s return; this discards it",
        )
        assert not is_guard_predicate_hypothesis("")


class TestDeterminism:
    def test_seeded_runs_are_reproducible(self):
        src = "".join(
            _loop_fn(f"sum_{c}", "i < n") for c in "abc"
        ) + _loop_fn("sum_d", "i <= n")
        a = detect_guard_predicate_deviations(
            {"peers.c": src}, seed=b"x",
        )
        b = detect_guard_predicate_deviations(
            {"peers.c": src}, seed=b"x",
        )
        assert [d.to_dict() for d in a[0]] == [
            d.to_dict() for d in b[0]
        ]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
