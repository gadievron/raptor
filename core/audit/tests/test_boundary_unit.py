"""Boundary/unit census: bound-expression drift at a fixed operator,
unit-scale drift over literal arguments, the flag-mode hand-off, and
the enumerated inconclusives."""

from __future__ import annotations

import pytest

from core.audit.boundary_unit import (
    DIMENSION_BOUNDARY_UNIT,
    KIND_BOUND_EXPR,
    KIND_UNIT_SCALE,
    REASON_BOUND_DATA_DEPENDENT,
    REASON_SCALE_UNRESOLVED,
    detect_boundary_unit_deviations,
)
from core.testing import requires_ts

pytestmark = requires_ts("c")


def _loop_fn(name: str, bound: str) -> str:
    return (
        f"int {name}(int *a, int n)\n"
        "{\n"
        "    int i, t = 0;\n"
        f"    for (i = 0; i < {bound}; i++)\n"
        "        t += a[i];\n"
        "    return t;\n"
        "}\n"
    )


def _detect(src: str, **kwargs):
    return detect_boundary_unit_deviations(
        {"peers.c": src}, seed=b"pin", **kwargs,
    )


class TestBoundExpression:
    def test_shifted_bound_flags_the_deviant(self):
        src = "".join(
            _loop_fn(f"sum_{c}", "n") for c in "abc"
        ) + _loop_fn("sum_d", "n + 1")
        devs, stats = _detect(src)
        assert [d.kind for d in devs] == [KIND_BOUND_EXPR]
        d = devs[0]
        assert d.enclosing_function == "sum_d"
        assert d.cwe == "CWE-193"
        assert (d.n, d.conforming) == (4, 3)
        assert "n + 1" in d.deviant_repr
        pe = d.peer_evidence
        assert pe is not None
        assert pe.dimension == DIMENSION_BOUNDARY_UNIT
        assert pe.rule_id == "consistency:boundary-unit-majority"
        assert stats["bound_ops"] > 0

    def test_non_adjacent_bound_is_generic_calculation(self):
        src = "".join(
            _loop_fn(f"sum_{c}", "n") for c in "abc"
        ) + _loop_fn("sum_d", "m")
        devs, _stats = _detect(src)
        assert [d.cwe for d in devs] == ["CWE-682"]

    def test_uniform_bounds_are_clean(self):
        src = "".join(_loop_fn(f"sum_{c}", "n") for c in "abcd")
        devs, _stats = _detect(src)
        assert devs == []

    def test_operator_drift_is_not_this_census(self):
        # A flipped operator moves the site into a different idiom
        # group — the guard-predicate census owns that axis.
        src = "".join(
            _loop_fn(f"sum_{c}", "n") for c in "abc"
        ) + (
            "int sum_d(int *a, int n)\n"
            "{\n"
            "    int i, t = 0;\n"
            "    for (i = 0; i <= n; i++)\n"
            "        t += a[i];\n"
            "    return t;\n"
            "}\n"
        )
        devs, _stats = _detect(src)
        assert devs == []

    def test_call_bounds_are_enumerated(self):
        src = "".join(
            _loop_fn(f"sum_{c}", "limit(n)") for c in "abc"
        ) + _loop_fn("sum_d", "limit(n) - 1")
        devs, stats = _detect(src)
        assert devs == []
        assert stats["inconclusive_reasons"].get(
            REASON_BOUND_DATA_DEPENDENT,
        )


def _timeout_fn(name: str, value: str) -> str:
    return (
        f"void {name}(void)\n"
        "{\n"
        f"    wait_for(dev, {value});\n"
        "}\n"
    )


class TestUnitScale:
    def test_raw_literal_among_scaled_peers_flags(self):
        src = (
            _timeout_fn("job_a", "5000")
            + _timeout_fn("job_b", "10000")
            + _timeout_fn("job_c", "30000")
            + _timeout_fn("job_d", "30")
        )
        devs, _stats = _detect(src)
        assert [d.kind for d in devs] == [KIND_UNIT_SCALE]
        d = devs[0]
        assert d.enclosing_function == "job_d"
        assert d.cwe == "CWE-682"
        assert "raw" in d.deviant_repr

    def test_exact_value_majority_stays_with_flag_mode(self):
        src = (
            _timeout_fn("job_a", "5000")
            + _timeout_fn("job_b", "5000")
            + _timeout_fn("job_c", "5000")
            + _timeout_fn("job_d", "30")
        )
        devs, _stats = _detect(src)
        assert devs == []

    def test_uniform_scale_is_clean(self):
        src = (
            _timeout_fn("job_a", "5000")
            + _timeout_fn("job_b", "10000")
            + _timeout_fn("job_c", "30000")
            + _timeout_fn("job_d", "60000")
        )
        devs, _stats = _detect(src)
        assert devs == []

    def test_non_literal_arguments_are_enumerated(self):
        src = (
            _timeout_fn("job_a", "5000")
            + _timeout_fn("job_b", "10000")
            + _timeout_fn("job_c", "30000")
            + _timeout_fn("job_d", "30")
            + _timeout_fn("job_e", "cfg->timeout")
        )
        _devs, stats = _detect(src)
        assert stats["inconclusive_reasons"].get(
            REASON_SCALE_UNRESOLVED,
        )


class TestDeterminism:
    def test_seeded_runs_are_reproducible(self):
        src = "".join(
            _loop_fn(f"sum_{c}", "n") for c in "abc"
        ) + _loop_fn("sum_d", "n + 1")
        a = _detect(src)
        b = _detect(src)
        assert [d.to_dict() for d in a[0]] == [
            d.to_dict() for d in b[0]
        ]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
