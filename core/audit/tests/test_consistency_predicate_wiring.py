"""Shared-machinery wiring pins for the guard-predicate,
path-symmetry and boundary/unit dimensions: receipt-map completeness
for the promote-capable rule id, the single-namespace aggregation
firewall (across phases too), floors-registry threading, and one
prepass run exercising all three censuses with per-dimension
telemetry."""

from __future__ import annotations

import pytest

from core.audit.evidence_grade import _RECEIPT_MAP, is_tool_evidence
from core.audit.peer_evidence import is_detection_rule_id, rule_id
from core.testing import requires_ts

NEW_DIMENSIONS = (
    "guard-predicate", "path-symmetry", "boundary-unit",
)

PRIOR_DIMENSIONS = (
    "return-check", "flag-mode", "cleanup", "argument-shape",
    "ordering", "interface", "sanitize-sink", "guard-presence",
    "clone-drift", "enum-switch",
)


class TestDimensionNamePins:
    def test_verdict_and_census_agree_on_the_name(self):
        from core.audit.consistency_verify import (
            DIMENSION_GUARD_PREDICATE as verdict_name,
        )
        from core.audit.guard_predicate import (
            DIMENSION_GUARD_PREDICATE as census_name,
        )
        assert verdict_name == census_name == "guard-predicate"

    def test_rule_ids_construct_and_classify(self):
        for dim in NEW_DIMENSIONS:
            detect = rule_id(dim, detection=True)
            promote = rule_id(dim, detection=False)
            assert detect == f"consistency:{dim}-majority"
            assert is_detection_rule_id(detect)
            assert not is_detection_rule_id(promote)


class TestReceiptMap:
    def test_the_promote_capable_rule_has_a_receipt(self):
        assert "consistency:guard-predicate" in _RECEIPT_MAP

    def test_promote_capable_rule_is_tool_evidence_alone(self):
        assert is_tool_evidence("consistency:guard-predicate")


class TestAggregationFirewall:
    def test_two_consistency_majority_stamps_never_jointly_promote(
        self,
    ):
        for a in NEW_DIMENSIONS:
            for b in NEW_DIMENSIONS + PRIOR_DIMENSIONS:
                stamp = (
                    f"consistency:{a}-majority"
                    f"+consistency:{b}-majority"
                )
                assert not is_tool_evidence(stamp), stamp

    def test_majority_plus_independent_namespace_qualifies(self):
        assert is_tool_evidence(
            "coccinelle+consistency:guard-predicate-majority",
        )
        assert is_tool_evidence(
            "compiler:analyzer+consistency:path-symmetry-majority",
        )


class TestFloorsRegistry:
    def test_new_keys_are_registered_and_overridable(self):
        from core.audit.consistency_stats import floors_registry
        keys = {s.key: s for s in floors_registry()}
        for key in (
            "guard-predicate.min_sites",
            "guard-predicate.ratio",
            "guard-predicate.promote_ratio",
            "path-symmetry.min_pairs",
            "path-symmetry.ratio",
            "boundary-unit.min_sites",
            "boundary-unit.ratio",
        ):
            assert key in keys, key
            assert keys[key].overridable, key

    def test_override_validation_still_strict(self):
        from core.audit.consistency_stats import resolve_floors
        with pytest.raises(ValueError):
            resolve_floors({"guard-predicate.ratio": 2.0})
        floors = resolve_floors({"guard-predicate.min_sites": 5})
        assert floors.value("guard-predicate.min_sites") == 5


def _loop(name: str, cond: str) -> str:
    return (
        f"int {name}(int *a, int n)\n"
        "{\n"
        "    int i, t = 0;\n"
        f"    for (i = 0; {cond}; i++)\n"
        "        t += a[i];\n"
        "    return t;\n"
        "}\n"
    )


def _pair(name: str, checked: bool) -> str:
    guard = "    if (v < 0) return -1;\n" if checked else ""
    return (
        f"int get_{name}(void)\n"
        "{\n"
        f"    return g_{name};\n"
        "}\n"
        f"int set_{name}(int v)\n"
        "{\n"
        f"{guard}"
        f"    g_{name} = v;\n"
        "    return 0;\n"
        "}\n"
    )


def _wait(name: str, value: str) -> str:
    return (
        f"void {name}(void)\n"
        "{\n"
        f"    wait_for(dev, {value});\n"
        "}\n"
    )


FIXTURE = (
    # guard-predicate: 3 strict bounds + 1 inclusive.
    _loop("sum_a", "i < n") + _loop("sum_b", "i < n")
    + _loop("sum_c", "i < n") + _loop("sum_d", "i <= n")
    # boundary-unit: 3 bound at m + 1 at m + 1 (walk_* family so the
    # loop idiom groups apart from the sum_* one).
    + _loop("walk_a", "i < m") + _loop("walk_b", "i < m")
    + _loop("walk_c", "i < m") + _loop("walk_d", "i < m + 1")
    # path-symmetry: 3 checked setters + 1 unchecked.
    + _pair("gain", True) + _pair("rate", True)
    + _pair("mode", True) + _pair("level", False)
    # boundary-unit unit-scale: 3 scaled literals + 1 raw.
    + _wait("job_a", "5000") + _wait("job_b", "10000")
    + _wait("job_c", "30000") + _wait("job_d", "30")
)


@requires_ts("c")
class TestPrepassWiring:
    def _run(self, **kwargs):
        from core.audit.consistency_prepass import (
            run_consistency_prepass,
        )
        return run_consistency_prepass(
            {"src/all.c": FIXTURE}, **kwargs,
        )

    def test_all_three_dimensions_report_telemetry(self):
        result = self._run()
        dims = result["telemetry"]["dimensions"]
        for dim in NEW_DIMENSIONS:
            assert dim in dims, dims
            assert dims[dim]["confirmed"] >= 1, (dim, dims)

    def test_leads_and_mechanical_records_ride_the_namespace(self):
        result = self._run()
        for dim in NEW_DIMENSIONS:
            dim_leads = [
                lead for lead in result["leads"]
                if lead["dimension"] == dim
            ]
            assert dim_leads, dim
            for lead in dim_leads:
                assert lead["rule_id"].startswith("consistency:")
                assert "score" in lead and "formation" in lead
        detectors = {
            rec["detector"] for rec in result["mechanical"]
        }
        assert "guard_predicate_deviation" in detectors
        assert "path_symmetry_deviation" in detectors
        assert "boundary_unit_deviation" in detectors

    def test_floor_overrides_thread_into_the_censuses(self):
        # Raising every new min floor above the fixture families
        # (4 members each) must silence all three dimensions.
        result = self._run(floor_overrides={
            "guard-predicate.min_sites": 9,
            "path-symmetry.min_pairs": 9,
            "boundary-unit.min_sites": 9,
        })
        dims = result["telemetry"]["dimensions"]
        for dim in NEW_DIMENSIONS:
            assert dims.get(dim, {}).get("confirmed", 0) == 0, (
                dim, dims,
            )

    def test_dimension_failure_is_counted_not_fatal(self, monkeypatch):
        import core.audit.path_symmetry as ps

        def boom(*_a, **_k):
            raise RuntimeError("census exploded")

        monkeypatch.setattr(
            ps, "detect_path_symmetry_deviations", boom,
        )
        result = self._run()
        failures = result["telemetry"]["dimension_failures"]
        assert failures.get("path-symmetry") == 1
        # The other censuses still ran.
        dims = result["telemetry"]["dimensions"]
        assert "guard-predicate" in dims
        assert "boundary-unit" in dims


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
