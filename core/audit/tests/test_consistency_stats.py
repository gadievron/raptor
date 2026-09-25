"""Tests for the consistency stats module: lead-strength score,
stratified sort key, and the per-dimension floors registry."""

from __future__ import annotations

import json

import pytest

from core.audit.consistency_stats import (
    _VALID_KINDS,
    KIND_MIN_SITES,
    KIND_MIN_TOKENS,
    KIND_RATIO,
    RUN_CONFIG_FLOORS_KEY,
    default_floors,
    floor_overrides_from_run_config,
    floors_registry,
    floors_table,
    lead_strength_score,
    lead_stratum,
    resolve_floors,
    stratified_lead_sort_key,
)
from core.dataflow.sanitizer_cut_parity import wilson_interval


class TestLeadStrengthScore:
    def test_is_the_canonical_wilson_lower_bound(self):
        # Anti-drift fence: the score IS wilson_interval's lower
        # bound — no third Wilson implementation may creep in.
        for conforming, n in ((9, 10), (3, 4), (18, 20), (1, 3)):
            assert lead_strength_score(conforming, n) == \
                wilson_interval(conforming, n)[0]

    def test_bounds(self):
        assert lead_strength_score(0, 0) == 0.0
        assert lead_strength_score(5, 0) == 0.0
        assert lead_strength_score(0, 10) == 0.0
        assert 0.0 < lead_strength_score(10, 10) < 1.0

    def test_shrinkage_below_the_ratio(self):
        # The whole point: the score sits BELOW the raw ratio, and
        # further below for smaller families.
        assert lead_strength_score(9, 10) < 0.9
        assert lead_strength_score(3, 4) < 0.75

    def test_monotone_in_family_size_at_fixed_ratio(self):
        # 3/4 < 9/12 < 30/40 < 300/400 in score, all ratio 0.75.
        scores = [
            lead_strength_score(c, n)
            for c, n in ((3, 4), (9, 12), (30, 40), (300, 400))
        ]
        assert scores == sorted(scores)
        assert len(set(scores)) == len(scores)

    def test_monotone_in_conforming_at_fixed_n(self):
        scores = [lead_strength_score(c, 20) for c in range(21)]
        assert scores == sorted(scores)

    def test_malformed_receipt_clamped(self):
        # conforming > n never scores above the well-formed maximum.
        assert lead_strength_score(15, 10) == lead_strength_score(10, 10)
        assert lead_strength_score(-3, 10) == 0.0


class TestStratifiedSortKey:
    @staticmethod
    def _lead(**kw):
        base = {
            "dimension": "return-check",
            "formation": "same_callee",
            "contract_source": "majority",
            "security_relevant": True,
            "ratio": 0.9,
            "score": 0.8,
            "file": "a.c",
            "line": 1,
        }
        base.update(kw)
        return base

    def test_chain_dominates_score(self):
        # A higher ratio always beats a higher score.
        hi_ratio = self._lead(ratio=0.95, score=0.5)
        hi_score = self._lead(ratio=0.9, score=0.99)
        ranked = sorted([hi_score, hi_ratio],
                        key=stratified_lead_sort_key)
        assert ranked[0] is hi_ratio

    def test_contract_and_security_precede_ratio(self):
        registry = self._lead(contract_source="wur", ratio=0.5)
        majority = self._lead(ratio=1.0, score=1.0)
        assert sorted(
            [majority, registry], key=stratified_lead_sort_key,
        )[0] is registry
        insecure = self._lead(security_relevant=False, ratio=1.0)
        secure = self._lead(ratio=0.5)
        assert sorted(
            [insecure, secure], key=stratified_lead_sort_key,
        )[0] is secure

    def test_score_orders_within_a_stratum(self):
        small = self._lead(score=lead_strength_score(9, 10),
                           file="z.c")
        large = self._lead(score=lead_strength_score(18, 20),
                           file="a.c")
        # Same stratum, same chain values: the larger family wins
        # despite the later file name.
        ranked = sorted([small, large], key=stratified_lead_sort_key)
        assert ranked[0] is large

    def test_strata_never_interleave_by_score(self):
        # Cross-stratum tie on the chain: ordered by stratum id, and
        # the LOWER-score lead in the earlier stratum still precedes
        # the higher-score lead in the later one.
        early_stratum_low_score = self._lead(
            dimension="flag-mode", score=0.1, file="z.c",
        )
        late_stratum_high_score = self._lead(
            dimension="return-check", score=0.99, file="a.c",
        )
        ranked = sorted(
            [late_stratum_high_score, early_stratum_low_score],
            key=stratified_lead_sort_key,
        )
        assert ranked[0] is early_stratum_low_score

    def test_file_line_tail_still_deterministic(self):
        a = self._lead(file="a.c", line=5)
        b = self._lead(file="a.c", line=9)
        assert sorted([b, a], key=stratified_lead_sort_key)[0] is a

    def test_stratum_helper(self):
        assert lead_stratum(self._lead()) == \
            ("return-check", "same_callee")
        assert lead_stratum({}) == ("", "")


class TestFloorsRegistry:
    def test_keys_unique_and_well_formed(self):
        keys = [s.key for s in floors_registry()]
        assert len(keys) == len(set(keys))
        for s in floors_registry():
            assert s.key == f"{s.dimension}.{s.name}"
            assert s.kind in _VALID_KINDS
            assert s.consumer

    def test_defaults_match_the_live_constants(self):
        # Sibling-drift fence: the registry references the inline
        # constants; a constant edit that misses the registry (or
        # vice versa) fails here.
        from core.audit import callsite_consistency as cc
        from core.audit import clone_drift as clone
        from core.audit import consistency_dimensions as cd
        from core.audit import consistency_verify as cv
        expected = {
            "return-check.lead_min_sites": cc.MIN_CALL_SITES,
            "return-check.lead_majority_threshold":
                cc.MAJORITY_THRESHOLD,
            "return-check.contract_min_sites":
                cc.MAJORITY_CONTRACT_MIN_SITES,
            "return-check.contract_ratio": cc.MAJORITY_CONTRACT_RATIO,
            "return-check.verdict_min_sites": cv.VERDICT_MIN_SITES,
            "return-check.verdict_majority_ratio":
                cv.VERDICT_MAJORITY_RATIO,
            "flag-mode.min_sites": cd.MIN_GROUP_SITES,
            "flag-mode.ratio": cd.CONSISTENCY_RATIO,
            "cleanup.min_group": cd.MIN_GROUP_SITES,
            "cleanup.ratio": cd.CONSISTENCY_RATIO,
            "argument-shape.min_sites": cd.ARGSHAPE_MIN_SITES,
            "argument-shape.ratio": cd.ARGSHAPE_RATIO,
            "interface.min_group": cd.INTERFACE_MIN_GROUP,
            "interface.ratio": cd.CONSISTENCY_RATIO,
            "ordering.min_group": cd.ORDERING_MIN_GROUP,
            "ordering.ratio": cd.CONSISTENCY_RATIO,
            "sanitize-sink.min_sites": cd.MIN_GROUP_SITES,
            "sanitize-sink.ratio": cd.CONSISTENCY_RATIO,
            "sanitize-sink.promote_ratio": cd.RATIO_PROMOTE,
            "guard-presence.min_sites": cd.MIN_GROUP_SITES,
            "guard-presence.ratio": cd.CONSISTENCY_RATIO,
            "guard-presence.promote_ratio": cd.RATIO_PROMOTE,
            "clone-drift.similarity": clone.CLONE_SIMILARITY,
            "clone-drift.fix_anchor_similarity":
                clone.FIX_ANCHOR_SIMILARITY,
            "clone-drift.min_clone_tokens": clone.MIN_CLONE_TOKENS,
        }
        actual = {s.key: s.default for s in floors_registry()}
        assert actual == expected

    def test_kind_contracts_hold_for_every_default(self):
        for s in floors_registry():
            if s.kind == KIND_RATIO:
                assert 0.0 < float(s.default) <= 1.0, s.key
            else:
                assert s.kind in (KIND_MIN_SITES, KIND_MIN_TOKENS)
                assert isinstance(s.default, int), s.key
                assert s.default >= 1, s.key

    def test_table_enumerates_every_spec(self):
        table = floors_table()
        assert {row["key"] for row in table} == \
            {s.key for s in floors_registry()}
        for row in table:
            assert set(row) == {
                "key", "dimension", "name", "default", "kind",
                "overridable", "consumer",
            }


class TestResolveFloors:
    def test_defaults(self):
        floors = resolve_floors(None)
        assert floors.overridden() == {}
        for s in floors_registry():
            assert floors.value(s.key) == s.default

    def test_default_floors_shared_instance(self):
        assert default_floors() is default_floors()
        assert default_floors().overridden() == {}

    def test_override_applies(self):
        floors = resolve_floors(
            {"return-check.verdict_min_sites": 6},
        )
        assert floors.value("return-check.verdict_min_sites") == 6
        assert floors.overridden() == {
            "return-check.verdict_min_sites": 6,
        }
        # Everything else stays at default.
        assert floors.value("return-check.verdict_majority_ratio") == \
            default_floors().value("return-check.verdict_majority_ratio")

    def test_unknown_key_refused(self):
        with pytest.raises(ValueError, match="unknown consistency floor"):
            resolve_floors({"return-check.nope": 3})

    def test_non_overridable_key_refused(self):
        with pytest.raises(ValueError, match="not run-overridable"):
            resolve_floors({"clone-drift.similarity": 0.5})

    def test_min_sites_rejects_bool_float_and_zero(self):
        for bad in (True, 3.5, 0, -1):
            with pytest.raises(ValueError):
                resolve_floors(
                    {"return-check.verdict_min_sites": bad},
                )

    def test_ratio_rejects_out_of_range_and_non_numeric(self):
        for bad in (0.0, -0.1, 1.5, "0.9", None, True):
            with pytest.raises(ValueError):
                resolve_floors(
                    {"return-check.verdict_majority_ratio": bad},
                )

    def test_ratio_accepts_one(self):
        floors = resolve_floors(
            {"return-check.verdict_majority_ratio": 1},
        )
        assert floors.value("return-check.verdict_majority_ratio") == 1.0

    def test_unregistered_key_lookup_raises(self):
        with pytest.raises(KeyError):
            default_floors().value("no-such.threshold")


class TestRunConfigChannel:
    def test_reads_consistency_floors_key(self, tmp_path):
        cfg = {
            "version": 1,
            RUN_CONFIG_FLOORS_KEY: {
                "return-check.verdict_min_sites": 5,
            },
        }
        (tmp_path / "audit-run-config.json").write_text(
            json.dumps(cfg),
        )
        assert floor_overrides_from_run_config(tmp_path) == {
            "return-check.verdict_min_sites": 5,
        }

    def test_absent_file_and_absent_key_mean_no_overrides(self, tmp_path):
        assert floor_overrides_from_run_config(tmp_path) == {}
        (tmp_path / "audit-run-config.json").write_text(
            json.dumps({"version": 1}),
        )
        assert floor_overrides_from_run_config(tmp_path) == {}

    def test_non_dict_value_means_no_overrides(self, tmp_path):
        (tmp_path / "audit-run-config.json").write_text(
            json.dumps({RUN_CONFIG_FLOORS_KEY: [1, 2]}),
        )
        assert floor_overrides_from_run_config(tmp_path) == {}
