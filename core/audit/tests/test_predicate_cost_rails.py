"""Load-bearing cost-rail pins for the guard-predicate, path-symmetry
and boundary/unit censuses.

Every rail is revert-probed: each pin monkeypatches the rail's bound
low enough that the rail MUST bind on the fixture, then asserts the
observable effect (the stats counter, the caps_hit marker, the
excluded vote) — deleting the rail's check fails its pin instead of
leaving a vacuously-green assertion.  The seeded-survivor pins hold
the anti-eviction property: a deviant in the last-sorting file must
still be found across seeded trials (deterministic first-N admission
scores zero and fails them)."""

from __future__ import annotations

import pytest

import core.audit.boundary_unit as bu
import core.audit.guard_predicate as gp
import core.audit.path_symmetry as ps
from core.testing import requires_ts

pytestmark = requires_ts("c")


def _loop(name: str, base: str, cond: str) -> str:
    return (
        f"int {name}(int *{base}, int n)\n"
        "{\n"
        "    int i, t = 0;\n"
        f"    for (i = 0; {cond}; i++)\n"
        f"        t += {base}[i];\n"
        "    return t;\n"
        "}\n"
    )


def _assert_deviant_last(
    texts: dict[str, str], deviant_file: str = "zz.c",
) -> dict[str, str]:
    """Placement guard: the anti-eviction pins are load-bearing only
    while the deviant's file sorts LAST (a first-N cut in file order
    must be ABLE to miss it) — a fixture rename that broke the sort
    would leave those pins vacuously green."""
    assert max(texts) == deviant_file
    return texts


def _loop_texts(
    n_conforming: int, deviant_cond: str | None,
    base: str = "arr",
) -> dict[str, str]:
    """One loop group spread over sorted files, the deviant LAST."""
    texts: dict[str, str] = {}
    for i in range(n_conforming):
        texts[f"a{i:02d}.c"] = _loop(f"ok_{i}", base, "i < n")
    if deviant_cond is not None:
        texts["zz.c"] = _loop("dev_fn", base, deviant_cond)
        _assert_deviant_last(texts)
    return texts


class TestGuardPredicateRails:
    def test_group_cap_binds_and_is_marked(self, monkeypatch):
        monkeypatch.setattr(gp, "MAX_PREDICATE_GROUPS", 2)
        texts = {}
        for g in range(4):
            for i in range(3):
                texts[f"g{g}f{i}.c"] = _loop(
                    f"fn_{g}_{i}", f"arr{g}", "i < n",
                )
        devs, stats = gp.detect_guard_predicate_deviations(
            texts, seed=b"pin",
        )
        assert stats["caps_hit"] is True
        assert stats["groups"] == 2
        assert devs == []

    def test_ops_budget_excludes_groups_loudly(self, monkeypatch):
        monkeypatch.setattr(gp, "MAX_PREDICATE_OPS", 8)
        texts = _loop_texts(3, "i <= n")
        devs, stats = gp.detect_guard_predicate_deviations(
            texts, seed=b"pin",
        )
        # 4 members cost 16 vote steps > 8: the group is EXCLUDED
        # (census-degraded), never half-voted into a deviation.
        assert devs == []
        assert stats["caps_hit"] is True
        assert stats["inconclusive_reasons"].get(
            gp.REASON_CENSUS_DEGRADED,
        )

    def test_ops_counter_is_observable_and_grows(self):
        small = gp.detect_guard_predicate_deviations(
            _loop_texts(3, "i <= n"), seed=b"pin",
        )[1]
        large = gp.detect_guard_predicate_deviations(
            _loop_texts(9, "i <= n"), seed=b"pin",
        )[1]
        assert small["predicate_ops"] > 0
        assert large["predicate_ops"] > small["predicate_ops"]

    def test_member_cap_samples_and_discloses(self, monkeypatch):
        monkeypatch.setattr(gp, "MAX_SITES_PER_GROUP", 4)
        texts = _loop_texts(9, "i <= n")
        found_disclosure = False
        for trial in range(30):
            devs, stats = gp.detect_guard_predicate_deviations(
                texts, seed=bytes([trial]),
            )
            assert stats["caps_hit"] is True
            for d in devs:
                assert d.sampled_from == 10
                assert d.n == 4
                assert "seeded sample" in d.description
                found_disclosure = True
        assert found_disclosure

    def test_survivor_sampling_is_seeded_not_first_n(
        self, monkeypatch,
    ):
        # The deviant lives in the LAST-sorting file; with a member
        # cap of 4 over 10 members, deterministic first-N admission
        # in file order would keep only conforming decoys and NEVER
        # find it.  Seeded-random survivors find it across trials.
        monkeypatch.setattr(gp, "MAX_SITES_PER_GROUP", 4)
        texts = _loop_texts(9, "i <= n")
        detections = 0
        for trial in range(30):
            devs, _stats = gp.detect_guard_predicate_deviations(
                texts, seed=bytes([trial]),
            )
            if any(
                d.enclosing_function == "dev_fn" for d in devs
            ):
                detections += 1
        assert detections > 0

    def test_deviation_cap_binds(self, monkeypatch):
        monkeypatch.setattr(gp, "MAX_DEVIATIONS", 1)
        texts = _loop_texts(3, "i <= n")
        texts.update({
            f"b{i:02d}.c": _loop(f"okb_{i}", "brr", "i < n")
            for i in range(3)
        })
        texts["zy.c"] = _loop("dev_fn_b", "brr", "i <= n")
        devs, stats = gp.detect_guard_predicate_deviations(
            texts, seed=b"pin",
        )
        assert len(devs) == 1
        assert stats["caps_hit"] is True


def _pair_src(stem: str, checked: bool) -> str:
    guard = "    if (v < 0) return -1;\n" if checked else ""
    return (
        f"int get_{stem}(void)\n"
        "{\n"
        f"    return g_{stem};\n"
        "}\n"
        f"int set_{stem}(int v)\n"
        "{\n"
        f"{guard}"
        f"    g_{stem} = v;\n"
        "    return 0;\n"
        "}\n"
    )


def _pair_texts(n_conforming: int, deviant: bool) -> dict[str, str]:
    texts = {
        f"p{i:02d}.c": _pair_src(f"s{i:02d}", True)
        for i in range(n_conforming)
    }
    if deviant:
        texts["zz.c"] = _pair_src("zzdev", False)
        _assert_deviant_last(texts)
        # The pair census orders by STEM: the deviant stem must also
        # sort last for the anti-eviction pin to bite.
        assert all(f"s{i:02d}" < "zzdev" for i in range(n_conforming))
    return texts


class TestPathSymmetryRails:
    def test_vote_budget_excludes_cohorts_loudly(self, monkeypatch):
        monkeypatch.setattr(ps, "MAX_VOTE_OPS", 4)
        devs, stats = ps.detect_path_symmetry_deviations(
            _pair_texts(3, True), seed=b"pin",
        )
        assert devs == []
        assert stats["caps_hit"] is True
        assert stats["families"] == 0

    def test_ops_counter_is_observable_and_grows(self):
        small = ps.detect_path_symmetry_deviations(
            _pair_texts(3, True), seed=b"pin",
        )[1]
        large = ps.detect_path_symmetry_deviations(
            _pair_texts(9, True), seed=b"pin",
        )[1]
        assert small["vote_ops"] > 0
        assert large["vote_ops"] > small["vote_ops"]

    def test_pair_cap_samples_and_discloses(self, monkeypatch):
        monkeypatch.setattr(ps, "MAX_PAIRS_PER_FAMILY", 4)
        texts = _pair_texts(9, True)
        found = False
        for trial in range(30):
            devs, stats = ps.detect_path_symmetry_deviations(
                texts, seed=bytes([trial]),
            )
            assert stats["caps_hit"] is True
            for d in devs:
                assert d.sampled_from == 10
                assert d.n == 4
                found = True
        assert found

    def test_survivor_sampling_is_seeded_not_first_n(
        self, monkeypatch,
    ):
        # The deviant pair's stem sorts LAST; first-N admission in
        # stem order would keep only conforming decoys.
        monkeypatch.setattr(ps, "MAX_PAIRS_PER_FAMILY", 4)
        texts = _pair_texts(9, True)
        detections = 0
        for trial in range(30):
            devs, _stats = ps.detect_path_symmetry_deviations(
                texts, seed=bytes([trial]),
            )
            if any(
                d.enclosing_function == "set_zzdev" for d in devs
            ):
                detections += 1
        assert detections > 0


def _wait_texts(values: list[str]) -> dict[str, str]:
    return {
        f"w{i:02d}.c": (
            f"void job_{i}(void)\n"
            "{\n"
            f"    wait_for(dev, {v});\n"
            "}\n"
        )
        for i, v in enumerate(values)
    }


class TestBoundaryUnitRails:
    def test_group_cap_binds(self, monkeypatch):
        monkeypatch.setattr(bu, "MAX_BOUND_GROUPS", 1)
        texts = {}
        for g in range(3):
            for i in range(3):
                texts[f"g{g}f{i}.c"] = _loop(
                    f"fn_{g}_{i}", f"arr{g}", "i < n",
                )
        _devs, stats = bu.detect_boundary_unit_deviations(
            texts, seed=b"pin",
        )
        assert stats["caps_hit"] is True
        assert stats["groups"] == 1

    def test_ops_budget_excludes_groups_loudly(self, monkeypatch):
        monkeypatch.setattr(bu, "MAX_BOUND_OPS", 2)
        texts = _loop_texts(3, None)
        texts["zz.c"] = _loop("dev_fn", "arr", "i < m")
        devs, stats = bu.detect_boundary_unit_deviations(
            texts, seed=b"pin",
        )
        assert devs == []
        assert stats["caps_hit"] is True

    def test_ops_counter_is_observable_and_grows(self):
        small = bu.detect_boundary_unit_deviations(
            _wait_texts(["5000", "10000", "30000", "30"]),
            seed=b"pin",
        )[1]
        large = bu.detect_boundary_unit_deviations(
            _wait_texts(
                ["5000", "10000", "30000", "15000", "20000",
                 "25000", "35000", "40000", "45000", "30"],
            ),
            seed=b"pin",
        )[1]
        assert small["bound_ops"] > 0
        assert large["bound_ops"] > small["bound_ops"]

    def test_member_cap_samples_and_discloses(self, monkeypatch):
        monkeypatch.setattr(bu, "MAX_SITES_PER_GROUP", 4)
        texts = _loop_texts(9, None)
        texts["zz.c"] = _loop("dev_fn", "arr", "i < m")
        _assert_deviant_last(texts)
        found = False
        for trial in range(30):
            devs, stats = bu.detect_boundary_unit_deviations(
                texts, seed=bytes([trial]),
            )
            assert stats["caps_hit"] is True
            for d in devs:
                assert d.sampled_from == 10
                assert d.n == 4
                found = True
        assert found

    def test_survivor_sampling_is_seeded_not_first_n(
        self, monkeypatch,
    ):
        monkeypatch.setattr(bu, "MAX_SITES_PER_GROUP", 4)
        texts = _loop_texts(9, None)
        texts["zz.c"] = _loop("dev_fn", "arr", "i < m")
        _assert_deviant_last(texts)
        detections = 0
        for trial in range(30):
            devs, _stats = bu.detect_boundary_unit_deviations(
                texts, seed=bytes([trial]),
            )
            if any(
                d.enclosing_function == "dev_fn" for d in devs
            ):
                detections += 1
        assert detections > 0

    def test_deviation_cap_binds(self, monkeypatch):
        monkeypatch.setattr(bu, "MAX_DEVIATIONS", 1)
        texts = _loop_texts(3, None)
        texts["zz.c"] = _loop("dev_fn", "arr", "i < m")
        for i in range(3):
            texts[f"b{i:02d}.c"] = _loop(f"okb_{i}", "brr", "i < n")
        texts["zy.c"] = _loop("dev_fn_b", "brr", "i < m")
        devs, stats = bu.detect_boundary_unit_deviations(
            texts, seed=b"pin",
        )
        assert len(devs) == 1
        assert stats["caps_hit"] is True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
