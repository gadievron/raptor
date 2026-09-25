"""Tests for the enum×switch completeness census.

Pins the census's join rules (definition merge, ambiguity refusals),
the majority vote and its enumerated inconclusive reasons, the
detection-grade receipt discipline, the L8 cohort producer and
resolver layer, and the cost rails (per-family caps, run-level
presence-ops budget — both directions, flood shapes included).
"""

from __future__ import annotations

import pytest

try:
    import tree_sitter  # noqa: F401
    _HAS_TS = True
except ImportError:
    _HAS_TS = False
pytestmark = pytest.mark.skipif(
    not _HAS_TS, reason="tree-sitter not installed",
)

from core.audit.enum_switch import (  # noqa: E402
    DIMENSION_ENUM_SWITCH,
    MAX_PRESENCE_OPS,
    MAX_SWITCHES_PER_ENUM,
    detect_enum_switch_deviations,
    enum_switch_cohorts,
)
from core.audit.peer_evidence import is_detection_rule_id  # noqa: E402
from core.testing.treesitter import requires_ts  # noqa: E402

_ENUM = """\
enum pkt_kind { PKT_DATA, PKT_ACK, PKT_RESET };
"""


def _switch(fn: str, labels: list[str], *, default: bool = False) -> str:
    arms = "\n".join(
        f"    case {label}: return {i};"
        for i, label in enumerate(labels)
    )
    if default:
        arms += "\n    default: return -1;"
    return (
        f"int {fn}(enum pkt_kind k) {{\n"
        f"    switch (k) {{\n{arms}\n    }}\n"
        f"    return 0;\n}}\n"
    )


ALL = ["PKT_DATA", "PKT_ACK", "PKT_RESET"]


def _sources(*fn_labels, default_for=()):
    body = _ENUM + "\n".join(
        _switch(fn, labels, default=fn in default_for)
        for fn, labels in fn_labels
    )
    return {"pkt.c": body}


class TestCensus:
    @requires_ts("c")
    def test_missing_member_flags_the_deviant(self):
        sources = _sources(
            ("h_a", ALL), ("h_b", ALL), ("h_c", ALL),
            ("h_d", ["PKT_DATA", "PKT_ACK"]),
        )
        devs, stats = detect_enum_switch_deviations(sources)
        assert len(devs) == 1
        dev = devs[0]
        assert dev.missing_member == "PKT_RESET"
        assert dev.enclosing_function == "h_d"
        assert dev.n == 4 and dev.conforming == 3
        assert dev.cwe == "CWE-478"
        assert stats["families"] == 1
        # Detection-grade under the single consistency namespace.
        assert dev.peer_evidence is not None
        assert is_detection_rule_id(dev.peer_evidence.rule_id)
        assert dev.peer_evidence.rule_id == (
            f"consistency:{DIMENSION_ENUM_SWITCH}-majority"
        )
        assert dev.peer_evidence.contract_source == "majority"

    @requires_ts("c")
    def test_default_arm_is_enumerated_inconclusive(self):
        sources = _sources(
            ("h_a", ALL), ("h_b", ALL), ("h_c", ALL),
            ("h_d", ["PKT_DATA", "PKT_ACK"]),
            default_for=("h_d",),
        )
        devs, stats = detect_enum_switch_deviations(sources)
        assert devs == []
        reasons = stats["inconclusive_reasons"]
        assert reasons.get("non_exhaustive_idiom_default") == 1

    @requires_ts("c")
    def test_uniformly_missing_member_is_not_a_lead(self):
        # No peer handles PKT_RESET: no majority, no deviant — the
        # all-weak case belongs to uniform-absence/P8, never here.
        partial = ["PKT_DATA", "PKT_ACK"]
        sources = _sources(
            ("h_a", partial), ("h_b", partial), ("h_c", partial),
        )
        devs, stats = detect_enum_switch_deviations(sources)
        assert devs == []
        assert stats["inconclusive_reasons"].get(
            "uniformly_missing_member") == 1

    @requires_ts("c")
    def test_below_ratio_majority_stays_silent(self):
        sources = _sources(
            ("h_a", ALL), ("h_b", ALL),
            ("h_c", ["PKT_DATA", "PKT_ACK"]),
            ("h_d", ["PKT_DATA", "PKT_ACK"]),
        )
        devs, _stats = detect_enum_switch_deviations(sources)
        assert devs == []

    @requires_ts("c")
    def test_below_min_group_no_family(self):
        sources = _sources(("h_a", ALL), ("h_b", ["PKT_DATA",
                                                  "PKT_ACK"]))
        devs, stats = detect_enum_switch_deviations(sources)
        assert devs == []
        assert stats["families"] == 0

    @requires_ts("c")
    def test_conflicting_definitions_refused(self):
        sources = {
            "a.c": "enum k { A_ONE, A_TWO };\n" + _switch(
                "f1", ["A_ONE", "A_TWO"]),
            "b.c": "enum k { A_ONE, A_TWO, A_THREE };\n" + _switch(
                "f2", ["A_ONE", "A_TWO"]),
            "c.c": _switch("f3", ["A_ONE", "A_TWO"]),
            "d.c": _switch("f4", ["A_ONE"] + ["A_TWO"]),
        }
        devs, stats = detect_enum_switch_deviations(sources)
        assert devs == []
        assert stats["inconclusive_reasons"].get(
            "definition_ambiguous") == 1

    @requires_ts("c")
    def test_ambiguous_switch_labels_join_nothing(self):
        # Labels present in both enums: joining either is a guess.
        sources = {"amb.c": (
            "enum e1 { COMMON_A, COMMON_B };\n"
            "enum e2 { COMMON_A, COMMON_B };\n"
            + _switch("f1", ["COMMON_A", "COMMON_B"])
        )}
        devs, stats = detect_enum_switch_deviations(sources)
        assert devs == []
        assert stats["inconclusive_reasons"].get("enum_ambiguous") == 1

    @requires_ts("c")
    def test_capped_definition_never_mints_absence_claims(self):
        from core.audit.ts_extract import MAX_ENUM_MEMBERS

        members = ", ".join(
            f"M_{i:04d}" for i in range(MAX_ENUM_MEMBERS + 5)
        )
        handled = [f"M_{i:04d}" for i in range(3)]
        sources = {"flood.c": (
            f"enum flood {{ {members} }};\n"
            + _switch("f1", handled)
            + _switch("f2", handled)
            + _switch("f3", handled)
            + _switch("f4", handled[:2])
        )}
        devs, stats = detect_enum_switch_deviations(sources)
        assert devs == []
        assert stats["inconclusive_reasons"].get(
            "census_degraded") == 1


def _eviction_shape(n_decoys: int) -> dict[str, str]:
    """The reviewer's decoy-eviction corpus: *n_decoys* conforming
    switches in an early-sorting file, the real family (2 conforming
    + 1 deviant) in a late-sorting file."""
    members = ["E0_M%d" % m for m in range(8)]

    def sw(fn, skip=None):
        arms = "\n".join(
            f"    case {la}: return 1;"
            for la in members if la != skip
        )
        return (f"int {fn}(enum en0 v) {{\n    switch (v) {{\n"
                f"{arms}\n    }}\n    return 0;\n}}\n")

    enum = "enum en0 { " + ", ".join(members) + " };\n"
    return {
        "aa_decoys.c": enum + "".join(
            sw(f"dcy{s}") for s in range(n_decoys)
        ),
        "zz_real.c": (
            sw("real_conf_a") + sw("real_conf_b")
            + sw("real_deviant", skip="E0_M7")
        ),
    }


def _deviant_flagged(sources, seed):
    devs, stats = detect_enum_switch_deviations(sources, seed=seed)
    assert stats["caps_hit"] is True
    return any(
        d.enclosing_function == "real_deviant" for d in devs
    )


class TestSwitchCapEviction:
    """The per-enum cap keeps seeded-random survivors, never a
    deterministic prefix: with a first-N cut in sorted-file order,
    conforming decoys in an early-sorting file evicted the real
    deviant with certainty (zero deviations, caps_hit the only
    trace). These pins hold the sampling in both directions."""

    @requires_ts("c")
    def test_seeded_survivor_keeps_the_deviant(self):
        # 400 switches, cap 200: this seed's sample includes the
        # deviant, so the lead fires despite 397 early decoys —
        # under a deterministic prefix it NEVER fires (revert-probe
        # direction A).
        sources = _eviction_shape(397)
        assert _deviant_flagged(sources, b"trial-0") is True

    @requires_ts("c")
    def test_seeded_survivor_can_also_evict(self):
        # Direction B: sampling is genuinely uniform, not rigged to
        # keep deviants — this seed's sample misses it (caps_hit is
        # the in-band trace).
        sources = _eviction_shape(397)
        assert _deviant_flagged(sources, b"trial-3") is False

    @requires_ts("c")
    def test_survival_rate_matches_the_sample_math(self):
        # 400 switches, sample 200: P(deviant kept) = 0.5. Over 30
        # seeded trials the survivor count must sit inside [3, 27]
        # (two-sided binomial tail ~1e-6 — a deterministic prefix
        # scores 0/30 and fails direction A; keep-the-deviant
        # rigging scores 30/30 and fails direction B).
        sources = _eviction_shape(397)
        survived = sum(
            _deviant_flagged(sources, f"trial-{i}".encode())
            for i in range(30)
        )
        assert 3 <= survived <= 27, survived


class TestCostRails:
    @requires_ts("c")
    def test_switch_flood_is_capped_in_band(self):
        n = MAX_SWITCHES_PER_ENUM + 10
        sources = {"flood.c": _ENUM + "".join(
            _switch(f"h_{i:04d}", ALL) for i in range(n)
        )}
        devs, stats = detect_enum_switch_deviations(sources)
        assert devs == []
        assert stats["caps_hit"] is True
        # The presence walk stayed inside the per-family bound.
        assert stats["presence_ops"] <= 3 * MAX_SWITCHES_PER_ENUM

    @requires_ts("c")
    def test_presence_ops_budget_excludes_loudly(self, monkeypatch):
        # Load-bearing budget pin: with the run budget forced below
        # one family's matrix, the enum is EXCLUDED (census_degraded,
        # caps_hit, zero deviations) — removing the budget check
        # censuses it and fails here.
        from core.audit import enum_switch as es

        monkeypatch.setattr(es, "MAX_PRESENCE_OPS", 5)
        sources = _sources(
            ("h_a", ALL), ("h_b", ALL), ("h_c", ALL),
            ("h_d", ["PKT_DATA", "PKT_ACK"]),
        )
        devs, stats = detect_enum_switch_deviations(sources)
        assert devs == []
        assert stats["caps_hit"] is True
        assert stats["presence_ops"] == 0
        assert stats["inconclusive_reasons"].get(
            "census_degraded") == 1

    @requires_ts("c")
    def test_presence_ops_scale_linearly_in_switches(self):
        # Growth-ratio pin: doubling the switch count doubles the
        # matrix work (member-major walk is member×switch linear —
        # never pairwise over switches). A superlinear regression
        # here reopens the macro-flood DoS the rails close.
        def ops_for(n_switches: int) -> int:
            sources = {"lin.c": _ENUM + "".join(
                _switch(f"h_{i:04d}", ALL) for i in range(n_switches)
            )}
            _devs, stats = detect_enum_switch_deviations(sources)
            return stats["presence_ops"]

        small, large = ops_for(20), ops_for(40)
        assert small > 0
        assert large <= 2 * small + 3  # linear, +members slack

    def test_ops_budget_excludes_rather_than_truncates(self):
        # Mechanical pin (no parsing): the budget check runs BEFORE a
        # family's walk, so an over-budget family contributes zero
        # ops and one census_degraded reason — never a partial matrix.
        assert MAX_PRESENCE_OPS >= 256 * MAX_SWITCHES_PER_ENUM


class TestCohortsAndLayer:
    @requires_ts("c")
    def test_cohorts_and_l8_groups(self):
        from core.analysis.peer_groups import (
            GROUP_TYPE_ENUM_SWITCH,
            resolve_peer_groups,
        )

        sources = _sources(("h_a", ALL), ("h_b", ALL), ("h_c", ALL))
        cohorts = enum_switch_cohorts(sources)
        assert cohorts == [("pkt_kind", ["h_a", "h_b", "h_c"])]
        functions = [
            {"name": n, "file": "pkt.c", "line": 1}
            for n in ("h_a", "h_b", "h_c")
        ]
        groups = resolve_peer_groups(functions, enum_cohorts=cohorts)
        l8 = [
            g for g in groups
            if g.sibling_type == GROUP_TYPE_ENUM_SWITCH
        ]
        assert len(l8) == 1
        assert sorted(s.function for s in l8[0].siblings) == [
            "h_a", "h_b", "h_c",
        ]
        # Non-exclusive: L8 groups never enter the interface
        # dimension's admission set.
        from core.audit.consistency_dimensions import (
            _INTERFACE_GROUP_TYPES,
        )
        assert GROUP_TYPE_ENUM_SWITCH not in _INTERFACE_GROUP_TYPES

    @requires_ts("c")
    def test_no_cohorts_is_equivalence_pinned(self):
        from core.analysis.peer_groups import resolve_peer_groups

        functions = [
            {"name": n, "file": "pkt.c", "line": 1}
            for n in ("h_a", "h_b")
        ]
        with_none = resolve_peer_groups(functions, enum_cohorts=None)
        baseline = resolve_peer_groups(functions)
        assert [g.group_id for g in with_none] == [
            g.group_id for g in baseline
        ]

    @requires_ts("c")
    def test_hostile_enum_name_escaped_in_group(self):
        from core.analysis.peer_groups import _enum_switch_groups

        functions = [
            {"name": n, "file": "pkt.c", "line": 1}
            for n in ("h_a", "h_b")
        ]
        groups = _enum_switch_groups(
            [("evil\x1b[31menum", ["h_a", "h_b"])], functions,
        )
        assert len(groups) == 1
        assert "\x1b" not in groups[0].group_id
        assert "\\x1b" in groups[0].group_id


class TestPrepassWiring:
    @requires_ts("c")
    def test_census_lead_rides_the_prepass(self):
        from core.audit.consistency_prepass import (
            run_consistency_prepass,
        )

        sources = _sources(
            ("h_a", ALL), ("h_b", ALL), ("h_c", ALL),
            ("h_d", ["PKT_DATA", "PKT_ACK"]),
        )
        result = run_consistency_prepass(sources)
        es_leads = [
            lead for lead in result["leads"]
            if lead.get("dimension") == DIMENSION_ENUM_SWITCH
        ]
        assert len(es_leads) == 1
        lead = es_leads[0]
        assert lead["function"] == "h_d"
        assert lead["callee"] == "PKT_RESET"
        assert lead["rule_id"] == (
            f"consistency:{DIMENSION_ENUM_SWITCH}-majority"
        )
        assert 0 < lead["score"] < lead["ratio"]
        mech = [
            m for m in result["mechanical"]
            if m.get("detector") == "enum_switch_deviation"
        ]
        assert len(mech) == 1
        dims = result["telemetry"]["dimensions"]
        assert dims.get(DIMENSION_ENUM_SWITCH, {}).get(
            "confirmed") == 1

    @requires_ts("c")
    def test_floors_thread_through_the_prepass(self):
        from core.audit.consistency_prepass import (
            run_consistency_prepass,
        )

        sources = _sources(
            ("h_a", ALL), ("h_b", ALL), ("h_c", ALL),
            ("h_d", ["PKT_DATA", "PKT_ACK"]),
        )
        # Raising min_switches above the family size silences it.
        result = run_consistency_prepass(
            sources,
            floor_overrides={"enum-switch.min_switches": 5},
        )
        assert [
            lead for lead in result["leads"]
            if lead.get("dimension") == DIMENSION_ENUM_SWITCH
        ] == []
