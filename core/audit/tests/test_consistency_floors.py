"""Floor threading through the consistency prepass and verdict layer:
two-direction regression tests for the registered thresholds, the
run-config override channel, and default-equivalence pins."""

from __future__ import annotations

import json
import textwrap
from types import SimpleNamespace

from core.audit.callsite_consistency import (
    USAGE_DISCARDED,
    USAGE_TESTED,
    CalleeCensus,
    CallSite,
)
from core.audit.consistency_prepass import run_consistency_prepass
from core.audit.consistency_stats import (
    RUN_CONFIG_FLOORS_KEY,
    resolve_floors,
)
from core.audit.consistency_verify import (
    RULE_GUARD_PRESENCE,
    RULE_RETURN_CHECK_MAJORITY,
    census_verdict,
    guard_presence_verdict,
)


def _entry(tested: int, discarded: int = 1, callee: str = "verify_sig"):
    sites = [
        CallSite(
            file=f"src/t{i}.c", line=10 + i, callee=callee,
            enclosing_function=f"ok{i}", usage=USAGE_TESTED,
        )
        for i in range(tested)
    ]
    deviants = [
        CallSite(
            file="src/dev.c", line=99 + i, callee=callee,
            enclosing_function=f"dev{i}", usage=USAGE_DISCARDED,
        )
        for i in range(discarded)
    ]
    entry = CalleeCensus(callee=callee, sites=sites + deviants)
    return entry, deviants[0]


class TestVerdictFloorsTwoDirections:
    """The census majority-leg floors, exercised from both sides at
    the defaults and again under an override — a threshold move in
    either direction fails one of these."""

    def test_at_the_default_floors_confirms(self):
        entry, dev = _entry(tested=9)   # 9/10 considered = 0.9
        res = census_verdict(entry, dev)
        assert res.outcome == "confirmed"
        assert res.rule_id == RULE_RETURN_CHECK_MAJORITY

    def test_just_below_the_default_ratio_is_inconclusive(self):
        entry, dev = _entry(tested=8)   # 8/9 ≈ 0.889 < 0.9
        res = census_verdict(entry, dev)
        assert res.outcome == "inconclusive"
        # 8/9 clears the 0.8 contract-majority floor, so a
        # (non-registry) majority contract binds and the enumerated
        # reason is the ratio one.
        assert res.reason.startswith("ratio-below-threshold")

    def test_just_below_the_default_min_sites_is_group_too_small(self):
        entry, dev = _entry(tested=2)   # considered 3 < 4
        res = census_verdict(entry, dev)
        assert res.outcome == "inconclusive"
        assert res.reason.startswith("group-too-small")

    def test_ratio_override_moves_the_gate_down(self):
        entry, dev = _entry(tested=8)   # 0.889
        floors = resolve_floors(
            {"return-check.verdict_majority_ratio": 0.85},
        )
        res = census_verdict(entry, dev, floors=floors)
        assert res.outcome == "confirmed"
        assert res.rule_id == RULE_RETURN_CHECK_MAJORITY

    def test_min_sites_override_moves_the_gate_up(self):
        entry, dev = _entry(tested=9)   # considered 10
        floors = resolve_floors(
            {"return-check.verdict_min_sites": 11},
        )
        res = census_verdict(entry, dev, floors=floors)
        assert res.outcome == "inconclusive"
        assert res.reason.startswith("group-too-small")

    def test_default_floors_object_matches_no_floors(self):
        entry, dev = _entry(tested=9)
        bare = census_verdict(entry, dev)
        defaulted = census_verdict(
            entry, dev, floors=resolve_floors(None),
        )
        assert bare.to_dict() == defaulted.to_dict()


class TestGuardPromoteFloorOverride:
    @staticmethod
    def _deviation(ratio: float):
        from core.audit.consistency_dimensions import (
            detect_guard_presence_deviations,
        )
        conforming = round(ratio / (1 - ratio))
        parts = []
        for i in range(conforming):
            parts.append(textwrap.dedent(f"""\
                int use_{i}(map_t *m) {{
                    entry_t *e = lookup_entry(m);
                    if (!e)
                        return -1;
                    return e->value;
                }}
            """))
        parts.append(textwrap.dedent("""\
            int use_dev(map_t *m) {
                entry_t *e = lookup_entry(m);
                return e->value;
            }
        """))
        devs = detect_guard_presence_deviations(
            {"src/map.c": "\n".join(parts)},
        )
        assert devs and abs(devs[0].ratio - ratio) < 1e-9
        return devs[0]

    def test_below_default_promote_floor_stays_detection_grade(self):
        dev = self._deviation(0.75)
        res = guard_presence_verdict(
            dev,
            smt_check=lambda d: SimpleNamespace(
                feasible=True, reasoning="sat", witness=None,
            ),
        )
        assert res.rule_id == "consistency:guard-presence-majority"

    def test_promote_floor_override_promotes_the_same_family(self):
        dev = self._deviation(0.75)
        floors = resolve_floors(
            {"guard-presence.promote_ratio": 0.7},
        )
        res = guard_presence_verdict(
            dev,
            smt_check=lambda d: SimpleNamespace(
                feasible=True, reasoning="sat", witness=None,
            ),
            floors=floors,
        )
        assert res.rule_id == RULE_GUARD_PRESENCE
        assert res.contract is not None
        assert res.contract["source"] == "smt_witness"


def _majority_corpus() -> dict[str, str]:
    """verify_sig checked at 9 sites, discarded at 1 — exactly the
    default majority-leg floor (9/10 = 0.9)."""
    src = "int verify_sig(int x);\n"
    for i in range(9):
        src += (
            f"int m{i}(void) "
            f"{{ if (verify_sig({i})) return 1; return 0; }}\n"
        )
    src += "void m9(void) { verify_sig(9); }\n"
    return {"major.c": src}


def _discard_majority_corpus() -> dict[str, str]:
    """logf discarded at 4 of 5 sites — the discard-ok refutation
    fires at the default contract floors (4/5 = 0.8, considered 5)."""
    src = "int logf_msg(int x);\n"
    for i in range(4):
        src += f"void d{i}(void) {{ logf_msg({i}); }}\n"
    src += "int d4(void) { if (logf_msg(4)) return 1; return 0; }\n"
    return {"logs.c": src}


def _majority_findings(result) -> list:
    return [
        f for f in result["findings"]
        if f["rule_id"] == RULE_RETURN_CHECK_MAJORITY
    ]


class TestPrepassOverrideWiring:
    def test_default_run_records_no_override_telemetry(self, tmp_path):
        result = run_consistency_prepass(
            _majority_corpus(), out_dir=tmp_path,
        )
        assert "floor_overrides" not in result["telemetry"]
        assert "floor_override_error" not in result["telemetry"]
        assert len(_majority_findings(result)) == 1

    def test_explicit_empty_overrides_equal_defaults(self, tmp_path):
        base = run_consistency_prepass(
            _majority_corpus(), out_dir=tmp_path / "a",
        )
        empty = run_consistency_prepass(
            _majority_corpus(), out_dir=tmp_path / "b",
            floor_overrides={},
        )
        assert base["findings"] == empty["findings"]
        assert base["leads"] == empty["leads"]

    def test_verdict_ratio_override_raises_the_gate(self, tmp_path):
        result = run_consistency_prepass(
            _majority_corpus(), out_dir=tmp_path,
            floor_overrides={
                "return-check.verdict_majority_ratio": 0.95,
            },
        )
        assert result["telemetry"]["floor_overrides"] == {
            "return-check.verdict_majority_ratio": 0.95,
        }
        assert _majority_findings(result) == []
        assert result["telemetry"]["inconclusive_reasons"].get(
            "ratio-below-threshold", 0,
        ) >= 1

    def test_contract_floor_override_withholds_discard_ok(
        self, tmp_path,
    ):
        base = run_consistency_prepass(
            _discard_majority_corpus(), out_dir=tmp_path / "a",
        )
        assert base["telemetry"]["dimensions"]["return-check"][
            "refuted"
        ] == 4
        raised = run_consistency_prepass(
            _discard_majority_corpus(), out_dir=tmp_path / "b",
            floor_overrides={"return-check.contract_min_sites": 6},
        )
        # The 4/5 discard majority no longer clears the (overridden)
        # contract floor, so the definitive refutation is withheld.
        assert raised["telemetry"]["dimensions"]["return-check"][
            "refuted"
        ] == 0

    def test_run_config_is_the_override_channel(self, tmp_path):
        (tmp_path / "audit-run-config.json").write_text(json.dumps({
            "version": 1,
            RUN_CONFIG_FLOORS_KEY: {
                "return-check.verdict_majority_ratio": 0.95,
            },
        }))
        result = run_consistency_prepass(
            _majority_corpus(), out_dir=tmp_path,
        )
        assert result["telemetry"]["floor_overrides"] == {
            "return-check.verdict_majority_ratio": 0.95,
        }
        assert _majority_findings(result) == []

    def test_explicit_overrides_win_over_run_config(self, tmp_path):
        (tmp_path / "audit-run-config.json").write_text(json.dumps({
            RUN_CONFIG_FLOORS_KEY: {
                "return-check.verdict_majority_ratio": 0.95,
            },
        }))
        result = run_consistency_prepass(
            _majority_corpus(), out_dir=tmp_path,
            floor_overrides={},
        )
        assert "floor_overrides" not in result["telemetry"]
        assert len(_majority_findings(result)) == 1

    def test_invalid_override_falls_back_to_defaults_loudly(
        self, tmp_path,
    ):
        base = run_consistency_prepass(
            _majority_corpus(), out_dir=tmp_path / "a",
        )
        bad = run_consistency_prepass(
            _majority_corpus(), out_dir=tmp_path / "b",
            floor_overrides={"return-check.nope": 3},
        )
        assert "unknown consistency floor" in \
            bad["telemetry"]["floor_override_error"]
        assert "floor_overrides" not in bad["telemetry"]
        assert bad["findings"] == base["findings"]
        assert bad["leads"] == base["leads"]
