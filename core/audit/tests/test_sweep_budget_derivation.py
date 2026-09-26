"""Derived census budget: the fixed 30s default covered ~18% of a
kernel-scale census (measured 28.2 ms/file — see the module's
derivation comment). The default derives from census size, floored at
the old default, ceilinged as the DoS backstop; explicit budgets are
honoured verbatim. The return-domain sweep deliberately keeps its
fixed budget — see its module comment: findings are structurally
gated to zero on >_MAX_WALK_FILES trees, so a bigger budget buys
nothing until the walk-cap redesign lands.
"""

from __future__ import annotations



def _texts_with_sites(n: int) -> dict[str, str]:
    # Real call sites so census entries exist and truncation is
    # observable — a site-less fixture cannot distinguish budgets.
    return {
        f"f{i}.c": (
            "int helper(void);\n"
            f"int fn{i}(void) {{ if (helper() < 0) return -1; return 0; }}\n"
        )
        for i in range(n)
    }


class TestCensusBudgetDerivation:
    def test_directions(self):
        from core.audit.callsite_consistency import (
            _CENSUS_BUDGET_CEILING_S,
            _CENSUS_BUDGET_S,
            _derive_census_budget_s,
        )
        assert _derive_census_budget_s(10) == _CENSUS_BUDGET_S  # floor
        assert _derive_census_budget_s(5903) == 5903 * 0.05  # kernel
        assert _derive_census_budget_s(10**6) == _CENSUS_BUDGET_CEILING_S

    def test_default_wiring_consults_the_derivation(self, monkeypatch):
        # Revert-pin on the WIRING (not just the helper arithmetic): a
        # zero-second derived budget must truncate a censusable set —
        # under the old fixed default the derivation is never
        # consulted and this fails.
        import core.audit.callsite_consistency as cc
        seen: list[int] = []

        def fake_derive(n: int) -> float:
            seen.append(n)
            return 0.0

        monkeypatch.setattr(cc, "_derive_census_budget_s", fake_derive)
        texts = _texts_with_sites(8)
        census = cc.build_return_census(texts)
        assert seen == [8]
        assert census == {} or all(
            c.truncated for c in census.values())

    def test_explicit_budget_never_consults_the_derivation(
            self, monkeypatch):
        import core.audit.callsite_consistency as cc

        def boom(n: int) -> float:
            raise AssertionError("derivation consulted for explicit budget")

        monkeypatch.setattr(cc, "_derive_census_budget_s", boom)
        texts = _texts_with_sites(4)
        census = cc.build_return_census(texts, budget_s=60.0)
        assert census  # sites censused under the explicit budget
        assert not any(c.truncated for c in census.values())

    def test_none_still_means_unlimited(self):
        from core.audit.callsite_consistency import build_return_census
        census = build_return_census(_texts_with_sites(3), budget_s=None)
        assert census and not any(c.truncated for c in census.values())


class TestPrepassCensusLane:
    @staticmethod
    def _capture_census(monkeypatch, sleep_s: float = 0.0):
        import time as _time

        import core.audit.consistency_prepass as cp
        calls: list[dict] = []

        def fake_census(source_texts, **kwargs):
            calls.append(kwargs)
            if sleep_s:
                _time.sleep(sleep_s)
            return {}

        monkeypatch.setattr(cp, "build_return_census", fake_census)
        return cp, calls

    def test_sentinel_default_lets_census_derive(self, monkeypatch):
        # Behavioral pin (not textual): at the SENTINEL default the
        # census receives NO explicit budget (it derives); any
        # explicit float — 60.0 included — passes the verbatim half.
        cp, calls = self._capture_census(monkeypatch)
        cp.run_consistency_prepass({"a.c": "int x;\n"})
        assert "budget_s" not in calls[-1]
        cp.run_consistency_prepass(
            {"a.c": "int x;\n"}, budget_s=60.0)
        assert calls[-1]["budget_s"] == 30.0
        cp.run_consistency_prepass(
            {"a.c": "int x;\n"}, budget_s=40.0)
        assert calls[-1]["budget_s"] == 20.0

    def test_derived_census_never_starves_the_dimensions(
            self, monkeypatch):
        # Two-direction deadline pin: a census wall past the whole
        # prepass budget must NOT trip the dimension gates in derived
        # mode (deadline re-anchors after the census) — and MUST trip
        # them under an explicit budget (which bounds the whole
        # prepass deliberately).
        cp, calls = self._capture_census(monkeypatch, sleep_s=0.25)
        monkeypatch.setattr(cp, "PREPASS_BUDGET_S", 0.1)
        result = cp.run_consistency_prepass({"a.c": "int x;\n"})
        assert not result["telemetry"].get("budget_exceeded")
        result = cp.run_consistency_prepass(
            {"a.c": "int x;\n"}, budget_s=0.1)
        assert result["telemetry"].get("budget_exceeded")

    def test_wall_time_covers_the_census(self, monkeypatch):
        # Telemetry pin: wall_time_s reports the WHOLE prepass wall.
        # The derived-mode deadline re-anchor after the census must
        # not subtract the census's share from the reported figure
        # (the deadline anchor and the telemetry anchor are different
        # clocks).
        cp, _calls = self._capture_census(monkeypatch, sleep_s=0.25)
        result = cp.run_consistency_prepass({"a.c": "int x;\n"})
        assert result["telemetry"]["wall_time_s"] >= 0.25

    def test_truncated_cached_census_is_a_miss(self, tmp_path):
        # Pre-derive segments cached 30s-truncated censuses; serving
        # them on fingerprint match would pin the truncation forever.
        from core.audit.callsite_consistency import CalleeCensus
        from core.audit.consistency_prepass import (
            _load_census_cache,
            _write_census_cache,
        )
        trunc = CalleeCensus(callee="f", truncated=True)
        _write_census_cache(tmp_path, "fp1", {"f": trunc})
        assert _load_census_cache(tmp_path, "fp1") is None
        ok = CalleeCensus(callee="f", truncated=False)
        _write_census_cache(tmp_path, "fp2", {"f": ok})
        got = _load_census_cache(tmp_path, "fp2")
        assert got and not got["f"].truncated


class TestReturnDomainKeepsFixedBudget:
    def test_fixed_default_with_structural_rationale(self):
        import inspect

        import core.audit.return_domain as rd
        sig = inspect.signature(rd.detect_return_domain_mismatches)
        assert sig.parameters["budget_s"].default == rd._DEFAULT_BUDGET_S
        src = inspect.getsource(rd)
        # The retreat is deliberate and documented — a future
        # derivation must first remove the structural zero-yield gate.
        assert "_MAX_WALK_FILES" in src and "zero-yield" in src
