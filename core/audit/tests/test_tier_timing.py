"""Tier-diagnostics wall-clock accumulation.

``TierCounters.wall_time_s`` was declared and reported (tier
diagnostics table + tier-diagnostics.json) but never accumulated
anywhere — every run showed 0.0 for every tier. The tool chain now
brackets each entry with a monotonic timer and books the elapsed time
onto the entry's tier. No real tools run here — the sweep is stubbed.
"""

from __future__ import annotations

import time
import types

from core.audit.orchestrator import (
    OrchestratorConfig,
    _make_tier_counters,
    _run_tool_chain,
)


def _mk_config(tmp_path):
    (tmp_path / "out").mkdir(exist_ok=True)
    return OrchestratorConfig(
        target_path=tmp_path, out_dir=tmp_path / "out",
    )


def _run(tmp_path, monkeypatch, *, outcome="refuted", sleep_s=0.02):
    def fake_sweep(**kwargs):
        time.sleep(sleep_s)
        return types.SimpleNamespace(
            outcome=outcome, rule_id="stub", errors=[], details={},
        )

    monkeypatch.setattr(
        "core.audit.orchestrator.run_semgrep_sweep", fake_sweep,
    )
    tier_counters = _make_tier_counters()
    chain = [{"type": "semgrep", "config": {"rule": "unused.yaml"}}]
    confirmed = _run_tool_chain(
        chain,
        config=_mk_config(tmp_path),
        file_path="src/a.c",
        function_name="handler",
        source="void handler(void) {}",
        hypothesis="buffer overflow via unchecked strcpy",
        line_start=10,
        tier_counters=tier_counters,
    )
    return confirmed, tier_counters


class TestTierWallTime:
    def test_wall_time_accumulates(self, tmp_path, monkeypatch):
        _, tiers = _run(tmp_path, monkeypatch, sleep_s=0.02)
        assert tiers["semgrep"].wall_time_s >= 0.02
        assert tiers["semgrep"].refuted == 1

    def test_wall_time_accumulates_across_calls(self, tmp_path, monkeypatch):
        _, tiers_a = _run(tmp_path, monkeypatch, sleep_s=0.02)
        first = tiers_a["semgrep"].wall_time_s

        # Second chain over the SAME counters dict keeps adding.
        def fake_sweep(**kwargs):
            time.sleep(0.02)
            return types.SimpleNamespace(
                outcome="refuted", rule_id="stub", errors=[], details={},
            )

        monkeypatch.setattr(
            "core.audit.orchestrator.run_semgrep_sweep", fake_sweep,
        )
        chain = [{"type": "semgrep", "config": {"rule": "unused.yaml"}}]
        _run_tool_chain(
            chain,
            config=_mk_config(tmp_path),
            file_path="src/a.c",
            function_name="handler",
            source="void handler(void) {}",
            hypothesis="buffer overflow via unchecked strcpy",
            line_start=10,
            tier_counters=tiers_a,
        )
        assert tiers_a["semgrep"].wall_time_s >= first + 0.02

    def test_untouched_tiers_stay_zero(self, tmp_path, monkeypatch):
        _, tiers = _run(tmp_path, monkeypatch)
        assert tiers["smt"].wall_time_s == 0.0
        assert tiers["joern"].wall_time_s == 0.0

    def test_erroring_tool_still_booked(self, tmp_path, monkeypatch):
        # The finally bracket books time even when the tool raises.
        def boom(**kwargs):
            time.sleep(0.02)
            raise RuntimeError("tool exploded")

        monkeypatch.setattr(
            "core.audit.orchestrator.run_semgrep_sweep", boom,
        )
        tier_counters = _make_tier_counters()
        chain = [{"type": "semgrep", "config": {"rule": "unused.yaml"}}]
        confirmed = _run_tool_chain(
            chain,
            config=_mk_config(tmp_path),
            file_path="src/a.c",
            function_name="handler",
            source="void handler(void) {}",
            hypothesis="buffer overflow via unchecked strcpy",
            line_start=10,
            tier_counters=tier_counters,
        )
        assert confirmed == []
        assert tier_counters["semgrep"].wall_time_s >= 0.02

    def test_diagnostics_render_wall_time(self, tmp_path, monkeypatch):
        import re

        from core.audit.diagnostics import format_tier_diagnostics

        _, tiers = _run(tmp_path, monkeypatch, sleep_s=0.2)
        table = format_tier_diagnostics(tiers)
        semgrep_line = next(
            line for line in table.splitlines() if "semgrep" in line
        )
        # The wall clock actually rendered (pre-fix wall_time_s was
        # always 0.0 so the duration column never appeared).
        m = re.search(r"(\d+\.\d)s", semgrep_line)
        assert m, semgrep_line
        assert float(m.group(1)) >= 0.2
