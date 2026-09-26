"""Tier-counter registration and unknown-tier loudness.

Chain channels tally through ``increment_tier_dict``, whose
``if tier in tier_counters`` membership guard drops unknown tiers: a
channel whose tier name is missing from ``_make_tier_counters()``
never shows a row in the tier-effectiveness table, no matter how
often it confirms, errors, or refuses. These pin (a) every
chain-dispatched tier is registered, (b) a chain leg's tallies
actually land on its registered tier, and (c) an unknown tier warns
— once per tier per process — instead of dropping silently, while
telemetry never becomes a crash path.
"""

from __future__ import annotations

import logging
import time
import types

from core.audit.diagnostics import increment_tier, increment_tier_dict
from core.audit.orchestrator import (
    OrchestratorConfig,
    _make_tier_counters,
    _run_tool_chain,
)
from core.audit.propagation import _tick_tier


def _mk_config(tmp_path):
    (tmp_path / "out").mkdir(exist_ok=True)
    return OrchestratorConfig(
        target_path=tmp_path, out_dir=tmp_path / "out",
    )


class TestChainTierRegistration:
    def test_chain_dispatched_tiers_registered(self):
        """Every tier the tool chain tallies must be registered.

        ``sanwit`` and the binary-lane sweeps reach
        ``increment_tier_dict`` through the chain's dynamic
        ``tool_type``; ``joern_xf`` through the cross-function verify
        leg. An unregistered name makes every one of those tallies a
        no-op.
        """
        tc = _make_tier_counters()
        missing = [
            name
            for name in (
                "sanwit",
                "joern_xf",
                "integer_truncation",
                "proto_length",
                "struct_field",
            )
            if name not in tc
        ]
        assert not missing, (
            f"chain-dispatched tiers unregistered in "
            f"_make_tier_counters(): {missing}"
        )

    def test_sanwit_chain_tallies_land(self, tmp_path, monkeypatch):
        """A sanwit chain entry's outcome lands on the sanwit tier."""

        def fake_check(*args, **kwargs):
            time.sleep(0.01)
            return types.SimpleNamespace(
                outcome="confirmed",
                rule_id="sanwit:insufficient-sanitizer",
                reason="stub",
                errors=[],
                details={},
            )

        monkeypatch.setattr(
            "core.audit.sanwit.run_sanwit_check", fake_check,
        )
        tier_counters = _make_tier_counters()
        confirmed = _run_tool_chain(
            [{"type": "sanwit", "config": {}}],
            config=_mk_config(tmp_path),
            file_path="src/a.php",
            function_name="handler",
            source="<?php function handler($x) {}",
            hypothesis="unsanitized sink reachable",
            tier_counters=tier_counters,
        )
        assert confirmed == ["sanwit:insufficient-sanitizer"]
        assert tier_counters["sanwit"].confirmed == 1
        # The chain's per-entry wall-clock bracket books onto the
        # same tier — zero here means the tally dropped.
        assert tier_counters["sanwit"].wall_time_s > 0


class TestUnknownTierLoudness:
    def test_increment_tier_dict_unknown_warns_once(self, caplog):
        tc = _make_tier_counters()
        with caplog.at_level(
            logging.WARNING, logger="core.audit.diagnostics",
        ):
            increment_tier_dict(tc, "zz_unknown_dict_case", "confirmed")
            increment_tier_dict(tc, "zz_unknown_dict_case", "errors")
        warnings = [
            r for r in caplog.records
            if "zz_unknown_dict_case" in r.getMessage()
        ]
        assert len(warnings) == 1, (
            "unknown tier must warn exactly once per process"
        )
        # No crash, no phantom entry: the drop stays a drop.
        assert "zz_unknown_dict_case" not in tc

    def test_increment_tier_unknown_warns(self, caplog):
        result = types.SimpleNamespace(tier_counters=_make_tier_counters())
        with caplog.at_level(
            logging.WARNING, logger="core.audit.diagnostics",
        ):
            increment_tier(result, "zz_unknown_result_case", "confirmed")
        assert any(
            "zz_unknown_result_case" in r.getMessage()
            for r in caplog.records
        )
        assert "zz_unknown_result_case" not in result.tier_counters

    def test_tick_tier_unknown_warns(self, caplog):
        stub = types.SimpleNamespace(resolved=False, resolution=None)
        with caplog.at_level(
            logging.WARNING, logger="core.audit.diagnostics",
        ):
            _tick_tier(_make_tier_counters(), "zz_unknown_tick_case", stub)
        assert any(
            "zz_unknown_tick_case" in r.getMessage()
            for r in caplog.records
        )

    def test_tick_tier_none_counters_stays_silent(self, caplog):
        """``tier_counters=None`` means telemetry is off for the
        call, not that a tier went unregistered — no warning."""
        stub = types.SimpleNamespace(resolved=False, resolution=None)
        with caplog.at_level(
            logging.WARNING, logger="core.audit.diagnostics",
        ):
            _tick_tier(None, "zz_none_counters_case", stub)
        assert not any(
            "zz_none_counters_case" in r.getMessage()
            for r in caplog.records
        )

    def test_registered_tier_never_warns(self, caplog):
        tc = _make_tier_counters()
        with caplog.at_level(
            logging.WARNING, logger="core.audit.diagnostics",
        ):
            increment_tier_dict(tc, "semgrep", "confirmed")
        assert tc["semgrep"].confirmed == 1
        assert not caplog.records
