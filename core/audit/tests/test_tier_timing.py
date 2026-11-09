"""Tier-diagnostics wall-clock accumulation.

``TierCounters.wall_time_s`` was declared and reported (tier
diagnostics table + tier-diagnostics.json) but never accumulated
anywhere — every run showed 0.0 for every tier. The tool chain now
brackets each entry with a monotonic timer and books the elapsed time
onto the entry's tier. No real tools run here — the sweep is stubbed.
"""

from __future__ import annotations

import sys
import threading
import time
import types

from core.testing.threads import retiring_threads

from core.audit.orchestrator import (
    OrchestratorConfig,
    _make_tier_counters,
    _run_tool_chain,
)


def _mk_config(tmp_path):
    source = tmp_path / "src" / "a.c"
    source.parent.mkdir(exist_ok=True)
    source.write_text("void handler(void) {}\n")
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


class TestIncrementTierThreadSafety:
    """``increment_tier`` runs in parallel review workers; its
    read-modify-write on the shared ``TierCounters`` must hold the
    module lock or concurrent increments are silently lost
    (under-counted tier-diagnostics.json on parallel runs)."""

    def test_concurrent_increments_are_exact(self):
        from core.audit.diagnostics import increment_tier

        result = types.SimpleNamespace(tier_counters=_make_tier_counters())
        n_threads, n_iter = 8, 500
        start = threading.Barrier(n_threads)

        def worker() -> None:
            try:
                start.wait()
            except threading.BrokenBarrierError:
                return
            for _ in range(n_iter):
                increment_tier(result, "semgrep", "confirmed")
                increment_tier(result, "semgrep", "refuted")

        # Shrink the bytecode switch interval so unlocked
        # read-modify-write races actually interleave.
        old = sys.getswitchinterval()
        sys.setswitchinterval(1e-5)
        try:
            threads = [
                threading.Thread(target=worker) for _ in range(n_threads)
            ]
            with retiring_threads(threads, release=start.abort, timeout=5):
                for t in threads:
                    t.start()
                for t in threads:
                    t.join()
        finally:
            sys.setswitchinterval(old)

        assert result.tier_counters["semgrep"].confirmed == n_threads * n_iter
        assert result.tier_counters["semgrep"].refuted == n_threads * n_iter

    def test_increment_takes_the_shared_lock(self, monkeypatch):
        # Structural pin: the exactness test above can pass by luck on
        # a quiet interpreter even without the lock; entering the
        # module lock cannot.
        from core.audit import diagnostics

        entered: list[bool] = []

        class RecordingLock:
            def __enter__(self) -> None:
                entered.append(True)

            def __exit__(self, *exc: object) -> bool:
                return False

        monkeypatch.setattr(
            diagnostics, "_TIER_COUNTER_LOCK", RecordingLock(),
        )
        result = types.SimpleNamespace(tier_counters=_make_tier_counters())
        diagnostics.increment_tier(result, "semgrep", "confirmed")
        assert entered
        assert result.tier_counters["semgrep"].confirmed == 1
