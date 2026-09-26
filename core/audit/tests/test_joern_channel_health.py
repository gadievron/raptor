"""Joern channel-health gate: trip semantics (distinct-key rule,
half-open probe), dispatch gating with honest skip records,
gate-resolution integrity, guard-veto gating, per-query budgets,
diagnostics/report surfacing, and the pre-sweep window budget."""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

import core.audit.orchestrator as orch
from core.audit.diagnostics import write_tier_diagnostics
from core.audit.joern_health import (
    MIN_DISTINCT_TRIP_KEYS,
    REPROBE_AFTER_SKIPS,
    JoernChannelHealth,
    channel_unhealthy,
    dispatch_blocked,
    health_snapshot,
    record_outcome,
)
from core.audit.orchestrator import (
    TierCounters,
    _guard_blocks_promotion,
    _joern_live_timeout_s,
    _run_tool_chain,
)
from core.audit.sweep import _presweep_bulk_timeout_s


def _trip(h: JoernChannelHealth) -> None:
    """Drive a gate to its trip across distinct keys."""
    n = max(h.unhealthy_after, MIN_DISTINCT_TRIP_KEYS)
    for i in range(n):
        h.record_error("timed out", key=f"a.c:fn{i % MIN_DISTINCT_TRIP_KEYS}")


class TestTripSemantics:
    def test_trips_after_threshold_across_distinct_keys(self):
        h = JoernChannelHealth(unhealthy_after=3)
        h.record_error("timed out", key="a.c:f")
        h.record_error("timed out", key="a.c:g")
        assert not h.tripped
        h.record_error("timed out", key="a.c:h")
        assert h.tripped
        assert "3 consecutive" in (h.trip_reason or "")

    def test_single_key_streak_never_trips(self):
        # One pathological query shape on a healthy server must not
        # silence the whole channel.
        h = JoernChannelHealth(unhealthy_after=2)
        for _ in range(20):
            h.record_error("timed out", key="a.c:same_fn")
        assert not h.tripped

    def test_success_resets_streak_and_keys(self):
        h = JoernChannelHealth(unhealthy_after=3)
        h.record_error(key="a.c:f")
        h.record_error(key="a.c:g")
        h.record_success()
        h.record_error(key="a.c:f")
        h.record_error(key="a.c:g")
        assert not h.tripped
        h.record_error(key="a.c:h")
        assert h.tripped

    def test_threshold_floor_is_one(self):
        h = JoernChannelHealth(unhealthy_after=0)
        h.record_error(key="a.c:f")
        h.record_error(key="a.c:g")
        assert h.tripped

    def test_to_dict_shape(self):
        h = JoernChannelHealth(unhealthy_after=2)
        h.record_error("no CPG loaded", key="a.c:f")
        h.record_error("no CPG loaded", key="a.c:g")
        d = h.to_dict()
        assert d["tripped"] is True
        assert d["total_errors"] == 2
        assert d["total_successes"] == 0
        assert d["unhealthy_after"] == 2
        assert "no CPG loaded" in d["trip_reason"]


class TestHalfOpenProbe:
    def test_probe_granted_after_skip_threshold(self):
        h = JoernChannelHealth(unhealthy_after=2)
        _trip(h)
        grants = [h.allow_dispatch() for _ in range(REPROBE_AFTER_SKIPS + 5)]
        assert grants.count(True) == 1
        assert grants.index(True) == REPROBE_AFTER_SKIPS - 1

    def test_probe_success_recovers_the_channel(self):
        h = JoernChannelHealth(unhealthy_after=2)
        _trip(h)
        while not h.allow_dispatch():
            pass
        h.record_success()
        assert not h.tripped
        assert h.allow_dispatch()
        assert h.to_dict().get("recovered_once") is True

    def test_probe_failure_seals_the_gate(self):
        h = JoernChannelHealth(unhealthy_after=2)
        _trip(h)
        while not h.allow_dispatch():
            pass
        h.record_error("still restarting", key="a.c:probe")
        assert h.tripped
        # No second probe for the run.
        assert not any(
            h.allow_dispatch() for _ in range(3 * REPROBE_AFTER_SKIPS)
        )

    def test_second_trip_is_final(self):
        h = JoernChannelHealth(unhealthy_after=2)
        _trip(h)
        while not h.allow_dispatch():
            pass
        h.record_success()
        assert not h.tripped
        _trip(h)
        assert h.tripped
        assert not any(
            h.allow_dispatch() for _ in range(3 * REPROBE_AFTER_SKIPS)
        )


class TestConfigHelpers:
    def test_config_without_field_reads_healthy(self):
        class _Bare:
            pass

        assert channel_unhealthy(_Bare()) is False
        assert dispatch_blocked(_Bare()) is False
        record_outcome(_Bare(), error=True)  # no-op, no raise
        assert health_snapshot(_Bare()) is None

    def test_snapshot_empty_until_first_error(self):
        class _HealthOnlyCfg:
            joern_health = JoernChannelHealth()

        cfg = _HealthOnlyCfg()
        cfg.joern_health.record_success()
        assert health_snapshot(cfg) is None
        cfg.joern_health.record_error(key="a.c:f")
        snap = health_snapshot(cfg)
        assert snap is not None
        assert snap["joern"]["total_errors"] == 1

    def test_channel_unhealthy_is_read_only(self):
        class _HealthOnlyCfg:
            joern_health = JoernChannelHealth(unhealthy_after=1)

        cfg = _HealthOnlyCfg()
        _trip(cfg.joern_health)
        before = cfg.joern_health.to_dict().get("skips_since_trip", 0)
        assert channel_unhealthy(cfg) is True
        assert cfg.joern_health.to_dict().get(
            "skips_since_trip", 0,
        ) == before


class _Cfg:
    """Minimal OrchestratorConfig stand-in for _run_tool_chain."""

    def __init__(self, target: Path, unhealthy_after: int = 3):
        self.target_path = target
        self.out_dir = None
        self.codeql_db_path = None
        self.project_sinks = None
        self.joern_health = JoernChannelHealth(
            unhealthy_after=unhealthy_after,
        )


@pytest.fixture
def counters():
    return {
        "joern": TierCounters(),
        "joern_guard": TierCounters(),
        "joern_flow": TierCounters(),
    }


class TestDispatchGating:
    HYP = "attacker data from `argv` reaches system()"
    CHAIN = [{"type": "joern", "config": {"sinks": ["system"]}}]

    def _dispatch(
        self, cfg, counters, monkeypatch, calls, function_name="f",
        skipped_types=None,
    ):
        def fake_live_query(
            server, fn, sinks, timeout=30, errors_out=None, **kw,
        ):
            calls.append(fn)
            if errors_out is not None:
                errors_out.append("query timed out after 300s")
            return []

        monkeypatch.setattr(orch, "_joern_live_query", fake_live_query)
        return _run_tool_chain(
            self.CHAIN,
            config=cfg,
            file_path="src/a.c",
            function_name=function_name,
            source="",
            hypothesis=self.HYP,
            tier_counters=counters,
            joern_server=object(),
            skipped_types=skipped_types,
        )

    def test_gate_stops_dispatch_after_threshold(
        self, tmp_path, counters, monkeypatch,
    ):
        cfg = _Cfg(tmp_path, unhealthy_after=3)
        calls: list[str] = []
        # Errors across distinct functions: the third trips the gate.
        for i in range(5):
            self._dispatch(
                cfg, counters, monkeypatch, calls,
                function_name=f"fn{i}",
            )
        assert len(calls) == 3
        assert counters["joern"].errors == 3
        assert counters["joern"].skipped == 2
        assert cfg.joern_health.tripped

    def test_gated_skip_populates_skipped_types(
        self, tmp_path, counters, monkeypatch,
    ):
        """MUST-FIX: a gated channel must leave the dispatch record —
        callers compute dispatched = chain − skipped, and a phantom
        'joern' there lets gate resolution demote on coverage the
        gate itself prevented."""
        cfg = _Cfg(tmp_path, unhealthy_after=1)
        cfg.joern_health.record_error("dead", key="a.c:x")
        cfg.joern_health.record_error("dead", key="a.c:y")
        assert cfg.joern_health.tripped
        skipped: set = set()
        self._dispatch(
            cfg, counters, monkeypatch, [], skipped_types=skipped,
        )
        assert "joern" in skipped

    def test_no_server_skip_populates_skipped_types(
        self, tmp_path, counters, monkeypatch,
    ):
        cfg = _Cfg(tmp_path)
        skipped: set = set()
        monkeypatch.setattr(
            orch, "_joern_live_query",
            lambda *a, **kw: pytest.fail("dispatched without server"),
        )
        _run_tool_chain(
            self.CHAIN,
            config=cfg,
            file_path="src/a.c",
            function_name="f",
            source="",
            hypothesis=self.HYP,
            tier_counters=counters,
            joern_server=None,
            skipped_types=skipped,
        )
        assert "joern" in skipped

    def test_guard_step_respects_tripped_gate(
        self, tmp_path, counters, monkeypatch,
    ):
        import core.audit.joern_verify as jv

        cfg = _Cfg(tmp_path, unhealthy_after=1)
        cfg.joern_health.record_error("dead", key="a.c:x")
        cfg.joern_health.record_error("dead", key="a.c:y")
        called: list[str] = []
        monkeypatch.setattr(
            jv, "run_guard_dominance_check",
            lambda **kw: called.append("guard"),
        )
        skipped: set = set()
        chain = [{"type": "joern_guard", "config": {"sinks": ["memcpy"]}}]
        _run_tool_chain(
            chain,
            config=cfg,
            file_path="src/a.c",
            function_name="f",
            source="",
            hypothesis="missing bounds check on `len` before memcpy",
            tier_counters=counters,
            joern_server=object(),
            skipped_types=skipped,
        )
        assert called == []
        assert counters["joern_guard"].skipped == 1
        assert "joern_guard" in skipped

    def test_guard_errors_feed_the_gate(
        self, tmp_path, counters, monkeypatch,
    ):
        import core.audit.joern_verify as jv
        from core.audit.sweep import SweepResult

        cfg = _Cfg(tmp_path, unhealthy_after=2)

        def fake_guard(**kw):
            return SweepResult(
                tool="joern", file_path=kw["file_path"],
                function_name=kw["function_name"],
                outcome="error", rule_id="joern:guard",
                errors=["query timed out after 300s"],
            )

        monkeypatch.setattr(jv, "run_guard_dominance_check", fake_guard)
        chain = [{"type": "joern_guard", "config": {"sinks": ["memcpy"]}}]
        for fn in ("f", "g"):
            _run_tool_chain(
                chain,
                config=cfg,
                file_path="src/a.c",
                function_name=fn,
                source="",
                hypothesis="missing bounds check on `len` before memcpy",
                tier_counters=counters,
                joern_server=object(),
            )
        assert cfg.joern_health.tripped
        assert "timed out" in (cfg.joern_health.trip_reason or "")

    def test_cached_presweep_evidence_survives_trip(
        self, tmp_path, counters, monkeypatch,
    ):
        """A tripped gate must not discard already-earned pre-sweep
        receipts — only live round trips are gated."""
        cfg = _Cfg(tmp_path, unhealthy_after=1)
        cfg.joern_health.record_error("dead", key="a.c:x")
        cfg.joern_health.record_error("dead", key="a.c:y")

        class _Rec:
            def all_joern_flows(self):
                return [object()]

        monkeypatch.setattr(
            orch, "_joern_live_query",
            lambda *a, **kw: pytest.fail("live query dispatched"),
        )
        confirmed = _run_tool_chain(
            self.CHAIN,
            config=cfg,
            file_path="src/a.c",
            function_name="f",
            source="",
            hypothesis=self.HYP,
            tier_counters=counters,
            joern_server=None,
            evidence_index={"src/a.c:f": _Rec()},
        )
        assert "joern:pre_sweep" in confirmed


class TestGateResolutionIntegrity:
    """MUST-FIX: phantom coverage from a gated channel must not demote
    suspicious → clean."""

    def test_skipped_channel_not_class_covered(self):
        from core.audit.tool_coverage import is_class_covered

        chain_types = {"joern", "smt"}
        skipped = {"joern", "smt"}
        ran = chain_types - skipped
        assert not is_class_covered(
            cwe_field="CWE-78",
            mechanism="command injection via system()",
            hypothesis="attacker data reaches system()",
            available_tools={"joern": True, "smt": True},
            ran_tools=ran,
        )

    def test_tripped_gate_marks_joern_unavailable_for_coverage(self):
        # Belt-and-braces direction: even a STALE dispatch record
        # cannot claim coverage once the gate marked the channel down.
        from core.audit.tool_coverage import is_class_covered

        stale_record = {"joern"}
        assert not is_class_covered(
            cwe_field="CWE-78",
            mechanism="command injection via system()",
            hypothesis="attacker data reaches system()",
            available_tools={"joern": False},
            ran_tools=stale_record,
        )

    def test_gate_resolution_never_cleans_on_gated_channel(
        self, tmp_path, monkeypatch,
    ):
        from core.audit.orchestrator import (
            OrchestratorResult,
            ReviewOutcome,
            _resolve_gate_demoted,
        )

        monkeypatch.setattr(
            orch, "_has_mechanical_corroboration",
            lambda *a, **kw: False,
        )
        monkeypatch.setattr(
            orch, "_probe_backed_suspicious", lambda *a, **kw: False,
        )
        outcome = ReviewOutcome(
            file="a.c", function="f", status="suspicious",
            body="looks off",
            hypothesis="attacker data reaches system()", line=3,
        )
        outcome.review_result = {
            "cwe": "CWE-78",
            "mechanism": "command injection",
        }
        # Post-fix dispatch record: the gated joern step landed in
        # tools_skipped, not tools_dispatched.
        outcome.tools_dispatched = set()
        outcome.tools_skipped = {"joern"}
        result = OrchestratorResult()
        result.outcomes = [outcome]
        result.suspicious = 1
        config = orch.OrchestratorConfig(
            target_path=tmp_path, out_dir=None,
        )
        _resolve_gate_demoted(
            result, config, None, None,
            available_tools={"joern": True},
        )
        assert result.outcomes[0].status != "clean"


class TestProactiveValidationGating:
    def test_tripped_gate_skips_the_proactive_joern_leg(
        self, tmp_path, counters, monkeypatch,
    ):
        from core.audit.orchestrator import (
            ReviewOutcome,
            _proactive_validate,
        )

        cfg = _Cfg(tmp_path, unhealthy_after=1)
        cfg.joern_health.record_error("dead", key="a.c:x")
        cfg.joern_health.record_error("dead", key="a.c:y")
        assert cfg.joern_health.tripped
        monkeypatch.setattr(
            orch, "_joern_live_query",
            lambda *a, **kw: pytest.fail("dialed a tripped channel"),
        )
        outcome = ReviewOutcome(
            file="a.c", function="f", status="suspicious",
            body="looks off",
            hypothesis="attacker data reaches system()", line=3,
        )
        outcome.review_result = {
            "cwe": "CWE-78",
            "mechanism": "command injection",
        }
        result = _proactive_validate(
            outcome, cfg,
            tier_counters=counters,
            joern_server=object(),
        )
        # The gated channel must not land in the dispatch record —
        # skipped is counted, ran is not claimed.
        assert "joern" not in (result.tools_dispatched or set())
        assert counters["joern"].skipped == 1


class TestGuardVetoGating:
    def test_tripped_gate_short_circuits_the_veto(
        self, tmp_path, monkeypatch,
    ):
        cfg = _Cfg(tmp_path, unhealthy_after=1)
        cfg.joern_health.record_error("dead", key="a.c:x")
        cfg.joern_health.record_error("dead", key="a.c:y")
        monkeypatch.setattr(
            orch, "_check_sink_guarded_cached",
            lambda *a: pytest.fail("dialed a tripped channel"),
        )
        blk = _guard_blocks_promotion(
            "f", object(), None, config=cfg,
        )
        # Fail-closed is preserved — just without the doomed dial.
        assert blk == "guard-unavailable"

    def test_guard_unavailable_feeds_the_gate(
        self, tmp_path, monkeypatch,
    ):
        from core.analysis.reachability_gates import GUARD_UNAVAILABLE

        cfg = _Cfg(tmp_path, unhealthy_after=2)
        monkeypatch.setattr(
            orch, "_check_sink_guarded_cached",
            lambda *a: GUARD_UNAVAILABLE,
        )
        _guard_blocks_promotion("f", object(), None, config=cfg)
        _guard_blocks_promotion("g", object(), None, config=cfg)
        assert cfg.joern_health.tripped


class TestPerQueryBudget:
    def _server(self, size: int | None):
        return SimpleNamespace(cpg_size_bytes=lambda: size)

    def test_small_cpg_keeps_base(self, tmp_path):
        cfg = _Cfg(tmp_path)
        assert _joern_live_timeout_s(cfg, self._server(None)) == 30
        assert _joern_live_timeout_s(
            cfg, self._server(64 * 1024 * 1024),
        ) == 30

    def test_large_cpg_scales_capped(self, tmp_path):
        cfg = _Cfg(tmp_path)
        assert _joern_live_timeout_s(
            cfg, self._server(300 * 1024 * 1024),
        ) == 60
        huge = 100 * 1024 * 1024 * 1024
        assert _joern_live_timeout_s(cfg, self._server(huge)) == 120

    def test_deadline_clamps_and_skips(self, tmp_path):
        cfg = _Cfg(tmp_path)
        cfg.run_deadline_monotonic = time.monotonic() + 45
        assert _joern_live_timeout_s(
            cfg, self._server(100 * 1024 * 1024 * 1024),
        ) <= 45
        cfg.run_deadline_monotonic = time.monotonic() + 1
        assert _joern_live_timeout_s(cfg, self._server(None)) == 0


class TestDiagnosticsAndReport:
    def test_tier_diagnostics_carries_channel_health(self, tmp_path):
        counters = {"joern": TierCounters()}
        write_tier_diagnostics(
            counters, tmp_path,
            channel_health={"joern": {"tripped": True}},
        )
        data = json.loads((tmp_path / "tier-diagnostics.json").read_text())
        assert data["channel_health"]["joern"]["tripped"] is True

    def test_tier_diagnostics_omits_empty_health(self, tmp_path):
        counters = {"joern": TierCounters()}
        write_tier_diagnostics(counters, tmp_path, channel_health=None)
        data = json.loads((tmp_path / "tier-diagnostics.json").read_text())
        assert "channel_health" not in data

    def test_report_surfaces_tripped_channel(self, tmp_path):
        from core.audit.report import generate_report

        h = JoernChannelHealth(unhealthy_after=2)
        h.record_error("query timed out after 300s", key="a.c:f")
        h.record_error("query timed out after 300s", key="a.c:g")
        write_tier_diagnostics(
            {"joern": TierCounters()}, tmp_path,
            channel_health={"joern": h.to_dict()},
        )
        report = generate_report(tmp_path)
        assert report["channel_health"]["joern"]["tripped"] is True
        assert "joern channel unhealthy" in report["summary"]
        assert "Skipped is not refuted" in report["summary"]

    def test_report_quiet_when_untripped(self, tmp_path):
        from core.audit.report import generate_report

        h = JoernChannelHealth(unhealthy_after=5)
        h.record_error("one blip", key="a.c:f")
        write_tier_diagnostics(
            {"joern": TierCounters()}, tmp_path,
            channel_health={"joern": h.to_dict()},
        )
        report = generate_report(tmp_path)
        assert "channel_health" not in report
        assert "channel unhealthy" not in report["summary"]


class TestPresweepBulkBudget:
    """Pins the central derivation's shape at this call site: floor =
    configured budget (small/unknown CPGs, operator-raised budgets),
    linear in CPG size, hard cap (the old fixed 4x multiple starved a
    kernel-scale graph)."""

    def test_small_or_unknown_cpg_keeps_configured_budget(self):
        assert _presweep_bulk_timeout_s(300, None) == 300
        assert _presweep_bulk_timeout_s(300, 0) == 300
        assert _presweep_bulk_timeout_s(300, 10 * 1024 * 1024) == 300

    def test_large_cpg_scales_budget_up(self):
        # A kernel-scale (~190 MiB) CPG must clear the old fixed
        # 4x cap (1200 s) that killed its sweep, inside the hard cap.
        derived = _presweep_bulk_timeout_s(300, 190 * 1024 * 1024)
        assert derived > 4 * 300
        assert derived <= 7200

    def test_budget_is_capped(self):
        # Hostile/corrupt size input: a multi-TB claim must bound at
        # the hard cap, never mint an unbounded REPL-holding window.
        huge = 100 * 1024 * 1024 * 1024
        assert _presweep_bulk_timeout_s(300, huge) == 7200
        assert _presweep_bulk_timeout_s(300, 4 * 1024**4) == 7200

    def test_operator_raised_budget_passes_through(self):
        # The floor is the CONFIGURED budget: an operator value above
        # the derived number is never tightened by the derivation.
        assert _presweep_bulk_timeout_s(9000, 10 * 1024 * 1024) == 9000

    def test_degenerate_timeout_passthrough(self):
        assert _presweep_bulk_timeout_s(0, 10**9) == 0


class TestPresweepDeadlineClamp:
    class _Server:
        """Scripted server: first window interrupted, then recovered."""

        restarting = False
        _cpg_loaded = True

        def __init__(self):
            self.windows: list[int] = []

        def cpg_size_bytes(self):
            return None

        def ensure_alive(self):
            return True

        def query_script(self, script, timeout=300, substitutions=None):
            self.windows.append(int(timeout))
            return SimpleNamespace(errors=[], flows=[])

    def test_no_deadline_keeps_configured_window(self):
        from core.audit.sweep import run_joern_pre_sweep

        server = self._Server()
        run_joern_pre_sweep(
            Path("."), {}, server=server, query_timeout=300,
        )
        assert server.windows == [300]

    def test_window_clamped_to_remaining_budget(self):
        from core.audit.sweep import run_joern_pre_sweep

        server = self._Server()
        run_joern_pre_sweep(
            Path("."), {}, server=server, query_timeout=300,
            deadline_monotonic=time.monotonic() + 100,
        )
        assert len(server.windows) == 1
        assert server.windows[0] <= 100

    def test_exhausted_budget_skips_the_window(self):
        from core.audit.sweep import run_joern_pre_sweep

        server = self._Server()
        flows = run_joern_pre_sweep(
            Path("."), {}, server=server, query_timeout=300,
            deadline_monotonic=time.monotonic() + 5,
        )
        assert flows == {}
        assert server.windows == []


class TestPresweepRequeueClamp:
    """The composed pre-sweep worst case (window + bounded re-queues +
    recovery waits) must track the shrinking wall budget: each re-queue
    window clamps to the remainder, and both abandonment legs (floor
    breach before a re-queue, recovery wait exhausted) fire loudly."""

    class _InterruptedServer:
        """Every window times out; the server itself stays healthy."""

        restarting = False
        _cpg_loaded = True

        def __init__(self):
            self.windows: list[int] = []

        def cpg_size_bytes(self):
            return None

        def ensure_alive(self):
            return True

        def query_script(self, script, timeout=300, substitutions=None):
            self.windows.append(int(timeout))
            return SimpleNamespace(
                errors=["query timed out after 300s"], flows=[],
            )

    class _SteppedClock:
        """Advances by a fixed step on every monotonic() call, so the
        wait legs consume deterministic budget without sleeping."""

        def __init__(self, step: float):
            self.now = 0.0
            self.step = step

        def monotonic(self) -> float:
            self.now += self.step
            return self.now

        def sleep(self, _s: float) -> None:
            pass

    def _run(self, monkeypatch, deadline, step=100.0):
        import core.audit.sweep as sweep_mod
        from core.audit.sweep import run_joern_pre_sweep

        server = self._InterruptedServer()
        if deadline is not None:
            monkeypatch.setattr(
                sweep_mod, "time", self._SteppedClock(step),
            )
        run_joern_pre_sweep(
            Path("."), {}, server=server, query_timeout=300,
            deadline_monotonic=deadline,
        )
        return server

    def test_no_deadline_runs_three_raised_windows(self, monkeypatch):
        server = self._run(monkeypatch, deadline=None)
        # Initial window + both bounded re-queues. Timeout-class
        # interruptions never re-buy the identical wall: each re-queue
        # doubles the window (capped at the derivation ceiling) — the
        # timed-out wall is proven insufficient, so an identical
        # re-queue is guaranteed waste.
        assert server.windows == [300, 600, 1200]

    def test_deadline_clamps_requeue_window_then_abandons_recovery(
        self, monkeypatch, caplog,
    ):
        # Clock steps 100s per look: the first re-queue window clamps
        # to the 200s remainder; the second re-queue's recovery wait
        # is clamped so hard it exhausts, and the loud recovery
        # abandonment names the EFFECTIVE (clamped) wait.
        with caplog.at_level(logging.WARNING):
            server = self._run(monkeypatch, deadline=700.0)
        assert server.windows == [300, 200]
        msgs = [r.getMessage() for r in caplog.records]
        assert any(
            "did not recover within 100s" in m for m in msgs
        ), msgs

    def test_deadline_floor_abandons_before_requeue_submit(
        self, monkeypatch, caplog,
    ):
        # The remainder collapses below the minimum window between
        # the recovery wait and the re-queue submission — the re-queue
        # is abandoned loudly instead of submitting a doomed window.
        with caplog.at_level(logging.WARNING):
            server = self._run(monkeypatch, deadline=450.0)
        assert server.windows == [300]
        msgs = [r.getMessage() for r in caplog.records]
        assert any("below the minimum window" in m for m in msgs), msgs
