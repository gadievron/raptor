"""Tests for core.audit.cost_tracker."""

from __future__ import annotations

import json
import math

from core.audit.cost_tracker import PhaseCost, PhaseCostLedger


class TestPhaseCost:
    def test_defaults_zero(self):
        pc = PhaseCost()
        assert pc.wall_time_s == 0.0
        assert pc.calls == 0
        assert pc.cost_usd == 0.0

    def test_to_dict(self):
        pc = PhaseCost(wall_time_s=1.5, calls=3, cost_usd=0.05)
        d = pc.to_dict()
        assert d["wall_time_s"] == 1.5
        assert d["calls"] == 3
        assert d["cost_usd"] == 0.05


class TestCostTracker:
    def test_record_call(self):
        ct = PhaseCostLedger()
        ct.record_call("review", cost_usd=0.01, tokens_in=100, tokens_out=50)
        ct.record_call("review", cost_usd=0.02, tokens_in=200, tokens_out=100)
        assert ct.phases["review"].calls == 2
        assert ct.phases["review"].cost_usd == 0.03
        assert ct.phases["review"].tokens_in == 300
        assert ct.phases["review"].tokens_out == 150

    def test_total_cost(self):
        ct = PhaseCostLedger()
        ct.record_call("review", cost_usd=0.10)
        ct.record_call("refinement", cost_usd=0.05)
        ct.record_call("sweep", cost_usd=0.00)
        assert abs(ct.total_cost_usd - 0.15) < 1e-9

    def test_total_calls(self):
        ct = PhaseCostLedger()
        ct.record_call("review")
        ct.record_call("review")
        ct.record_call("sweep")
        assert ct.total_calls == 3

    def test_to_dict(self):
        ct = PhaseCostLedger()
        ct.record_call("review", cost_usd=0.01, wall_time_s=1.0)
        ct.record_call("sweep", cost_usd=0.00, wall_time_s=5.0)
        d = ct.to_dict()
        assert "phases" in d
        assert "totals" in d
        assert d["totals"]["calls"] == 2
        assert d["totals"]["cost_usd"] == 0.01

    def test_write(self, tmp_path):
        ct = PhaseCostLedger()
        ct.record_call("review", cost_usd=0.50)
        path = ct.write(tmp_path)
        assert path.exists()
        data = json.loads(path.read_text())
        assert data["totals"]["cost_usd"] == 0.50

    def test_summary(self):
        ct = PhaseCostLedger()
        ct.record_call("review", cost_usd=0.10)
        ct.record_call("refinement", cost_usd=0.05)
        s = ct.summary()
        assert "$0.15" in s
        assert "review=" in s
        assert "refinement=" in s

    def test_phase_summary(self):
        ct = PhaseCostLedger()
        ct.record_call("review", cost_usd=0.10, wall_time_s=2.0)
        text = ct.phase_summary()
        assert "review" in text
        assert "2.0s" in text

    def test_start_end_phase(self):
        ct = PhaseCostLedger()
        ct.start_phase("review")
        ct.end_phase()
        assert "review" in ct.phases
        assert ct.phases["review"].wall_time_s >= 0.0

    def test_start_phase_ends_previous(self):
        ct = PhaseCostLedger()
        ct.start_phase("review")
        ct.start_phase("sweep")
        assert "review" in ct.phases
        assert ct._active_phase == "sweep"
        ct.end_phase()
        assert "sweep" in ct.phases

    def test_empty_tracker(self):
        ct = PhaseCostLedger()
        assert ct.total_cost_usd == 0.0
        assert ct.total_calls == 0
        s = ct.summary()
        assert "$0.00" in s

    def test_serializable(self):
        ct = PhaseCostLedger()
        ct.record_call("review", cost_usd=0.01)
        json.dumps(ct.to_dict())


class TestPhaseWallClock:
    """Phase markers book wall time into cost-breakdown.json."""

    def _fake_clock(self, monkeypatch):
        import core.audit.cost_tracker as ct_mod

        state = {"now": 100.0}

        def fake_monotonic():
            return state["now"]

        monkeypatch.setattr(ct_mod.time, "monotonic", fake_monotonic)
        return state

    def test_phases_serialize_pass_wall_time(self, monkeypatch):
        clock = self._fake_clock(monkeypatch)
        ct = PhaseCostLedger()
        ct.start_phase("prep_gap_compute")
        clock["now"] += 2.5
        # Sequential marker: closes prep_gap_compute, opens the next.
        ct.start_phase("prep_triage")
        clock["now"] += 1.25
        ct.end_phase()

        d = ct.to_dict()
        assert d["phases"]["prep_gap_compute"]["pass_wall_time_s"] == 2.5
        assert d["phases"]["prep_triage"]["pass_wall_time_s"] == 1.25
        # Zero-call, wall-only phases still serialize.
        assert d["phases"]["prep_gap_compute"]["calls"] == 0
        # Marker time never lands in the PER-CALL accounting.
        assert d["phases"]["prep_gap_compute"]["wall_time_s"] == 0.0

    def test_pass_wall_never_mixes_with_call_wall(self, monkeypatch):
        """The two wall accountings stay separate: a call booked
        inside an instrumented pass keeps its per-call wall figure in
        wall_time_s, the pass keeps its boundary clock in
        pass_wall_time_s, and the totals sum them independently —
        folding them together double-counted every in-pass call."""
        clock = self._fake_clock(monkeypatch)
        ct = PhaseCostLedger()
        ct.start_phase("sweep_promotion")
        ct.record_call("sweep_promotion", cost_usd=0.01, wall_time_s=4.0)
        clock["now"] += 10.0
        ct.end_phase()

        pc = ct.phases["sweep_promotion"]
        assert pc.wall_time_s == 4.0
        assert pc.pass_wall_time_s == 10.0
        d = ct.to_dict()
        assert d["totals"]["wall_time_s"] == 4.0
        assert d["totals"]["pass_wall_time_s"] == 10.0

    def test_boundary_attribution_binds_the_middle_end(self, monkeypatch):
        """Time between an ended pass and the next start is
        unattributed — deleting a middle end_phase() would smear the
        gap into the earlier pass."""
        clock = self._fake_clock(monkeypatch)
        ct = PhaseCostLedger()
        ct.start_phase("pass_x")
        clock["now"] += 1.0
        ct.end_phase()
        clock["now"] += 5.0  # un-instrumented gap
        ct.start_phase("pass_y")
        clock["now"] += 2.0
        ct.end_phase()

        assert ct.phases["pass_x"].pass_wall_time_s == 1.0
        assert ct.phases["pass_y"].pass_wall_time_s == 2.0
        assert ct.total_pass_wall_time_s == 3.0

    def test_end_phase_without_active_is_a_noop(self):
        ct = PhaseCostLedger()
        ct.end_phase()
        assert ct.phases == {}

    def test_repeated_phase_accumulates(self, monkeypatch):
        clock = self._fake_clock(monkeypatch)
        ct = PhaseCostLedger()
        for _ in range(2):
            ct.start_phase("sweep_promotion")
            clock["now"] += 1.0
            ct.end_phase()
        assert ct.phases["sweep_promotion"].pass_wall_time_s == 2.0

    def test_markers_tolerate_concurrent_record_call(self):
        """Serial phase markers on the main thread + record_call from
        parallel workers: no deadlock, no lost bookings. (Two threads
        MARKING phases is unsupported by design — single slot.)"""
        import threading

        ct = PhaseCostLedger()
        stop = threading.Event()

        def worker():
            while not stop.is_set():
                ct.record_call("review", cost_usd=0.001, wall_time_s=0.01)

        threads = [threading.Thread(target=worker) for _ in range(4)]
        for t in threads:
            t.start()
        for i in range(200):
            ct.start_phase(f"pass_{i % 3}")
        ct.end_phase()
        stop.set()
        for t in threads:
            t.join(timeout=10)
            assert not t.is_alive()

        calls = ct.phases["review"].calls
        assert calls > 0
        # Total-magnitude-scaled closeness: repeated float ``+=``
        # drift is QUADRATIC in the booking count (measured ~1.7e-8
        # absolute at 1e6 bookings, ~5.6e-7 at 5e6), so any fixed
        # epsilon — and any bound linear in calls (crossed near 6e7
        # bookings) — fails on a loaded runner where the marker loop
        # runs long enough for the spinning workers to record
        # millions of bookings. rel_tol = calls * 2**-52 is the
        # standard recursive-summation error bound (~6x above the
        # measured drift); one LOST booking stays outside it for any
        # count the loop can physically reach.
        assert math.isclose(
            ct.phases["review"].cost_usd, calls * 0.001,
            rel_tol=calls * 2**-52, abs_tol=1e-9,
        )
        assert ct._active_phase is None


class TestEndOfRunBookingLocks:
    """book_prior_segments / book_unbooked_classes / to_dict mutate or
    iterate the same ``phases`` map the lock-protected hot path
    (record_call) mutates from workers — they must take the ledger
    lock, not rely on an unstated end-of-run-serial convention (the
    mid-run cadence tick serialises to_dict while the loop is still
    reviewing)."""

    class _SpyLock:
        def __init__(self):
            self.acquisitions = 0

        def __enter__(self):
            self.acquisitions += 1
            return self

        def __exit__(self, *exc):
            return False

    def _spied(self):
        ledger = PhaseCostLedger()
        spy = self._SpyLock()
        object.__setattr__(ledger, "_lock", spy)
        return ledger, spy

    def test_book_prior_segments_takes_the_lock(self):
        ledger, spy = self._spied()
        ledger.book_prior_segments(1.25, segment=2)
        assert spy.acquisitions == 1

    def test_book_unbooked_classes_takes_the_lock(self):
        ledger, spy = self._spied()
        ledger.book_unbooked_classes({"iris": (3, 0.5)})
        assert spy.acquisitions == 1

    def test_to_dict_takes_the_lock(self):
        ledger, spy = self._spied()
        ledger.to_dict()
        assert spy.acquisitions == 1
