"""Tests for the raptor_agentic.py scan-phase overlap machinery.

Covers:
  1. ``_BackgroundPhase`` — result delivery, verbatim exception
     re-raise at the collection point, join idempotence, non-daemon
     worker threads (abort paths and interpreter exit both reap lane
     subprocesses instead of orphaning them).
  2. ``_join_scan_lanes`` — the deliberate-abort discipline: every
     lane is joined, unfinished lanes announce the wait on stderr.
  3. Source-level ordering contracts: the SCA and OpenAnt lanes start
     BEFORE scanner collection, their results are consumed at the
     original phase positions, OpenAnt SARIF-dedup stays after the
     scan outputs exist, and every deliberate abort out of the
     collection region joins the lanes first.
  4. Interrupt reaping: an interrupt inside one join still joins the
     remaining lanes; live lanes are registered for the
     ``_cli_entry`` Ctrl-C reap and pruned after a completed join; a
     second interrupt abandons the wait loudly without raising.
"""

from __future__ import annotations

import sys
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from unittest.mock import patch

import pytest

_RAPTOR_ROOT = Path(__file__).resolve().parents[3]


@pytest.fixture(autouse=True)
def _user_state_in_tmp(tmp_path: Path) -> Iterator[None]:
    """User registries stay out of the real home: the root-conftest
    layer doing this is stripped from release extracts (conftest.py
    is export-ignore), so the pin must travel in-file."""
    from core.testing.state_isolation import pin_user_state_dirs
    with pytest.MonkeyPatch.context() as mp:
        pin_user_state_dirs(mp, tmp_path)
        yield


def _import_agentic():
    with patch.object(sys, "path", list(sys.path)):
        if str(_RAPTOR_ROOT) not in sys.path:
            sys.path.insert(0, str(_RAPTOR_ROOT))
        import raptor_agentic
        return raptor_agentic


# ---------------------------------------------------------------------------
# _BackgroundPhase
# ---------------------------------------------------------------------------


class TestBackgroundPhase:

    def test_result_delivers_callable_return(self):
        agentic = _import_agentic()
        phase = agentic._BackgroundPhase("t-result", lambda: ("a", 2))
        assert phase.result() == ("a", 2)

    def test_exception_reraised_verbatim_at_collection(self):
        agentic = _import_agentic()
        boom = RuntimeError("lane exploded")

        def _fail():
            raise boom

        phase = agentic._BackgroundPhase("t-fail", _fail)
        with pytest.raises(RuntimeError) as exc_info:
            phase.result()
        # The SAME exception object — collection-point try/excepts
        # must classify exactly what the serial call would have raised.
        assert exc_info.value is boom

    def test_join_and_result_are_idempotent(self):
        agentic = _import_agentic()
        calls: list[int] = []

        def _once() -> int:
            calls.append(1)
            return 7

        phase = agentic._BackgroundPhase("t-idem", _once)
        phase.join()
        phase.join()
        assert phase.result() == 7
        assert phase.result() == 7
        assert calls == [1]
        assert phase.done()

    def test_deferred_lane_runs_at_collection_on_calling_thread(self):
        # overlap=False (a traced build will mutate the target tree
        # while the scanners run): the callable must not run at
        # construction or join — only at result(), synchronously on
        # the collecting thread, i.e. the shipped serial ordering.
        agentic = _import_agentic()
        ran_on: list[threading.Thread] = []

        def _probe() -> int:
            ran_on.append(threading.current_thread())
            return 11

        phase = agentic._BackgroundPhase("t-defer", _probe, overlap=False)
        phase.join()
        assert ran_on == []
        assert phase.done()  # nothing to reap on an abort path
        assert phase.result() == 11
        assert ran_on == [threading.current_thread()]

    def test_deferred_lane_reraises_verbatim(self):
        agentic = _import_agentic()
        boom = RuntimeError("deferred lane exploded")

        def _fail():
            raise boom

        phase = agentic._BackgroundPhase("t-defer-fail", _fail,
                                         overlap=False)
        with pytest.raises(RuntimeError) as exc_info:
            phase.result()
        assert exc_info.value is boom

    def test_worker_thread_is_named_and_non_daemon(self):
        agentic = _import_agentic()
        seen: dict[str, object] = {}

        def _probe() -> None:
            cur = threading.current_thread()
            seen["name"] = cur.name
            seen["daemon"] = cur.daemon

        phase = agentic._BackgroundPhase("t-probe", _probe)
        phase.join()
        assert seen["name"] == "phase-t-probe"
        # Non-daemon: interpreter exit joins the lane, so lane
        # subprocesses are reaped on every exit path, never orphaned.
        assert seen["daemon"] is False


# ---------------------------------------------------------------------------
# _join_scan_lanes
# ---------------------------------------------------------------------------


class TestJoinScanLanes:

    def test_joins_all_and_announces_unfinished(self, capsys):
        agentic = _import_agentic()
        release = threading.Event()

        def _slow() -> None:
            release.wait(timeout=10)
            time.sleep(0.05)

        slow = agentic._BackgroundPhase("slow-lane", _slow)
        fast = agentic._BackgroundPhase("fast-lane", lambda: None)
        fast.join()
        release.set()
        agentic._join_scan_lanes([slow, fast])
        assert slow.done() and fast.done()
        err = capsys.readouterr().err
        assert "slow-lane" in err
        assert "before aborting" in err
        assert "fast-lane" not in err

    def test_does_not_consume_results_or_raise(self):
        agentic = _import_agentic()

        def _fail() -> None:
            raise RuntimeError("lane failure must not mask the abort")

        phase = agentic._BackgroundPhase("failing-lane", _fail)
        # The abort wins: join only, never re-raise lane errors here.
        agentic._join_scan_lanes([phase])
        assert phase.done()

    def test_deferred_lane_never_runs_on_abort(self, capsys):
        # A deferred lane holds no thread and no subprocesses: the
        # abort discipline must neither announce a wait for it nor
        # trigger its work.
        agentic = _import_agentic()
        ran: list[int] = []

        def _work() -> None:
            ran.append(1)

        phase = agentic._BackgroundPhase("deferred-lane", _work,
                                         overlap=False)
        agentic._join_scan_lanes([phase])
        assert ran == []
        assert "deferred-lane" not in capsys.readouterr().err


# ---------------------------------------------------------------------------
# Interrupt reaping
# ---------------------------------------------------------------------------


class _StubLane:
    """Duck-typed lane for the join/reap discipline tests: raising
    KeyboardInterrupt from ``join`` models Ctrl-C landing inside the
    wait for that lane."""

    def __init__(self, name: str, exc: BaseException | None = None) -> None:
        self.name = name
        self._exc = exc
        self.joined = False

    def done(self) -> bool:
        return True

    def join(self) -> None:
        if self._exc is not None:
            raise self._exc
        self.joined = True


class TestInterruptReap:

    def test_interrupted_join_still_joins_remaining_lanes(self):
        # Ctrl-C inside the FIRST lane's join must not abandon the
        # lanes after it: the tail joins complete, then the interrupt
        # propagates.
        agentic = _import_agentic()
        ki = _StubLane("ki-lane", exc=KeyboardInterrupt())
        rest = [_StubLane("a"), _StubLane("b")]
        with pytest.raises(KeyboardInterrupt):
            agentic._join_scan_lanes([ki, *rest])
        assert all(lane.joined for lane in rest)

    def test_background_phase_registers_and_prunes_on_join(self):
        agentic = _import_agentic()
        phase = agentic._BackgroundPhase("t-registry", lambda: 11)
        assert phase in agentic._ACTIVE_SCAN_LANES
        assert phase.result() == 11
        assert phase not in agentic._ACTIVE_SCAN_LANES
        # Idempotent: a second join must not raise on the pruned entry.
        phase.join()

    def test_reap_joins_registered_lanes(self, monkeypatch):
        agentic = _import_agentic()
        left_over = _StubLane("left-over")
        monkeypatch.setattr(agentic, "_ACTIVE_SCAN_LANES", [left_over])
        agentic._reap_scan_lanes_on_interrupt()
        assert left_over.joined

    def test_second_interrupt_abandons_loudly(self, monkeypatch, capsys):
        # A second Ctrl-C during the reap wait is swallowed (exit code
        # stays 130 upstream) with a loud abandonment notice; lanes
        # after the interrupted one are still join-attempted.
        agentic = _import_agentic()
        ki = _StubLane("ki-lane", exc=KeyboardInterrupt())
        tail = _StubLane("tail")
        monkeypatch.setattr(agentic, "_ACTIVE_SCAN_LANES", [ki, tail])
        agentic._reap_scan_lanes_on_interrupt()
        assert tail.joined
        err = capsys.readouterr().err
        assert "second interrupt" in err
        assert "abandoning" in err

    def test_reap_is_noop_without_lanes(self, monkeypatch, capsys):
        agentic = _import_agentic()
        monkeypatch.setattr(agentic, "_ACTIVE_SCAN_LANES", [])
        agentic._reap_scan_lanes_on_interrupt()
        assert capsys.readouterr().err == ""


# ---------------------------------------------------------------------------
# Source-level ordering contracts
# ---------------------------------------------------------------------------


class TestOverlapOrderingContracts:

    @classmethod
    def setup_class(cls):
        cls.source = (_RAPTOR_ROOT / "raptor_agentic.py").read_text(
            encoding="utf-8")

    def test_sca_lane_starts_before_scanner_collection(self):
        start = self.source.index('_BackgroundPhase("sca"')
        collect = self.source.index("# ---- Collect Semgrep results ----")
        assert start < collect

    def test_sca_collection_stays_at_phase_1b(self):
        consume = self.source.index("_sca_bg.result()")
        codeql_collect = self.source.index(
            "# ---- Collect CodeQL results ----")
        assert consume > codeql_collect

    def test_openant_lane_starts_before_scanner_collection(self):
        start = self.source.index('_BackgroundPhase("openant"')
        collect = self.source.index("# ---- Collect Semgrep results ----")
        assert start < collect

    def test_openant_collection_precedes_banner(self):
        # A not-configured RuntimeError must keep its pre-banner
        # surface: collection re-raises before the banner prints.
        consume = self.source.index("_openant_bg.result()")
        banner = self.source.index('print("OPENANT SEMANTIC SCAN")')
        assert consume < banner

    def test_openant_dedup_waits_for_scan_outputs(self):
        # Only the SARIF-dedup step consumes scanner output — it must
        # sit after both scanner collections.
        dedup = self.source.rindex("deduplicate_with_sarif(")
        codeql_collect = self.source.index(
            "# ---- Collect CodeQL results ----")
        assert dedup > codeql_collect

    def test_openant_scan_has_no_early_dedup(self):
        # The lane body (before scanner collection) must not touch
        # dedup or the scanners' SARIF lists.
        lane_begin = self.source.index('_BackgroundPhase("openant"')
        collect = self.source.index("# ---- Collect Semgrep results ----")
        lane_region = self.source[
            self.source.index("def _openant_lane"):lane_begin]
        assert "deduplicate_with_sarif" not in lane_region
        assert "all_sarif_files" not in lane_region
        assert lane_begin < collect

    def test_traced_build_defers_every_lane(self):
        # Determinism gate: a traced/commanded CodeQL extraction
        # executes the repo's build, mutating the tree the lanes read.
        # The gate flag must consult both build triggers, the SCA and
        # OpenAnt lanes must honor it, and the Joern overlap must
        # refuse under it (its serial phase re-decides from scratch).
        gate = self.source.index("_overlap_scan_lanes = not (run_codeql")
        gate_expr = self.source[gate:gate + 160]
        assert "args.traced_build" in gate_expr
        assert "args.build_command" in gate_expr
        for lane in ('"sca"', '"openant"'):
            start = self.source.index(f"_BackgroundPhase({lane}")
            call = self.source[start:start + 160]
            assert "overlap=_overlap_scan_lanes" in call
        joern_gate = self.source.index("if _overlap_scan_lanes:")
        assert joern_gate < self.source.index("joern_concurrency_gate(",
                                              joern_gate)

    def test_every_collection_abort_joins_the_lanes(self):
        # The five deliberate aborts out of the scanner-collection
        # region (semgrep timeout / sandbox error / failure, codeql
        # sandbox error, codeql-only failure) must join the lanes so
        # no lane subprocess is orphaned by the abort.
        collect = self.source.index("# ---- Collect Semgrep results ----")
        phase_1a = self.source.index("# PHASE 1a: JOERN CPG SCAN")
        region = self.source[collect:phase_1a]
        assert region.count("_join_scan_lanes(_scan_lanes)") >= 5

    def test_cli_entry_interrupt_reaps_before_backstop(self):
        # The Ctrl-C arm of _cli_entry must reap still-live scan lanes
        # BEFORE closing the lifecycle marker: the collection-region
        # joins only cover aborts raised there, not an interrupt that
        # unwound past them.
        entry = self.source[self.source.index("def _cli_entry"):]
        reap = entry.index("_reap_scan_lanes_on_interrupt()")
        backstop = entry.index('_backstop_lifecycle("cancelled", "")')
        assert reap < backstop
