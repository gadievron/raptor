"""Tests for core.audit.environment: preflight floors, the resource
watchdog (pause/resume hysteresis, bounded-wait conclude), and the
systemic-fault circuit breaker."""

from __future__ import annotations

import errno
import json
import threading as _threading
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from core.audit.environment import (
    BREAKER_MAX_PROBE_WAIT_S,
    BREAKER_TRIP_COUNT,
    BREAKER_WINDOW,
    CLASS_AUTH,
    CLASS_DISK,
    CLASS_FDS,
    CLASS_MEMORY,
    CLASS_NETWORK,
    PREFLIGHT_REFUSE_FREE_BYTES,
    PREFLIGHT_REFUSE_FREE_INODES,
    PREFLIGHT_WARN_FREE_BYTES,
    WATCHDOG_CHECK_INTERVAL_S,
    WATCHDOG_MAX_PAUSE_S,
    WATCHDOG_PAUSE_FREE_BYTES,
    WATCHDOG_RESUME_FREE_BYTES,
    EnvironmentGuard,
    EnvironmentPreflightError,
    classify_systemic,
    note_dispatch_failure,
    preflight_environment,
)

GIB = 1024 * 1024 * 1024


def _stat(free_bytes: int, free_inodes: int = 1_000_000,
          total_inodes: int = 2_000_000,
          total_bytes: int = 64 * 1024 * 1024 * 1024) -> SimpleNamespace:
    return SimpleNamespace(
        f_bavail=free_bytes, f_frsize=1, f_blocks=total_bytes,
        f_favail=free_inodes, f_files=total_inodes,
    )


class _FakeFs:
    """statvfs stub returning a mutable per-call state."""

    def __init__(self, stat: SimpleNamespace) -> None:
        self.stat = stat
        self.calls = 0

    def __call__(self, path: str) -> SimpleNamespace:
        self.calls += 1
        return self.stat


class _Clock:
    def __init__(self) -> None:
        self.t = 0.0

    def __call__(self) -> float:
        return self.t

    def sleep(self, s: float) -> None:
        self.t += s


class _BarrierFs(_FakeFs):
    """``_FakeFs`` with measurement barriers.

    Real-thread tests wait for the worker to demonstrably reach a
    loop (its statvfs measurement observed) instead of sleeping a
    wall-clock guess and asserting a state the thread may not have
    reached yet — a stalled thread start made those asserts pass for
    the wrong reason, and latency bounds measured scheduler load, not
    guard logic."""

    def __init__(self, stat: SimpleNamespace) -> None:
        super().__init__(stat)
        self.guard: EnvironmentGuard | None = None
        #: any measurement at all (the breaker's probe loop measures
        #: on its first probe attempt, before any sleep)
        self.first_measure = _threading.Event()
        #: a measurement taken while the guard was paused — only the
        #: watchdog wait loop measures in that state
        self.paused_measure = _threading.Event()
        self._cond = _threading.Condition()
        self._measured_threads: set[_threading.Thread] = set()

    def __call__(self, path: str) -> SimpleNamespace:
        self.first_measure.set()
        g = self.guard
        if g is not None and g._paused:
            self.paused_measure.set()
        with self._cond:
            self._measured_threads.add(_threading.current_thread())
            self._cond.notify_all()
        return super().__call__(path)

    def wait_for_thread(self, th: _threading.Thread,
                        timeout: float = 10.0) -> bool:
        """True once *th* has taken a measurement (i.e. reached a
        code path that measures); False on timeout."""
        with self._cond:
            return self._cond.wait_for(
                lambda: th in self._measured_threads, timeout)


# ── Preflight ─────────────────────────────────────────────────────────


class TestPreflight:
    def test_healthy_passes_silently(self, caplog):
        fs = _FakeFs(_stat(4 * GIB))
        with caplog.at_level("WARNING"):
            preflight_environment([Path("/x")], statvfs_fn=fs)
        assert not caplog.records

    def test_refuses_below_byte_floor(self):
        fs = _FakeFs(_stat(PREFLIGHT_REFUSE_FREE_BYTES - 1))
        with pytest.raises(EnvironmentPreflightError) as ei:
            preflight_environment([Path("/x")], statvfs_fn=fs)
        # Loud: the measured numbers and the path are in the message.
        assert "/x" in str(ei.value)
        assert "MiB free" in str(ei.value)

    def test_refuses_below_inode_floor(self):
        fs = _FakeFs(_stat(4 * GIB, free_inodes=PREFLIGHT_REFUSE_FREE_INODES - 1))
        with pytest.raises(EnvironmentPreflightError) as ei:
            preflight_environment([Path("/x")], statvfs_fn=fs)
        assert "free inodes" in str(ei.value)

    def test_warns_between_floors_and_continues(self, caplog):
        fs = _FakeFs(_stat(PREFLIGHT_WARN_FREE_BYTES - 1))
        with caplog.at_level("WARNING"):
            preflight_environment([Path("/x")], statvfs_fn=fs)
        assert any("low" in r.message for r in caplog.records)

    def test_inode_unlimited_fs_never_trips_inode_floor(self):
        # btrfs-style: f_files == 0 means "no inode accounting", not
        # "zero inodes left".
        fs = _FakeFs(_stat(4 * GIB, free_inodes=0, total_inodes=0))
        preflight_environment([Path("/x")], statvfs_fn=fs)

    def test_unmeasurable_path_is_skipped(self):
        def _raise(path: str) -> SimpleNamespace:
            raise OSError("no such filesystem")

        preflight_environment([Path("/x")], statvfs_fn=_raise)

    def test_no_statvfs_degrades_to_noop(self, monkeypatch):
        import core.audit.environment as env

        monkeypatch.setattr(env, "_default_statvfs", lambda: None)
        preflight_environment([Path("/x")])


# ── Watchdog ──────────────────────────────────────────────────────────


def _guard(fs: Any, clock: _Clock, **kw: Any) -> EnvironmentGuard:
    return EnvironmentGuard(
        tmp_dir=Path("/x"),
        clock=clock,
        sleep_fn=clock.sleep,
        statvfs_fn=fs,
        **kw,
    )


class TestWatchdog:
    def test_healthy_tick_is_cheap_and_rate_limited(self):
        clock = _Clock()
        fs = _FakeFs(_stat(4 * GIB))
        g = _guard(fs, clock)
        g.tick()
        first = fs.calls
        assert first >= 1
        g.tick()  # within the interval: no re-measure
        assert fs.calls == first
        clock.t += WATCHDOG_CHECK_INTERVAL_S + 0.1
        g.tick()
        assert fs.calls > first
        assert not g.concluded

    def test_pause_then_recovery_above_resume_floor(self):
        clock = _Clock()
        fs = _FakeFs(_stat(WATCHDOG_PAUSE_FREE_BYTES - 1))

        real_sleep = clock.sleep

        def recovering_sleep(s: float) -> None:
            real_sleep(s)
            if clock.t >= 20.0:
                fs.stat = _stat(WATCHDOG_RESUME_FREE_BYTES + 1)

        g = EnvironmentGuard(
            tmp_dir=Path("/x"), clock=clock,
            sleep_fn=recovering_sleep, statvfs_fn=fs,
        )
        g.tick()
        assert not g.concluded
        assert clock.t < WATCHDOG_MAX_PAUSE_S  # resumed, not timed out

    def test_hysteresis_between_pause_and_resume_floor_stays_paused(self):
        # Recovery to just above the PAUSE floor is not enough — the
        # resume floor is 2x (hysteresis), so the guard keeps waiting
        # and eventually concludes.
        clock = _Clock()
        fs = _FakeFs(_stat(WATCHDOG_PAUSE_FREE_BYTES - 1))

        real_sleep = clock.sleep

        def partial_recovery_sleep(s: float) -> None:
            real_sleep(s)
            fs.stat = _stat(WATCHDOG_PAUSE_FREE_BYTES + 1)

        g = EnvironmentGuard(
            tmp_dir=Path("/x"), clock=clock,
            sleep_fn=partial_recovery_sleep, statvfs_fn=fs,
        )
        g.tick()
        assert g.concluded
        assert "resource pressure" in g.conclude_reason

    def test_bounded_pause_concludes_with_reason(self):
        clock = _Clock()
        fs = _FakeFs(_stat(WATCHDOG_PAUSE_FREE_BYTES - 1))
        g = _guard(fs, clock)
        g.tick()
        assert g.concluded
        assert "/x" in g.conclude_reason
        assert clock.t >= WATCHDOG_MAX_PAUSE_S
        # A concluded guard never re-enters the pause loop.
        t = clock.t
        g.tick()
        assert clock.t == t

    def test_inode_pressure_pauses_too(self):
        clock = _Clock()
        fs = _FakeFs(_stat(4 * GIB, free_inodes=1))
        g = _guard(fs, clock)
        g.tick()
        assert g.concluded
        assert "inodes" in g.conclude_reason

    def test_abort_check_exits_pause_without_conclude(self):
        clock = _Clock()
        fs = _FakeFs(_stat(WATCHDOG_PAUSE_FREE_BYTES - 1))
        aborted = {"v": False}
        g = _guard(fs, clock, abort_check=lambda: aborted["v"])

        real_sleep = clock.sleep

        def aborting_sleep(s: float) -> None:
            real_sleep(s)
            aborted["v"] = True

        g._sleep = aborting_sleep
        g.tick()
        # The shutdown rails own the conclusion; the guard stands down.
        assert not g.concluded

    def test_no_statvfs_degrades_to_noop(self):
        clock = _Clock()
        g = EnvironmentGuard(
            tmp_dir=Path("/x"), clock=clock,
            sleep_fn=clock.sleep, statvfs_fn=None,
        )
        # statvfs_fn=None falls back to the platform default; force
        # the degraded state directly.
        g._statvfs = None
        g.tick()
        assert not g.concluded


# ── Systemic classification ──────────────────────────────────────────


def _oserror(eno: int, filename: str | None = None) -> OSError:
    return OSError(eno, "synthetic", filename)


def _wrapped(eno: int) -> RuntimeError:
    exc = RuntimeError("dispatch failed")
    exc.__cause__ = _oserror(eno)
    return exc


def _auth_error() -> RuntimeError:
    exc = RuntimeError("request rejected")
    exc.status_code = 401
    return exc


class TestClassifySystemic:
    def test_disk_errnos_direct_and_chained(self):
        assert classify_systemic(_oserror(errno.ENOSPC)) == CLASS_DISK
        assert classify_systemic(_oserror(errno.EDQUOT)) == CLASS_DISK
        assert classify_systemic(_oserror(errno.EROFS)) == CLASS_DISK
        assert classify_systemic(_wrapped(errno.ENOSPC)) == CLASS_DISK

    def test_fd_memory_network(self):
        assert classify_systemic(_oserror(errno.EMFILE)) == CLASS_FDS
        assert classify_systemic(_oserror(errno.ENFILE)) == CLASS_FDS
        assert classify_systemic(_oserror(errno.ENOMEM)) == CLASS_MEMORY
        assert classify_systemic(_oserror(errno.ECONNREFUSED)) == CLASS_NETWORK

    def test_dns_failures_are_network(self):
        import socket

        assert classify_systemic(socket.gaierror(-2, "no name")) == CLASS_NETWORK

    def test_network_counts_on_cause_chain(self):
        # The wrapped shape a real transport connect failure arrives
        # in: RuntimeError raised `from` the ECONNREFUSED OSError.
        exc = RuntimeError("dispatch failed")
        exc.__cause__ = _oserror(errno.ECONNREFUSED)
        assert classify_systemic(exc) == CLASS_NETWORK

    def test_network_in_implicit_context_is_not_network(self):
        # A TimeoutError raised while an ECONNREFUSED was being
        # handled (implicit __context__) is a timeout: classifying it
        # network would strip the timeout's reduced-context retry.
        exc = TimeoutError("review call timed out")
        exc.__context__ = _oserror(errno.ECONNREFUSED)
        assert classify_systemic(exc) is None

    def test_disk_still_counts_via_context(self):
        # Disk errnos keep the full-chain walk: an error raised while
        # HANDLING an ENOSPC is still an ENOSPC environment.
        exc = RuntimeError("journal append failed")
        exc.__context__ = _oserror(errno.ENOSPC)
        assert classify_systemic(exc) == CLASS_DISK

    def test_auth_refusal_via_client_taxonomy(self):
        assert classify_systemic(_auth_error()) == CLASS_AUTH

    def test_budget_never_systemic(self):
        from core.llm.client import LLMBudgetExceededError

        assert classify_systemic(
            LLMBudgetExceededError("LLM budget exceeded"),
        ) is None
        assert classify_systemic(
            RuntimeError("LLM budget exceeded: cap reached"),
        ) is None

    def test_refusal_and_schema_never_systemic(self):
        assert classify_systemic(RuntimeError("model refused")) is None
        try:
            json.loads("{nope")
        except json.JSONDecodeError as exc:
            assert classify_systemic(exc) is None

    def test_ordinary_oserror_not_systemic(self):
        assert classify_systemic(_oserror(errno.ENOENT)) is None


# ── Circuit breaker ───────────────────────────────────────────────────


class TestCircuitBreaker:
    def _fail(self, g: EnvironmentGuard, exc: BaseException,
              n: int = BREAKER_TRIP_COUNT, prefix: str = "f") -> None:
        for i in range(n):
            g.note_dispatch_failure(f"a.py:{prefix}{i}", exc)

    def test_trips_on_homogeneous_window_and_probe_recovers(self, tmp_path):
        clock = _Clock()
        fs = _FakeFs(_stat(4 * GIB))
        g = EnvironmentGuard(
            tmp_dir=tmp_path, clock=clock,
            sleep_fn=clock.sleep, statvfs_fn=fs,
        )
        self._fail(g, _wrapped(errno.ENOSPC))
        assert g._tripped_class == CLASS_DISK
        g.tick()  # probe: statvfs healthy + canary write in tmp_path
        assert not g.concluded
        assert g._tripped_class is None
        assert not g._window  # recovery resets the window

    def test_does_not_trip_on_repeats_of_one_function(self):
        g = EnvironmentGuard(tmp_dir=Path("/x"), statvfs_fn=None)
        for _ in range(BREAKER_WINDOW):
            g.note_dispatch_failure("a.py:same", _wrapped(errno.ENOSPC))
        assert g._tripped_class is None

    def test_does_not_trip_on_mixed_classes(self):
        g = EnvironmentGuard(tmp_dir=Path("/x"), statvfs_fn=None)
        g.note_dispatch_failure("a.py:f1", _wrapped(errno.ENOSPC))
        g.note_dispatch_failure("a.py:f2", _wrapped(errno.EMFILE))
        g.note_dispatch_failure("a.py:f3", _wrapped(errno.ENOSPC))
        g.note_dispatch_failure("a.py:f4", _wrapped(errno.EMFILE))
        g.note_dispatch_failure("a.py:f5", _wrapped(errno.ENOSPC))
        g.note_dispatch_failure("a.py:f6", _wrapped(errno.EMFILE))
        assert g._tripped_class is None

    def test_does_not_trip_on_budget_or_refusal_failures(self):
        from core.llm.client import LLMBudgetExceededError

        g = EnvironmentGuard(tmp_dir=Path("/x"), statvfs_fn=None)
        self._fail(g, LLMBudgetExceededError("LLM budget exceeded"),
                   n=BREAKER_WINDOW)
        assert g._tripped_class is None
        self._fail(g, RuntimeError("model refused"), n=BREAKER_WINDOW,
                   prefix="r")
        assert g._tripped_class is None

    def test_heterogeneous_dilution_prevents_trip(self):
        # A non-systemic failure inside the window keeps the systemic
        # count below the trip threshold.
        g = EnvironmentGuard(tmp_dir=Path("/x"), statvfs_fn=None)
        self._fail(g, _wrapped(errno.ENOSPC), n=BREAKER_TRIP_COUNT - 1)
        g.note_dispatch_failure("a.py:other", RuntimeError("parse error"))
        g.note_dispatch_failure("a.py:more", RuntimeError("parse error"))
        assert g._tripped_class is None

    def test_probe_failure_concludes_after_bounded_wait(self, tmp_path):
        clock = _Clock()
        fs = _FakeFs(_stat(WATCHDOG_PAUSE_FREE_BYTES - 1))
        g = EnvironmentGuard(
            tmp_dir=tmp_path, clock=clock,
            sleep_fn=clock.sleep, statvfs_fn=fs,
        )
        self._fail(g, _wrapped(errno.ENOSPC))
        g.tick()
        assert g.concluded
        assert CLASS_DISK in g.conclude_reason
        assert clock.t >= BREAKER_MAX_PROBE_WAIT_S

    def test_auth_trip_is_non_recoverable(self):
        clock = _Clock()
        g = EnvironmentGuard(
            tmp_dir=Path("/x"), clock=clock,
            sleep_fn=clock.sleep, statvfs_fn=None,
        )
        self._fail(g, _auth_error())
        assert g._tripped_class == CLASS_AUTH
        g.tick()
        assert g.concluded
        assert CLASS_AUTH in g.conclude_reason
        assert clock.t == 0.0  # no probe loop: concluded immediately

    def test_fd_probe_recovers(self):
        clock = _Clock()
        g = EnvironmentGuard(
            tmp_dir=Path("/x"), clock=clock,
            sleep_fn=clock.sleep, statvfs_fn=None,
        )
        self._fail(g, _wrapped(errno.EMFILE))
        assert g._tripped_class == CLASS_FDS
        g.tick()  # os.open(devnull) succeeds here
        assert not g.concluded
        assert g._tripped_class is None

    def test_disabled_breaker_never_trips(self):
        g = EnvironmentGuard(
            tmp_dir=Path("/x"), statvfs_fn=None, breaker_enabled=False,
        )
        self._fail(g, _wrapped(errno.ENOSPC), n=BREAKER_WINDOW)
        assert g._tripped_class is None
        assert not g._window

    def test_disk_probe_prefers_implicated_dir(self, tmp_path):
        # The exception names a file: its parent joins the probe set.
        clock = _Clock()
        fs = _FakeFs(_stat(4 * GIB))
        g = EnvironmentGuard(
            tmp_dir=tmp_path, clock=clock,
            sleep_fn=clock.sleep, statvfs_fn=fs,
        )
        implicated = tmp_path / "staging"
        implicated.mkdir()
        exc = RuntimeError("dispatch failed")
        exc.__cause__ = _oserror(
            errno.ENOSPC, str(implicated / "cc-file.txt"),
        )
        self._fail(g, exc)
        assert g._trip_hint_dir == implicated
        g.tick()
        assert g._tripped_class is None

    def test_hint_unwritable_but_guard_dirs_healthy_recovers(self, tmp_path):
        # A contained hint dir that stays unwritable while tmp and out
        # are healthy is read-only-by-design (or swept away) — it must
        # not hold the pause to its full bound and conclude the run.
        clock = _Clock()
        fs = _FakeFs(_stat(4 * GIB))
        g = EnvironmentGuard(
            tmp_dir=tmp_path, clock=clock,
            sleep_fn=clock.sleep, statvfs_fn=fs,
        )
        staging = tmp_path / "staging"
        staging.mkdir()
        exc = RuntimeError("dispatch failed")
        exc.__cause__ = _oserror(errno.ENOSPC, str(staging / "f.txt"))
        self._fail(g, exc)
        assert g._trip_hint_dir == staging
        staging.rmdir()  # now unwritable/gone; tmp_path stays healthy
        g.tick()
        assert not g.concluded
        assert g._tripped_class is None

    def test_note_helper_noops_without_guard(self):
        config = SimpleNamespace()
        note_dispatch_failure(config, "a.py:f", _wrapped(errno.ENOSPC))

    def test_note_helper_feeds_config_guard(self):
        g = EnvironmentGuard(tmp_dir=Path("/x"), statvfs_fn=None)
        config = SimpleNamespace(environment_guard_state=g)
        for i in range(BREAKER_TRIP_COUNT):
            note_dispatch_failure(
                config, f"a.py:f{i}", _wrapped(errno.ENOSPC),
            )
        assert g._tripped_class == CLASS_DISK


# ── Canary-probe containment ─────────────────────────────────────────


class TestFaultDirHintContainment:
    """The disk probe WRITES a canary in the hinted directory — the
    hint must never escape the guard's own dirs (a probe write inside
    the scanned target, through a planted symlink, or into the
    harness CWD is a write into attacker-influenceable space)."""

    def _trip(self, g: "EnvironmentGuard", exc: BaseException) -> None:
        for i in range(BREAKER_TRIP_COUNT):
            g.note_dispatch_failure(f"a.py:f{i}", exc)

    def _probed_dirs(self, monkeypatch) -> list:
        from contextlib import contextmanager
        import core.audit.environment as env_mod

        recorded: list = []
        real = env_mod.temporary_text

        @contextmanager
        def rec(*args: Any, **kwargs: Any):
            with real(*args, **kwargs) as path:
                recorded.append(path.parent.resolve())
                yield path

        monkeypatch.setattr(env_mod, "temporary_text", rec)
        return recorded

    def test_chained_context_target_path_is_ignored(self, tmp_path):
        # An unrelated FileNotFoundError from the scanned target joins
        # the chain via implicit __context__ during ENOSPC handling —
        # its filename must not become the probe dir.
        guard_tmp = tmp_path / "guard"
        guard_tmp.mkdir()
        target = tmp_path / "target"
        target.mkdir()
        g = EnvironmentGuard(
            tmp_dir=guard_tmp, statvfs_fn=_FakeFs(_stat(4 * GIB)),
        )
        fnf = FileNotFoundError(
            errno.ENOENT, "missing", str(target / "cfg.json"),
        )
        enospc = _oserror(errno.ENOSPC)  # the disk error names no file
        enospc.__context__ = fnf
        exc = RuntimeError("dispatch failed")
        exc.__cause__ = enospc
        self._trip(g, exc)
        assert g._tripped_class == CLASS_DISK
        assert g._trip_hint_dir is None

    def test_symlinked_dir_inside_target_is_rejected(
        self, tmp_path, monkeypatch,
    ):
        # The disk error names a file under an attacker-planted
        # symlink inside the target pointing at an arbitrary outside
        # dir — no canary may be written through it.
        guard_tmp = tmp_path / "guard"
        guard_tmp.mkdir()
        outside = tmp_path / "outside"
        outside.mkdir()
        target = tmp_path / "target"
        target.mkdir()
        (target / "evil").symlink_to(outside)
        clock = _Clock()
        g = EnvironmentGuard(
            tmp_dir=guard_tmp, clock=clock, sleep_fn=clock.sleep,
            statvfs_fn=_FakeFs(_stat(4 * GIB)),
        )
        exc = RuntimeError("dispatch failed")
        exc.__cause__ = _oserror(
            errno.ENOSPC, str(target / "evil" / "cc-file.txt"),
        )
        self._trip(g, exc)
        assert g._trip_hint_dir is None
        probed = self._probed_dirs(monkeypatch)
        g.tick()  # healthy: probe recovers via the guard dirs only
        assert not g.concluded
        assert probed
        allowed = guard_tmp.resolve()
        for d in probed:
            assert d == allowed or allowed in d.parents
        assert outside.resolve() not in probed

    def test_relative_filename_never_probes_cwd(
        self, tmp_path, monkeypatch,
    ):
        # A relative filename resolves against the harness CWD — the
        # hint must be dropped, not turned into Path('.').
        guard_tmp = tmp_path / "guard"
        guard_tmp.mkdir()
        cwd = tmp_path / "cwd"
        cwd.mkdir()
        monkeypatch.chdir(cwd)
        clock = _Clock()
        g = EnvironmentGuard(
            tmp_dir=guard_tmp, clock=clock, sleep_fn=clock.sleep,
            statvfs_fn=_FakeFs(_stat(4 * GIB)),
        )
        exc = RuntimeError("dispatch failed")
        exc.__cause__ = _oserror(errno.ENOSPC, "cc-file.txt")
        self._trip(g, exc)
        assert g._trip_hint_dir is None
        probed = self._probed_dirs(monkeypatch)
        g.tick()
        assert not g.concluded
        assert cwd.resolve() not in probed


# ── Run-deadline clamp ───────────────────────────────────────────────


class TestDeadlineClamp:
    """Pause/probe waits are clamped to the run deadline minus the
    drain margin — a pause entered near the wall cap concludes with
    room to drain and report instead of blocking into the
    supervisor's kill, and cumulative pauses can never overshoot
    ``--max-time``."""

    _MARGIN = 300.0

    def _deadline_guard(self, fs: Any, clock: _Clock,
                        deadline: float) -> EnvironmentGuard:
        return EnvironmentGuard(
            tmp_dir=Path("/x"), clock=clock, sleep_fn=clock.sleep,
            statvfs_fn=fs, deadline_monotonic=deadline,
            drain_margin_s=self._MARGIN,
        )

    def test_pause_near_deadline_concludes_before_it(self):
        clock = _Clock()
        deadline = 100.0 + self._MARGIN  # 100s of room, << 600s bound
        fs = _FakeFs(_stat(WATCHDOG_PAUSE_FREE_BYTES - 1))
        g = self._deadline_guard(fs, clock, deadline)
        g.tick()
        assert g.concluded
        assert clock.t < deadline  # concluded BEFORE the deadline
        assert clock.t < WATCHDOG_MAX_PAUSE_S  # never took the full bound
        assert "deadline" in g.conclude_reason

    def test_no_room_left_concludes_without_waiting(self):
        clock = _Clock()
        clock.t = 50.0
        fs = _FakeFs(_stat(WATCHDOG_PAUSE_FREE_BYTES - 1))
        g = self._deadline_guard(fs, clock, 50.0 + self._MARGIN - 1.0)
        g.tick()
        assert g.concluded
        assert clock.t == 50.0  # no sleep at all

    def test_breaker_probe_clamped_to_deadline(self, tmp_path):
        clock = _Clock()
        deadline = 100.0 + self._MARGIN
        fs = _FakeFs(_stat(WATCHDOG_PAUSE_FREE_BYTES - 1))
        g = self._deadline_guard(fs, clock, deadline)
        for i in range(BREAKER_TRIP_COUNT):
            g.note_dispatch_failure(f"a.py:f{i}", _wrapped(errno.ENOSPC))
        g.tick()
        assert g.concluded
        assert clock.t < deadline
        assert clock.t < BREAKER_MAX_PROBE_WAIT_S

    def test_cumulative_pauses_cannot_exceed_deadline(self):
        # Oscillating filesystem: each pause recovers, pressure comes
        # back, a fresh pause begins. Without the deadline clamp every
        # cycle re-bought the full 600s; with it the clock (which runs
        # THROUGH pauses) caps the total at the deadline.
        clock = _Clock()
        deadline = 900.0 + self._MARGIN
        fs = _FakeFs(_stat(WATCHDOG_PAUSE_FREE_BYTES - 1))

        real_sleep = clock.sleep
        state = {"recover_at": 20.0}

        def oscillating_sleep(s: float) -> None:
            real_sleep(s)
            if clock.t >= state["recover_at"]:
                fs.stat = _stat(WATCHDOG_RESUME_FREE_BYTES + 1)

        g = EnvironmentGuard(
            tmp_dir=Path("/x"), clock=clock, sleep_fn=oscillating_sleep,
            statvfs_fn=fs, deadline_monotonic=deadline,
            drain_margin_s=self._MARGIN,
        )
        cycles = 0
        while not g.concluded and cycles < 500:
            fs.stat = _stat(WATCHDOG_PAUSE_FREE_BYTES - 1)  # pressure back
            state["recover_at"] = clock.t + 20.0
            clock.t += WATCHDOG_CHECK_INTERVAL_S + 0.1
            g.tick()
            cycles += 1
        assert g.concluded
        assert clock.t <= deadline
        assert cycles > 1  # genuinely oscillated before concluding

    def test_behavior_unchanged_without_deadline(self):
        clock = _Clock()
        fs = _FakeFs(_stat(WATCHDOG_PAUSE_FREE_BYTES - 1))
        g = _guard(fs, clock)  # no deadline
        g.tick()
        assert g.concluded
        assert clock.t >= WATCHDOG_MAX_PAUSE_S  # full bound, as before


# ── Operator floor override ──────────────────────────────────────────


class TestFloorOverride:
    """RAPTOR_ENV_FLOOR_MIB is the sanctioned way to run on a
    deliberately tight filesystem (container tmpfs)."""

    def test_preflight_refuses_then_override_admits(self, monkeypatch):
        fs = _FakeFs(_stat(16 * 1024 * 1024))  # 16 MiB free
        with pytest.raises(EnvironmentPreflightError):
            preflight_environment([Path("/x")], statvfs_fn=fs)
        monkeypatch.setenv("RAPTOR_ENV_FLOOR_MIB", "8")
        preflight_environment([Path("/x")], statvfs_fn=fs)

    def test_override_still_refuses_below_it(self, monkeypatch):
        monkeypatch.setenv("RAPTOR_ENV_FLOOR_MIB", "8")
        fs = _FakeFs(_stat(4 * 1024 * 1024))  # 4 MiB < 8 MiB floor
        with pytest.raises(EnvironmentPreflightError) as ei:
            preflight_environment([Path("/x")], statvfs_fn=fs)
        assert "RAPTOR_ENV_FLOOR_MIB" in str(ei.value)

    def test_zero_disables_byte_floors(self, monkeypatch):
        monkeypatch.setenv("RAPTOR_ENV_FLOOR_MIB", "0")
        fs = _FakeFs(_stat(0))
        preflight_environment([Path("/x")], statvfs_fn=fs)
        clock = _Clock()
        g = _guard(fs, clock)
        g.tick()
        assert not g.concluded  # watchdog byte floor disabled too

    def test_watchdog_pause_floor_overridden(self, monkeypatch):
        monkeypatch.setenv("RAPTOR_ENV_FLOOR_MIB", "8")
        clock = _Clock()
        # 16 MiB free: below the default 64 MiB pause floor, above the
        # 8 MiB override — no pause.
        fs = _FakeFs(_stat(16 * 1024 * 1024))
        g = _guard(fs, clock)
        g.tick()
        assert not g.concluded
        assert clock.t == 0.0  # never paused

    def test_invalid_override_keeps_defaults(self, monkeypatch):
        monkeypatch.setenv("RAPTOR_ENV_FLOOR_MIB", "lots")
        fs = _FakeFs(_stat(PREFLIGHT_REFUSE_FREE_BYTES - 1))
        with pytest.raises(EnvironmentPreflightError):
            preflight_environment([Path("/x")], statvfs_fn=fs)


# ── Resume-floor reachability clamp ──────────────────────────────────


class TestResumeFloorClamp:
    _MIB = 1024 * 1024

    def test_small_fs_recovery_is_reachable_and_stays_resumed(self):
        # Filesystem total (100 MiB) below the configured resume floor
        # (128 MiB): the clamps (resume = half of total = 50 MiB,
        # pause = quarter = 25 MiB) make genuine recovery detectable
        # instead of guaranteeing a full pause + conclude — and the
        # recovered state must SURVIVE the next measuring tick.
        total = 100 * self._MIB
        assert total < WATCHDOG_RESUME_FREE_BYTES
        clock = _Clock()
        # 10 MiB free: below the clamped 25 MiB pause floor.
        fs = _FakeFs(_stat(10 * self._MIB, total_bytes=total))

        real_sleep = clock.sleep
        sleeps = {"n": 0}

        def recovering_sleep(s: float) -> None:
            sleeps["n"] += 1
            real_sleep(s)
            if clock.t >= 20.0:
                # 60 MiB free: above half-of-total (50 MiB), below the
                # unclamped 128 MiB floor.
                fs.stat = _stat(60 * self._MIB, total_bytes=total)

        g = EnvironmentGuard(
            tmp_dir=Path("/x"), clock=clock,
            sleep_fn=recovering_sleep, statvfs_fn=fs,
        )
        g.tick()
        assert not g.concluded  # resumed
        assert clock.t < WATCHDOG_MAX_PAUSE_S
        # The NEXT measuring tick must not re-pause: 60 MiB free is
        # above the clamped 25 MiB pause floor. With only the resume
        # floor clamped, the unclamped 64 MiB pause floor sat ABOVE
        # the 50 MiB resume floor — inverted hysteresis, an immediate
        # re-pause.
        paused_sleeps = sleeps["n"]
        clock.t += WATCHDOG_CHECK_INTERVAL_S + 0.1
        g.tick()
        assert sleeps["n"] == paused_sleeps  # no new pause
        assert not g.concluded

    def test_small_fs_free_between_clamped_floors_never_flaps(self):
        # The inverted-hysteresis shape: 55 MiB free on a 100 MiB
        # filesystem. Unclamped pause floor (64 MiB) > clamped resume
        # floor (50 MiB) inverted the hysteresis: every measuring
        # tick paused (55 < 64) and recovered on its first poll
        # (55 >= 50). With the pause floor clamped in step
        # (total // 4 = 25 MiB), 55 MiB free is simply healthy.
        total = 100 * self._MIB
        clock = _Clock()
        fs = _FakeFs(_stat(55 * self._MIB, total_bytes=total))
        sleeps = {"n": 0}

        def counting_sleep(s: float) -> None:
            sleeps["n"] += 1
            clock.t += s

        g = EnvironmentGuard(
            tmp_dir=Path("/x"), clock=clock,
            sleep_fn=counting_sleep, statvfs_fn=fs,
        )
        for _ in range(5):
            g.tick()
            clock.t += WATCHDOG_CHECK_INTERVAL_S + 0.1
        assert sleeps["n"] == 0  # never paused, not even once
        assert not g.concluded

    def test_small_fs_inode_floors_clamped_in_step(self):
        # Same inversion on the inode pair: 400 total inodes clamp the
        # resume floor to 200 (< the 256 pause floor). The pause floor
        # clamps to 100 in step, so 150 free inodes is healthy.
        clock = _Clock()
        fs = _FakeFs(_stat(
            4 * GIB, free_inodes=150, total_inodes=400,
        ))
        sleeps = {"n": 0}

        def counting_sleep(s: float) -> None:
            sleeps["n"] += 1
            clock.t += s

        g = EnvironmentGuard(
            tmp_dir=Path("/x"), clock=clock,
            sleep_fn=counting_sleep, statvfs_fn=fs,
        )
        for _ in range(5):
            g.tick()
            clock.t += WATCHDOG_CHECK_INTERVAL_S + 0.1
        assert sleeps["n"] == 0
        assert not g.concluded

    def test_large_fs_hysteresis_preserved(self):
        # Other direction: on a filesystem with ample total capacity
        # the clamp is inert — recovery to just above the PAUSE floor
        # still does not resume (the 2x hysteresis holds).
        clock = _Clock()
        fs = _FakeFs(_stat(WATCHDOG_PAUSE_FREE_BYTES - 1))

        real_sleep = clock.sleep

        def partial_recovery_sleep(s: float) -> None:
            real_sleep(s)
            fs.stat = _stat(WATCHDOG_PAUSE_FREE_BYTES + 1)

        g = EnvironmentGuard(
            tmp_dir=Path("/x"), clock=clock,
            sleep_fn=partial_recovery_sleep, statvfs_fn=fs,
        )
        g.tick()
        assert g.concluded


# ── Stop-rail integration ────────────────────────────────────────────


class TestStopRails:
    def _config_and_result(self, tmp_path: Path):
        from core.audit.orchestrator import (
            OrchestratorConfig,
            OrchestratorResult,
        )

        config = OrchestratorConfig(
            target_path=tmp_path, out_dir=tmp_path / "out",
        )
        (tmp_path / "out").mkdir()
        return config, OrchestratorResult()

    def test_check_budget_reports_concluded_guard(self, tmp_path):
        import time as _time

        from core.audit.orchestrator import _check_budget

        config, result = self._config_and_result(tmp_path)
        clock = _Clock()
        fs = _FakeFs(_stat(WATCHDOG_PAUSE_FREE_BYTES - 1))
        g = _guard(fs, clock)
        g.tick()
        assert g.concluded
        config.environment_guard_state = g
        assert _check_budget(config, _time.monotonic(), result) is True
        assert result.terminated_by == "environment"
        assert result.environment_fault == g.conclude_reason

    def test_check_budget_ignores_healthy_guard(self, tmp_path):
        import time as _time

        from core.audit.orchestrator import _check_budget

        config, result = self._config_and_result(tmp_path)
        clock = _Clock()
        g = _guard(_FakeFs(_stat(4 * GIB)), clock)
        g.tick()
        config.environment_guard_state = g
        assert _check_budget(config, _time.monotonic(), result) is False
        assert result.terminated_by == "complete"

    def test_executor_stops_after_tick_concludes(self, tmp_path):
        """A tick that concludes the run stops the serial executor
        BEFORE the popped task's review dispatches."""
        from unittest.mock import MagicMock

        from core.audit.executor import ExecutorConfig, run_executor_sync
        from core.audit.task_graph import TaskGraph

        wq = [
            {"file": "a.py", "name": f"f{i}",
             "priority_score": 0.5, "line_start": 1}
            for i in range(4)
        ]
        graph = TaskGraph.from_workqueue(wq, [])
        reviewed: list[str] = []
        concluded = {"v": False}

        def tick(gap: dict) -> None:
            if len(reviewed) >= 2:
                concluded["v"] = True

        def review(gap, shared, config, review_fn, result_obj, **kw):
            reviewed.append(gap["name"])
            outcome = MagicMock()
            outcome.status = "clean"
            outcome.cost_usd = 0.0
            return outcome

        result = MagicMock()
        stats = run_executor_sync(
            graph, MagicMock(), MagicMock(), MagicMock(), result,
            ExecutorConfig(max_workers=1),
            review_one_fn=review,
            on_tick=tick,
            budget_check=lambda: concluded["v"],
        )
        assert stats.budget_stopped
        assert len(reviewed) == 2  # the third dispatch never happened

    def _glance_setup(self, monkeypatch, n: int = 3):
        """A serial executor whose every task is a GLANCE task, with
        the batch machinery stubbed so no LLM plumbing is needed."""
        import core.audit.executor as executor_mod
        from core.audit.task_graph import TaskGraph

        wq = [
            {"file": "a.py", "name": f"g{i}",
             "priority_score": 0.5, "line_start": 1}
            for i in range(n)
        ]
        graph = TaskGraph.from_workqueue(wq, [])
        batches: list[list] = []

        monkeypatch.setattr(
            executor_mod, "_get_batch_review_fn",
            lambda shared, config: (lambda *a, **kw: None),
        )
        monkeypatch.setattr(
            executor_mod, "_is_glance", lambda task, shared: True,
        )

        def fake_process(batch, *args: object, **kwargs: object) -> None:
            batches.append(list(batch))

        monkeypatch.setattr(
            executor_mod, "_process_glance_batch", fake_process,
        )
        return graph, batches

    def test_serial_glance_flush_ticks_before_dispatch(self, monkeypatch):
        """The serial glance-batch flush is a dispatch site: it must
        drive the guard's tick (once per batch) before the LLM batch
        call — a glance-heavy serial run otherwise never pauses."""
        from unittest.mock import MagicMock

        from core.audit.executor import ExecutorConfig, run_executor_sync

        graph, batches = self._glance_setup(monkeypatch)
        ticks: list[dict] = []
        stats = run_executor_sync(
            graph, MagicMock(), MagicMock(), MagicMock(), MagicMock(),
            ExecutorConfig(max_workers=1),
            review_one_fn=MagicMock(),
            on_tick=ticks.append,
            budget_check=lambda: False,
        )
        assert batches  # the batch dispatched
        assert ticks  # ...and the tick ran for it
        assert stats.completed == 3

    def test_serial_glance_flush_honors_concluding_tick(self, monkeypatch):
        """A tick that concludes the run stops the serial executor
        BEFORE the glance batch dispatches; the queued tasks stay
        unreviewed gaps."""
        from unittest.mock import MagicMock

        from core.audit.executor import ExecutorConfig, run_executor_sync

        graph, batches = self._glance_setup(monkeypatch)
        concluded = {"v": False}

        def tick(gap: dict) -> None:
            concluded["v"] = True  # the guard concluded during the tick

        stats = run_executor_sync(
            graph, MagicMock(), MagicMock(), MagicMock(), MagicMock(),
            ExecutorConfig(max_workers=1),
            review_one_fn=MagicMock(),
            on_tick=tick,
            budget_check=lambda: concluded["v"],
        )
        assert not batches  # the batch never dispatched
        assert stats.budget_stopped
        assert stats.completed == 0  # every glance task stays a gap


# ── Conclusion releases waiting tickers ──────────────────────────────


def _concluding_sleep(g: EnvironmentGuard, clock: _Clock,
                      after: int = 2) -> Any:
    """sleep_fn that concludes the guard externally after *after*
    sleeps — modelling another thread's bounded wait expiring while
    this one is still inside its own loop."""
    count = {"n": 0}

    def _sleep(s: float) -> None:
        clock.sleep(s)
        count["n"] += 1
        if count["n"] >= after:
            g._conclude("external conclusion from another thread")

    return _sleep


class TestConclusionReleasesWaiters:
    def test_pause_loop_exits_on_external_conclusion(self):
        clock = _Clock()
        fs = _FakeFs(_stat(WATCHDOG_PAUSE_FREE_BYTES - 1))
        g = _guard(fs, clock)
        g._sleep = _concluding_sleep(g, clock)
        g.tick()
        assert g.concluded
        assert "external conclusion" in g.conclude_reason
        # Released at the conclusion, not after this waiter's own
        # full remaining bound.
        assert clock.t < WATCHDOG_MAX_PAUSE_S / 2

    def test_breaker_probe_loop_exits_on_external_conclusion(self):
        clock = _Clock()
        # Below the resume floor: the disk probe keeps failing, so
        # only the external conclusion can end the loop early.
        fs = _FakeFs(_stat(WATCHDOG_PAUSE_FREE_BYTES - 1))
        g = _guard(fs, clock)
        g._sleep = _concluding_sleep(g, clock)
        for i in range(BREAKER_TRIP_COUNT):
            g.note_dispatch_failure(f"a.py:f{i}", _wrapped(errno.ENOSPC))
        g.tick()
        assert g.concluded
        assert "external conclusion" in g.conclude_reason
        assert clock.t < BREAKER_MAX_PROBE_WAIT_S / 2


# ── Fan-out pause parity (real guard, real threads) ──────────────────


class TestFanOutPauseParity:
    """Fan-out passes tick from several worker threads. During an
    active pause EVERY ticker must gate (the rate limiter must not
    hand siblings a measurement-free pass into the pressured
    environment), and one thread's conclusion must release the other
    waiters promptly."""

    def _dirs(self, tmp_path: Path) -> tuple[Path, Path]:
        t = tmp_path / "t"
        o = tmp_path / "o"
        t.mkdir(exist_ok=True)
        o.mkdir(exist_ok=True)
        return t, o

    def _real_guard(self, tmp_path: Path, fs: _FakeFs, **kw: Any,
                    ) -> EnvironmentGuard:
        t, o = self._dirs(tmp_path)
        return EnvironmentGuard(
            tmp_dir=t, out_dir=o, statvfs_fn=fs, **kw,
        )

    def _tick_in_thread(self, g: EnvironmentGuard) -> tuple[Any, Any]:
        done = _threading.Event()

        def _run() -> None:
            g.tick()
            done.set()

        th = _threading.Thread(target=_run, daemon=True)
        th.start()
        return th, done

    def test_sibling_gates_during_pause_and_releases_on_recovery(
        self, tmp_path, monkeypatch,
    ):
        import core.audit.environment as env_mod
        monkeypatch.setattr(env_mod, "WATCHDOG_MAX_PAUSE_S", 30.0)
        monkeypatch.setattr(env_mod, "WATCHDOG_POLL_S", 0.05)
        fs = _BarrierFs(_stat(1 * 1024 * 1024))
        g = self._real_guard(tmp_path, fs)
        fs.guard = g

        th_a, a_done = self._tick_in_thread(g)
        # Barrier: a measurement observed while the guard is paused
        # can only come from the watchdog wait loop — A is inside it.
        assert fs.paused_measure.wait(timeout=10)
        assert not a_done.is_set()  # A is inside the pause loop

        # Sibling B ticks within the check interval: it must gate on
        # the active pause, not skip measurement and dispatch.
        # Joiners skip the pause-floor sweep, so B's FIRST measurement
        # can only come from inside the wait loop; a rate-limiter
        # pass-through would return without ever measuring and this
        # barrier would time out.
        th_b, b_done = self._tick_in_thread(g)
        assert fs.wait_for_thread(th_b), (
            "sibling ticked through the rate limiter during a pause"
        )
        assert not b_done.is_set(), (
            "sibling ticked through the rate limiter during a pause"
        )

        fs.stat = _stat(4 * GIB)  # pressure clears above resume floor
        th_a.join(timeout=10)
        th_b.join(timeout=10)
        assert a_done.is_set() and b_done.is_set()
        assert not g.concluded

    def test_conclusion_releases_paused_worker_promptly(
        self, tmp_path, monkeypatch,
    ):
        import core.audit.environment as env_mod
        monkeypatch.setattr(env_mod, "WATCHDOG_MAX_PAUSE_S", 30.0)
        monkeypatch.setattr(env_mod, "WATCHDOG_POLL_S", 0.05)
        fs = _BarrierFs(_stat(1 * 1024 * 1024))
        g = self._real_guard(tmp_path, fs)
        fs.guard = g

        released = _threading.Event()

        def _run() -> None:
            g.tick()
            released.set()

        th = _threading.Thread(target=_run, daemon=True)
        th.start()
        assert fs.paused_measure.wait(timeout=10)
        assert not released.is_set()  # inside the pause loop
        g._conclude("external conclusion from another thread")
        # Released by the conclusion, not by the (30s) pause bound —
        # how fast the scheduler runs the thread is not under test.
        th.join(timeout=10)
        assert released.is_set()

    def test_conclusion_releases_probing_worker_promptly(
        self, tmp_path, monkeypatch,
    ):
        import core.audit.environment as env_mod
        monkeypatch.setattr(env_mod, "BREAKER_MAX_PROBE_WAIT_S", 30.0)
        monkeypatch.setattr(
            env_mod, "BREAKER_PROBE_BACKOFF_INITIAL_S", 0.05,
        )
        monkeypatch.setattr(env_mod, "BREAKER_PROBE_BACKOFF_MAX_S", 0.05)
        fs = _BarrierFs(_stat(1 * 1024 * 1024))
        g = self._real_guard(tmp_path, fs)
        fs.guard = g
        for i in range(BREAKER_TRIP_COUNT):
            g.note_dispatch_failure(f"f{i}.c:fn{i}", _wrapped(errno.ENOSPC))

        released = _threading.Event()

        def _run() -> None:
            g.tick()
            released.set()

        th = _threading.Thread(target=_run, daemon=True)
        th.start()
        # Barrier: the tripped breaker's first measurement happens
        # inside the probe loop (the probe runs before any backoff).
        assert fs.first_measure.wait(timeout=10)
        assert not released.is_set()  # inside the probe/backoff loop
        g._conclude("external conclusion")
        # Released by the conclusion, not by the (30s) probe bound.
        th.join(timeout=10)
        assert released.is_set()

    def test_sigterm_abort_releases_paused_tick_promptly(
        self, tmp_path, monkeypatch,
    ):
        import core.audit.environment as env_mod
        monkeypatch.setattr(env_mod, "WATCHDOG_MAX_PAUSE_S", 30.0)
        monkeypatch.setattr(env_mod, "WATCHDOG_POLL_S", 0.05)
        flag = _threading.Event()
        fs = _BarrierFs(_stat(1 * 1024 * 1024))
        g = self._real_guard(
            tmp_path, fs,
            abort_check=flag.is_set,
        )
        fs.guard = g

        released = _threading.Event()

        def _run() -> None:
            g.tick()
            released.set()

        th = _threading.Thread(target=_run, daemon=True)
        th.start()
        assert fs.paused_measure.wait(timeout=10)
        assert not released.is_set()  # inside the pause loop
        flag.set()
        # Released by the abort, not by the (30s) pause bound.
        th.join(timeout=10)
        assert released.is_set()
        # Deliberate parity: the abort releases the wait WITHOUT a
        # conclusion — the caller's adjacent SIGTERM rails own it.
        assert not g.concluded

    def test_staggered_pausers_release_at_first_conclusion(
        self, tmp_path, monkeypatch,
    ):
        import core.audit.environment as env_mod
        monkeypatch.setattr(env_mod, "WATCHDOG_MAX_PAUSE_S", 1.0)
        monkeypatch.setattr(env_mod, "WATCHDOG_POLL_S", 0.05)
        monkeypatch.setattr(env_mod, "WATCHDOG_CHECK_INTERVAL_S", 0.2)
        fs = _BarrierFs(_stat(1 * 1024 * 1024))
        g = self._real_guard(tmp_path, fs)
        fs.guard = g

        th_a, a_done = self._tick_in_thread(g)
        # Barrier: A demonstrably inside the pause loop under its own
        # 1s bound (a wall-clock stagger only measured scheduler
        # load, not guard logic).
        assert fs.paused_measure.wait(timeout=10)
        # B joins under a bound that cannot expire within the test —
        # the constant is read at wait entry, so B's release inside
        # the join window can only come from the first conclusion,
        # never from serving its OWN bound.
        monkeypatch.setattr(env_mod, "WATCHDOG_MAX_PAUSE_S", 300.0)
        th_b, b_done = self._tick_in_thread(g)

        th_a.join(timeout=10)
        assert a_done.is_set()
        assert g.concluded  # A's own pause bound expired
        th_b.join(timeout=10)
        assert b_done.is_set(), (
            "joiner not released by the first conclusion"
        )
