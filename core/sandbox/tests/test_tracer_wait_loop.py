"""Regression tests for the tracer wait loop's event latency.

Root cause pinned here: the wait loop's idle path used a plain
``time.sleep(0.05)`` between ``waitpid(WNOHANG)`` drains (parent-death
watchdog, W2-CC29). A tracee stopped by SCMP_ACT_TRACE stays FROZEN
until the tracer wakes and PTRACE_CONTs it, so every traced syscall
cost up to one full tick — the target was throttled to ~20
syscalls/sec. The Landlock-only spawn path wraps commands in the
Python pid1-shim whose interpreter startup alone is ~200 traced
syscalls, so ``sandbox_run(observe=True)`` with mount-ns unavailable
took 10+ seconds for ``/usr/bin/true`` and blew every caller timeout
("drain never sees pipe EOF" presentation; the two integration tests
in test_observe_namespaces.py timed out).

The fix keeps the tick-bounded watchdog but makes wakeups
event-driven: SIGCHLD is blocked and ``_idle_wait_for_sigchld`` uses
``signal.sigtimedwait`` — a pending tracee state change wakes it
immediately, and one raised between the WNOHANG drain and the wait
stays pending (no lost-wakeup race).

Two tiers:

* Hermetic (plain ``os.fork``, no ptrace, no namespaces): pin the
  helper's three contract properties — event-driven wake, no
  lost-wakeup race, bounded tick.
* Live kernel-gated (real user-ns + seccomp + ptrace; skips with a
  reason where unavailable): the user-visible regression — a
  Landlock-only observe run of ``/usr/bin/true`` completes in
  fractions of a second, not tens of seconds. This is the
  battery-runnable re-enablement of the coverage that the
  integration-marked test_observe_namespaces.py provides in full.
"""

from __future__ import annotations

import signal
import sys
import time
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(
    sys.platform != "linux",
    reason=(
        "Linux-only sandbox internals (mount-ns / Landlock / seccomp / "
        "ptrace tracer) — see core/sandbox/_macos_spawn.py for the macOS path"
    ),
)


# ---------------------------------------------------------------------------
# Hermetic — _idle_wait_for_sigchld contract (plain fork, no ptrace)
# ---------------------------------------------------------------------------
#
# The event-driven tests run inside a SINGLE-THREADED subprocess, not
# in the pytest process. The contract "a blocked SIGCHLD stays pending
# for sigtimedwait" only holds when no other thread has SIGCHLD
# unblocked: in a multi-threaded process (an xdist worker's execnet
# service threads) the kernel delivers the process-directed SIGCHLD
# to whichever thread doesn't block it, where the default disposition
# discards it. The production tracer is always a dedicated
# single-threaded ``python -m core.sandbox.tracer`` process (see the
# module docstring's "why a separate process" rationale), so the
# subprocess is the faithful environment, not a convenience.


_SUBPROC_PRELUDE = """
import os, signal, sys, time
sys.path.insert(0, os.environ["RAPTOR_DIR"])
from core.sandbox.tracer import _idle_wait_for_sigchld

signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGCHLD})
"""

_SUBPROC_WAKE_ON_EXIT = _SUBPROC_PRELUDE + """
pid = os.fork()
if pid == 0:
    time.sleep(0.2)
    os._exit(0)
t0 = time.monotonic()
_idle_wait_for_sigchld(5.0)
elapsed = time.monotonic() - t0
os.waitpid(pid, 0)
print(f"ELAPSED={elapsed:.3f}")
"""

_SUBPROC_PENDING = _SUBPROC_PRELUDE + """
pid = os.fork()
if pid == 0:
    os._exit(0)
# Ensure the child has exited (waitable, unreaped — SIGCHLD is
# blocked and this process is single-threaded, so it is queued
# pending).
deadline = time.monotonic() + 5.0
while time.monotonic() < deadline:
    if os.waitid(os.P_PID, pid,
                 os.WEXITED | os.WNOHANG | os.WNOWAIT) is not None:
        break
    time.sleep(0.01)
else:
    print("ELAPSED=child never became waitable")
    sys.exit(1)
t0 = time.monotonic()
_idle_wait_for_sigchld(5.0)
elapsed = time.monotonic() - t0
os.waitpid(pid, 0)
print(f"ELAPSED={elapsed:.3f}")
"""


def _run_single_threaded(script: str) -> float:
    """Run a timing probe in a fresh single-threaded interpreter;
    return the ELAPSED= value it prints. The probe locates the repo
    via RAPTOR_DIR (hard lookup — the conftest pins it to the tree
    under test)."""
    import subprocess

    proc = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True, text=True, timeout=30,
    )
    assert proc.returncode == 0, (
        f"probe subprocess failed rc={proc.returncode}: "
        f"stdout={proc.stdout!r} stderr={proc.stderr!r}"
    )
    for line in proc.stdout.splitlines():
        if line.startswith("ELAPSED="):
            return float(line.split("=", 1)[1])
    pytest.fail(f"probe printed no ELAPSED line: {proc.stdout!r}")


class TestIdleWaitForSigchld:

    def test_wakes_on_child_exit_before_tick(self):
        """A child state change must wake the wait immediately — NOT on
        the next tick. Pre-fix equivalent (plain sleep) would hold the
        full tick; with a 5s tick that difference is unmistakable."""
        elapsed = _run_single_threaded(_SUBPROC_WAKE_ON_EXIT)
        assert elapsed < 3.0, (
            f"idle wait held {elapsed:.2f}s despite a child exiting at "
            f"0.2s — event-driven wakeup regressed to tick-bound sleep"
        )

    def test_pending_sigchld_returns_immediately(self):
        """The lost-wakeup race: a SIGCHLD raised BEFORE the wait is
        entered (between the caller's WNOHANG drain and the wait) must
        be seen as pending and return immediately."""
        elapsed = _run_single_threaded(_SUBPROC_PENDING)
        assert elapsed < 1.0, (
            f"idle wait held {elapsed:.2f}s with SIGCHLD already "
            f"pending — the no-lost-wakeup contract is broken"
        )

    def test_tick_bounded_when_no_event(self):
        """With no child activity the wait must return at the tick —
        the parent-death watchdog depends on this bound. Thread-count
        agnostic (nothing raises SIGCHLD at all), so this one runs
        in-process."""
        from core.sandbox.tracer import _idle_wait_for_sigchld

        old_mask = signal.pthread_sigmask(
            signal.SIG_BLOCK, {signal.SIGCHLD},
        )
        try:
            t0 = time.monotonic()
            _idle_wait_for_sigchld(0.1)
            elapsed = time.monotonic() - t0
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, old_mask)
        assert elapsed < 3.0, (
            f"idle wait held {elapsed:.2f}s with a 0.1s tick — the "
            f"watchdog bound is gone"
        )
        # And it actually waited (didn't spin through instantly and
        # turn the wait loop into a busy poll).
        assert elapsed >= 0.05, (
            f"idle wait returned after {elapsed * 1000:.1f}ms with no "
            f"event and a 100ms tick — busy-spin risk"
        )


# ---------------------------------------------------------------------------
# Live kernel-gated — Landlock-only observe completes fast (the hang)
# ---------------------------------------------------------------------------


def _live_prereqs() -> tuple[bool, str]:
    """(ok, reason): can the observe tracer engage on this host?"""
    from core.sandbox.probes import check_net_available
    from core.sandbox.ptrace_probe import check_ptrace_available
    from core.sandbox.seccomp import check_seccomp_available
    if not check_net_available():
        return False, "user namespaces unavailable"
    if not check_seccomp_available():
        return False, "libseccomp unavailable"
    if not check_ptrace_available():
        return False, "ptrace blocked (Yama scope, container cap-drop)"
    return True, ""


class TestLandlockOnlyObserveLatency:
    """The user-visible regression: Landlock-only observe of
    ``/usr/bin/true`` must complete in well under the wrapper chain's
    pre-fix ~10.5s (unshare → prlimit → Python pid1-shim ≈ 200 traced
    syscalls × one 50ms tick each). Post-fix this runs in ~0.2s; the
    8s ceiling leaves a wide margin for loaded CI while still failing
    decisively if per-event tick latency ever comes back."""

    def test_observe_true_completes_fast(self, tmp_path):
        ok, reason = _live_prereqs()
        if not ok:
            pytest.skip(reason)

        from unittest.mock import patch

        from core.sandbox import run as sandbox_run

        run_dir = Path(tmp_path) / "observe-latency"
        run_dir.mkdir()

        t0 = time.monotonic()
        # Force the Landlock-only path the way the Ubuntu 24.04+
        # AppArmor default does (mount-ns unavailable), same as
        # test_observe_namespaces.py. timeout=30 keeps a regressed
        # world failing BOUNDED (TimeoutExpired) instead of hanging
        # the battery.
        with patch("core.sandbox._spawn.mount_ns_available",
                   return_value=False), \
             patch("core.sandbox.context.check_mount_available",
                   return_value=False):
            result = sandbox_run(
                ["/usr/bin/true"],
                target=str(run_dir), output=str(run_dir),
                observe=True,
                capture_output=True, text=True, timeout=30,
            )
        elapsed = time.monotonic() - t0

        assert result.returncode == 0, (
            f"true should exit 0; stderr={result.stderr!r}"
        )
        assert result.sandbox_info.get("observe_nonce"), (
            "observe_nonce must be populated — Landlock-only audit "
            "did not engage"
        )
        assert elapsed < 8.0, (
            f"Landlock-only observe of /usr/bin/true took "
            f"{elapsed:.1f}s — per-traced-syscall tick latency is "
            f"back (pre-fix baseline: ~10.5s at 50ms/event)"
        )


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
