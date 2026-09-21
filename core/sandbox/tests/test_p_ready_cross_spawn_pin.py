"""Step-4 p_ready wait must not block on a cross-spawn-pinned pipe.

Sibling spawns forked inside the p_ready-pipe-creation → parent-
close(p_ready_w) window inherit a copy of OUR p_ready_w, and the
sibling's SETUP child closes only its OWN fds — it retains the copy
for its entire life (the intermediate never execs, so no pre-exec
sweep runs there). Pre-fix, the parent's step-4 read was BLOCKING and
unbounded: when OUR child died before writing 'R' (unshare EPERM on a
userns-restricted host, stdio failure), the EOF could not arrive
until the sibling target finished — an engagement failure hung the
worker for a sibling run's full lifetime, and the run timeout only
arms later. Every other read on the same fd class already used the
non-blocking select+deadline idiom; p_ready_r was the missed member.

The pin shape is made deterministic by parking the FAILING spawn at
its Landlock availability probe — called after its p_ready pipe
exists and before its fork (the same seam the death-pipe sibling
tests barrier on) — until the sibling's target is provably RUNNING
(marker file written from inside the sibling's sandbox). At that
point the sibling intermediate exists and inherited the failing
spawn's p_ready_w (the pipe pre-dates the probe; the shared write end
is still open while the failing parent is parked before its own
fork), so when the failing child then dies pre-'R', the sibling's
copy is the only live write end and the EOF is genuinely withheld.
The sibling target blocks on a FIFO the test releases only after
asserting the failing spawn's outcome — "pinned to the sibling's
lifetime" and "bounded by the step-4 deadline" are separated by the
release point, not by a wall-clock race.
"""

from __future__ import annotations

import sys as _sys

import pytest as _pytest

pytestmark = [
    _pytest.mark.skipif(
        _sys.platform != "linux",
        reason="Linux-only sandbox internals (fork+newuidmap spawn path)",
    ),
    _pytest.mark.linux_native,
]

import contextlib  # noqa: E402
import errno  # noqa: E402
import os  # noqa: E402
import shutil  # noqa: E402
import threading  # noqa: E402
import time  # noqa: E402
from pathlib import Path  # noqa: E402


def _mount_ns_usable() -> bool:
    """True iff the fork+newuidmap spawn path works here."""
    if not shutil.which("newuidmap") or not shutil.which("newgidmap"):
        return False
    sysctl = Path("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
    if sysctl.exists() and sysctl.read_text().strip() == "1":
        return False
    return True


def _park_failing_thread_on_probe(monkeypatch, fail_local,
                                  marker: Path,
                                  sibling_dead: "threading.Event",
                                  ) -> None:
    """Park the failing thread's first check_landlock_available()
    call until *marker* exists (the sibling target is running).

    run_sandboxed calls the probe after creating its pipes and before
    forking (the seam the death-pipe sibling tests barrier on), so
    parking HERE pins the ordering the test needs: the sibling forks
    while the failing spawn's p_ready pipe is open and un-closed —
    the sibling chain provably inherits the write-end copy. Bails
    early when the sibling spawn died (degraded lane) so the park
    never burns its budget waiting for a marker that cannot arrive."""
    import core.sandbox.landlock as _ll

    real = _ll.check_landlock_available
    local = threading.local()

    def gated() -> bool:
        if (getattr(fail_local, "die", False)
                and not getattr(local, "seen", False)):
            local.seen = True
            deadline = time.monotonic() + 90
            while (time.monotonic() < deadline
                   and not marker.exists()
                   and not sibling_dead.is_set()):
                time.sleep(0.05)
        return real()

    monkeypatch.setattr(_ll, "check_landlock_available", gated)


def test_engagement_failure_not_pinned_to_sibling_lifetime(
        tmp_path, monkeypatch):
    """A child dying pre-'R' while a sibling holds our p_ready_w must
    surface its typed engagement error within the step-4 deadline —
    not after the sibling target's full lifetime."""
    if not _mount_ns_usable():
        _pytest.skip(
            "mount-ns unusable here (needs uidmap package + "
            "kernel.apparmor_restrict_unprivileged_userns=0)"
        )
    from core.sandbox import _spawn
    from core.sandbox.errors import SandboxSetupError

    # Short deadline so the test's post-fix runtime is seconds, not
    # the production 15s. raising=False keeps the test runnable on a
    # pre-fix tree (failing-first evidence), where the constant does
    # not exist — there the read is blocking and the value is unused.
    monkeypatch.setattr(_spawn, "_P_READY_DEADLINE_S", 3.0,
                        raising=False)

    sib_out = tmp_path / "sibling"
    sib_out.mkdir()
    marker = sib_out / "sibling-running.marker"
    fifo = sib_out / "hold.fifo"
    os.mkfifo(fifo)

    # Thread-local pre-'R' death: the fault flag is set only in the
    # failing spawn's thread, and fork clones exactly the calling
    # thread, so only the failing child takes the fault arm (the
    # sibling chain passes through to the real unshare).
    fail_local = threading.local()
    real_unshare = os.unshare

    def flaky_unshare(flags):
        if getattr(fail_local, "die", False):
            raise PermissionError(
                errno.EPERM, "unshare refused (test-induced)")
        return real_unshare(flags)

    monkeypatch.setattr(_spawn.os, "unshare", flaky_unshare)

    common = dict(
        block_network=True,
        nproc_limit=1024,
        limits={"memory_mb": 0, "max_file_mb": 1024,
                "cpu_seconds": 300},
        readable_paths=None,
        allowed_tcp_ports=None,
        seccomp_profile=None, seccomp_block_udp=False,
        env=None, cwd=None,
        capture_output=True, text=True,
        # The scenario needs the fork+newuidmap spawn, not Landlock:
        # tolerate Landlock-less lanes (the feature-matrix no-landlock
        # lane) instead of tripping the fail-closed default.
        landlock_required=False,
    )

    # Pre-flight: the scenario requires a working spawn for the
    # SIBLING role. Degraded lanes where the direct _spawn call
    # cannot run at all (mount tier refused mid-child, spawn refusal
    # ladders) get an honest skip — the pin fix itself is exercised
    # on spawn-capable hosts.
    preflight_out = tmp_path / "preflight"
    preflight_out.mkdir()
    try:
        pf = _spawn.run_sandboxed(
            ["true"], target=str(preflight_out),
            output=str(preflight_out),
            writable_paths=[str(preflight_out), "/tmp"],
            timeout=120, **common)
    except BaseException as exc:
        _pytest.skip(f"sandbox spawn unavailable on this lane: {exc!r}")
    if pf.returncode != 0:
        _pytest.skip(f"sandbox spawn degraded on this lane: {pf!r}")

    results: dict = {}
    sibling_dead = threading.Event()

    def _sibling():
        try:
            results["sibling"] = _spawn.run_sandboxed(
                ["sh", "-c",
                 f"echo up > {marker} && exec cat {fifo}"],
                target=str(sib_out), output=str(sib_out),
                writable_paths=[str(sib_out), "/tmp"],
                timeout=180,
                **common)
        except BaseException as e:
            results["sibling"] = e
        finally:
            if not marker.exists():
                sibling_dead.set()

    def _failing():
        fail_local.die = True
        out = tmp_path / "failing"
        out.mkdir()
        try:
            _spawn.run_sandboxed(
                ["true"],
                target=str(out), output=str(out),
                writable_paths=[str(out), "/tmp"],
                timeout=120,
                **common)
            results["failing"] = None
        except BaseException as e:
            results["failing"] = e

    def _release_fifo():
        with contextlib.suppress(OSError):
            os.close(os.open(fifo, os.O_WRONLY | os.O_NONBLOCK))

    _park_failing_thread_on_probe(monkeypatch, fail_local, marker,
                                  sibling_dead)

    sib_thread = threading.Thread(target=_sibling)
    fail_thread = threading.Thread(target=_failing)
    sib_thread.start()
    fail_thread.start()
    try:
        # The failing spawn must finish while the sibling target is
        # STILL HELD on the FIFO: generous engagement slack (barrier,
        # newuidmap latency, marker wait) + the shortened deadline.
        fail_thread.join(timeout=90)
        pinned = fail_thread.is_alive()
    finally:
        _release_fifo()
    fail_thread.join(timeout=60)
    sib_thread.join(timeout=60)
    assert not fail_thread.is_alive(), "failing spawn thread wedged"
    assert not sib_thread.is_alive(), "sibling spawn thread wedged"

    assert not pinned, (
        "the engagement failure did not surface until the sibling "
        "run was released — the step-4 p_ready read was pinned to "
        "the sibling's lifetime")
    err = results["failing"]
    assert isinstance(err, SandboxSetupError), (
        f"expected the typed engagement error, got {err!r}")
    # The sibling run itself is unaffected (cat EOFs with rc 0).
    sib = results["sibling"]
    assert not isinstance(sib, BaseException), f"sibling failed: {sib!r}"
    assert sib.returncode == 0
