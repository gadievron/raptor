"""Worker threads must block the handled terminal signals.

``main()`` installs Python-level SIGTERM/SIGINT handlers and then
blocks in ``child.wait()``. A process-directed terminal signal the
kernel routes to a worker thread (accept loop, connection pumps,
orphan watchdog) only trips CPython's C-level flag — the Python
handler waits for the main thread, whose waitpid is never
interrupted, so the stop request is silently absorbed until the
child dies on its own. The shield (``_start_signal_shielded``)
blocks exactly the handled signals in every worker so kernel
delivery lands on the main thread and unwedges the wait promptly.

These tests pin the observable invariant via ``/proc/self/task``
(SigBlk is per-thread), in-process — no namespaces, no subprocess.
"""

from __future__ import annotations

import contextlib
import os
import signal
import socket
import tempfile
import threading
import time

from packages.joern import netns_forwarder
from packages.joern.netns_forwarder import Forwarder, create_listener

#: Per-thread blocked-mask bits for the two handled terminal signals
#: (bit ``signum - 1`` of the SigBlk hex mask).
_TERM_BIT = 1 << (signal.SIGTERM - 1)
_INT_BIT = 1 << (signal.SIGINT - 1)


def _sig_blk(tid: int) -> int:
    with open(f"/proc/self/task/{tid}/status") as f:
        for line in f:
            if line.startswith("SigBlk:"):
                return int(line.split(":", 1)[1].strip(), 16)
    raise AssertionError(f"no SigBlk line for tid {tid}")


def _blocks_handled(tid: int) -> bool:
    blk = _sig_blk(tid)
    return bool(blk & _TERM_BIT) and bool(blk & _INT_BIT)


def test_start_signal_shielded_blocks_in_worker_restores_caller() -> None:
    caller_before = signal.pthread_sigmask(signal.SIG_BLOCK, ())
    seen: dict[str, object] = {}
    ready = threading.Event()
    release = threading.Event()

    def _probe() -> None:
        seen["mask"] = signal.pthread_sigmask(signal.SIG_BLOCK, ())
        ready.set()
        release.wait(10)

    t = threading.Thread(target=_probe, daemon=True)
    netns_forwarder._start_signal_shielded(t)
    try:
        assert ready.wait(10)
        assert signal.SIGTERM in seen["mask"]
        assert signal.SIGINT in seen["mask"]
        # The caller's own mask (and so its delivery eligibility) is
        # exactly what it was before the call.
        assert signal.pthread_sigmask(signal.SIG_BLOCK, ()) == caller_before
    finally:
        release.set()
        t.join(10)


def test_forwarder_threads_block_handled_terminal_signals() -> None:
    """Accept loop, connection handler, and back pump all run with
    SIGTERM/SIGINT blocked; the main thread stays unblocked."""
    d = tempfile.mkdtemp(prefix="sigmask-")
    sock_path = os.path.join(d, "f.sock")

    upstream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    upstream.bind(("127.0.0.1", 0))
    upstream.listen(4)
    port = upstream.getsockname()[1]

    listener = create_listener(sock_path)
    fwd = Forwarder(listener, ("127.0.0.1", port), socket_path=sock_path)

    tids_before = set(os.listdir("/proc/self/task"))
    fwd.start()
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    accepted = None
    try:
        client.settimeout(10)
        client.connect(sock_path)
        upstream.settimeout(10)
        accepted, _ = upstream.accept()

        # Accept thread + connection handler + back pump: all three
        # new threads must carry the block while the splice is live.
        deadline = time.monotonic() + 10
        new_tids: set[str] = set()
        while time.monotonic() < deadline:
            new_tids = set(os.listdir("/proc/self/task")) - tids_before
            if len(new_tids) >= 3:
                break
            time.sleep(0.01)
        assert len(new_tids) >= 3, f"expected 3 worker threads, {new_tids=}"
        for tid in new_tids:
            assert _blocks_handled(int(tid)), (
                f"worker tid {tid} does not block SIGTERM+SIGINT: "
                f"SigBlk={_sig_blk(int(tid)):#x}"
            )

        # The main thread must remain deliverable — the whole point is
        # forcing kernel routing onto it.
        main_tid = threading.main_thread().native_id
        assert main_tid is not None
        blk = _sig_blk(main_tid)
        assert not (blk & _TERM_BIT), f"main thread blocks SIGTERM {blk:#x}"
        assert not (blk & _INT_BIT), f"main thread blocks SIGINT {blk:#x}"
    finally:
        with contextlib.suppress(OSError):
            client.close()
        if accepted is not None:
            with contextlib.suppress(OSError):
                accepted.close()
        with contextlib.suppress(OSError):
            upstream.close()
        fwd.stop()
        with contextlib.suppress(OSError):
            os.rmdir(d)


def test_orphan_watchdog_blocks_handled_terminal_signals() -> None:
    d = tempfile.mkdtemp(prefix="sigmaskw-")
    sock_path = os.path.join(d, "w.sock")
    listener = create_listener(sock_path)
    fwd = Forwarder(listener, ("127.0.0.1", 1), socket_path=sock_path)
    # Drive the watchdog's parent-gone stage from a pipe we never write
    # and never close: the real watchdog escalates to killpg(0, SIGKILL)
    # of OUR OWN process group once it thinks the parent died and the
    # idle horizon lapsed — a getppid()-polling watchdog inside a pytest
    # worker could reach that if the xdist master ever died mid-run.
    # With an unreadable parent_gone_fd, stage 1 is unreachable no
    # matter what happens to this process's ancestry.
    gone_r, _gone_w = os.pipe()  # both ends stay open: never-readable by design
    try:
        t = netns_forwarder._start_orphan_watchdog(
            lambda: None, fwd, poll_s=30.0, parent_gone_fd=gone_r,
        )
        assert t.native_id is not None
        assert _blocks_handled(t.native_id), (
            f"watchdog does not block SIGTERM+SIGINT: "
            f"SigBlk={_sig_blk(t.native_id):#x}"
        )
    finally:
        fwd.stop()
        with contextlib.suppress(OSError):
            os.rmdir(d)


def test_shield_masks_creator_around_start_and_restores_exactly() -> None:
    """The mask must be in force on the CREATOR at the start() instant.

    A child-side variant (mask applied as the first action of ``run()``)
    passes the SigBlk pins above but leaves an unmasked window between
    thread birth and the first ``run()`` bytecode. Creator-side masking
    is the load-bearing property: it is what makes inheritance atomic.
    This pin also holds the shield to EXACT set semantics: the mask in
    force at start() is precisely the handled pair unioned with the
    creator's own blocked set (over-masking any other terminal — HUP,
    QUIT, ... — fails), and the restore puts back the creator's
    baseline verbatim (a strip-style SIG_UNBLOCK restore fails because
    the baseline deliberately pre-blocks one handled signal).
    """
    recorded: dict[str, object] = {}

    class _RecordingThread(threading.Thread):
        # Never spawns: records the creator's mask at the start() instant.
        def start(self) -> None:
            recorded["during"] = signal.pthread_sigmask(
                signal.SIG_BLOCK, (),
            )

    # Exact known baseline: SIGUSR1 blocked, plus SIGTERM pre-blocked
    # so a strip-style restore (SIG_UNBLOCK of the handled pair instead
    # of SETMASK(old)) is caught here, not only by the suite's
    # inner-shield inheritance pins.
    old = signal.pthread_sigmask(
        signal.SIG_SETMASK, {signal.SIGUSR1, signal.SIGTERM},
    )
    try:
        netns_forwarder._start_signal_shielded(
            _RecordingThread(target=lambda: None, daemon=True),
        )
        during = recorded["during"]
        # Exact set: handled pair unioned with the creator's blocked
        # set, nothing else. Any over-mask (HUP, QUIT, ...) and any
        # SETMASK clobber of the creator's own set fails here; unhandled
        # terminals' whole-process default disposition stays reachable.
        assert during == {signal.SIGUSR1, signal.SIGTERM, signal.SIGINT}
        after = signal.pthread_sigmask(signal.SIG_BLOCK, ())
        # Exact restoration: the creator's baseline comes back verbatim.
        assert after == {signal.SIGUSR1, signal.SIGTERM}
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, old)
