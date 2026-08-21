"""Slow-reap handling for a SIGKILLed Joern server.

A killed multi-GB JVM can spend more than the 5s foreground grace in
kernel-side address-space teardown before it becomes reapable.
``stop()`` must not block a restart on that — but pre-fix the child
was then never wait()ed again, leaking a zombie (and its pid) for the
rest of the run. A background reaper now holds the wait().

Hermetic — no real Joern process.
"""

from __future__ import annotations

import subprocess
import threading

from packages.joern.server import JoernServer, _reap_in_background


class _SlowExitProc:
    """poll()s alive; timed waits expire; untimed wait reaps."""

    def __init__(self):
        self.pid = 424242
        self.reaped = threading.Event()
        self.killed = False
        self.terminated = False

    def poll(self):
        return None

    def terminate(self):
        self.terminated = True

    def kill(self):
        self.killed = True

    def wait(self, timeout=None):
        if timeout is not None:
            raise subprocess.TimeoutExpired(cmd="joern", timeout=timeout)
        self.reaped.set()
        return -9


class TestSlowReap:
    def test_stop_proceeds_and_background_reaper_reaps(self):
        srv = JoernServer()
        proc = _SlowExitProc()
        srv._proc = proc

        srv.stop()  # must return despite both timed waits expiring

        # Cleanup proceeded: handle cleared, escalation happened.
        assert srv._proc is None
        assert proc.killed
        # The zombie is not abandoned: the background reaper wait()s.
        assert proc.reaped.wait(timeout=5), (
            "background reaper never wait()ed the killed child"
        )

    def test_reap_in_background_survives_wait_failure(self):
        class _Broken:
            pid = 7
            def wait(self):
                raise OSError("gone")

        # Must not raise; the daemon thread swallows the failure.
        _reap_in_background(_Broken())
