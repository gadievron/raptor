"""Tests for core.run.parent_liveness — the in-child orphan watchdog.

Unit layer: arm/disarm decisions and the ppid-change trigger, with the
group-kill action stubbed (a real ``killpg(0, SIGKILL)`` would take the
test session down). E2E layer: a real parent/child/grandchild process
tree under a hard parent SIGKILL, asserting the whole child group exits
within a bounded window — every process involved is spawned by the
test, in its own session, and reaped in ``finally``.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

from core.run import parent_liveness

_RAPTOR_ROOT = Path(__file__).resolve().parents[3]


def _wait_for(predicate, timeout_s: float, what: str) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.05)
    pytest.fail(f"timed out after {timeout_s}s waiting for {what}")


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except OSError:
        return True
    return True


class TestArmDecision:
    def test_unset_env_disarms(self, monkeypatch):
        monkeypatch.delenv(parent_liveness.WATCHDOG_ENV, raising=False)
        assert parent_liveness.maybe_start_orphan_watchdog("t") is None

    def test_garbled_value_disarms(self, monkeypatch):
        # A corrupted knob must never make a process kill itself.
        monkeypatch.setenv(parent_liveness.WATCHDOG_ENV, "yes please")
        assert parent_liveness.maybe_start_orphan_watchdog("t") is None

    def test_plain_enable_arms_daemon_thread(self, monkeypatch):
        monkeypatch.setenv(parent_liveness.WATCHDOG_ENV, "1")
        # Our real parent stays alive throughout, so the thread idles.
        t = parent_liveness.maybe_start_orphan_watchdog("t", poll_s=60.0)
        assert t is not None
        assert t.daemon
        assert t.is_alive()

    def test_pid_value_arms(self, monkeypatch, _stub_terminate):
        monkeypatch.setenv(
            parent_liveness.WATCHDOG_ENV, str(os.getppid()),
        )
        t = parent_liveness.maybe_start_orphan_watchdog("t", poll_s=60.0)
        assert t is not None
        assert t.is_alive()
        assert _stub_terminate == []


@pytest.fixture
def _stub_terminate(monkeypatch):
    """Replace the group-kill action with a recorder."""
    calls: list[str] = []
    monkeypatch.setattr(
        parent_liveness, "_terminate_group",
        lambda label: calls.append(label),
    )
    return calls


class TestTrigger:
    def test_ppid_change_fires(self, monkeypatch, _stub_terminate):
        real_ppid = os.getppid()
        seen = {"flipped": False}

        def fake_getppid() -> int:
            return real_ppid + 1 if seen["flipped"] else real_ppid

        monkeypatch.setattr(parent_liveness.os, "getppid", fake_getppid)
        parent_liveness.start_orphan_watchdog("trigger", poll_s=0.05)
        time.sleep(0.2)
        assert _stub_terminate == []  # parent "alive": no fire
        seen["flipped"] = True
        _wait_for(lambda: _stub_terminate == ["trigger"], 5.0,
                  "watchdog to fire on ppid change")

    def test_already_orphaned_expected_parent_fires(self, _stub_terminate):
        # The spawner recorded its pid, then died inside the spawn
        # window: getppid() never matches the recorded parent, so the
        # action fires at once instead of never.
        parent_liveness.start_orphan_watchdog(
            "orphaned", expected_parent=os.getppid() + 1, poll_s=0.05,
        )
        _wait_for(lambda: _stub_terminate == ["orphaned"], 5.0,
                  "watchdog to fire for an already-orphaned child")


@pytest.mark.linux_native
@pytest.mark.darwin_native
class TestParentHardKillE2E:
    """Failing-first contract for the orphan class the /tmp survey
    found: SIGKILL the parent and the detached child GROUP —
    grandchild included — must exit within a bounded window."""

    def test_child_group_dies_after_parent_sigkill(self, tmp_path):
        ready = tmp_path / "ready"
        child_code = (
            "import os, subprocess, sys, time\n"
            "sys.path.insert(0, os.environ['RAPTOR_DIR'])\n"
            "from core.run.parent_liveness import maybe_start_orphan_watchdog\n"
            "assert maybe_start_orphan_watchdog('e2e', poll_s=0.1) is not None\n"
            "g = subprocess.Popen(\n"
            "    [sys.executable, '-c', 'import time; time.sleep(300)'])\n"
            "with open(os.environ['READY_FILE'], 'w') as f:\n"
            "    f.write(f'{os.getpid()} {g.pid}')\n"
            "g.wait()\n"
        )
        parent_code = (
            "import os, subprocess, sys, time\n"
            "env = dict(os.environ)\n"
            "env['RAPTOR_PARENT_WATCHDOG'] = str(os.getpid())\n"
            "subprocess.Popen([sys.executable, '-c', sys.argv[1]],\n"
            "                 env=env, start_new_session=True)\n"
            "time.sleep(300)\n"
        )
        env = dict(os.environ)
        env["RAPTOR_DIR"] = str(_RAPTOR_ROOT)
        env["READY_FILE"] = str(ready)
        parent = subprocess.Popen(
            [sys.executable, "-c", parent_code, child_code],
            env=env, start_new_session=True,
        )
        child_pid = grand_pid = None
        try:
            _wait_for(ready.exists, 30.0, "child tree to come up")
            child_pid, grand_pid = (
                int(x) for x in ready.read_text().split()
            )
            os.kill(parent.pid, signal.SIGKILL)
            parent.wait(timeout=10)
            # Hard wall: watchdog polls at 0.1s; 15s is generous.
            _wait_for(lambda: not _pid_alive(child_pid), 15.0,
                      "orphaned child to exit")
            _wait_for(lambda: not _pid_alive(grand_pid), 15.0,
                      "orphaned grandchild to exit")
        finally:
            # Reap our own processes only, whatever the outcome.
            for pid in (parent.pid, child_pid, grand_pid):
                if pid is None:
                    continue
                for target in (self._pgid(pid), pid):
                    if target is None:
                        continue
                    try:
                        if target == pid:
                            os.kill(target, signal.SIGKILL)
                        else:
                            os.killpg(target, signal.SIGKILL)
                    except OSError:
                        pass
            parent.poll()

    @staticmethod
    def _pgid(pid: int) -> int | None:
        try:
            return os.getpgid(pid)
        except OSError:
            return None
