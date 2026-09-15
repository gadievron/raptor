"""Tests for core/sandbox/landlock.py's forked functional self-test.

The forked self-test child's dispatch is guarded — an exception raised
by ``_run_selftest_in_child`` outside its narrow try blocks must not
unwind into the duplicated interpreter (atexit handlers, buffered-IO
double flush). The parent must read EOF and report Landlock
unavailable (fail-safe), and the child must be reaped.
"""

from __future__ import annotations

import os
import sys as _sys

import pytest

from core.sandbox import landlock

pytestmark = pytest.mark.skipif(
    _sys.platform != "linux",
    reason="Landlock self-test forks; Linux-only",
)


class TestChildDispatchGuarded:

    def test_child_exception_reports_unavailable(self, monkeypatch):
        def _boom(libc):
            raise TypeError("simulated ctypes Structure failure")

        monkeypatch.setattr(landlock, "_run_selftest_in_child", _boom)
        # Fail-safe: parent reads EOF -> self-test reports failure.
        assert landlock._landlock_functional_self_test() is False

    def test_child_exception_leaves_no_zombie(self, monkeypatch):
        def _boom(libc):
            raise ValueError("simulated child crash")

        monkeypatch.setattr(landlock, "_run_selftest_in_child", _boom)
        landlock._landlock_functional_self_test()
        # The self-test reaps its own child; no stray zombie remains.
        # (Tolerate (0, 0) — an unrelated live child elsewhere in the
        # test process — but a reapable zombie here means the leak.)
        try:
            reaped = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            reaped = (0, 0)
        assert reaped == (0, 0)

    def test_normal_path_returns_bool(self):
        # Sanity: the guard must not change the healthy-path contract.
        assert landlock._landlock_functional_self_test() in (True, False)


class TestSelfTestChildReaped:
    """The functional self-test's forked child is reaped on EVERY
    parent path: an OSError from the verdict-pipe read used to skip
    the waitpid, leaving the child a zombie for the life of the
    process."""

    def test_read_failure_does_not_leak_a_zombie(self):
        import subprocess
        import sys as _sys
        from pathlib import Path
        # Subprocess probe: zombie detection needs waitpid(-1) over
        # ALL children, which is only deterministic in a process that
        # has none of its own.
        probe = (
            "import os, time\n"
            "from unittest import mock\n"
            "from core.sandbox import landlock\n"
            "with mock.patch('os.read', side_effect=OSError(5, 'io')):\n"
            "    ok = landlock._landlock_functional_self_test()\n"
            "assert ok is False, 'read failure must fail the probe'\n"
            "deadline = time.monotonic() + 10\n"
            "while True:\n"
            "    try:\n"
            "        pid, _ = os.waitpid(-1, os.WNOHANG)\n"
            "    except ChildProcessError:\n"
            "        print('REAPED-OK')\n"
            "        break\n"
            "    if pid:\n"
            "        print(f'ZOMBIE:{pid}')\n"
            "        break\n"
            "    if time.monotonic() > deadline:\n"
            "        print('TIMEOUT')\n"
            "        break\n"
            "    time.sleep(0.02)\n"
        )
        repo = Path(__file__).resolve().parents[3]
        r = subprocess.run(
            [_sys.executable, "-c", probe],
            capture_output=True, text=True, timeout=60,
            cwd=repo, env={**os.environ},
        )
        assert r.returncode == 0, r.stderr
        assert "REAPED-OK" in r.stdout, (
            f"self-test child left unreaped:\n"
            f"stdout={r.stdout}\nstderr={r.stderr}"
        )
