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
        def _boom():
            raise TypeError("simulated ctypes Structure failure")

        monkeypatch.setattr(landlock, "_run_selftest_in_child", _boom)
        # Fail-safe: parent reads EOF -> self-test reports failure.
        assert landlock._landlock_functional_self_test() is False

    def test_child_exception_leaves_no_zombie(self, monkeypatch):
        def _boom():
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
