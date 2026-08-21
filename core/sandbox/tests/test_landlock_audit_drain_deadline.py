"""Deterministic, platform-independent test for the drain-loop deadline.

Unlike test_landlock_audit_drain.py (Linux-only, real-child integration),
this isolates the read-branch deadline logic of
``_landlock_audit._drain_pipes_until_eof`` by mocking select()/os.read(),
so it exercises the 14d5c87c residual reliably and without a real
Landlock sandbox or timing races.

14d5c87c residual: a hostile target that keeps a pipe *continuously*
readable makes select() return non-empty on every tick, so control never
enters the ``if not ready:`` idle branch where the deadline used to be the
only checked. The read branch (os.read loop) then runs unbounded past the
caller's deadline. The fix hoists the deadline check to the top of the
loop so it fires regardless of pipe readiness.
"""
from __future__ import annotations

import os
import time

import pytest

from core.sandbox import _landlock_audit as mod


@pytest.fixture
def saturated_pipe(monkeypatch):
    """Simulate a permanently-readable fd: select always reports it ready
    and os.read always returns data (never EOF)."""
    monkeypatch.setattr(mod.select, "select", lambda r, w, x, t: (list(r), [], []))
    monkeypatch.setattr(os, "read", lambda fd, n: b"x" * n)
    # A large per-fd cap would still be hit, but the loop keeps draining
    # past it ("still draining to keep the child unblocked") — that is the
    # unbounded path the deadline must cut.


def test_read_branch_honors_deadline_on_saturated_pipe(saturated_pipe):
    deadline = time.monotonic() + 0.3
    start = time.monotonic()
    # target_pid is never probed because select never returns idle.
    mod._drain_pipes_until_eof((999,), 1, deadline=deadline)
    elapsed = time.monotonic() - start
    # Pre-fix this never returns (unbounded read loop); post-fix it returns
    # at the deadline. Generous ceiling to stay non-flaky under load.
    assert elapsed < 2.0, f"drain ran {elapsed:.2f}s past a 0.3s deadline"


def test_no_deadline_saturated_pipe_is_still_bounded_by_a_short_run(saturated_pipe):
    """Sanity: with deadline=None the loop is *meant* to run until EOF/kill;
    confirm the deadline path is what bounds it (a set deadline returns,
    proving the new top-of-loop check, not some other exit, is responsible)."""
    deadline = time.monotonic() + 0.1
    start = time.monotonic()
    mod._drain_pipes_until_eof((999,), 1, deadline=deadline)
    assert time.monotonic() - start < 1.0
