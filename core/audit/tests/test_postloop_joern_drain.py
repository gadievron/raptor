"""Post-executor Joern drain must degrade, never kill the run.

The wait on a still-running CPG build sits between the paid review
loop and every post-loop pass (deepen, sweeps, exports): a
concurrent.futures.TimeoutError (distinct from builtin TimeoutError on
Python 3.10) or the build's own re-raised exception escaping here
kills all of them.
"""

from __future__ import annotations

import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor

from core.audit.orchestrator import _await_joern_build


class TestAwaitJoernBuild:
    def test_completed_future_returned_for_drain(self):
        fut: Future = Future()
        fut.set_result({"a.c:f": ["flow"]})
        assert _await_joern_build(fut, 1) is fut

    def test_build_exception_degrades_to_none(self):
        # result() re-raises the build's exception — the wait must
        # swallow it (drain_joern_future's guarded contract), not let
        # it kill the post-loop passes.
        fut: Future = Future()
        fut.set_exception(RuntimeError("cpg build exploded"))
        assert _await_joern_build(fut, 1) is None

    def test_stalled_build_times_out_to_none(self):
        # A real executor-backed future so the wait raises
        # concurrent.futures.TimeoutError, the class the old handler
        # missed on Python 3.10.
        release = threading.Event()
        with ThreadPoolExecutor(max_workers=1) as pool:
            fut = pool.submit(release.wait, 5)
            try:
                t0 = time.monotonic()
                assert _await_joern_build(fut, 0) is None
                assert time.monotonic() - t0 < 4
            finally:
                release.set()

    def test_stalled_unstarted_future_cancelled(self):
        # A never-started future is cancelled so the executor can
        # drop it instead of running a doomed build later.
        fut: Future = Future()
        assert _await_joern_build(fut, 0) is None
        assert fut.cancelled()
