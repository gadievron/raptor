"""Retire native re-entrant run fixture workers before their state owners undo."""

import json
import threading

import pytest

from core.run.tests import test_run_gate_reentrant_oplock as native
from core.testing.module_bindings import patch_module_attribute

_user_state_in_tmp = native._user_state_in_tmp
monkeypatch = native.monkeypatch
env = native.env


@pytest.mark.parametrize("operation", ["start", "held_wait"])
@pytest.mark.parametrize("after", [False, True])
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt, SystemExit])
def test_native_lock_fixture_retires_worker_on_failure(
    env, monkeypatch, operation, after, error,
):
    entered, release = threading.Event(), threading.Event()
    workers, events, joined = [], [], []
    failure = error("owned native lock-fixture failure")
    fired = False

    class ObservedEvent(threading.Event):
        def __init__(self):
            super().__init__()
            events.append(self)

        def wait(self, timeout=None):
            nonlocal fired
            selected = operation == "held_wait" and timeout == 1.5 and not fired
            if selected:
                fired = True
                if not after:
                    raise failure
            result = super().wait(timeout)
            if selected:
                raise failure
            return result

    class Worker(threading.Thread):
        def __init__(self, *a, **k):
            super().__init__(*a, **k)
            workers.append(self)

        def run(self):
            entered.set()
            assert release.wait(10), "owned worker safety release timed out"
            super().run()

        def start(self):
            nonlocal fired
            if operation == "start" and not after:
                fired = True
                raise failure
            super().start()
            assert entered.wait(10)
            if operation == "start":
                fired = True
                raise failure
            # Keep the target parked for both fault schedules until join.

        def join(self, timeout=None):
            # Both fault schedules keep the actual target pending until its
            # owner joins it. The lock must already have been released.
            assert native._op_lock_is_free(env.project_dir)
            joined.append(self)
            release.set()
            super().join(timeout)

    with monkeypatch.context() as patch:
        patch_module_attribute(patch, native, "threading", "Thread", Worker)
        patch_module_attribute(patch, native, "threading", "Event", ObservedEvent)
        try:
            with pytest.raises(error) as caught:
                native.TestReentrantGateOpLock().test_reentrant_start_run_queues_behind_a_held_op_lock(env)
            assert caught.value is failure
            assert fired and len(workers) == 1
            assert not workers[0].is_alive()
            assert native._op_lock_is_free(env.project_dir)
            if workers[0].ident is not None:
                assert joined == workers
                assert events[0].is_set(), "real worker target did not complete"
                meta = json.loads((env.run_dir / native.metadata.RUN_METADATA_FILE).read_text())
                assert meta["status"] == "running"
            else:
                assert joined == []
        finally:
            release.set()
            for worker in workers:
                if worker.ident is not None:
                    threading.Thread.join(worker, 10)
                    assert not worker.is_alive()
