"""Real worker lifetime over an emulated cgroup control fixture.

Ordinary temporary files are used; these tests do not access kernel cgroups.
"""
import builtins
from contextlib import contextmanager
from types import FunctionType, ModuleType
import threading

import pytest

from core.security.tests import test_cgroup_scope as native


def _exercise(tmp_path, operation, position, error, after):
    workers, events = [], []
    main = threading.current_thread()
    failure = error("owned admission worker fault") if error else None
    fired = False
    original = native.test_closing_admission_waits_for_an_inflight_attach
    native_thread = threading.Thread
    borrowed_write = native.cgroup_scope._write

    class Event(threading.Event):
        def wait(self, *args, **kwargs):
            nonlocal fired
            if operation == "wait" and self is events[0] and threading.current_thread() is main and not fired:
                fired = True
                if after:
                    assert super().wait(*args, **kwargs), "actual emulated attach gate not reached"
                raise failure
            return super().wait(*args, **kwargs)

    class Worker(native_thread):
        def start(self):
            nonlocal fired
            if operation == "start" and workers.index(self) == position and not fired:
                fired = True
                if after:
                    super().start()
                raise failure
            return super().start()

        def join(self, *args, **kwargs):
            nonlocal fired
            if operation == "join" and workers.index(self) == position and not fired:
                fired = True
                if after:
                    super().join(*args, **kwargs)
                raise failure
            return super().join(*args, **kwargs)

    def thread(*args, **kwargs):
        worker = Worker(*args, **kwargs)
        workers.append(worker)
        return worker

    def event():
        value = Event()
        events.append(value)
        return value

    private = ModuleType("threading")
    vars(private).update(vars(threading))
    private.Thread, private.Event = thread, event

    def import_local(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "threading" and level == 0:
            return private
        return builtins.__import__(name, globals, locals, fromlist, level)

    body = FunctionType(original.__code__, {**original.__globals__, "__builtins__": {**vars(builtins), "__import__": import_local}})
    with contextmanager(native.scope.__wrapped__)(tmp_path) as scope:
        with pytest.MonkeyPatch.context() as patch:
            try:
                if error:
                    with pytest.raises(error) as caught:
                        body(scope, patch)
                    assert caught.value is failure
                    assert fired
                else:
                    body(scope, patch)
                assert len(workers) == 2 and len(events) == 3
                assert events[1].is_set()
                assert all(not worker.is_alive() for worker in workers)
                assert any(worker.ident is not None for worker in workers) or (operation == "start" and position == 0 and not after)
                assert threading.Thread is native_thread
                assert native.test_closing_admission_waits_for_an_inflight_attach is original
            finally:
                if len(events) > 1:
                    events[1].set()
                for worker in workers:
                    if worker.ident is not None:
                        native_thread.join(worker, timeout=2)
                        assert not worker.is_alive()
        assert native.cgroup_scope._write is borrowed_write
        assert all(not worker.is_alive() for worker in workers)
    assert scope.node is None and scope.parent is None


@pytest.mark.parametrize("operation,position", [("start", 0), ("start", 1), ("join", 0), ("join", 1), ("wait", 0)])
@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("after", [False, True])
def test_workers_retire_before_emulated_scope_cleanup(tmp_path, operation, position, error, after):
    _exercise(tmp_path, operation, position, error, after)


def test_emulated_admission_positive_control(tmp_path):
    _exercise(tmp_path, None, None, None, False)
