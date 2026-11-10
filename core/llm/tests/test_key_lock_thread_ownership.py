"""Actual key-lock test workers release their owned native lock on exit."""
from types import FunctionType, ModuleType
import threading

import pytest

from core.llm.tests import test_key_lock_handout as native


def _exercise(operation, position, error, after):
    workers, events, clients = [], [], []
    main = threading.current_thread()
    failure = error("owned key-lock worker fault") if error else None
    fired = False
    original = native.test_concurrent_handles_serialise_on_one_lock
    native_thread = threading.Thread

    class Event(threading.Event):
        def wait(self, *args, **kwargs):
            nonlocal fired
            if operation == "wait" and self is events[0] and threading.current_thread() is main and not fired:
                fired = True
                if after:
                    assert super().wait(*args, **kwargs), "native lock holder did not acquire"
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

    def client(*args, **kwargs):
        value = native._mini_client(*args, **kwargs)
        clients.append(value)
        return value

    private = ModuleType("threading")
    vars(private).update(vars(threading))
    private.Thread, private.Event = thread, event
    body = FunctionType(original.__code__, {**original.__globals__, "threading": private, "_mini_client": client})
    try:
        if error:
            with pytest.raises(error) as caught:
                body()
            assert caught.value is failure
            assert fired
        else:
            body()
        assert len(workers) == 2 and len(events) == 2 and len(clients) == 1
        assert events[1].is_set()
        assert all(not worker.is_alive() for worker in workers)
        assert any(worker.ident is not None for worker in workers) or (operation == "start" and position == 0 and not after)
        assert all(not lock.locked() for lock in clients[0]._key_locks.values())
        assert getattr(clients[0], "_key_lock_refs", {}) == {}
        assert threading.Thread is native_thread
        assert native.test_concurrent_handles_serialise_on_one_lock is original
    finally:
        if len(events) > 1:
            events[1].set()
        for worker in workers:
            if worker.ident is not None:
                native_thread.join(worker, timeout=5)
                assert not worker.is_alive()
        for value in clients:
            assert all(not lock.locked() for lock in value._key_locks.values())


@pytest.mark.parametrize("operation,position", [("start", 0), ("start", 1), ("join", 0), ("join", 1), ("wait", 0)])
@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("after", [False, True])
def test_key_lock_workers_retire_on_caller_fault(operation, position, error, after):
    _exercise(operation, position, error, after)


def test_native_key_lock_positive_control():
    _exercise(None, None, None, False)
