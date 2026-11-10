"""Actual annotation FIFO-refusal worker retires across caller faults."""
from types import FunctionType, ModuleType
import threading

import pytest

from core.annotations.tests import test_locking_bounded as native


def _exercise(tmp_path, operation, error, after):
    workers, events = [], []
    main = threading.current_thread()
    failure = error("owned FIFO caller fault") if error else None
    fired = False
    original = native.test_fifo_at_lock_path_is_refused_loudly
    native_thread = threading.Thread

    class Event(threading.Event):
        def wait(self, *args, **kwargs):
            nonlocal fired
            if operation == "wait" and threading.current_thread() is main and not fired:
                fired = True
                if after:
                    assert super().wait(*args, **kwargs), "native FIFO refusal did not complete"
                raise failure
            return super().wait(*args, **kwargs)

    class Worker(native_thread):
        def start(self):
            nonlocal fired
            if operation == "start" and not fired:
                fired = True
                if after:
                    super().start()
                raise failure
            return super().start()
        def join(self, *args, **kwargs):
            nonlocal fired
            if operation == "join" and not fired:
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
    body = FunctionType(original.__code__, {**original.__globals__, "threading": private})
    try:
        if error:
            with pytest.raises(error) as caught:
                body(tmp_path)
            assert caught.value is failure
            assert fired
        else:
            body(tmp_path)
        assert len(workers) == len(events) == 1
        assert not workers[0].is_alive()
        if operation == "start" and not after:
            assert workers[0].ident is None
        else:
            assert workers[0].ident is not None and events[0].is_set()
        assert threading.Thread is native_thread
        assert native.test_fifo_at_lock_path_is_refused_loudly is original
    finally:
        for worker in workers:
            if worker.ident is not None:
                native_thread.join(worker, timeout=10)
                assert not worker.is_alive()


@pytest.mark.parametrize("operation", ["start", "wait", "join"])
@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("after", [False, True])
def test_native_fifo_worker_retires_on_caller_fault(tmp_path, operation, error, after):
    _exercise(tmp_path, operation, error, after)


def test_native_fifo_refusal_positive_control(tmp_path):
    _exercise(tmp_path, None, None, False)
