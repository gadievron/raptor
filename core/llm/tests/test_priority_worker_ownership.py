"""Native throttle-priority fixture workers return all owned capacity."""
from types import FunctionType, ModuleType
import threading

import pytest

from core.llm.tests import test_throttle_priority as native


def _exercise(operation, position, error, after):
    workers, events, throttles = [], [], []
    failure = error("owned priority worker fault") if error else None
    fired = False
    original = native.TestLowPriorityAcquire.test_normal_waiter_beats_low_priority
    native_thread = threading.Thread

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
        value = threading.Event()
        events.append(value)
        return value

    def throttle(*args, **kwargs):
        value = native.AdaptiveThrottle(*args, **kwargs)
        throttles.append(value)
        return value

    private = ModuleType("threading")
    vars(private).update(vars(threading))
    private.Thread, private.Event = thread, event
    body = FunctionType(original.__code__, {**original.__globals__, "threading": private, "AdaptiveThrottle": throttle})
    try:
        if error:
            with pytest.raises(error) as caught:
                body(native.TestLowPriorityAcquire())
            assert caught.value is failure
            assert fired
        else:
            body(native.TestLowPriorityAcquire())
        expected_workers = 1 if operation == "start" and position == 0 else 3
        assert len(workers) == expected_workers and len(events) == 3 and len(throttles) == 1
        assert all(event.is_set() for event in events)
        assert all(not worker.is_alive() for worker in workers)
        assert any(worker.ident is not None for worker in workers) or (operation == "start" and position == 0 and not after)
        assert throttles[0].in_flight == 0
        assert throttles[0]._sync_waiters == 0
        assert threading.Thread is native_thread
        assert native.TestLowPriorityAcquire.test_normal_waiter_beats_low_priority is original
    finally:
        for event in events:
            event.set()
        for worker in workers:
            if worker.ident is not None:
                native_thread.join(worker, timeout=10)
                assert not worker.is_alive()
        for value in throttles:
            assert value.in_flight == 0


@pytest.mark.parametrize("operation", ["start", "join"])
@pytest.mark.parametrize("position", [0, 1, 2])
@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("after", [False, True])
def test_priority_workers_retire_on_caller_fault(operation, position, error, after):
    _exercise(operation, position, error, after)


def test_native_priority_positive_control():
    _exercise(None, None, None, False)
