"""Observe the actual delayed queue transition and its owning test."""

from contextlib import contextmanager
from types import ModuleType
import threading
import time
from core.audit.tests import test_journal_quiesce as native
from core.testing.module_views import module_function_view

@contextmanager
def exercise(phase):
    real = threading.Thread
    workers = []
    entered, release = threading.Event(), threading.Event()
    error = KeyboardInterrupt if "interrupt" in phase else RuntimeError
    class Thread(real):
        def __init__(self, *args, **kwargs):
            target = kwargs["target"]
            self.queue = dict(zip(target.__code__.co_freevars, (c.cell_contents for c in target.__closure__)))["sq"]
            self.joins = []
            super().__init__(*args, **kwargs)
            workers.append(self)
        def start(self):
            if phase.startswith("before-"):
                raise error("owned start failure")
            super().start()
            if phase.startswith("after-"):
                assert entered.wait(2), "actual queue transition callback not entered"
                raise error("owned start failure")
        def join(self, *args, **kwargs):
            self.joins.append((args, kwargs))
            release.set()
            return super().join(*args, **kwargs)
    def sleep(delay):
        assert delay == 0.1
        entered.set()
        if phase.startswith("after-"):
            assert release.wait(5), "probe fallback did not release delayed callback"
        time.sleep(delay)
    threads, clock = ModuleType("threading"), ModuleType("time")
    vars(threads).update(vars(threading))
    vars(clock).update(vars(time))
    threads.Thread, clock.sleep = Thread, sleep
    function = native.TestStudyQueuePauseProtocol.test_wait_quiescent_wakes_on_working_to_idle
    view = module_function_view(native, bindings={"_owned_case": function, "threading": threads, "time": clock})
    assert view._owned_case.__code__ is function.__code__
    try:
        yield lambda: view._owned_case(native.TestStudyQueuePauseProtocol()), workers
    finally:
        release.set()
        for worker in workers:
            if worker.ident is not None:
                real.join(worker, timeout=5)
                assert not worker.is_alive()
    assert threading.Thread is real
