from contextlib import contextmanager
from types import ModuleType
import threading
import pytest
from packages.joern import runner
import packages.joern.tests.test_runner_seam_binding as native
from core.testing.module_views import module_function_view

@contextmanager
def exercise(phase):
    real = threading.Thread
    threads = []
    error = KeyboardInterrupt if "interrupt" in phase else RuntimeError
    borrowed = dict(vars(runner._thread_bound_runner))
    patch = pytest.MonkeyPatch()
    patch.setitem(vars(runner._thread_bound_runner), "runner", borrowed.get("runner"))
    class Thread(real):
        def __init__(self, *args, **kwargs):
            target = kwargs["target"]
            self.native_target = target
            cells = dict(zip(target.__code__.co_freevars, (c.cell_contents for c in target.__closure__)))
            self.pinned, self.done, self.seen = cells["pinned"], cells["done"], cells["seen"]
            self.entered = threading.Event()
            self.completed, self.joins = False, []
            def running(*args, **kwargs):
                self.entered.set()
                result = target(*args, **kwargs)
                self.completed = True
                return result
            kwargs["target"] = running
            super().__init__(*args, **kwargs)
            threads.append(self)
        def start(self):
            if phase.startswith("before-"):
                raise error("owned start failure")
            super().start()
            if phase.startswith("after-"):
                assert self.entered.wait(5), "actual lookup callback not entered"
                raise error("owned start failure")
        def join(self, *args, **kwargs):
            self.joins.append((args, kwargs))
            return super().join(*args, **kwargs)
    namespace = ModuleType("threading")
    vars(namespace).update(vars(threading))
    namespace.Thread = Thread
    function = native.TestBoundSandboxRunner.test_pin_is_thread_local
    view = module_function_view(native, bindings={"_owned_case": function, "threading": namespace})
    assert view._owned_case.__code__ is function.__code__
    try:
        yield lambda: view._owned_case(native.TestBoundSandboxRunner()), threads
    finally:
        try:
            for thread in threads:
                thread.pinned.set()
            for thread in threads:
                if thread.ident is not None:
                    real.join(thread, timeout=30)
                    assert not thread.is_alive()
        finally:
            patch.undo()
    assert vars(runner._thread_bound_runner) == borrowed


@pytest.mark.parametrize("phase", ["normal", "before-error", "after-error", "before-interrupt", "after-interrupt"])
def test_lookup_worker_retires_before_pin_slot_restores(phase):
    original_thread = threading.Thread
    original_run = native.core.sandbox.run
    borrowed = dict(vars(runner._thread_bound_runner))
    with exercise(phase) as (invoke, threads):
        if phase == "normal":
            invoke()
        else:
            error = KeyboardInterrupt if "interrupt" in phase else RuntimeError
            with pytest.raises(error, match="owned start failure"):
                invoke()
        assert len(threads) == 1
        thread = threads[0]
        assert not thread.is_alive()
        assert thread.pinned.is_set()
        if phase.startswith("before-"):
            assert thread.ident is None
            assert not thread.completed and not thread.joins
            assert not thread.done.is_set()
            assert not thread.seen
        else:
            assert thread.completed and thread.joins
            assert thread.done.is_set()
            assert thread.seen == {"runner": original_run}
        assert thread.native_target.__code__.co_name == "other_thread"
        assert threading.Thread is original_thread
        assert native.core.sandbox.run is original_run
    assert vars(runner._thread_bound_runner) == borrowed
