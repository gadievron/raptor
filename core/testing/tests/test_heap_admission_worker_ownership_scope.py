from contextlib import contextmanager
from types import ModuleType
import threading
import time
import pytest
from packages.joern import heap_ledger, server as server_module
from packages.joern.tests import conftest as owners
import packages.joern.tests.test_heap_ledger as native
from core.testing.module_views import module_function_view

@contextmanager
def exercise(phase, tmp_path):
    real = threading.Thread
    threads = []
    error = KeyboardInterrupt if "interrupt" in phase else RuntimeError
    borrowed_ledger, borrowed_budget = heap_ledger._LEDGER_PATH, heap_ledger._host_budget_mb
    borrowed_subprocess = server_module.subprocess
    patch = pytest.MonkeyPatch()
    owners._isolated_heap_ledger.__wrapped__(tmp_path, patch)
    native._isolate_subprocess_launch_patches.__wrapped__(patch)
    class Thread(real):
        def __init__(self, *args, **kwargs):
            target = kwargs["target"]
            self.native_target = target
            cells = dict(zip(target.__code__.co_freevars, (c.cell_contents for c in target.__closure__)))
            self.barrier, self.grants = cells["barrier"], cells["grants"]
            self.ledger = cells["ledger"]
            self.completed, self.joins, self.barrier_errors = False, [], []
            self.index = len(threads)
            def running(*args, **kwargs):
                try:
                    result = target(*args, **kwargs)
                except threading.BrokenBarrierError as caught:
                    self.barrier_errors.append(caught)
                    result = None
                self.completed = True
                return result
            kwargs["target"] = running
            super().__init__(*args, **kwargs)
            threads.append(self)
        def start(self):
            if self.index == 0 and phase.startswith("before-"):
                raise error("owned start failure")
            super().start()
            if self.index == 0 and phase.startswith("after-"):
                deadline = time.monotonic() + 5
                while self.barrier.n_waiting != 1 and time.monotonic() < deadline:
                    threading.Event().wait(0.001)
                assert self.barrier.n_waiting == 1, "actual admission barrier not reached"
                raise error("owned start failure")
        def join(self, *args, **kwargs):
            self.joins.append((args, kwargs))
            assert heap_ledger._host_budget_mb() == 10000
            return super().join(*args, **kwargs)
    namespace = ModuleType("threading")
    vars(namespace).update(vars(threading))
    namespace.Thread = Thread
    function = native.TestConcurrentAdmission.test_racing_reservations_never_oversubscribe
    view = module_function_view(native, bindings={"_owned_case": function, "threading": namespace})
    assert view._owned_case.__code__ is function.__code__
    try:
        yield lambda: view._owned_case(native.TestConcurrentAdmission(), tmp_path, patch), threads
    finally:
        try:
            for thread in threads:
                thread.barrier.abort()
            for thread in threads:
                if thread.ident is not None:
                    real.join(thread, timeout=60)
                    assert not thread.is_alive()
        finally:
            patch.undo()
    assert heap_ledger._LEDGER_PATH is borrowed_ledger
    assert heap_ledger._host_budget_mb is borrowed_budget
    assert server_module.subprocess is borrowed_subprocess


@pytest.mark.parametrize("phase", ["normal", "before-error", "after-error", "before-interrupt", "after-interrupt"])
def test_admission_workers_cancel_before_native_owners_restore(phase, tmp_path):
    original_thread = threading.Thread
    borrowed_ledger, borrowed_budget = heap_ledger._LEDGER_PATH, heap_ledger._host_budget_mb
    borrowed_subprocess = server_module.subprocess
    with exercise(phase, tmp_path) as (invoke, threads):
        if phase == "normal":
            invoke()
        else:
            error = KeyboardInterrupt if "interrupt" in phase else RuntimeError
            with pytest.raises(error, match="owned start failure"):
                invoke()
        assert len(threads) == 2
        started = [thread for thread in threads if thread.ident is not None]
        expected = 2 if phase == "normal" else (0 if phase.startswith("before-") else 1)
        assert len(started) == expected
        assert all(not thread.is_alive() for thread in threads)
        assert all(thread.completed and thread.joins for thread in started)
        assert all(not thread.completed and not thread.joins for thread in threads if thread.ident is None)
        assert not any(thread.barrier_errors for thread in threads)
        assert threads[0].barrier.broken
        if phase == "normal":
            assert sorted(threads[0].grants) == [4000, 6000]
            rows = native._rows(threads[0].ledger)
            assert len(rows) == 2
        else:
            assert not threads[0].grants
            assert not threads[0].ledger.exists()
        assert heap_ledger._LEDGER_PATH == tmp_path / "heap-ledger.json"
        assert heap_ledger._host_budget_mb() == 10000
        assert threading.Thread is original_thread
    assert heap_ledger._LEDGER_PATH is borrowed_ledger
    assert heap_ledger._host_budget_mb is borrowed_budget
    assert server_module.subprocess is borrowed_subprocess
