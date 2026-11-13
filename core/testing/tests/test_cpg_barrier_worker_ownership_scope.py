from contextlib import ExitStack, contextmanager
from types import ModuleType
import threading
import time
import pytest
from core.run import scratch
from core.testing.module_views import module_function_view
from packages.joern import heap_ledger
from packages.joern.tests import conftest as owners
import packages.joern.tests.test_cpg_cache_concurrency as native

def cells(function):
    return dict(zip(function.__code__.co_freevars, (cell.cell_contents for cell in function.__closure__)))

@contextmanager
def exercise(phase, tmp_path):
    real = threading.Thread
    gate = threading.Event()
    threads = []
    error = KeyboardInterrupt if "interrupt" in phase else RuntimeError
    borrowed_ledger = heap_ledger._LEDGER_PATH
    borrowed_budget = heap_ledger._host_budget_mb
    borrowed_keepalive = (scratch._keepalive_paths, scratch._keepalive_thread, scratch._keepalive_loop)
    with ExitStack() as cleanup:
        patch = pytest.MonkeyPatch()
        cleanup.callback(patch.undo)
        owners._isolated_heap_ledger.__wrapped__(tmp_path, patch)
        keepalive = owners._isolated_graph_keepalive.__wrapped__()
        next(keepalive)
        cleanup.callback(keepalive.close)
        assert heap_ledger._LEDGER_PATH == tmp_path / "heap-ledger.json"
        class Thread(real):
            def __init__(self, *args, **kwargs):
                target = kwargs["target"]
                self.native_target = target
                state = cells(target)
                self.results = state["results"]
                self.barrier = cells(state["fake_runner"])["both_building"]
                self.barrier_errors = []
                self.completed = False
                def running(*args, **kwargs):
                    assert gate.wait(10), "owned worker gate not released"
                    try:
                        result = target(*args, **kwargs)
                    except threading.BrokenBarrierError as caught:
                        self.barrier_errors.append(caught)
                        result = None
                    self.completed = True
                    return result
                kwargs["target"] = running
                self.index, self.joins = len(threads), []
                super().__init__(*args, **kwargs)
                threads.append(self)
            def start(self):
                if self.index == 0 and phase.startswith("before-"):
                    raise error("owned start failure")
                gate.set()
                super().start()
                if self.index == 0 and phase.startswith("after-"):
                    deadline = time.monotonic() + 5
                    while self.barrier.n_waiting != 1 and time.monotonic() < deadline:
                        threading.Event().wait(0.001)
                    assert self.barrier.n_waiting == 1, "actual two-party barrier was not reached"
                    raise error("owned start failure")
            def join(self, *args, **kwargs):
                self.joins.append((args, kwargs))
                gate.set()
                return super().join(*args, **kwargs)
        namespace = ModuleType("threading")
        vars(namespace).update(vars(threading))
        namespace.Thread = Thread
        function = native.TestConcurrentDifferentTargets.test_parallel_builds_never_swap_payloads
        view = module_function_view(native, bindings={"_owned_case": function, "threading": namespace})
        assert view._owned_case.__code__ is function.__code__
        try:
            yield lambda: view._owned_case(native.TestConcurrentDifferentTargets(), tmp_path), threads
        finally:
            for thread in threads:
                thread.barrier.abort()
            gate.set()
            for thread in threads:
                if thread.ident is not None:
                    real.join(thread, timeout=60)
                    assert not thread.is_alive()
    assert heap_ledger._LEDGER_PATH is borrowed_ledger
    assert heap_ledger._host_budget_mb is borrowed_budget
    assert scratch._keepalive_paths is borrowed_keepalive[0]
    assert scratch._keepalive_thread is borrowed_keepalive[1]
    assert scratch._keepalive_loop is borrowed_keepalive[2]


@pytest.mark.parametrize("phase", ["normal", "before-error", "after-error", "before-interrupt", "after-interrupt"])
def test_distinct_target_workers_cancel_before_owner_teardown(phase, tmp_path):
    original_thread = threading.Thread
    original_build = native.build_cpg_cached
    borrowed_paths = scratch._keepalive_paths
    borrowed_ledger = heap_ledger._LEDGER_PATH
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
        results = threads[0].results
        assert len(results) == expected
        if phase == "normal":
            assert all(not result.build_failed and result.path.is_file() for result in results.values())
            assert len({result.path for result in results.values()}) == 2
        elif expected:
            assert results["a"].build_failed
            assert not results["a"].path.exists()
        assert not scratch._keepalive_paths
        assert scratch._keepalive_paths is not borrowed_paths
        assert heap_ledger._LEDGER_PATH == tmp_path / "heap-ledger.json"
        assert threading.Thread is original_thread
        assert native.build_cpg_cached is original_build
    assert scratch._keepalive_paths is borrowed_paths
    assert heap_ledger._LEDGER_PATH is borrowed_ledger
