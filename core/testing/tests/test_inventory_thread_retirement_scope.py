"""The actual inventory thread-pool test owns retirement on every exit."""

import concurrent.futures
import threading
from core.testing.module_views import module_function_view
import core.inventory.tests.test_pool_teardown as native
import pytest

@pytest.mark.parametrize("phase", ["normal", "body-error", "body-interrupt", "submit-error", "submit-interrupt"])
def test_actual_thread_teardown_caller_retires_worker(phase):
    real = concurrent.futures.ThreadPoolExecutor
    pools = []
    error = KeyboardInterrupt if "interrupt" in phase else RuntimeError
    class Queue:
        def __init__(self, queue, pool):
            self.queue, self.pool = queue, pool
        def get(self, *args, **kwargs):
            value = self.queue.get(*args, **kwargs)
            if value is None:
                self.pool.retiring.set()
                assert self.pool.release.wait(5)
            return value
        def get_nowait(self):
            return self.queue.get_nowait()
        def put(self, value):
            return self.queue.put(value)
    class Pool(real):
        def __init__(self, *args, **kwargs):
            assert kwargs == {'max_workers': 1}
            super().__init__(*args, **kwargs)
            self.release, self.retiring = threading.Event(), threading.Event()
            self.waits = []
            self._work_queue = Queue(self._work_queue, self)
            pools.append(self)
        def submit(self, *args, **kwargs):
            future = super().submit(*args, **kwargs)
            self.future = future
            if phase.startswith("submit-"):
                raise error("owned submit failure")
            return future
        def shutdown(self, wait=True, *, cancel_futures=False):
            self.waits.append((wait, cancel_futures))
            if wait:
                self.release.set()
            return super().shutdown(wait=wait, cancel_futures=cancel_futures)
    original = native._shutdown_pool_nowait
    def teardown(pool):
        original(pool)
        if phase.startswith("body-"):
            raise error("owned body failure")
    view = module_function_view(native, bindings={'ThreadPoolExecutor': Pool, '_shutdown_pool_nowait': teardown})
    assert view.test_teardown_no_ops_on_thread_pool.__code__ is native.test_teardown_no_ops_on_thread_pool.__code__
    try:
        if phase == "normal":
            view.test_teardown_no_ops_on_thread_pool()
        else:
            with pytest.raises(error, match="owned .* failure"):
                view.test_teardown_no_ops_on_thread_pool()
        assert len(pools) == 1
        pool = pools[0]
        expected = [(True, False)] if phase.startswith("submit-") else [(False, True), (True, False)]
        assert pool.waits == expected
        assert pool.future.done()
        assert pool.retiring.is_set() and pool.release.is_set()
        assert len(pool._threads) == 1
        assert all(not worker.is_alive() for worker in pool._threads)
        assert native._shutdown_pool_nowait is original
        assert native.ThreadPoolExecutor is real
        assert concurrent.futures.ThreadPoolExecutor is real
    finally:
        for pool in pools:
            pool.release.set()
            real.shutdown(pool, wait=True)
            assert all(not worker.is_alive() for worker in pool._threads)
