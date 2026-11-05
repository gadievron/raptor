"""Own mocked SCA calibration workers before restoring borrowed registries."""

from contextlib import ExitStack, contextmanager
from types import ModuleType

from core.testing.module_state import isolated_module_state


def _module_view(original):
    view = ModuleType(original.__name__)
    view.__dict__.update(vars(original))
    return view


@contextmanager
def isolated_stress_workers(stress, monkeypatch):
    """Drain owned mock-scan pools and heartbeat threads before state restoration.

    The tests supply bounded mock scans and release their blocked scans in
    finally blocks. This scope joins them even when the production sweep
    deliberately abandons a timed-out future. It does not alter scan budgets.
    """
    pools, threads, events = [], [], []
    threading = _module_view(stress.threading)
    concurrent = _module_view(stress.concurrent)
    futures = _module_view(stress.concurrent.futures)
    concurrent.futures = futures
    real_event = threading.Event
    real_executor = futures.ThreadPoolExecutor

    class OwnedThread(threading.Thread):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            threads.append(self)

    class OwnedExecutor(real_executor):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            pools.append(self)

    def event(*args, **kwargs):
        owned = real_event(*args, **kwargs)
        events.append(owned)
        return owned

    threading.Thread = OwnedThread
    threading.Event = event
    futures.ThreadPoolExecutor = OwnedExecutor

    def join(thread):
        if thread.ident is not None:
            thread.join(timeout=5)
            assert not thread.is_alive(), "calibration heartbeat failed to stop"

    def shutdown(pool):
        try:
            pool.shutdown(wait=True, cancel_futures=True)
        except BaseException:
            # A shutdown hook or interrupted join can raise before taking
            # effect. Finish this real owned pool via the original class before
            # propagating the error and restoring any borrowed bindings.
            real_executor.shutdown(pool, wait=True, cancel_futures=True)
            raise

    def finish_workers():
        for owned in events:
            owned.set()
        with ExitStack() as cleanup:
            for thread in reversed(threads):
                cleanup.callback(join, thread)
            for pool in reversed(pools):
                cleanup.callback(shutdown, pool)

    with isolated_module_state(stress, {
        "_ACTIVE_SCANS": {}, "threading": threading, "concurrent": concurrent,
    }, lock=stress._ACTIVE_SCANS_LOCK):
        with ExitStack() as cleanup:
            # Keep the scan seams and registry private until every owned worker
            # has finished; only then may test-body patches and borrowed state
            # be restored.
            cleanup.callback(monkeypatch.undo)
            cleanup.callback(finish_workers)
            yield
