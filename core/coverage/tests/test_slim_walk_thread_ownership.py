"""Concurrent slim-walk probes own each native worker before startup."""

import builtins
import threading
from types import FunctionType, SimpleNamespace

import pytest

from core.coverage.tests import test_journal_slim_clean as native


def _exercise(tmp_path, error, index, after):
    workers = []
    completed = []
    joined = []
    failure = error("owned slim walk startup error") if error else None

    class Worker(threading.Thread):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.index = len(workers)
            self.entered = threading.Event()
            self.release = threading.Event()
            workers.append(self)

        def start(self):
            if error and self.index == index and not after:
                raise failure
            super().start()
            assert self.entered.wait(5), "native worker did not enter the consumer"
            if error and self.index == index:
                raise failure
            if not error and self.index == 1:
                for worker in workers:
                    worker.release.set()

        def join(self, timeout=None):
            joined.append(self)
            self.release.set()
            return super().join(timeout=timeout)

    def compact(*args, **kwargs):
        worker = threading.current_thread()
        worker.entered.set()
        assert worker.release.wait(10), "owned test gate not released"
        result = native.compact_journal(*args, **kwargs)
        completed.append(worker)
        return result

    def importing(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "threading":
            return SimpleNamespace(Thread=Worker)
        return builtins.__import__(name, globals, locals, fromlist, level)

    method = native.TestSidecarLockProbes.test_concurrent_slim_walks_offsets_and_stubs_hold
    body = FunctionType(method.__code__, {
        **method.__globals__,
        "compact_journal": compact,
        "__builtins__": {**vars(builtins), "__import__": importing},
    })
    try:
        if error:
            with pytest.raises(error) as caught:
                body(native.TestSidecarLockProbes(), tmp_path)
            assert caught.value is failure
        else:
            body(native.TestSidecarLockProbes(), tmp_path)
        assert len(workers) == 2
        started = [worker for worker in workers if worker.ident is not None]
        assert len(started) == (index + int(after) if error else 2)
        assert not any(worker.is_alive() for worker in workers)
        assert set(completed) == set(started)
        assert all(worker in joined for worker in started)
    finally:
        for worker in workers:
            worker.release.set()
        for worker in workers:
            if worker.ident is not None:
                threading.Thread.join(worker, timeout=60)
                assert not worker.is_alive()


@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("index", [0, 1])
@pytest.mark.parametrize("after", [False, True])
def test_slim_walk_start_errors_retire_started_workers(tmp_path, error, index, after):
    _exercise(tmp_path, error, index, after)


def test_native_concurrent_walks_keep_assertions_and_retire_workers(tmp_path):
    _exercise(tmp_path, None, 1, True)
