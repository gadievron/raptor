"""Actual journal cache stress caller partial-start ownership baseline."""
from contextlib import contextmanager
from types import FunctionType, ModuleType
import threading

import pytest

from core.coverage.tests import test_journal_load_cache as native
from core.testing.state_isolation import pin_user_state_dirs


@pytest.fixture(autouse=True)
def _owned_native_state(tmp_path, monkeypatch):
    pin_user_state_dirs(monkeypatch, tmp_path / "user")
    for key, leaf in [("HOME", "home"), ("XDG_DATA_HOME", "data"),
                      ("XDG_CONFIG_HOME", "config"), ("XDG_CACHE_HOME", "cache")]:
        monkeypatch.setenv(key, str(tmp_path / leaf))
    with contextmanager(native._clean_cache.__wrapped__)():
        yield


def _exercise(tmp_path, monkeypatch, operation="start", position=1,
              error=RuntimeError, after=False, expect_retired=True):
    workers, events = [], []
    failure = error("owned journal-worker boundary fault") if error else None
    fired = False
    original = native.TestThreadSafety.test_concurrent_loads_during_appends_across_rolls
    native_thread = threading.Thread

    class Worker(native_thread):
        def start(self):
            nonlocal fired
            if operation == "start" and len(workers) > position and workers.index(self) == position and not fired:
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

    private = ModuleType("threading")
    vars(private).update(vars(threading))
    private.Thread = thread
    private.Event = event
    body = FunctionType(original.__code__, {**original.__globals__, "threading": private},
                        original.__name__, original.__defaults__, original.__closure__)
    try:
        if error:
            with pytest.raises(error, match="owned journal-worker boundary fault") as caught:
                body(native.TestThreadSafety(), tmp_path / "journal", monkeypatch)
            assert caught.value is failure
            assert fired
        else:
            body(native.TestThreadSafety(), tmp_path / "journal", monkeypatch)
        assert len(workers) == 5 and len(events) == 1
        started = [worker for worker in workers if worker.ident is not None]
        assert started or (operation == "start" and position == 0 and not after)
        if expect_retired:
            assert all(not worker.is_alive() for worker in workers)
        else:
            assert any(worker.is_alive() for worker in started), "baseline did not demonstrate a surviving worker"
        assert native.TestThreadSafety.test_concurrent_loads_during_appends_across_rolls is original
        assert threading.Thread is native_thread
    finally:
        for done in events:
            done.set()
        for worker in workers:
            if worker.ident is not None:
                native_thread.join(worker, timeout=60)
                assert not worker.is_alive(), "external baseline rescue failed"



@pytest.mark.parametrize("operation", ["start", "join"])
@pytest.mark.parametrize("position", [0, 1, 4])
@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("after", [False, True])
def test_native_worker_boundary_retires_threads(tmp_path, monkeypatch, operation, position, error, after):
    _exercise(tmp_path, monkeypatch, operation, position, error, after)


def test_native_worker_positive_control(tmp_path, monkeypatch):
    _exercise(tmp_path, monkeypatch, operation=None, error=None)
