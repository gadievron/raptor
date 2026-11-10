"""Actual native atomic writer caller partial-start ownership baseline."""
import builtins
from types import FunctionType, ModuleType
import threading

import pytest

from core.atomic_fs.tests import test_atomic_fs as native
from core.testing.state_isolation import pin_user_state_dirs


@pytest.fixture(autouse=True)
def _owned_native_state(tmp_path, monkeypatch):
    pin_user_state_dirs(monkeypatch, tmp_path / "user")
    for key, leaf in [("HOME", "home"), ("XDG_DATA_HOME", "data"),
                      ("XDG_CONFIG_HOME", "config"), ("XDG_CACHE_HOME", "cache")]:
        monkeypatch.setenv(key, str(tmp_path / leaf))
    yield


def _exercise(tmp_path, monkeypatch, operation="start", position=1,
              error=RuntimeError, after=False, expect_retired=True):
    workers, events = [], []
    failure = error("owned atomic-worker boundary fault") if error else None
    fired = False
    original = native.TestAdversarial.test_concurrent_same_process_threads
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
    def import_local(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "threading" and level == 0:
            return private
        return builtins.__import__(name, globals, locals, fromlist, level)
    namespace = {**original.__globals__, "__builtins__": {**vars(builtins), "__import__": import_local}}
    body = FunctionType(original.__code__, namespace,
                        original.__name__, original.__defaults__, original.__closure__)
    try:
        if error:
            with pytest.raises(error, match="owned atomic-worker boundary fault") as caught:
                body(native.TestAdversarial(), tmp_path / "atomic")
            assert caught.value is failure
            assert fired
        else:
            body(native.TestAdversarial(), tmp_path / "atomic")
        assert len(workers) == 8 and not events
        started = [worker for worker in workers if worker.ident is not None]
        assert started or (operation == "start" and position == 0 and not after)
        if expect_retired:
            assert all(not worker.is_alive() for worker in workers)
        else:
            assert any(worker.is_alive() for worker in started), "baseline did not demonstrate a surviving worker"
        assert native.TestAdversarial.test_concurrent_same_process_threads is original
        assert threading.Thread is native_thread
    finally:
        for done in events:
            done.set()
        for worker in workers:
            if worker.ident is not None:
                native_thread.join(worker, timeout=60)
                assert not worker.is_alive(), "external baseline rescue failed"



@pytest.mark.parametrize("operation", ["start", "join"])
@pytest.mark.parametrize("position", [0, 1, 7])
@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("after", [False, True])
def test_native_worker_boundary_retires_threads(tmp_path, monkeypatch, operation, position, error, after):
    _exercise(tmp_path, monkeypatch, operation, position, error, after)


def test_native_worker_positive_control(tmp_path, monkeypatch):
    _exercise(tmp_path, monkeypatch, operation=None, error=None)
