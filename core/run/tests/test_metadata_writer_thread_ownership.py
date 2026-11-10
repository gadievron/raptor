"""Metadata test writers retire before their actual temporary directory."""
import builtins
from pathlib import Path
from types import FunctionType, ModuleType
import threading

import pytest

from core.run.tests import test_metadata as native
from core.testing.state_isolation import pin_user_state_dirs


def _exercise(tmp_path, monkeypatch, operation, position, error, after):
    pin_user_state_dirs(monkeypatch, tmp_path / "user")
    workers, barriers, directories, exits = [], [], [], []
    failure = error("owned metadata writer fault") if error else None
    fired = False
    original = native.TestUpdateStatusConcurrency.test_concurrent_extra_updates_all_land
    native_thread = threading.Thread
    native_directory = native.TemporaryDirectory

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

    def barrier(*args, **kwargs):
        value = threading.Barrier(*args, **kwargs)
        barriers.append(value)
        return value

    class Directory(native_directory):
        def __enter__(self):
            value = super().__enter__()
            directories.append(Path(value))
            return value

        def __exit__(self, *args):
            assert all(not worker.is_alive() for worker in workers)
            assert barriers[0].broken
            exits.append(args[0])
            return super().__exit__(*args)

    private = ModuleType("threading")
    vars(private).update(vars(threading))
    private.Thread, private.Barrier = thread, barrier

    def import_local(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "threading" and level == 0:
            return private
        return builtins.__import__(name, globals, locals, fromlist, level)

    body = FunctionType(original.__code__, {**original.__globals__, "TemporaryDirectory": Directory, "__builtins__": {**vars(builtins), "__import__": import_local}})
    try:
        if error:
            with pytest.raises(error) as caught:
                body(native.TestUpdateStatusConcurrency())
            assert caught.value is failure
            assert fired
        else:
            body(native.TestUpdateStatusConcurrency())
        assert len(workers) == 8 and len(barriers) == 1 and len(directories) == 1
        assert len(exits) == 1
        assert not directories[0].exists()
        assert all(not worker.is_alive() for worker in workers)
        assert any(worker.ident is not None for worker in workers) or (operation == "start" and position == 0 and not after)
        assert threading.Thread is native_thread
        assert native.TemporaryDirectory is native_directory
        assert native.TestUpdateStatusConcurrency.test_concurrent_extra_updates_all_land is original
    finally:
        for value in barriers:
            value.abort()
        for worker in workers:
            if worker.ident is not None:
                native_thread.join(worker, timeout=30)
                assert not worker.is_alive()


@pytest.mark.parametrize("operation", ["start", "join"])
@pytest.mark.parametrize("position", [0, 1, 7])
@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("after", [False, True])
def test_writer_retirement_precedes_directory_cleanup(tmp_path, monkeypatch, operation, position, error, after):
    _exercise(tmp_path, monkeypatch, operation, position, error, after)


def test_native_metadata_updates_positive_control(tmp_path, monkeypatch):
    _exercise(tmp_path, monkeypatch, None, None, None, False)
