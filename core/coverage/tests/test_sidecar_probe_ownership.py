"""Sidecar lock probes own native writers and threads across startup errors."""

import builtins
import threading
from types import FunctionType, SimpleNamespace
import pytest
from core.coverage import journal_compact
from core.coverage.tests import test_journal_slim_clean as native

def _exercise(tmp_path, error, after):
    entered = threading.Event()
    writers = []
    workers = []
    failure = error("owned native startup error") if error else None
    class Writer(journal_compact._SidecarWriter):
        def __init__(self, *args):
            super().__init__(*args)
            writers.append(self)
        def open(self):
            if len(writers) == 2:
                entered.set()
            return super().open()
    class Worker(threading.Thread):
        def start(self):
            workers.append(self)
            if error and not after:
                raise failure
            super().start()
            assert entered.wait(5), "second writer did not enter open"
            if error:
                raise failure
    def importing(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "threading":
            return SimpleNamespace(Thread=Worker, Event=threading.Event)
        if name == "core.coverage.journal_compact" and "_SidecarWriter" in fromlist:
            return SimpleNamespace(_SidecarWriter=Writer)
        return builtins.__import__(name, globals, locals, fromlist, level)
    method = native.TestSidecarLockProbes.test_second_writer_blocks_then_rereads_offset_under_lock
    body = FunctionType(method.__code__, {**method.__globals__, "__builtins__": {**vars(builtins), "__import__": importing}})
    try:
        if error:
            with pytest.raises(error) as caught:
                body(native.TestSidecarLockProbes(), tmp_path)
            assert caught.value is failure
        else:
            body(native.TestSidecarLockProbes(), tmp_path)
        assert len(workers) == 1
        assert not workers[0].is_alive()
        assert all(writer._fd is None for writer in writers)
    finally:
        if writers:
            writers[0].close()
        for worker in workers:
            if worker.ident is not None:
                worker.join(10)
                assert not worker.is_alive()
        for writer in writers:
            writer.close()


@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("after", [False, True])
def test_probe_retires_writers_and_started_worker(tmp_path, error, after):
    _exercise(tmp_path, error, after)


def test_native_probe_positive_retires_all_resources(tmp_path):
    _exercise(tmp_path, None, True)
