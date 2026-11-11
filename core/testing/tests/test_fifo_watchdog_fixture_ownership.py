"""FIFO refusal watchdogs retire before caller fixtures leave scope."""

import errno
import os
import threading
import time
from types import FunctionType, ModuleType

import pytest
from core.coverage.tests import test_reader_fd_discipline as native


def _same(fd, identity):
    try:
        actual = os.fstat(fd)
    except OSError as error:
        assert error.errno == errno.EBADF
        return False
    return (actual.st_dev, actual.st_ino) == identity


def _rescue(fifo, mode, workers):
    held = None
    try:
        if any(worker.is_alive() for worker in workers):
            if mode == "writer":
                held = os.open(fifo, os.O_RDONLY | os.O_NONBLOCK)
            else:
                deadline = time.monotonic() + 5
                while any(worker.is_alive() for worker in workers):
                    try:
                        fd = os.open(fifo, os.O_WRONLY | os.O_NONBLOCK)
                    except OSError as error:
                        if error.errno != errno.ENXIO:
                            raise
                        assert time.monotonic() < deadline
                        time.sleep(0.005)
                    else:
                        os.close(fd)
                        break
        for worker in workers:
            if worker.ident is not None:
                threading.Thread.join(worker, timeout=5)
            assert not worker.is_alive()
    finally:
        if held is not None:
            os.close(held)


def _exercise(tmp_path, mode, operation, after, error):
    fifo = tmp_path / "owned.fifo"
    os.mkfifo(fifo)
    workers, acquired, results = [], [], []
    failure = error("owned watchdog boundary") if error else None
    actual_thread, actual_event = threading.Thread, threading.Event

    class Worker(actual_thread):
        def start(self):
            if operation == "start" and not after:
                raise failure
            super().start()
            if operation == "start":
                raise failure

    def thread(*args, **kwargs):
        worker = Worker(*args, **kwargs)
        workers.append(worker)
        return worker

    class Done:
        def __init__(self):
            self.event = actual_event()

        def __getattr__(self, name):
            return getattr(self.event, name)

        def wait(self, timeout):
            if operation == "wait" and not after:
                raise failure
            result = self.event.wait(timeout)
            if operation == "wait":
                raise failure
            return result

    private = ModuleType(threading.__name__)
    vars(private).update(vars(threading))
    private.Thread, private.Event = thread, Done
    original = native._bounded
    invoke = FunctionType(
        original.__code__,
        dict(original.__globals__, threading=private),
        original.__name__,
        original.__defaults__,
        original.__closure__,
    )

    def call():
        fd = os.open(fifo, os.O_WRONLY if mode == "writer" else os.O_RDONLY)
        state = os.fstat(fd)
        acquired.append((fd, (state.st_dev, state.st_ino)))
        try:
            if mode == "writer":
                assert os.write(fd, b"owned") == 5
                results.append("written")
            elif mode == "reader-eof":
                results.append(os.read(fd, 1))
            else:
                results.append("opened")
            return "owned operation"
        finally:
            os.close(fd)

    borrowed = (threading.Thread, threading.Event)
    try:
        if operation is None:
            with pytest.raises(AssertionError, match="call wedged on a planted FIFO"):
                invoke(call, secs=0.05, fifo=fifo, writer=mode == "writer")
        else:
            with pytest.raises(error) as caught:
                invoke(call, secs=0.05, fifo=fifo, writer=mode == "writer")
            assert caught.value is failure
        assert len(workers) == 1
        assert not workers[0].is_alive()
        assert all(not _same(fd, identity) for fd, identity in acquired)
        if operation == "start" and not after:
            assert not acquired and not results
        else:
            assert len(acquired) == 1
            assert results == [
                {"writer": "written", "reader-eof": b"", "reader-open": "opened"}[mode]
            ]
        assert threading.Thread is borrowed[0]
        assert threading.Event is borrowed[1]
    finally:
        _rescue(fifo, mode, workers)


@pytest.mark.parametrize("mode", ["reader-open", "reader-eof", "writer"])
def test_watchdog_timeout_retires_native_worker(tmp_path, mode):
    _exercise(tmp_path, mode, None, False, None)


@pytest.mark.parametrize("mode", ["reader-open", "reader-eof", "writer"])
@pytest.mark.parametrize("operation", ["start", "wait"])
@pytest.mark.parametrize("after", [False, True])
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt, SystemExit])
def test_watchdog_boundary_keeps_error_and_retires(
    tmp_path, mode, operation, after, error
):
    _exercise(tmp_path, mode, operation, after, error)


@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt, SystemExit])
def test_watchdog_returns_original_callee_error(error):
    failure = error("owned callee failure")

    def call():
        raise failure

    kind, actual = native._bounded(call, fifo=None, writer=False)
    assert kind == "raised"
    assert actual is failure
