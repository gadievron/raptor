"""Pack-lock fixtures close their holder before retiring any waiter."""

import os
import threading
from types import ModuleType

import pytest

from core.dataflow.tests import test_pack_write_lock_bounded as native
from core.testing.module_views import module_function_view


def _exercise(stage, error, after, tmp_path, monkeypatch, caplog):
    failure = error("owned pack lock fixture fault") if error else None
    holders = []
    sentinels = []
    closed = []
    reached = []
    workers = []
    ready, release = threading.Event(), threading.Event()
    os_view = ModuleType("os")
    vars(os_view).update(vars(os))

    def opened(path, flags, mode=0o777):
        assert path == str(tmp_path / "pack.json.lock")
        fd = os.open(path, flags, mode)
        stamp = os.fstat(fd)
        holders.append((fd, stamp.st_dev, stamp.st_ino))
        return fd

    def close(fd):
        assert len(holders) == 1 and fd == holders[0][0]
        stamp = os.fstat(fd)
        assert (stamp.st_dev, stamp.st_ino) == holders[0][1:]
        closed.append(fd)
        assert len(closed) == 1
        os.close(fd)
        sentinel = os.open(tmp_path / "caller-sentinel", os.O_RDWR | os.O_CREAT, 0o600)
        stamp = os.fstat(sentinel)
        sentinels.append((sentinel, stamp.st_dev, stamp.st_ino))
        release.set()

    os_view.open, os_view.close = opened, close
    thread_view = ModuleType("threading")
    vars(thread_view).update(vars(threading))

    def fail(*args, **kwargs):
        reached.append(True)
        raise failure

    class Worker(threading.Thread):
        def run(self):
            if stage == "start":
                ready.set()
                assert release.wait(10), "holder cleanup did not release the owned worker"
            super().run()

        def start(self):
            if stage != "start":
                return super().start()
            reached.append(True)
            if after:
                super().start()
                assert ready.wait(5), "owned worker did not reach its startup gate"
            raise failure

    def worker(*args, **kwargs):
        value = Worker(*args, **kwargs)
        workers.append(value)
        return value

    thread_view.Thread = worker
    if stage in {"Event", "Thread"}:
        setattr(thread_view, stage, fail)
    view = module_function_view(native, bindings={"os": os_view, "threading": thread_view})
    function = view.test_wedged_holder_degrades_after_bounded_wait
    assert function.__code__ is native.test_wedged_holder_degrades_after_bounded_wait.__code__
    try:
        if error:
            with pytest.raises(error) as caught:
                function(tmp_path, monkeypatch, caplog)
            assert caught.value is failure and reached == [True]
        else:
            function(tmp_path, monkeypatch, caplog)
        assert len(holders) == len(closed) == len(sentinels) == 1
        assert all(not thread.is_alive() for thread in workers)
        for fd, dev, ino in sentinels:
            stamp = os.fstat(fd)
            assert (stamp.st_dev, stamp.st_ino) == (dev, ino)
    finally:
        # The independent rescue owns only resources captured by this proof.
        release.set()
        for thread in workers:
            if thread.ident is not None:
                threading.Thread.join(thread, timeout=10)
                assert not thread.is_alive(), "owned worker survived rescue"
        if not closed:
            for fd, dev, ino in holders:
                stamp = os.fstat(fd)
                assert (stamp.st_dev, stamp.st_ino) == (dev, ino)
                os.close(fd)
        for fd, dev, ino in sentinels:
            stamp = os.fstat(fd)
            assert (stamp.st_dev, stamp.st_ino) == (dev, ino)
            os.close(fd)


@pytest.mark.parametrize("stage", ["Event", "Thread"])
@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt])
def test_constructor_fault_closes_holder_once(stage, error, tmp_path, monkeypatch, caplog):
    _exercise(stage, error, False, tmp_path, monkeypatch, caplog)


@pytest.mark.parametrize("after", [False, True])
@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt])
def test_start_fault_closes_holder_before_waiter_retirement(after, error, tmp_path, monkeypatch, caplog):
    _exercise("start", error, after, tmp_path, monkeypatch, caplog)


def test_normal_bounded_wait_preserves_caller_descriptor(tmp_path, monkeypatch, caplog):
    _exercise("normal", None, False, tmp_path, monkeypatch, caplog)
