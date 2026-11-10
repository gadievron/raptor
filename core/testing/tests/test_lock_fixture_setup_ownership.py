"""Actual held-lock fixture constructors cannot strand native holder FDs."""
import errno
import os
from types import FunctionType, ModuleType
import threading

import pytest

from core.annotations.tests import test_locking_bounded as annotation
from core.coverage.tests import test_lock_bounded as coverage
from core.run.tests import test_metadata_lock_bounded as metadata
from core.testing.state_isolation import pin_user_state_dirs


CASES = [
    (annotation, "test_wedged_holder_raises_after_bounded_wait"),
    (coverage, "test_store_lock_degrades_after_bounded_wait"),
    (coverage, "test_journal_append_fails_loudly_after_bounded_wait"),
    (metadata, "test_wedged_holder_never_blocks_finalisers_unboundedly"),
]


def _same_descriptor(fd, identity):
    try:
        current = os.fstat(fd)
    except OSError as error:
        assert error.errno == errno.EBADF
        return False
    return (current.st_dev, current.st_ino) == identity


@pytest.mark.parametrize("module,name", CASES, ids=["annotation", "coverage-store", "journal", "metadata"])
@pytest.mark.parametrize("phase", ["event", "thread"])
@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("after", [False, True])
def test_actual_lock_fixture_construction_failure_retires_holder(tmp_path, monkeypatch, caplog, module, name, phase, error, after):
    pin_user_state_dirs(monkeypatch, tmp_path / "user")
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg-data"))
    opened, workers, events = [], [], []
    failure = error("owned lock fixture construction fault")
    original = getattr(module, name)
    native_thread, native_event = threading.Thread, threading.Event
    def opened_fd(*args, **kwargs):
        fd = os.open(*args, **kwargs)
        current = os.fstat(fd)
        opened.append((fd, (current.st_dev, current.st_ino)))
        return fd
    def thread(*args, **kwargs):
        if after:
            workers.append(native_thread(*args, **kwargs))
        raise failure
    def event(*args, **kwargs):
        if phase == "event" and not after:
            raise failure
        value = native_event(*args, **kwargs)
        events.append(value)
        if phase == "event":
            raise failure
        return value
    private_os = ModuleType("os")
    vars(private_os).update(vars(os))
    private_os.open = opened_fd
    private_threading = ModuleType("threading")
    vars(private_threading).update(vars(threading))
    private_threading.Thread, private_threading.Event = thread, event
    body = FunctionType(original.__code__, {**original.__globals__, "os": private_os, "threading": private_threading})
    args = {"tmp_path": tmp_path, "monkeypatch": monkeypatch}
    if "caplog" in original.__code__.co_varnames[:original.__code__.co_argcount]:
        args["caplog"] = caplog
    try:
        with pytest.raises(error) as caught:
            body(**args)
        assert caught.value is failure
        assert len(opened) == 1
        assert len(events) == (0 if phase == "event" and not after else 1)
        assert len(workers) == int(phase == "thread" and after)
        assert all(worker.ident is None and not worker.is_alive() for worker in workers)
        assert all(not _same_descriptor(fd, identity) for fd, identity in opened)
        assert threading.Thread is native_thread and threading.Event is native_event
        assert getattr(module, name) is original
    finally:
        for fd, identity in opened:
            if _same_descriptor(fd, identity):
                os.close(fd)
