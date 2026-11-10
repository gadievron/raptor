"""Actual in-process startup test owns sockets until explicit adoption.

Setup-fault controls never enter child main. The native positive case forces
its original probe failure before limits/confinement are applied.
"""
import errno
import os
import socket
from types import FunctionType, ModuleType

import pytest

from core.llm.dispatcher import _usage_scan_child as child
from core.llm.dispatcher.tests import test_usage_scan_jail as native
from core.sandbox import landlock


def _same_descriptor(fd, identity):
    try:
        current = os.fstat(fd)
    except OSError as error:
        assert error.errno == errno.EBADF
        return False
    return (current.st_dev, current.st_ino) == identity


def _exercise(attribute=None, error=None, after=False):
    pairs, identities, detaches, worker_closes = [], {}, [], []
    failure = error("owned stage instrumentation fault") if error else None
    fired = False
    original = native.TestStartupAttribution.test_startup_exception_reports_stage_in_ready_frame
    borrowed_pair = socket.socketpair
    borrowed = (child._close_inherited_fds, child._SOCK_FD, landlock.check_landlock_available)
    class WorkerSocket:
        def __init__(self, raw):
            self.raw = raw
        def __getattr__(self, name):
            return getattr(self.raw, name)
        def detach(self):
            fd = self.raw.detach()
            detaches.append(fd)
            return fd
        def close(self):
            worker_closes.append(self.raw.fileno())
            return self.raw.close()
    def pair():
        parent, worker = borrowed_pair()
        pairs.append((parent, worker))
        for stream in (parent, worker):
            current = os.fstat(stream.fileno())
            identities[stream.fileno()] = (current.st_dev, current.st_ino)
        return parent, WorkerSocket(worker)
    private = ModuleType("socket")
    vars(private).update(vars(socket))
    private.socketpair = pair
    body = FunctionType(original.__code__, {**original.__globals__, "socket": private})
    try:
        with pytest.MonkeyPatch.context() as scope:
            class Patch:
                def setattr(self, target, name, value, *args, **kwargs):
                    nonlocal fired
                    if name == attribute:
                        fired = True
                        if after:
                            scope.setattr(target, name, value, *args, **kwargs)
                        raise failure
                    scope.setattr(target, name, value, *args, **kwargs)
            if error:
                with pytest.raises(error) as caught:
                    body(native.TestStartupAttribution(), Patch())
                assert caught.value is failure
                assert fired
                assert detaches == []
                assert all(not _same_descriptor(fd, identity) for fd, identity in identities.items())
            else:
                body(native.TestStartupAttribution(), Patch())
                assert len(detaches) == 1
                assert worker_closes == [-1], "cleanup retried an adopted raw descriptor"
            assert len(pairs) == 1 and len(identities) == 2
            assert all(stream.fileno() == -1 for stream in pairs[0])
            assert socket.socketpair is borrowed_pair
            assert native.TestStartupAttribution.test_startup_exception_reports_stage_in_ready_frame is original
        assert child._close_inherited_fds is borrowed[0]
        assert child._SOCK_FD == borrowed[1]
        assert landlock.check_landlock_available is borrowed[2]
    finally:
        for pair in pairs:
            for stream in pair:
                stream.close()
        # A detached descriptor belongs to child main; never retry its raw FD.


@pytest.mark.parametrize("attribute", ["_close_inherited_fds", "_SOCK_FD", "check_landlock_available"])
@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("after", [False, True])
def test_actual_stage_setup_failure_retires_owned_sockets(attribute, error, after):
    _exercise(attribute, error, after)


def test_native_attributed_failure_positive_control():
    _exercise()
