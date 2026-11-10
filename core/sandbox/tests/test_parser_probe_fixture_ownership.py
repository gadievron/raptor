"""Actual direct parser-worker probe owns startup sockets and native child.

Lifecycle fault cases do not establish confinement. The original readiness
probe is also selected, with its native assertions unchanged.
"""
import errno
import os
import socket
import subprocess
from types import FunctionType, ModuleType

import pytest

from core.sandbox.tests import test_parser_jail as native
from core.testing.processes import reap_on_exit
from core.sandbox import _parser_jail_child as child
from core.sandbox import landlock
from core.testing.state_isolation import pin_user_state_dirs


def _exercise_direct(tmp_path, monkeypatch, phase=None, error=None, after=False):
    pin_user_state_dirs(monkeypatch, tmp_path / "user")
    pairs, children = [], []
    failure = error("owned parser probe startup fault") if error else None
    fired = False
    borrowed_socketpair, borrowed_popen = socket.socketpair, subprocess.Popen
    original = native.TestStartupAttribution.test_direct_spawn_ready_frame_with_stderr_captured
    class ChildSocket:
        def __init__(self, raw):
            self.raw = raw
        def __getattr__(self, name):
            return getattr(self.raw, name)
        def close(self):
            nonlocal fired
            if phase == "child-close" and not fired:
                fired = True
                if after:
                    self.raw.close()
                raise failure
            return self.raw.close()
    def pair():
        parent, child = borrowed_socketpair()
        pairs.append((parent, child))
        return parent, ChildSocket(child)
    def popen(*args, **kwargs):
        nonlocal fired
        if phase == "spawn":
            fired = True
            raise failure
        child = borrowed_popen(*args, **kwargs)
        children.append(child)
        return child
    private_socket = ModuleType("socket")
    vars(private_socket).update(vars(socket))
    private_socket.socketpair = pair
    private_subprocess = ModuleType("subprocess")
    vars(private_subprocess).update(vars(subprocess))
    private_subprocess.Popen = popen
    body = FunctionType(original.__code__, {**original.__globals__, "socket": private_socket, "subprocess": private_subprocess})
    try:
        if error:
            with pytest.raises(error) as caught:
                body(native.TestStartupAttribution())
            assert caught.value is failure
            assert fired
        else:
            body(native.TestStartupAttribution())
        assert len(pairs) == 1
        assert all(stream.fileno() == -1 for stream in pairs[0])
        assert len(children) == int(phase != "spawn")
        for child in children:
            assert child.returncode is not None
            assert child.stderr is not None and child.stderr.closed
            with pytest.raises(ChildProcessError):
                os.waitpid(child.pid, os.WNOHANG)
        assert socket.socketpair is borrowed_socketpair
        assert subprocess.Popen is borrowed_popen
        assert native.TestStartupAttribution.test_direct_spawn_ready_frame_with_stderr_captured is original
    finally:
        for pair in pairs:
            for stream in pair:
                stream.close()
        for child in children:
            with reap_on_exit(child):
                pass
            assert child.returncode is not None


@pytest.mark.parametrize("phase,after", [("spawn", False), ("child-close", False), ("child-close", True)])
@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt, SystemExit])
def test_actual_parser_probe_startup_fault_retires_resources(tmp_path, monkeypatch, phase, after, error):
    _exercise_direct(tmp_path, monkeypatch, phase, error, after)


def test_actual_native_parser_probe_positive_control(tmp_path, monkeypatch):
    _exercise_direct(tmp_path, monkeypatch)


def _same_descriptor(fd, identity):
    try:
        current = os.fstat(fd)
    except OSError as error:
        assert error.errno == errno.EBADF
        return False
    return (current.st_dev, current.st_ino) == identity


def _exercise_stage(attribute=None, error=None, after=False):
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
def test_actual_parser_stage_setup_failure_retires_owned_sockets(attribute, error, after):
    _exercise_stage(attribute, error, after)


def test_native_parser_attributed_failure_positive_control():
    _exercise_stage()
