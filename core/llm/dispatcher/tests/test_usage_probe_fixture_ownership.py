"""Actual direct usage-worker probe owns startup sockets and native child.

Lifecycle fault cases do not establish confinement. The original readiness
probe is also selected, with its native assertions unchanged.
"""
import os
import socket
import subprocess
from types import FunctionType, ModuleType

import pytest

from core.llm.dispatcher.tests import test_usage_scan_jail as native
from core.testing.processes import reap_on_exit
from core.testing.state_isolation import pin_user_state_dirs


def _exercise(tmp_path, monkeypatch, phase=None, error=None, after=False):
    pin_user_state_dirs(monkeypatch, tmp_path / "user")
    pairs, children = [], []
    failure = error("owned usage probe startup fault") if error else None
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
def test_actual_usage_probe_startup_fault_retires_resources(tmp_path, monkeypatch, phase, after, error):
    _exercise(tmp_path, monkeypatch, phase, error, after)


def test_actual_native_usage_probe_positive_control(tmp_path, monkeypatch):
    _exercise(tmp_path, monkeypatch)
