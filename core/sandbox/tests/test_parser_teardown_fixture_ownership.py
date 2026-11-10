"""Native-child ownership in the existing signal-race teardown fixture."""
import os
import socket
import subprocess
from types import FunctionType, ModuleType

import pytest

from core.sandbox.tests import test_parser_jail_teardown as native
from core.testing.processes import reap_on_exit


def _exercise(phase=None, error=None, after=False):
    children, pairs, restorations = [], [], []
    failure = error("owned teardown setup fault") if error else None
    fired = False
    original = native.TestParserWorkerTeardown.test_signal_error_still_reaps_real_child
    borrowed_pair, borrowed_popen = socket.socketpair, subprocess.Popen

    def popen(*args, **kwargs):
        nonlocal fired
        if phase == "spawn":
            fired = True
            raise failure
        proc = borrowed_popen(*args, **kwargs)
        children.append(proc)
        restorations.append(proc.kill)
        return proc

    def pair():
        nonlocal fired
        if phase == "socketpair":
            fired = True
            raise failure
        result = borrowed_pair()
        pairs.append(result)
        return result

    private_process = ModuleType("subprocess")
    vars(private_process).update(vars(subprocess))
    private_process.Popen = popen
    private_socket = ModuleType("socket")
    vars(private_socket).update(vars(socket))
    private_socket.socketpair = pair
    body = FunctionType(original.__code__, {**original.__globals__, "subprocess": private_process, "socket": private_socket})
    try:
        with pytest.MonkeyPatch.context() as scope:
            class Patch:
                def setattr(self, *args, **kwargs):
                    nonlocal fired
                    if phase == "kill-publication":
                        fired = True
                        if after:
                            scope.setattr(*args, **kwargs)
                        raise failure
                    scope.setattr(*args, **kwargs)

            if error:
                with pytest.raises(error) as caught:
                    body(native.TestParserWorkerTeardown(), Patch())
                assert caught.value is failure
                assert fired
            else:
                body(native.TestParserWorkerTeardown(), Patch())
            assert len(children) == int(phase != "spawn")
            assert len(pairs) == int(phase not in ("spawn", "socketpair"))
            for proc, original_kill in zip(children, restorations):
                assert proc.returncode is not None
                assert proc.kill == original_kill
                with pytest.raises(ChildProcessError):
                    os.waitpid(proc.pid, os.WNOHANG)
            assert all(stream.fileno() == -1 for pair in pairs for stream in pair)
            assert subprocess.Popen is borrowed_popen
            assert socket.socketpair is borrowed_pair
            assert native.TestParserWorkerTeardown.test_signal_error_still_reaps_real_child is original
    finally:
        for pair in pairs:
            for stream in pair:
                stream.close()
        for proc, original_kill in zip(children, restorations):
            proc.kill = original_kill
            with reap_on_exit(proc):
                pass
            assert proc.returncode is not None


@pytest.mark.parametrize("phase,after", [("spawn", False), ("socketpair", False), ("kill-publication", False), ("kill-publication", True)])
@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt, SystemExit])
def test_actual_teardown_setup_fault_retires_native_resources(phase, after, error):
    _exercise(phase, error, after)


def test_actual_signal_race_positive_control():
    _exercise()
