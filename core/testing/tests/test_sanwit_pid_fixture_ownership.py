"""Native live-PID fixture retains its child through teardown faults."""

import ast
import builtins
from collections.abc import Iterator
import contextlib
import os
from pathlib import Path
import signal
import subprocess
import sys
from types import ModuleType

import pytest

from core.testing.processes import reap_on_exit

ROOT = Path(__file__).resolve().parents[3]
NATIVE = "core/audit/tests/test_sanwit_channel.py"
pytestmark = [pytest.mark.slow, pytest.mark.skipif(os.name != "posix", reason="POSIX live-PID fixture")]


def _fixture(*, streams, phase=None, error=None, import_error=None):
    processes, reached = [], []
    failure = error("owned fixture boundary fault") if error else None
    private = ModuleType("subprocess")
    vars(private).update(vars(subprocess))

    def spawn(*args, **kwargs):
        if streams:
            kwargs.update(stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        process = subprocess.Popen(*args, **kwargs)
        processes.append(process)
        native_kill, native_wait = process.kill, process.wait
        waits = 0

        def killing():
            result = native_kill()
            if phase == "after_kill":
                reached.append(phase)
                raise failure
            return result

        def waiting(*args, **kwargs):
            nonlocal waits
            waits += 1
            if waits == 1 and phase == "before_wait":
                reached.append(phase)
                raise failure
            result = native_wait(*args, **kwargs)
            if waits == 1 and phase == "after_wait":
                reached.append(phase)
                raise failure
            return result

        process.kill, process.wait = killing, waiting
        return process

    private.Popen = spawn

    def importing(name, *args, **kwargs):
        if name == "subprocess":
            return private
        if name == "core.testing.processes" and import_error:
            raise import_error("owner import interrupted")
        return builtins.__import__(name, *args, **kwargs)

    namespace = dict(contextlib=contextlib, Iterator=Iterator,
                     __builtins__=dict(vars(builtins), __import__=importing))
    cls = next(n for n in ast.parse((ROOT / NATIVE).read_text()).body
               if isinstance(n, ast.ClassDef) and n.name == "TestOrphanContainment")
    node = next(n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == "_live_pid")
    exec(compile(ast.Module(body=[node], type_ignores=[]), NATIVE, "exec"), namespace)
    return namespace["_live_pid"], processes, reached, failure


def _assert_reaped(processes):
    assert len(processes) == 1
    process = processes[0]
    assert process.args == [sys.executable, "-c", "import time; time.sleep(60)"]
    assert process.returncode == -signal.SIGKILL
    with pytest.raises(ChildProcessError):
        os.waitpid(process.pid, os.WNOHANG)
    assert all(stream is None or stream.closed for stream in (process.stdin, process.stdout, process.stderr))


def _cleanup(processes):
    for process in processes:
        with reap_on_exit(process):
            pass


@pytest.mark.parametrize("streams", [False, True])
@pytest.mark.parametrize("finish", ["resume", "close", "error", "interrupt"])
def test_fixture_exit_reaps_owned_live_pid(streams, finish):
    factory, processes, _, _ = _fixture(streams=streams)
    scope = factory(object())
    try:
        if finish == "close":
            pid = scope.__enter__()
            assert pid == processes[0].pid and processes[0].poll() is None
            scope.gen.close()
        else:
            expected = (pytest.raises(OSError if finish == "error" else KeyboardInterrupt)
                        if finish in ("error", "interrupt") else contextlib.nullcontext())
            with expected:
                with scope as pid:
                    assert pid == processes[0].pid and processes[0].poll() is None
                    if finish == "error":
                        raise OSError("owned body error")
                    if finish == "interrupt":
                        raise KeyboardInterrupt("owned body interruption")
        _assert_reaped(processes)
    finally:
        scope.gen.close()
        _cleanup(processes)


@pytest.mark.parametrize("streams", [False, True])
@pytest.mark.parametrize("phase,error", [
    ("after_kill", OSError), ("after_kill", KeyboardInterrupt), ("after_kill", SystemExit),
    ("before_wait", KeyboardInterrupt),
    ("after_wait", OSError), ("after_wait", KeyboardInterrupt), ("after_wait", SystemExit),
])
def test_teardown_fault_reaps_closes_and_preserves_error(streams, phase, error):
    factory, processes, reached, failure = _fixture(streams=streams, phase=phase, error=error)
    try:
        with pytest.raises(error) as caught:
            with factory(object()) as pid:
                assert pid == processes[0].pid and processes[0].poll() is None
        assert caught.value is failure and reached == [phase]
        _assert_reaped(processes)
    finally:
        _cleanup(processes)


@pytest.mark.parametrize("error", [ImportError, KeyboardInterrupt])
def test_owner_import_precedes_native_child(error):
    factory, processes, _, _ = _fixture(streams=False, import_error=error)
    with pytest.raises(error, match="owner import interrupted"):
        with factory(object()):
            pytest.fail("body reached after failed owner import")
    assert processes == []
