"""Known-dead PID helpers retain child ownership when their wait fails."""

import ast
import builtins
from inspect import signature
import os
from pathlib import Path
import signal
import subprocess
import sys
from types import ModuleType

import pytest

from core.testing.processes import reap_on_exit


ROOT = Path(__file__).resolve().parents[3]
CASES = [
    ("packages/joern/tests/test_workspace_sweep.py", "_dead_pid"),
    ("core/llm/dispatcher/tests/test_inproc_scratch_cleanup.py", "_dead_pid"),
    ("core/run/tests/test_emu_basetemp_sweep.py", "_dead_pid"),
    ("core/run/tests/test_metadata.py", "_dead_pid"),
    ("core/run/tests/test_session_scratch_sweep.py", "_dead_pid"),
    ("core/run/tests/test_tmp_ownership.py", "_dead_pid"),
    ("core/run/tests/test_tmp_reaper.py", "TestDeadPidDirReaping._dead_pid"),
    ("core/run/tests/test_tmp_reaper.py", "TestPidSuffixDirReaping._dead_pid"),
    ("core/run/tests/test_tmp_reaper.py", "TestPidFileReaping._dead_pid"),
    ("core/run/tests/test_tmp_reaper.py", "TestPidLivenessAgeFloor._dead_pid"),
    ("core/run/tests/test_tmp_reaper.py", "TestMidSweepVanish._dead_pid"),
]
pytestmark = [pytest.mark.slow, pytest.mark.skipif(os.name != "posix", reason="POSIX known-dead PID controls")]


def _error(error):
    if error is subprocess.TimeoutExpired:
        return error("owned test child", 10)
    return error("wait interrupted")


def _helper(case, streams=False, *, phase=None, error=None, import_error=None):
    processes, calls = [], []
    view = ModuleType("subprocess")
    view.__dict__.update(vars(subprocess))

    def spawn(args, **kwargs):
        launched = [sys.executable, "-c", "import time; time.sleep(300)"] if phase == "before" else args
        if streams:
            kwargs.update(stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        process = subprocess.Popen(launched, **kwargs)
        processes.append(process)
        wait, kill = process.wait, process.kill
        seen = 0
        record = {"args": args, "waits": [], "kills": 0}
        calls.append(record)

        def waiting(*args, **kwargs):
            nonlocal seen
            seen += 1
            record["waits"].append((args, kwargs))
            if seen == 1 and phase == "before":
                raise _error(error)
            result = wait(*args, **kwargs)
            if seen == 1 and phase == "after":
                raise _error(error)
            return result

        def killing():
            record["kills"] += 1
            return kill()

        process.wait, process.kill = waiting, killing
        return process

    view.Popen = spawn

    def private_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "subprocess":
            return view
        if name == "core.testing.processes" and import_error is not None:
            raise import_error("owner import interrupted")
        return builtins.__import__(name, globals, locals, fromlist, level)

    namespace = {"subprocess": view, "sys": sys,
                 "__builtins__": dict(vars(builtins), __import__=private_import)}
    path, qualified = case
    node = ast.parse((ROOT / path).read_text())
    for part in qualified.split("."):
        node = next(n for n in node.body if getattr(n, "name", None) == part)
    node.decorator_list = []
    # Compile the qualified helper without importing the enclosing test
    # module and its unrelated module/class fixtures.
    exec(compile(ast.Module(body=[node], type_ignores=[]), path, "exec"), namespace)
    function = namespace[node.name]

    def invoke():
        return function(**{"self": object()} if "self" in signature(function).parameters else {})

    def restored():
        for process in processes:
            assert process.returncode is not None
            with pytest.raises(ChildProcessError):
                os.waitpid(process.pid, os.WNOHANG)
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream is not None:
                    assert stream.closed

    def cleanup():
        for process in processes:
            # The external guard still owns a child if a regression prevents
            # the native helper from reaching its reaper.
            with reap_on_exit(process):
                pass

    return invoke, processes, calls, restored, cleanup


@pytest.mark.parametrize("case", CASES, ids=[p + ":" + n for p, n in CASES])
@pytest.mark.parametrize("streams", [False, True], ids=["inherited-streams", "owned-streams"])
def test_known_dead_pid_is_reaped_and_returned(case, streams):
    invoke, processes, calls, restored, cleanup = _helper(case, streams)
    try:
        result = invoke()
        assert len(processes) == 1
        assert result == processes[0].pid
        assert processes[0].returncode == 0
        assert calls[0]["kills"] == 0
        restored()
    finally:
        cleanup()


@pytest.mark.parametrize("case", CASES, ids=[p + ":" + n for p, n in CASES])
@pytest.mark.parametrize("streams", [False, True], ids=["inherited-streams", "owned-streams"])
@pytest.mark.parametrize("phase", ["before", "after"])
@pytest.mark.parametrize("error", [subprocess.TimeoutExpired, OSError, KeyboardInterrupt])
def test_wait_failure_releases_owned_child(case, streams, phase, error):
    invoke, processes, calls, restored, cleanup = _helper(case, streams, phase=phase, error=error)
    try:
        with pytest.raises(error):
            invoke()
        assert len(processes) == 1
        assert calls[0]["kills"] == (1 if phase == "before" else 0)
        assert processes[0].returncode == (-signal.SIGKILL if phase == "before" else 0)
        restored()
    finally:
        cleanup()


@pytest.mark.parametrize("case", CASES, ids=[p + ":" + n for p, n in CASES])
@pytest.mark.parametrize("error", [ImportError, KeyboardInterrupt])
def test_owner_import_failure_precedes_child_creation(case, error):
    invoke, processes, _, _, cleanup = _helper(case, import_error=error)
    try:
        with pytest.raises(error, match="owner import interrupted"):
            invoke()
        assert processes == []
    finally:
        cleanup()
