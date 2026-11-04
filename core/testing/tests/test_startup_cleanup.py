"""Readiness failures retire children before startup ownership is returned."""

import contextlib
import importlib
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
from types import SimpleNamespace

import pytest

_HELPERS = ("holder", "audit", "lifecycle", "wrapper")
_MODULES = {
    "holder": "core.atomic_fs.tests.test_fs_lock_bounded",
    "audit": "core.audit.tests.test_run_lock",
    "lifecycle": "core.run.tests.test_lifecycle_hook",
    "wrapper": "packages.joern.tests.test_runner",
    "checkpoint": "core.coverage.tests.test_journal_checkpoint_killmatrix",
}
_CASES = [
    (helper, fault)
    for helper in _HELPERS
    for fault in ("io", "interrupt", "invalid", "none")
]
_CASES += [("wrapper", "identity")]
_CASES += [("checkpoint", fault) for fault in ("clock", "interrupt", "wait", "none")]


def _alive(pid):
    try:
        stat = Path(f"/proc/{pid}/stat")
        if stat.exists():
            return stat.read_text().rsplit(")", 1)[1].split()[0] != "Z"
        os.kill(pid, 0)
        return True
    except (ProcessLookupError, FileNotFoundError):
        return False


def _in_group(pid, group):
    try:
        return _alive(pid) and os.getpgid(pid) == group
    except ProcessLookupError:
        return False


@pytest.mark.skipif(os.name != "posix", reason="POSIX owned child fixtures")
@pytest.mark.parametrize("helper,fault", _CASES)
def test_readiness_setup_owns_child_until_return(helper, fault, tmp_path, monkeypatch):
    module = importlib.import_module(_MODULES[helper])
    started = []
    descendants = []
    real_popen = subprocess.Popen
    ready = tmp_path / "owned-startup"
    code = "import pathlib,subprocess,sys,time\n"
    if helper == "wrapper":
        code += "p=subprocess.Popen([sys.executable,'-I','-c','import time; time.sleep(60)'])\npid=p.pid\nline=str(pid)\n"
    else:
        code += "pid=0\n"
        code += (
            "line="
            + repr(
                {
                    "holder": "held",
                    "audit": "READY",
                    "lifecycle": "ready",
                    "checkpoint": "unused",
                }[helper]
            )
            + "\n"
        )
    code += f"ready=pathlib.Path({str(ready)!r})\npending=ready.with_suffix('.pending')\npending.write_text(str(pid))\npending.replace(ready)\n"
    if helper == "checkpoint" and fault == "none":
        code += f"pathlib.Path({str(tmp_path / 'ready-controlled')!r}).touch()\n"
    code += "print(line,flush=True)\ntime.sleep(60)\n"

    def failure(*args, **kwargs):
        if fault == "interrupt":
            raise KeyboardInterrupt("owned readiness interruption")
        if fault == "identity":
            raise RuntimeError("owned readiness identity failure")
        raise OSError("owned readiness failure")

    class StartupStream:
        def __init__(self, stream):
            self.stream = stream

        def __getattr__(self, name):
            return getattr(self.stream, name)

        def readline(self, *args, **kwargs):
            if fault in ("io", "interrupt"):
                return failure()
            if fault == "invalid":
                return "not-ready\n"
            return self.stream.readline(*args, **kwargs)

    def popen(command, **options):
        process = real_popen(
            [sys.executable, "-I", "-c", code],
            **(options | {"start_new_session": True}),
        )
        started.append(process)
        deadline = time.monotonic() + 5
        while not ready.exists():
            assert time.monotonic() < deadline, "owned fixture did not initialize"
            time.sleep(0.01)
        pid = int(ready.read_text())
        if pid:
            descendants.append(pid)
        if helper != "checkpoint":
            process.stdout = StartupStream(process.stdout)
        return process

    def invoke():
        if helper == "holder":
            return module._spawn_holder(tmp_path / "lock", 60, tmp_path)
        if helper == "audit":
            return module._spawn("owned stub")
        if helper == "lifecycle":
            return getattr(
                module, "TestSessionEndLivenessProof"
            )._spawn_claude_shaped_stub(tmp_path)
        if helper == "wrapper":
            return module.TestStallKillAddressesTheGroup()._wrapper_with_grandchild()
        return module._kill_at("controlled", tmp_path / "out", tmp_path)

    try:
        with monkeypatch.context() as patcher:
            # Also catches the wrapper's function-local subprocess import.
            patcher.setattr(subprocess, "Popen", popen)
            if helper == "checkpoint":
                overrides = {}
                if fault in ("clock", "interrupt"):
                    overrides["monotonic"] = failure
                elif fault == "wait":
                    overrides["sleep"] = failure
                patcher.setattr(
                    module, "time", SimpleNamespace(**(vars(time) | overrides))
                )
            if fault == "identity":
                from packages.joern import server

                patcher.setattr(server, "_proc_starttime", failure)
            if fault == "none":
                result = invoke()
            else:
                error = (
                    KeyboardInterrupt
                    if fault == "interrupt"
                    else (ValueError, AssertionError)
                    if fault == "invalid"
                    else RuntimeError
                    if fault == "identity"
                    else OSError
                )
                with pytest.raises(error):
                    invoke()
        assert len(started) == 1
        process = started[0]
        if fault == "none" and helper != "checkpoint":
            assert process.poll() is None, "successful startup lost the owned child"
            returned = result[0] if helper == "wrapper" else result
            assert returned is process
        else:
            assert process.returncode is not None, (
                "failed startup did not reap its child"
            )
            assert all(
                stream is None or stream.closed
                for stream in (
                    process.stdin,
                    process.stdout,
                    process.stderr,
                )
            ), "startup left captured pipes open"
            deadline = time.monotonic() + 2
            while (
                any(_alive(pid) for pid in descendants) and time.monotonic() < deadline
            ):
                time.sleep(0.01)
            assert not any(_alive(pid) for pid in descendants), (
                "failed startup left a descendant alive"
            )
    finally:
        for process in started:
            if process.poll() is None or any(
                _in_group(pid, process.pid) for pid in descendants
            ):
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream is not None:
                    stream.close()
