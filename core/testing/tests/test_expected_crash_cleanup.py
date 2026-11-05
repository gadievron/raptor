"""Expected-crash scaffolding owns pipes and its tracer even after setup errors."""

import ctypes
import errno
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from core.testing import expected_crash as module
from core.testing import processes as support


def _identity(fd):
    try:
        stat = os.fstat(fd)
    except OSError as exc:
        if exc.errno == errno.EBADF:
            return None
        raise
    return stat.st_dev, stat.st_ino


@pytest.mark.parametrize(
    "stage,error",
    [
        (stage, error)
        for stage in ("fork", "read")
        for error in (OSError, KeyboardInterrupt)
    ]
    + [("none", None)],
)
def test_trace_setup_pipe_closes_after_fork_or_read_failure(stage, error, monkeypatch):
    owned = []
    failure = error("owned trace setup failure") if error else None

    def pipe():
        pair = os.pipe()
        owned.extend((fd, _identity(fd)) for fd in pair)
        return pair

    def fork():
        if stage == "fork":
            raise failure
        return 123456

    def read(*args):
        if stage == "read":
            raise failure
        return os.read(*args)

    filesystem = SimpleNamespace(
        **(
            vars(os)
            | {
                "pipe": pipe,
                "fork": fork,
                "read": read,
                "waitpid": lambda *args: (123456, 0),
            }
        )
    )
    library = SimpleNamespace(ptrace=Mock(return_value=0))
    try:
        monkeypatch.setattr(module, "os", filesystem)
        monkeypatch.setattr(
            module,
            "ctypes",
            SimpleNamespace(**(vars(ctypes) | {"CDLL": Mock(return_value=library)})),
        )
        if error:
            with pytest.raises(error, match="owned trace setup failure"):
                module._trace(["inert"], time.monotonic() + 2, None)
        else:
            result = module._trace(["inert"], time.monotonic() + 2, None)
            assert result["returncode"] == 0
            assert result["error"] is None
        assert len(owned) == 2
        assert all(_identity(fd) != identity for fd, identity in owned), (
            "trace setup left a pipe descriptor open"
        )
    finally:
        for fd, identity in owned:
            if _identity(fd) == identity:
                os.close(fd)


def _live_member(pid, group):
    try:
        status = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[0]
        return status != "Z" and os.getpgid(pid) == group
    except (ProcessLookupError, FileNotFoundError):
        return False


_INVOKE_CASES = [
    (stage, error)
    for stage in ("first-only", "repeat-error", "signal-error")
    for error in (OSError, KeyboardInterrupt, subprocess.TimeoutExpired)
]
_INVOKE_CASES += [
    (stage, None) for stage in ("bad-json", "nonzero", "missing-report", "normal")
]


@pytest.mark.skipif(sys.platform != "linux", reason="Linux owned process-group checks")
@pytest.mark.parametrize("stage,error", _INVOKE_CASES)
@pytest.mark.parametrize("text", [False, True])
def test_invoke_cleanup_owns_tracer_after_communication_failure(
    stage, error, text, tmp_path, monkeypatch
):
    processes, descendants, attempts, options_seen = [], [], [], []
    ready = tmp_path / "owned-tracer-ready"
    communicating = stage in ("first-only", "repeat-error", "signal-error")
    primary = (
        subprocess.TimeoutExpired("owned tracer", 0.01)
        if error is subprocess.TimeoutExpired
        else error("owned communication failed")
        if error
        else None
    )
    signal_error = OSError("owned signal failed after taking effect")
    payload = "fixture payload" if text else b"fixture payload"
    real_killpg = os.killpg

    def popen(argv, **kwargs):
        options_seen.append(kwargs.copy())
        report = Path(argv[argv.index("--report") + 1])
        code = "import json,pathlib,subprocess,sys,time\n"
        code += (
            "child=subprocess.Popen([sys.executable,'-I','-c','import time; time.sleep(60)'])\npid=child.pid\n"
            if communicating
            else "pid=0\n"
        )
        code += f"ready=pathlib.Path({str(ready)!r})\npending=ready.with_suffix('.pending')\npending.write_text(str(pid))\npending.replace(ready)\n"
        if communicating:
            code += "time.sleep(60)\n"
        elif stage == "nonzero":
            code += "sys.exit(7)\n"
        else:
            code += "payload=sys.stdin.buffer.read()\nsys.stdout.buffer.write(payload)\nsys.stderr.write('fixture diagnostic')\n"
            if stage == "normal":
                code += f"pathlib.Path({str(report)!r}).write_text(json.dumps({{'returncode':0}}))\n"
            elif stage == "bad-json":
                code += f"pathlib.Path({str(report)!r}).write_text('{{')\n"
        # This controlled child replaces the tracer executable. No ptrace,
        # fatal signal, provider script, or caller-supplied command executes.
        process = subprocess.Popen([sys.executable, "-I", "-c", code], **kwargs)
        processes.append(process)
        deadline = time.monotonic() + 5
        while not ready.exists():
            assert time.monotonic() < deadline, "owned tracer did not initialize"
            time.sleep(0.01)
        pid = int(ready.read_text())
        if pid:
            descendants.append(pid)
        communicate = process.communicate

        def communicate_once(*args, **options):
            attempts.append(options.copy())
            if communicating and len(attempts) == 1:
                raise primary
            if stage == "repeat-error":
                raise RuntimeError("second communication failed")
            return communicate(*args, **options)

        process.communicate = communicate_once
        return process

    def killpg(*args):
        real_killpg(*args)
        if stage == "signal-error":
            raise signal_error

    filesystem = SimpleNamespace(**(vars(os) | {"killpg": killpg}))
    try:
        with monkeypatch.context() as patcher:
            patcher.setattr(
                module,
                "subprocess",
                SimpleNamespace(**(vars(subprocess) | {"Popen": popen})),
            )
            patcher.setattr(module, "os", filesystem)
            patcher.setattr(support, "os", filesystem)
            if stage == "normal":
                result, data = module._invoke(
                    ["inert"],
                    timeout=2,
                    cwd=tmp_path,
                    env={"PATH": os.defpath},
                    input=payload,
                    text=text,
                    encoding="utf-8" if text else None,
                )
                assert result.returncode == 0
                assert result.stdout == payload
                assert result.stderr == (
                    "fixture diagnostic" if text else b"fixture diagnostic"
                )
                assert data == {"returncode": 0}
            else:
                with pytest.raises(BaseException) as caught:
                    module._invoke(
                        ["inert"],
                        timeout=2,
                        cwd=tmp_path,
                        env={"PATH": os.defpath},
                        input=payload,
                        text=text,
                        encoding="utf-8" if text else None,
                    )
        assert len(processes) == 1
        process = processes[0]
        assert process.returncode is not None, "invoke cleanup left its tracer unreaped"
        with pytest.raises(ChildProcessError):
            os.waitpid(process.pid, os.WNOHANG)
        assert all(
            stream.closed for stream in (process.stdin, process.stdout, process.stderr)
        ), "invoke cleanup left tracer pipes open"
        assert options_seen[0]["start_new_session"] is True
        if stage in ("first-only", "repeat-error"):
            assert caught.value is primary
        elif stage == "signal-error":
            assert caught.value is signal_error
        elif stage == "bad-json":
            assert isinstance(caught.value, json.JSONDecodeError)
        elif stage in ("nonzero", "missing-report"):
            assert isinstance(caught.value, module.ExpectedCrashError)
        if communicating:
            deadline = time.monotonic() + 5
            while any(_live_member(pid, process.pid) for pid in descendants):
                assert time.monotonic() < deadline, (
                    "owned tracer descendant survived cleanup"
                )
                time.sleep(0.01)
        assert attempts[0] == {"input": payload, "timeout": 7}
    finally:
        for process in processes:
            if process.returncode is None or any(
                _live_member(pid, process.pid) for pid in descendants
            ):
                try:
                    real_killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            process.wait(timeout=5)
            for stream in (process.stdin, process.stdout, process.stderr):
                stream.close()
