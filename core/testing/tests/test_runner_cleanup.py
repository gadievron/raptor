"""Test runners reclaim controlled children after communication failures."""

import base64
import contextlib
import importlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
from types import SimpleNamespace

import pytest

_RUNNERS = [
    "annotations",
    "annotations-session",
    "startup",
    "startup-parser",
    "probe",
    "protocol",
    "lane",
    "rr",
    "rr-record",
]
_MODULES = {
    "annotations": "core.annotations.tests.test_cli",
    "annotations-session": "core.annotations.tests.test_cli",
    "startup": "core.startup.tests.test_cli_smoke",
    "startup-parser": "core.startup.tests.test_cli_smoke",
    "probe": "core.sandbox.tests.test_coordinator_isolation",
    "protocol": "core.sandbox.tests.test_coordinator_isolation",
    "lane": "core.sandbox.tests.test_lane_isolation",
    "rr": "packages.binary_analysis.tests.test_rr_native",
    "rr-record": "packages.binary_analysis.tests.test_rr_record_native",
}


def _alive(pid):
    try:
        status = Path(f"/proc/{pid}/stat")
        if status.exists():
            return status.read_text().rsplit(")", 1)[1].split()[0] != "Z"
        os.kill(pid, 0)
        return True
    except (ProcessLookupError, FileNotFoundError):
        return False


def _in_group(pid, group):
    try:
        return _alive(pid) and os.getpgid(pid) == group
    except ProcessLookupError:
        return False


@pytest.mark.skipif(os.name != "posix", reason="POSIX owned process groups")
@pytest.mark.parametrize("runner", _RUNNERS)
@pytest.mark.parametrize("fault", ["timeout", "io", "interrupt", "dead-leader", "none"])
def test_runner_reclaims_process_and_pipes(runner, fault, tmp_path, monkeypatch):
    if fault == "dead-leader" and not hasattr(os, "WNOWAIT"):
        pytest.skip("waitid WNOWAIT required for a deterministic exited leader")
    module = importlib.import_module(_MODULES[runner])
    started = []
    descendants = []
    options_seen = []
    real_popen = subprocess.Popen
    grouped = runner not in ("annotations", "annotations-session")
    ready = tmp_path / "ready"
    reply = {
        "owned": True,
        "target": {
            "returncode": 0,
            "stdout_b64": base64.b64encode(b"owned").decode(),
            "stderr_b64": "",
        },
    }
    code = "import pathlib,subprocess,sys,time\n"
    if fault != "none" and grouped:
        code += "p=subprocess.Popen([sys.executable,'-I','-c','import time; time.sleep(60)'])\npid=p.pid\n"
    else:
        code += "pid=0\n"
    code += f"ready=pathlib.Path({str(ready)!r})\npending=ready.with_suffix('.pending')\npending.write_text(str(pid))\npending.replace(ready)\n"
    if fault == "none":
        code += f"print({json.dumps(reply)!r},flush=True)\n"
    elif fault == "dead-leader":
        code += "import os; os._exit(0)\n"
    else:
        code += "time.sleep(60)\n"
    error = (
        subprocess.TimeoutExpired("owned", 0.01)
        if fault == "timeout"
        else OSError("owned communication failure")
        if fault in ("io", "dead-leader")
        else KeyboardInterrupt("owned interruption")
    )

    def popen(command, **options):
        options_seen.append(options.copy())
        # Always contain the regression itself, including on an old runner
        # that forgot to create its own session; check the requested flag below.
        process = real_popen(
            [sys.executable, "-I", "-c", code],
            **(options | {"start_new_session": True, "process_group": None}),
        )
        started.append(process)
        deadline = time.monotonic() + 5
        while not ready.exists():
            assert time.monotonic() < deadline, "owned child did not initialize"
            time.sleep(0.01)
        descendant = int(ready.read_text())
        if descendant:
            descendants.append(descendant)
        if fault == "dead-leader":
            os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOWAIT)
        if fault != "none":

            def fail(*args, **kwargs):
                raise error

            process.communicate = fail
        return process

    def invoke():
        if runner.startswith("annotations"):
            return module._run(
                "ls",
                "--base",
                str(tmp_path),
                tty=("stdin",),
                setsid=runner == "annotations-session",
            )
        if runner == "startup":
            return module._run_raptor("--help")
        if runner == "startup-parser":
            return module._run_mode_parser("fuzz", "--binary", "/owned")
        if runner == "probe":
            return module._run_probe_via_coordinator("pass")
        if runner == "protocol":
            return module._drive_coordinator(b"{}")
        if runner == "lane":
            _, go = module._child_connect(str(tmp_path / "unused.sock"))
            return go()
        return module._owned_run(["owned"], timeout=5)

    try:
        with monkeypatch.context() as patcher:
            patcher.setattr(
                module,
                "subprocess",
                SimpleNamespace(
                    **(vars(subprocess) | {"Popen": popen}),
                ),
            )
            if runner in ("probe", "protocol"):
                patcher.setattr(module, "_probe_output_dir", lambda: str(tmp_path))
            if fault == "none":
                result = invoke()
                if runner == "probe":
                    assert result == (0, "owned", "")
                elif runner == "protocol":
                    assert result["owned"] is True
                elif runner == "lane":
                    assert json.loads(result)["owned"] is True
                else:
                    assert result.returncode == 0
                    assert json.loads(result.stdout)["owned"] is True
            else:
                with pytest.raises(type(error)):
                    invoke()
        assert len(started) == 1
        process = started[0]
        assert process.returncode is not None, "runner did not reap its child"
        assert all(
            stream is None or stream.closed
            for stream in (
                process.stdin,
                process.stdout,
                process.stderr,
            )
        ), "runner left captured pipes open"
        if grouped:
            assert options_seen[0].get("start_new_session") is True
        deadline = time.monotonic() + 2
        while any(_alive(pid) for pid in descendants) and time.monotonic() < deadline:
            time.sleep(0.01)
        assert not any(_alive(pid) for pid in descendants), (
            "runner left an owned descendant alive"
        )
    finally:
        for process in started:
            owns_group = process.poll() is None or any(
                _in_group(pid, process.pid) for pid in descendants
            )
            if owns_group:
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream is not None:
                    stream.close()


@pytest.mark.parametrize("exited", [False, True])
def test_group_permission_error_requires_an_exited_child(exited, monkeypatch):
    from unittest.mock import Mock
    from core.testing.processes import reap_on_exit

    child = Mock(pid=12345, returncode=None, stdin=None, stdout=None, stderr=None)
    child.poll.return_value = -signal.SIGKILL if exited else None
    denied = PermissionError("group signal denied")
    monkeypatch.setattr(os, "killpg", Mock(side_effect=denied))
    if exited:
        with reap_on_exit(child, process_group=True):
            pass
        child.wait.assert_called_once()
    else:
        with pytest.raises(PermissionError) as caught:
            with reap_on_exit(child, process_group=True):
                pass
        assert caught.value is denied
