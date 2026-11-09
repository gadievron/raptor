"""Dispatcher integration callers reap their children after communication errors."""

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

from core.llm.dispatcher import spawn
from core.llm.tests import test_dispatcher_integration as module


_SITES = [
    ("TestGrandchildRelay", "test_grandchild_subprocess_uses_relayed_session"),
    ("TestPhaseBChainE2E", "test_full_chain_no_api_keys_anywhere"),
    ("TestPhaseBChainE2EGemini", "test_full_chain_gemini_no_api_keys_anywhere"),
    (
        "TestEndToEndCredentialIsolationThroughProviders",
        "test_subprocess_via_anthropic_provider_no_env_key",
    ),
]


def _live_member(pid, group):
    try:
        status = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[0]
        return status != "Z" and os.getpgid(pid) == group
    except (ProcessLookupError, FileNotFoundError):
        return False


@pytest.mark.skipif(
    sys.platform != "linux", reason="Linux owned process-group and zombie checks"
)
@pytest.mark.parametrize(
    "owner,name,fault",
    [
        pytest.param(owner, name, fault, id=f"{fault}-{owner}-{name}")
        for fault in ("timeout", "io", "interrupt", "dead-leader", "bad-json", "nonzero")
        for owner, name in _SITES
    ] + [
        pytest.param(*_SITES[-1], fault, id=f"{fault}-{_SITES[-1][0]}-{_SITES[-1][1]}")
        for fault in ("ready-eof", "ready-invalid")
    ],
)
def test_integration_caller_reaps_owned_process_tree(
    owner, name, fault, tmp_path, monkeypatch
):
    started, descendants, requested, communicated = [], [], [], []
    ready = tmp_path / "owned-ready"
    original = SimpleNamespace(
        name="fixture", inject_headers={}, strip_request_headers=()
    )
    dispatcher = SimpleNamespace(
        _rules={"anthropic": original, "gemini": original},
        shutdown=Mock(),
    )
    upstream = SimpleNamespace(shutdown=Mock(), captured={})
    server = SimpleNamespace(
        server_address=("127.0.0.1", 1),
        serve_forever=lambda: None,
        shutdown=Mock(),
        server_close=Mock(),
    )
    code = "import os,pathlib,subprocess,sys,time\n"
    if fault in ("bad-json", "nonzero"):
        code += "pid=0\n"
    else:
        code += "child=subprocess.Popen([sys.executable,'-I','-c','import time; time.sleep(60)'])\npid=child.pid\n"
    code += f"ready=pathlib.Path({str(ready)!r})\npending=ready.with_suffix('.pending')\npending.write_text(str(pid))\npending.replace(ready)\n"
    if fault == "bad-json":
        code += "print('{',flush=True)\n"
    elif fault == "nonzero":
        code += "sys.exit(7)\n"
    elif fault == "dead-leader":
        code += "os._exit(0)\n"
    else:
        code += "time.sleep(60)\n"
    failure = (
        subprocess.TimeoutExpired("owned fixture child", 0.01)
        if fault == "timeout"
        else KeyboardInterrupt("owned interruption")
        if fault == "interrupt"
        else OSError("owned communication failure")
    )

    def controlled_spawn(dispatcher, **kwargs):
        requested.append(kwargs.copy())
        # Always contain the regression itself, including when exercising
        # an old caller that omitted start_new_session. The requested option
        # is checked separately below. No generated provider script runs.
        inherited = tuple(kwargs.get("pass_fds", ()))
        worker_code = code
        if name == "test_subprocess_via_anthropic_provider_no_env_key":
            readiness_fd = int(kwargs["cmd"][-1])
            assert inherited == (readiness_fd,)
            signal_ready = (
                "" if fault == "ready-eof"
                else f"os.write({readiness_fd}, {b'!' if fault == 'ready-invalid' else b'R'!r})\n"
            )
            # The replacement worker must complete the same startup protocol
            # before exercising its intended communication/exit failure.
            prelude = "import os\n" + signal_ready + f"os.close({readiness_fd})\n"
            worker_code = prelude + code
        process = subprocess.Popen(
            [sys.executable, "-I", "-c", worker_code],
            pass_fds=inherited,
            start_new_session=True,
            env={"PATH": os.defpath},
            stdout=kwargs["stdout"],
            stderr=kwargs["stderr"],
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
            # Preserve the exited leader as an unreaped group anchor. A
            # poll-before-group-kill implementation would lose that anchor.
            os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOWAIT)
        real_communicate = process.communicate

        def communicate(*args, **kwargs):
            communicated.append(True)
            if fault not in ("bad-json", "nonzero"):
                raise failure
            return real_communicate(*args, **kwargs)

        process.communicate = communicate
        return process

    expected = (
        json.JSONDecodeError
        if fault == "bad-json"
        else AssertionError
        if fault in ("nonzero", "ready-eof", "ready-invalid")
        else type(failure)
    )
    try:
        with monkeypatch.context() as patcher:
            patcher.setattr(module, "LLMDispatcher", Mock(return_value=dispatcher))
            patcher.setattr(module, "_wired_dispatcher", Mock(return_value=dispatcher))
            patcher.setattr(module, "_CaptiveUpstream", Mock(return_value=upstream))
            patcher.setattr(module.http.server, "HTTPServer", Mock(return_value=server))
            patcher.setattr(module.pytest, "importorskip", lambda *args, **kwargs: None)
            patcher.setattr(spawn, "spawn_worker", controlled_spawn)
            match = (
                "worker exited before client readiness"
                if fault in ("ready-eof", "ready-invalid")
                else "worker failed: rc=7"
                if fault == "nonzero"
                and name == "test_subprocess_via_anthropic_provider_no_env_key"
                else None
            )
            with pytest.raises(expected, match=match):
                getattr(getattr(module, owner)(), name)(None, tmp_path)
        assert communicated == (
            [] if fault in ("ready-eof", "ready-invalid") else [True]
        ), "caller did not reach the intended communication failure"
        assert len(started) == 1
        process = started[0]
        assert process.returncode is not None, "caller left its child unreaped"
        with pytest.raises(ChildProcessError):
            os.waitpid(process.pid, os.WNOHANG)
        assert all(
            stream is None or stream.closed
            for stream in (process.stdin, process.stdout, process.stderr)
        ), "caller left subprocess streams open"
        if fault not in ("bad-json", "nonzero"):
            assert requested[0].get("start_new_session") is True
            deadline = time.monotonic() + 5
            while any(_live_member(pid, process.pid) for pid in descendants):
                assert time.monotonic() < deadline, (
                    "caller left an owned grandchild alive"
                )
                time.sleep(0.01)
        dispatcher.shutdown.assert_called_once()
    finally:
        # Independent cleanup keeps baseline failures contained to private
        # groups created by this test. Never signal the pytest worker group.
        for process in started:
            if process.returncode is None or any(
                _live_member(pid, process.pid) for pid in descendants
            ):
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            process.wait(timeout=5)
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream is not None:
                    stream.close()
