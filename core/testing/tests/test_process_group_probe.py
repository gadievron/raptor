"""Test probes preserve session shape and clean up failed communication."""

from contextlib import contextmanager
import io
import json
import os
import signal
import subprocess
import sys
from types import SimpleNamespace

import pytest

from core.testing import processes
from core.testing.module_views import module_function_view

pytestmark = pytest.mark.skipif(os.name != "posix", reason="POSIX process groups")


@pytest.mark.parametrize("new_session", [False, True], ids=["inherited", "session-leader"])
def test_native_probe_has_private_group_and_expected_session(new_session):
    command = [sys.executable, "-I", "-c", (
        "import json,os,sys; "
        "print(json.dumps([os.getpid(),os.getpgrp(),os.getsid(0)])); "
        "print('owned stderr',file=sys.stderr)"
    )]
    result = processes.run_in_process_group(
        command, timeout=10, start_new_session=new_session,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    pid, group, session = json.loads(result.stdout)
    assert group == pid
    assert session == (pid if new_session else os.getsid(0))
    assert result.args == command and result.returncode == 0
    assert result.stderr == "owned stderr\n"


@pytest.mark.parametrize("check", [False, True], ids=["return-status", "raise-status"])
def test_native_failed_probe_keeps_output(check):
    command = [sys.executable, "-I", "-c", "print('owned failure'); raise SystemExit(7)"]

    def run():
        return processes.run_in_process_group(
            command, timeout=10, check=check,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )

    if check:
        with pytest.raises(subprocess.CalledProcessError) as caught:
            run()
        result = caught.value
    else:
        result = run()
    assert result.returncode == 7
    assert result.stdout == "owned failure\n"
    assert result.stderr == ""


def test_native_probe_can_receive_input():
    result = processes.run_in_process_group(
        [sys.executable, "-I", "-c", "import sys; print(sys.stdin.read().upper())"],
        timeout=10, input="owned input", text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    assert result.returncode == 0 and result.stdout == "OWNED INPUT\n"


@pytest.mark.parametrize("interrupted", [False, True], ids=["timeout", "interrupt"])
def test_failed_communication_signals_group_reaps_and_closes_streams(interrupted):
    failure = (KeyboardInterrupt("owned interruption") if interrupted else
               subprocess.TimeoutExpired(["owned"], 30, output="partial output"))
    calls = []
    process = SimpleNamespace(
        pid=123456, returncode=None, args=["owned"],
        stdin=io.StringIO(), stdout=io.StringIO(), stderr=io.StringIO(),
    )

    def communicate(*, input, timeout):
        assert timeout == 30 and input is None
        raise failure

    def wait(*, timeout):
        calls.append(("wait", timeout))
        process.returncode = -signal.SIGKILL
        return process.returncode

    process.communicate, process.wait = communicate, wait
    consumer = module_function_view(processes, bindings={
        # contextmanager's wrapper belongs to contextlib. Clone the owned
        # generator first so its OS lookup cannot escape to the real module.
        "reap_on_exit": processes.reap_on_exit.__wrapped__,
        "subprocess": SimpleNamespace(Popen=lambda *a, **kw: process),
        "os": SimpleNamespace(killpg=lambda pid, sig: calls.append(("killpg", pid, sig))),
    })
    consumer.reap_on_exit = contextmanager(consumer.reap_on_exit)
    with pytest.raises(type(failure)) as caught:
        consumer.run_in_process_group(["owned"], timeout=30)
    assert caught.value is failure
    assert calls == [("killpg", process.pid, signal.SIGKILL), ("wait", 5)]
    assert all(getattr(process, name).closed for name in ("stdin", "stdout", "stderr"))
