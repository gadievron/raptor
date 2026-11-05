"""Subprocess teardown attempts waiting and every stream after cleanup errors."""

from contextlib import ExitStack
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from core.testing import processes as module


_CASES = [
    (group, stage, error, owner)
    for group in (False, True)
    for stage in (["poll"] if not group else [])
    + ["signal", "wait", "stdin", "stdout", "stderr", "none"]
    for error in (OSError, KeyboardInterrupt, RuntimeError)
    for owner in ("reap", "startup")
]


class _CloseFailure:
    def __init__(self, raw, failure, calls=None, name=None):
        self.raw, self.failure, self.calls, self.name = raw, failure, calls, name

    @property
    def closed(self):
        return self.raw.closed

    def close(self):
        if self.calls is not None:
            self.calls.append(self.name)
        self.raw.close()
        if self.failure is not None:
            raise self.failure


@pytest.mark.parametrize("group,stage,error,owner", _CASES)
def test_cleanup_error_still_waits_and_closes_all_streams(
    group, stage, error, owner, monkeypatch
):
    failure = error("injected cleanup failure")
    calls = []
    with ExitStack() as independent:
        streams = {
            name: independent.enter_context(tempfile.TemporaryFile())
            for name in ("stdin", "stdout", "stderr")
        }
        process = SimpleNamespace(returncode=None, pid=123456)
        for name, raw in streams.items():
            setattr(
                process,
                name,
                _CloseFailure(raw, failure if stage == name else None, calls, name),
            )

        def poll():
            if stage == "poll":
                raise failure
            return None

        def terminate(*args):
            if stage == "signal":
                raise failure

        def wait(**kwargs):
            process.returncode = -9
            if stage == "wait":
                raise failure
            return -9

        process.poll = Mock(side_effect=poll)
        process.kill = Mock(side_effect=terminate)
        process.wait = Mock(side_effect=wait)
        killpg = Mock(side_effect=terminate)
        monkeypatch.setattr(
            module, "os", SimpleNamespace(**(vars(os) | {"killpg": killpg}))
        )
        suppressed = stage in streams and error is OSError
        expected = LookupError if owner == "startup" else None
        if stage != "none" and not suppressed:
            expected = error

        def invoke():
            context = (
                module.reap_on_exit(process, process_group=group)
                if owner == "reap"
                else module.cleanup_on_startup_error(process, process_group=group)
            )
            with context:
                if owner == "startup":
                    raise LookupError("original startup failure")

        if expected:
            with pytest.raises(expected):
                invoke()
        else:
            invoke()
        process.wait.assert_called_once_with(timeout=5)
        assert all(stream.closed for stream in streams.values()), (
            "cleanup abandoned a later stream"
        )
        assert calls == ["stdin", "stdout", "stderr"]
        if group:
            killpg.assert_called_once_with(process.pid, signal.SIGKILL)
            process.poll.assert_not_called()
        elif stage != "poll":
            process.kill.assert_called_once()


@pytest.mark.parametrize("group", [False, True])
def test_ready_startup_transfers_process_without_cleanup(group):
    with ExitStack() as independent:
        streams = [
            independent.enter_context(tempfile.TemporaryFile()) for _ in range(3)
        ]
        process = SimpleNamespace(
            stdin=streams[0],
            stdout=streams[1],
            stderr=streams[2],
            poll=Mock(),
            kill=Mock(),
            wait=Mock(),
        )
        with module.cleanup_on_startup_error(process, process_group=group):
            pass
        assert all(not stream.closed for stream in streams)
        process.poll.assert_not_called()
        process.kill.assert_not_called()
        process.wait.assert_not_called()


def _live_member(pid, group):
    try:
        status = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[0]
        return status != "Z" and os.getpgid(pid) == group
    except (ProcessLookupError, FileNotFoundError):
        return False


@pytest.mark.skipif(sys.platform != "linux", reason="Linux owned process-group checks")
@pytest.mark.parametrize("group", [False, True])
@pytest.mark.parametrize("stage", ["signal", "wait", "stdin", "stdout", "none"])
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_native_cleanup_failure_reaps_child_and_closes_pipes(
    group, stage, error, tmp_path, monkeypatch
):
    ready = tmp_path / "ready"
    code = "import pathlib,subprocess,sys,time\n"
    code += (
        "child=subprocess.Popen([sys.executable,'-I','-c','import time; time.sleep(60)'])\npid=child.pid\n"
        if group
        else "pid=0\n"
    )
    code += f"ready=pathlib.Path({str(ready)!r})\npending=ready.with_suffix('.pending')\npending.write_text(str(pid))\npending.replace(ready)\ntime.sleep(60)\n"
    process = subprocess.Popen(
        [sys.executable, "-I", "-c", code],
        start_new_session=True,
        env={"PATH": os.defpath},
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    raw_streams = [process.stdin, process.stdout, process.stderr]
    real_kill, real_wait, real_killpg = process.kill, process.wait, os.killpg
    failure = error("injected native cleanup failure")
    descendant = 0

    def terminate():
        real_kill()
        if stage == "signal":
            raise failure

    def terminate_group(*args):
        real_killpg(*args)
        if stage == "signal":
            raise failure

    def wait(**kwargs):
        result = real_wait(**kwargs)
        if stage == "wait":
            raise failure
        return result

    try:
        deadline = time.monotonic() + 5
        while not ready.exists():
            assert time.monotonic() < deadline, "owned child did not initialize"
            time.sleep(0.01)
        descendant = int(ready.read_text())
        with monkeypatch.context() as patcher:
            patcher.setattr(process, "kill", terminate)
            patcher.setattr(process, "wait", wait)
            patcher.setattr(
                module,
                "os",
                SimpleNamespace(**(vars(os) | {"killpg": terminate_group})),
            )
            if stage in ("stdin", "stdout"):
                patcher.setattr(
                    process, stage, _CloseFailure(getattr(process, stage), failure)
                )
            if stage == "none" or stage in ("stdin", "stdout") and error is OSError:
                with module.reap_on_exit(process, process_group=group):
                    pass
            else:
                with pytest.raises(error, match="injected native cleanup failure"):
                    with module.reap_on_exit(process, process_group=group):
                        pass
        assert process.returncode is not None, "signal error left a dead child unreaped"
        with pytest.raises(ChildProcessError):
            os.waitpid(process.pid, os.WNOHANG)
        assert all(stream.closed for stream in raw_streams), (
            "cleanup error left subprocess pipes open"
        )
        if descendant:
            deadline = time.monotonic() + 5
            while _live_member(descendant, process.pid):
                assert time.monotonic() < deadline, (
                    "owned descendant survived group cleanup"
                )
                time.sleep(0.01)
    finally:
        if (
            process.returncode is None
            or descendant
            and _live_member(descendant, process.pid)
        ):
            try:
                real_killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        real_wait(timeout=5)
        for stream in raw_streams:
            stream.close()


@pytest.mark.parametrize("group", [False, True])
@pytest.mark.parametrize("error", [PermissionError, OSError, KeyboardInterrupt])
def test_wait_failure_does_not_mask_signal_failure(group, error, monkeypatch):
    primary = error("owned signal failed")
    wait_failure = subprocess.TimeoutExpired("owned wait", 5)
    with ExitStack() as independent:
        streams = [
            independent.enter_context(tempfile.TemporaryFile()) for _ in range(3)
        ]
        process = SimpleNamespace(
            pid=123456,
            returncode=None,
            stdin=streams[0],
            stdout=streams[1],
            stderr=streams[2],
            poll=Mock(return_value=None),
            kill=Mock(side_effect=primary),
            wait=Mock(side_effect=wait_failure),
        )
        monkeypatch.setattr(
            module,
            "os",
            SimpleNamespace(**(vars(os) | {"killpg": Mock(side_effect=primary)})),
        )
        with pytest.raises(error) as caught:
            with module.reap_on_exit(process, process_group=group):
                pass
        process.wait.assert_called_once_with(timeout=5)
        assert caught.value is primary
        assert caught.value.__cause__ is wait_failure
        assert all(stream.closed for stream in streams)
