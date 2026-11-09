"""An interrupted cleanup wait retains bounded ownership of its child."""

from contextlib import contextmanager
import os
import signal
import subprocess
import sys
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from core.testing import processes as module


@contextmanager
def _child(group):
    process = subprocess.Popen(
        [sys.executable, "-I", "-c", "import time; time.sleep(60)"],
        start_new_session=group, env={"PATH": os.defpath},
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    kill, wait = process.kill, process.wait
    try:
        yield process, kill, wait
    finally:
        process.kill, process.wait = kill, wait
        with module.reap_on_exit(process, process_group=group):
            pass


@pytest.mark.skipif(os.name != "posix", reason="POSIX owned process groups")
@pytest.mark.parametrize("group", [False, True])
@pytest.mark.parametrize("after_effect", [False, True])
@pytest.mark.parametrize("startup", [False, True])
def test_native_interrupted_wait_reaps_child(group, after_effect, startup):
    interrupted = KeyboardInterrupt("cleanup wait interrupted")
    with _child(group) as (process, _kill, wait):
        calls = []

        def waiting(*, timeout):
            calls.append(timeout)
            if len(calls) == 1:
                if after_effect:
                    wait(timeout=timeout)
                raise interrupted
            return wait(timeout=timeout)

        process.wait = waiting
        owner = (module.cleanup_on_startup_error(process, process_group=group)
                 if startup else module.reap_on_exit(process, process_group=group))
        with pytest.raises(KeyboardInterrupt) as caught:
            with owner:
                if startup:
                    raise LookupError("startup failed")
        assert caught.value is interrupted
        assert calls[0] == 5
        assert len(calls) == (1 if after_effect else 2)
        if not after_effect:
            assert 0 <= calls[1] <= calls[0]
        assert process.returncode is not None
        with pytest.raises(ChildProcessError):
            os.waitpid(process.pid, os.WNOHANG)
        assert all(stream.closed for stream in (process.stdin, process.stdout, process.stderr))


def _process(wait):
    return SimpleNamespace(
        stdin=Mock(), stdout=Mock(), stderr=Mock(),
        returncode=None, pid=123456, poll=Mock(return_value=None),
        kill=Mock(), wait=Mock(side_effect=wait),
    )


@pytest.mark.parametrize("timeout,elapsed,remaining", [(5, 2, 3), (5, 8, 0), (None, 2, None)])
@pytest.mark.parametrize("drain", ["success", "timeout", "interrupt", "same_interrupt"])
def test_retry_keeps_deadline_and_original_interrupt(timeout, elapsed, remaining, drain, monkeypatch):
    interrupted = KeyboardInterrupt("first interrupt")
    secondary = (interrupted if drain == "same_interrupt" else
                 KeyboardInterrupt("second interrupt") if drain == "interrupt" else
                 subprocess.TimeoutExpired("owned", remaining))
    clock = iter([100, 100 + elapsed])
    monkeypatch.setattr(module, "time", SimpleNamespace(monotonic=lambda: next(clock)))
    calls = []

    def wait(**kwargs):
        calls.append(kwargs)
        if len(calls) == 1:
            raise interrupted
        if drain != "success":
            raise secondary
        process.returncode = -signal.SIGKILL

    process = _process(wait)
    with pytest.raises(KeyboardInterrupt) as caught:
        with module.reap_on_exit(process, wait_timeout=timeout):
            pass
    assert caught.value is interrupted
    assert calls == [{"timeout": timeout}, {"timeout": remaining}]
    assert caught.value.__cause__ is (secondary if drain in ("timeout", "interrupt") else None)
    assert caught.value.__cause__ is not caught.value
    for stream in (process.stdin, process.stdout, process.stderr):
        stream.close.assert_called_once_with()


@pytest.mark.parametrize("error", [OSError("wait failed"), subprocess.TimeoutExpired("owned", 5)])
def test_non_interrupt_wait_failure_is_not_retried(error):
    process = _process(lambda **kwargs: (_ for _ in ()).throw(error))
    with pytest.raises(type(error)) as caught:
        with module.reap_on_exit(process):
            pass
    assert caught.value is error
    process.wait.assert_called_once_with(timeout=5)


@pytest.mark.parametrize("drain_fails", [False, True])
def test_signal_error_remains_primary_after_wait_interrupt(drain_fails):
    primary = PermissionError("signal failed after effect")
    interrupted = KeyboardInterrupt("cleanup interrupted")
    secondary = subprocess.TimeoutExpired("owned", 5)
    calls = []

    def wait(**kwargs):
        calls.append(kwargs)
        if len(calls) == 1:
            raise interrupted
        if drain_fails:
            raise secondary
        process.returncode = -signal.SIGKILL

    process = _process(wait)
    process.kill.side_effect = primary
    with pytest.raises(PermissionError) as caught:
        with module.reap_on_exit(process):
            pass
    assert caught.value is primary
    assert primary.__cause__ is interrupted
    assert interrupted.__cause__ is (secondary if drain_fails else None)
    assert len(calls) == 2
    assert calls[0] == {"timeout": 5}
    assert 0 <= calls[1]["timeout"] <= 5
