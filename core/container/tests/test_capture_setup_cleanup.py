"""Partial capture setup retires owned pipes and reports failures to callers."""

import errno
import os
import subprocess
import threading
from types import SimpleNamespace

import pytest

from core.container import proc
from core.testing.module_bindings import patch_module_attribute


def still_owned(fd, identity):
    try:
        info = os.fstat(fd)
    except OSError as error:
        if error.errno == errno.EBADF:
            return False
        raise
    return (info.st_dev, info.st_ino) == identity


@pytest.fixture
def capture_fault(monkeypatch):
    pipes, threads, spawns = [], [], []
    real_pipe, real_thread = os.pipe, threading.Thread

    def install(stage, error, *, close_error=None):
        pipe_calls = 0
        drainer_calls = 0
        close_faults = []

        def pipe():
            nonlocal pipe_calls
            pipe_calls += 1
            if stage == f"pipe{pipe_calls}":
                raise error
            pair = real_pipe()
            for index, fd in enumerate(pair):
                info = os.fstat(fd)
                pipes.append((fd, (info.st_dev, info.st_ino), index == 1))
            return pair

        def close(fd):
            os.close(fd)
            if (close_error is not None and not close_faults
                    and any(writer and owned_fd == fd for owned_fd, _, writer in pipes)):
                close_faults.append(fd)
                raise close_error

        class FailedStart:
            def start(self):
                raise error

        def thread(*args, **kwargs):
            nonlocal drainer_calls
            draining = kwargs["target"].__name__ == "_drain"
            if draining:
                drainer_calls += 1
                kind = f"drainer{drainer_calls}"
            else:
                kind = "worker"
            if stage == f"{kind}_ctor":
                raise error
            if stage == f"{kind}_start":
                return FailedStart()
            result = real_thread(*args, **kwargs)
            threads.append(result)
            return result

        def run(argv, **kwargs):
            spawns.append(argv)
            if stage == "spawn":
                raise error
            os.write(kwargs["stdout"], b"captured output")
            os.write(kwargs["stderr"], b"captured diagnostic")
            return subprocess.CompletedProcess(argv, 0)

        patch_module_attribute(monkeypatch, proc, "os", "pipe", pipe)
        patch_module_attribute(monkeypatch, proc, "os", "close", close)
        patch_module_attribute(monkeypatch, proc, "threading", "Thread", thread)
        patch_module_attribute(monkeypatch, proc, "subprocess", "run", run)
        return SimpleNamespace(
            invoke=lambda: proc.run_cli(["owned-tool"], timeout=1, env={}),
            pipes=pipes, threads=threads, spawns=spawns, close_faults=close_faults,
        )

    yield install
    # Release only our writer endpoints first, allowing an old leaking
    # implementation's started drainers to reach EOF before joining them.
    for fd, identity, writer in pipes:
        if writer and still_owned(fd, identity):
            os.close(fd)
    for thread in threads:
        if thread.ident is not None:
            thread.join(timeout=2)
    for fd, identity, _ in pipes:
        if still_owned(fd, identity):
            os.close(fd)


@pytest.mark.parametrize("stage", [
    "pipe1", "pipe2", "drainer1_ctor", "drainer2_ctor",
    "drainer1_start", "drainer2_start", "worker_ctor", "worker_start",
])
@pytest.mark.parametrize("error_type", [OSError, RuntimeError, KeyboardInterrupt, SystemExit])
def test_setup_failure_reports_and_retires_partial_capture(capture_fault, stage, error_type):
    error = error_type("controlled capture setup failure")
    owned = capture_fault(stage, error)
    if issubclass(error_type, Exception):
        outcome = owned.invoke()
        assert outcome.returncode is None and not outcome.timed_out
        assert outcome.stderr.startswith("os_error:")
        assert "controlled capture setup failure" in outcome.stderr
    else:
        with pytest.raises(error_type) as caught:
            owned.invoke()
        assert caught.value is error
    assert owned.spawns == []
    assert not any(still_owned(fd, identity) for fd, identity, _ in owned.pipes)
    assert not any(thread.is_alive() for thread in owned.threads)


def test_completed_setup_transfers_reads_and_captures_both_streams(capture_fault):
    owned = capture_fault("none", None)
    outcome = owned.invoke()
    assert outcome.returncode == 0 and not outcome.timed_out
    assert outcome.stdout == "captured output"
    assert outcome.stderr == "captured diagnostic"
    assert len(owned.spawns) == 1
    assert not any(still_owned(fd, identity) for fd, identity, _ in owned.pipes)
    assert not any(thread.is_alive() for thread in owned.threads)


@pytest.mark.parametrize("error_type", [RuntimeError, KeyboardInterrupt])
def test_setup_error_survives_secondary_close_failure(capture_fault, error_type):
    error = error_type("primary setup failure")
    owned = capture_fault("drainer2_start", error, close_error=SystemExit("secondary close"))
    if issubclass(error_type, Exception):
        result = owned.invoke()
        assert result.returncode is None and "primary setup failure" in result.stderr
    else:
        with pytest.raises(error_type) as caught:
            owned.invoke()
        assert caught.value is error
    assert owned.close_faults and owned.spawns == []
    assert not any(still_owned(fd, identity) for fd, identity, _ in owned.pipes)
    assert not any(thread.is_alive() for thread in owned.threads)


@pytest.mark.parametrize("error_type", [RuntimeError, KeyboardInterrupt])
def test_new_cleanup_error_is_reported_after_retiring_other_handles(capture_fault, error_type):
    error = error_type("cleanup failed")
    owned = capture_fault("none", None, close_error=error)
    if issubclass(error_type, Exception):
        result = owned.invoke()
        assert result.returncode is None and "cleanup failed" in result.stderr
    else:
        with pytest.raises(error_type) as caught:
            owned.invoke()
        assert caught.value is error
    assert owned.close_faults and len(owned.spawns) == 1
    assert not any(still_owned(fd, identity) for fd, identity, _ in owned.pipes)
    assert not any(thread.is_alive() for thread in owned.threads)


@pytest.mark.parametrize("error_type", [OSError, RuntimeError, KeyboardInterrupt, SystemExit])
def test_dispatch_failure_also_retires_started_capture(capture_fault, error_type):
    error = error_type("dispatch failed")
    owned = capture_fault("spawn", error)
    if issubclass(error_type, Exception):
        result = owned.invoke()
        assert result.returncode is None and "dispatch failed" in result.stderr
    else:
        with pytest.raises(error_type) as caught:
            owned.invoke()
        assert caught.value is error
    assert len(owned.spawns) == 1
    assert not any(still_owned(fd, identity) for fd, identity, _ in owned.pipes)
    assert not any(thread.is_alive() for thread in owned.threads)
