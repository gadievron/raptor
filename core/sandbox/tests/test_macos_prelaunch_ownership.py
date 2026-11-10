"""Parent setup ownership with real pipes; no native Darwin enforcement claim."""

import builtins
import errno
import os
import subprocess
import sys
from types import SimpleNamespace

import pytest

from core.sandbox import _macos_spawn as mac
from core.sandbox.errors import SandboxSetupError
from core.testing.module_views import module_function_view


def exercise(tmp_path, stage, failure_type=OSError, *, cleanup_fault=False):
    failure = (OSError(errno.EMFILE, "owned preparation failure")
               if failure_type is OSError else failure_type("owned preparation failure"))
    owned, streamer_fds, parent_fds = {}, [], []
    stopped, registered, attempts, closes = [], [], [], []
    real_stat, real_close = os.fstat, os.close
    pipe_calls = 0
    secondary = MemoryError("owned close failed after effect")
    secondary_raised = False

    def remember(pair, selected):
        for fd in pair:
            info = real_stat(fd)
            owned[fd] = (info.st_dev, info.st_ino)
            selected.append(fd)
        return pair

    def close_owned(fd):
        try:
            info = real_stat(fd)
        except OSError as exc:
            if exc.errno == errno.EBADF:
                return
            raise
        if (info.st_dev, info.st_ino) == owned[fd]:
            real_close(fd)

    class Streamer:
        def register_target_pid(self, pid):
            registered.append(pid)

        def stop(self):
            stopped.append(True)
            for fd in streamer_fds:
                close_owned(fd)

    def start_streamer(*args, **kwargs):
        remember(os.pipe(), streamer_fds)
        return Streamer()

    def pipe():
        nonlocal pipe_calls
        pipe_calls += 1
        if (stage == "first" and pipe_calls == 1) or (stage == "second" and pipe_calls == 2):
            raise failure
        return remember(os.pipe(), parent_fds)

    def close(fd):
        nonlocal secondary_raised
        closes.append(fd)
        real_close(fd)
        if cleanup_fault and fd in parent_fds and not secondary_raised:
            secondary_raised = True
            raise secondary

    def no_prelaunch_read(*args):
        pytest.fail("pre-launch cleanup must close channels without waiting for a report")

    def quarantine(*args):
        raise failure

    def pin_problem(*args):
        if stage == "pin-refusal":
            return "owned grant changed"
        if stage == "pin":
            raise failure
        return None

    class Process:
        pid = 987654321
        returncode = 0
        stdin = stdout = stderr = None

        def __init__(self, *args, **kwargs):
            attempts.append(True)
            assert stage == "normal", "a failed setup must not dispatch a target"
            os.write(int(kwargs["env"]["_RAPTOR_STATUS_FD"]), b"K")

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def communicate(self, input=None, timeout=None):
            return b"", b""

        def poll(self):
            return self.returncode

        def wait(self, timeout=None):
            return self.returncode

    def import_local(name, globals=None, locals=None, fromlist=(), level=0):
        if level == 1 and not name and "seatbelt_audit" in fromlist:
            return SimpleNamespace(seatbelt_audit=SimpleNamespace(
                start_log_streamer=start_streamer))
        if level == 1 and name == "_env_quarantine" and stage == "environment":
            return SimpleNamespace(quarantine_loader_env=quarantine)
        return builtins.__import__(name, globals, locals, fromlist, level)

    out = tmp_path / "output"
    out.mkdir()
    private = module_function_view(mac, bindings={
        "os": module_function_view(os, bindings={
            "pipe": pipe, "close": close,
            "read": os.read if stage == "normal" else no_prelaunch_read,
        }),
        "subprocess": module_function_view(subprocess, bindings={"Popen": Process}),
        "_grant_pin_mismatch": pin_problem,
        "_ps_snapshot": lambda: [],
        "_sweep_descendants": lambda *args, **kwargs: set(),
    }, import_hook=import_local)

    def invoke():
        return private.run_sandboxed(
            [sys.executable, "-c", "pass"], env={}, nproc_limit=0,
            output=str(out), audit_mode=True, audit_run_dir=str(tmp_path))

    try:
        if stage == "normal":
            result = invoke()
            assert result.returncode == 0
            assert result._setup_status is None
            assert attempts == [True] and registered == [Process.pid]
        elif stage == "pin-refusal":
            with pytest.raises(SandboxSetupError) as raised:
                invoke()
            assert raised.value.setup_category == "P"
            assert "owned grant changed" in str(raised.value)
        else:
            with pytest.raises(failure_type) as raised:
                invoke()
            assert raised.value is failure
        assert len(streamer_fds) == 2
        assert stopped == [True], "pre-launch failure abandoned the audit owner"
        if stage != "normal":
            assert attempts == []
        if cleanup_fault:
            assert secondary_raised
        assert len(closes) == len(set(closes)), "numeric parent endpoint closed twice"
        for fd, identity in owned.items():
            try:
                info = real_stat(fd)
            except OSError as exc:
                assert exc.errno == errno.EBADF
            else:
                assert (info.st_dev, info.st_ino) != identity, "owned pipe survived cleanup"
    finally:
        for fd in owned:
            close_owned(fd)


@pytest.mark.parametrize("stage", ["first", "second", "environment", "pin"])
@pytest.mark.parametrize("failure_type", [OSError, MemoryError, KeyboardInterrupt])
def test_prelaunch_failure_retires_all_acquired_owners(tmp_path, stage, failure_type):
    exercise(tmp_path, stage, failure_type)


def test_secondary_close_failure_does_not_abandon_other_owners(tmp_path):
    exercise(tmp_path, "environment", KeyboardInterrupt, cleanup_fault=True)


def test_prelaunch_pin_refusal_keeps_security_category_and_retires_owners(tmp_path):
    exercise(tmp_path, "pin-refusal")


def test_normal_audit_dispatch_keeps_readiness_and_retires_owners(tmp_path):
    exercise(tmp_path, "normal")
