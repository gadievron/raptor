"""Pipe-backed test helpers retain ownership through failed setup."""

import errno
import importlib
import os
import sys
import threading
from types import SimpleNamespace

import pytest

_CASES = [
    ("daemon", "second-pipe"),
    ("daemon", "construction"),
    ("daemon", "start"),
    ("daemon", "host"),
    ("daemon", "lock"),
    ("host", "construction"),
    ("host", "start"),
    ("host", "host"),
    ("host", "lock"),
    ("stdout", "write"),
    ("stdout", "reader"),
    ("waiter", "fork"),
    ("waiter", "preclosed-fork"),
    ("rules", "fork"),
]
_MODULES = {
    "daemon": "test_daemon_rpc_hardening",
    "host": "test_suppress_narrowing",
    "stdout": "test_seatbelt_audit_warmup",
    "waiter": "test_supervised_waiter_contract",
    "rules": "test_seccomp_socketcall",
}


@pytest.mark.parametrize("helper,fault", _CASES)
def test_failed_pipe_helper_setup_releases_descriptors(helper, fault, monkeypatch):
    if helper in ("waiter", "rules") and sys.platform != "linux":
        pytest.skip("Linux fork helper internals")
    module = importlib.import_module(f"core.sandbox.tests.{_MODULES[helper]}")
    allocated = []
    threads = []
    real_pipe = os.pipe
    real_thread = threading.Thread

    def pipe():
        if fault == "second-pipe" and allocated:
            raise OSError("injected second pipe failure")
        pair = real_pipe()
        for fd in pair:
            stat = os.fstat(fd)
            allocated.append((fd, stat.st_dev, stat.st_ino))
        return pair

    def fail(*args, **kwargs):
        raise OSError("injected setup failure")

    def thread(*args, **kwargs):
        if fault == "construction":
            return fail()
        instance = real_thread(*args, **kwargs)
        threads.append(instance)
        if fault == "start":
            instance.start = fail
        return instance

    def still_owned(item):
        fd, device, inode = item
        try:
            stat = os.fstat(fd)
        except OSError as error:
            assert error.errno == errno.EBADF
            return False
        return (stat.st_dev, stat.st_ino) == (device, inode)

    try:
        with monkeypatch.context() as patcher:
            replacements = {"pipe": pipe}
            if helper in ("waiter", "rules"):
                replacements["fork"] = fail
            if helper == "stdout":
                # This constructor imports os locally.
                patcher.setattr(os, "pipe", pipe)
                if fault == "write":
                    patcher.setattr(os, "write", fail)
                else:
                    patcher.setattr(module, "open", fail, raising=False)
            else:
                patcher.setattr(
                    module, "os", SimpleNamespace(**(vars(os) | replacements))
                )
            if helper in ("daemon", "host"):
                patcher.setattr(
                    module,
                    "threading",
                    SimpleNamespace(
                        **(
                            vars(threading)
                            | {
                                "Thread": thread,
                                "Lock": fail if fault == "lock" else threading.Lock,
                            }
                        ),
                    ),
                )
                if fault == "host":
                    patcher.setattr(module, "SandboxHost", fail)
            with pytest.raises(OSError, match="injected .* failure"):
                if helper == "daemon":
                    module._FakeDaemonHost(lambda request: {"ok": True})
                elif helper == "host":
                    module._make_host()
                elif helper == "stdout":
                    module._FakeStdout([b"fixture\n"])
                elif helper == "waiter":
                    module._launch_supervised_waiter(
                        ":", live_w_preclosed=fault == "preclosed-fork"
                    )
                else:
                    module._rules_for({})
        assert allocated
        assert not [fd for fd in allocated if still_owned(fd)], (
            "failed setup leaked pipe descriptors"
        )
        assert all(not t.is_alive() for t in threads), (
            "failed setup left a worker running"
        )
    finally:
        # Verify pipe identity before cleanup so an already-closed/reused fd is
        # never mistaken for one of this controlled test's resources.
        for item in allocated:
            if still_owned(item):
                os.close(item[0])
        for t in threads:
            if t.ident is not None:
                t.join(timeout=3)
