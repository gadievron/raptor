"""Full context routing with owned parent pipes and a private executor."""

import builtins
from contextlib import contextmanager
import errno
import os
import subprocess
import sys

import pytest

from core.sandbox import context, _spawn, landlock, seccomp
from core.testing.module_views import module_function_view


@pytest.mark.skipif(sys.platform != "linux", reason="Linux parent routing control")
@pytest.mark.parametrize("stage,operation_failure", [
    ("normal", False), ("writer", False), ("reader", False), ("sweep", False),
    ("writer", True), ("reader", True), ("sweep", True),
])
def test_plain_finalizer_attempts_each_owner(stage, operation_failure):
    owned = {}
    calls = []
    failure = KeyboardInterrupt("owned writer close interruption")
    reaper = []
    holders = []
    original = ValueError("owned executor failure")

    def open_pipe():
        pair = os.pipe()
        for fd in pair:
            info = os.fstat(fd)
            owned[fd] = (info.st_dev, info.st_ino)
        return pair

    def close_writer(fd):
        os.close(fd)
        calls.append("writer")
        if stage == "writer":
            raise failure

    def close_reader(fd):
        os.close(fd)
        calls.append("reader")
        if stage == "reader":
            raise failure

    def sweep(token):
        assert token
        calls.append("sweep")
        if stage == "sweep":
            raise failure

    def preexec(*args, **kwargs):
        reaper.append(kwargs["reaper_cell"])
        return None

    def execute(cmd, pk, holder, start_new_session, **kwargs):
        calls.append("executor")
        assert holder[0] in owned
        holders.append(holder)
        if operation_failure:
            raise original
        return subprocess.CompletedProcess(cmd, 0, b"", b"")

    spawn = module_function_view(_spawn, bindings={
        "open_death_pipe": open_pipe, "close_death_w": close_writer,
    })
    ll = module_function_view(landlock, bindings={
        "check_landlock_available": lambda: True, "_get_landlock_abi": lambda: 8,
    })
    sc = module_function_view(seccomp, bindings={"check_seccomp_available": lambda: True})

    def imports(name, globals=None, locals=None, fromlist=(), level=0):
        if level == 1 and name == "_spawn":
            return spawn
        if level == 1 and name == "landlock":
            return ll
        if level == 1 and name == "seccomp":
            return sc
        return builtins.__import__(name, globals, locals, fromlist, level)

    private = module_function_view(context, bindings={
        "sandbox": context.sandbox.__wrapped__,
        "check_net_available": lambda: True,
        "check_mount_available": lambda: True,
        "check_seatbelt_available": lambda: False,
        "_make_preexec_fn": preexec,
        "_run_teardown_first_timeout": execute,
        "_sweep_marked_processes": sweep,
        "os": module_function_view(os, bindings={"close": close_reader}),
    }, import_hook=imports)
    try:
        def invoke():
            with contextmanager(private.sandbox)(profile="full", block_network=False) as run:
                return run(["/bin/true"], capture_output=True)

        if stage == "normal":
            assert invoke().returncode == 0
        else:
            expected = original if operation_failure else failure
            with pytest.raises(type(expected)) as caught:
                invoke()
            assert caught.value is expected
        assert calls == ["executor", "writer", "reader", "sweep"]
        assert holders[0][0] is None
        assert len(owned) == 2
        assert reaper and reaper[0]["death_local"].fd is None
        for fd in owned:
            with pytest.raises(OSError) as closed:
                os.fstat(fd)
            assert closed.value.errno == errno.EBADF
    finally:
        # Never close an unrelated descriptor if an implementation reuses it.
        for fd, identity in owned.items():
            try:
                info = os.fstat(fd)
            except OSError:
                continue
            if (info.st_dev, info.st_ino) == identity:
                os.close(fd)
