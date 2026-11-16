"""Sibling tracer startup waits for target ptracer setup and owns failures."""

from contextlib import ExitStack
import errno
import os
import select
import sys
from types import ModuleType

import pytest

from core.sandbox import _landlock_audit as audit
from core.testing.module_views import module_function_view
from core.testing.wallclock import check_wall_deadline


pytestmark = [pytest.mark.slow, pytest.mark.linux_native,
              pytest.mark.skipif(sys.platform != "linux", reason="Linux ptrace startup")]
_CONTROL_WAIT_S = 8


def _recorded_os():
    private = ModuleType("owned_audit_os")
    vars(private).update(vars(os))
    descriptors, children = {}, []

    def pipe():
        pair = os.pipe()
        for fd in pair:
            info = os.fstat(fd)
            descriptors[fd] = (info.st_dev, info.st_ino)
        return pair

    def fork():
        pid = os.fork()
        if pid:
            children.append(pid)
        return pid

    private.pipe, private.fork = pipe, fork
    return private, descriptors, children


def _assert_retired(descriptors, children):
    for fd, identity in descriptors.items():
        try:
            info = os.fstat(fd)
        except OSError as error:
            assert error.errno == errno.EBADF
        else:
            assert (info.st_dev, info.st_ino) != identity, "audit pipe owner leaked"
    for pid in children:
        with pytest.raises(ChildProcessError):
            os.waitpid(pid, os.WNOHANG)


def _wait_byte(fd, expected):
    ready, _, _ = select.select([fd], [], [], _CONTROL_WAIT_S)
    assert ready and os.read(fd, 1) == expected


def test_tracer_launch_waits_for_target_ptracer_setup(tmp_path):
    from core.sandbox.ptrace_probe import check_ptrace_available
    if not check_ptrace_available():
        pytest.skip("requires actual ptrace support")
    owned_os, descriptors, children = _recorded_os()
    with ExitStack() as stack:
        gate_r, gate_w = os.pipe()
        acknowledged_r, acknowledged_w = os.pipe()
        for fd in (gate_r, gate_w, acknowledged_r, acknowledged_w):
            stack.callback(os.close, fd)
        prepared, released = [], []

        def hold_before_optin():
            _wait_byte(gate_r, b"G")

        def optin(libc):
            audit._set_ptracer_any_in_child(libc)
            os.write(acknowledged_w, b"R")

        def readable(fds, timeout):
            if not released:
                assert not prepared, "tracer started before target ptracer setup"
                released.append(True)
                os.write(gate_w, b"G")
            return audit._readable_fds(fds, timeout)

        def prepare(*args, **kwargs):
            ready, _, _ = select.select([acknowledged_r], [], [], 0)
            assert ready and os.read(acknowledged_r, 1) == b"R", (
                "tracer started before target ptracer setup")
            prepared.append(True)
            return audit.prepare_tracer_launch(*args, **kwargs)

        private = module_function_view(audit, bindings={
            "os": owned_os, "_set_ptracer_any_in_child": optin,
            "_readable_fds": readable, "prepare_tracer_launch": prepare,
        })
        try:
            result = private.run_landlock_audit(
                ["/bin/sh", "-c", "printf ready"], audit_run_dir=str(tmp_path),
                env={"PATH": "/usr/bin:/bin"}, rlimit_preexec=hold_before_optin,
                timeout=5, capture_output=True, text=True,
            )
        finally:
            _assert_retired(descriptors, children)
        assert prepared == released == [True]
        assert result.returncode == 0 and result.stdout == "ready"


@pytest.mark.parametrize("fault", ["eof", "invalid", "timeout"])
def test_target_not_ready_refuses_before_tracer_and_retires_owners(tmp_path, fault):
    import time

    owned_os, descriptors, children = _recorded_os()
    prepared = []

    def prepare(*args, **kwargs):
        prepared.append(True)
        raise AssertionError("tracer must not start for an unready target")

    def optin(libc):
        if fault == "eof":
            raise RuntimeError("controlled target setup failure")
        audit._set_ptracer_any_in_child(libc)

    def write(fd, value):
        return os.write(fd, b"X" if fault == "invalid" and value == b"R" else value)

    owned_os.write = write
    with ExitStack() as stack:
        gate_r, gate_w = os.pipe()
        stack.callback(os.close, gate_r)
        stack.callback(os.close, gate_w)

        def hold():
            if fault == "timeout":
                _wait_byte(gate_r, b"G")

        private = module_function_view(audit, bindings={
            "os": owned_os, "_set_ptracer_any_in_child": optin,
            "prepare_tracer_launch": prepare, "_TRACER_READY_TIMEOUT_S": 0.25,
        })
        started = time.monotonic()
        with pytest.raises(RuntimeError, match="target.*ptrace readiness"):
            private.run_landlock_audit(
                ["/bin/true"], audit_run_dir=str(tmp_path),
                env={"PATH": "/usr/bin:/bin"}, rlimit_preexec=hold,
                timeout=5, capture_output=True,
            )
        assert not prepared
        _assert_retired(descriptors, children)
        check_wall_deadline(time.monotonic() - started, 4,
                            code_bound_s=_CONTROL_WAIT_S, what="target-ready retirement")
