"""stdout=/stderr= forwarding parity on the seatbelt and
Landlock-audit dispatches.

The Linux spawn dispatch forwards both kwargs; pre-fix the seatbelt
dispatch and the Landlock-only-audit dispatch dropped them. On macOS
that defeated run_untrusted's write-only fd-1/2 tty reopen — every
non-capturing call handed the untrusted child the parent's original
O_RDWR pty slave (a keystroke read channel) while the reopened
write-only fds sat unused — and seatbelt-lane callers passing
redirects silently lost them. The Landlock-audit lane had no
stdout=/stderr= parameters at all.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from unittest import mock

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[3]


class TestSeatbeltDispatchStdio:
    """Kwarg-threading parity for the seatbelt dispatch — pure logic,
    backend stubbed (see TestContextDispatchParity in
    test_seatbelt_keep_trust.py for the pattern); runs everywhere."""

    def _captured_kwargs(self, tmp_path, **run_kwargs):
        from core.sandbox import _macos_spawn as macos_mod
        from core.sandbox import context
        captured = {}

        def fake_run(cmd, **kwargs):
            captured.update(kwargs)
            cp = subprocess.CompletedProcess(cmd, returncode=0,
                                             stdout="", stderr="")
            cp._setup_status = None
            cp.sandbox_info = {"backend": "macos-seatbelt"}
            return cp

        with mock.patch.object(sys, "platform", "darwin"), \
             mock.patch.object(context, "check_seatbelt_available",
                               return_value=True), \
             mock.patch.object(context, "check_mount_available",
                               return_value=False), \
             mock.patch.object(context, "check_net_available",
                               return_value=False), \
             mock.patch.object(macos_mod, "run_sandboxed", fake_run):
            context.run(["/usr/bin/true"], target=str(tmp_path),
                        output=str(tmp_path), timeout=30, **run_kwargs)
        return captured

    def test_dispatch_forwards_stdout_and_stderr(self, tmp_path):
        kwargs = self._captured_kwargs(
            tmp_path, capture_output=False, stdout=77, stderr=88)
        assert kwargs.get("stdout") == 77, (
            "seatbelt dispatch dropped stdout= — the write-only tty "
            "reopen (and every caller redirect) is defeated on macOS")
        assert kwargs.get("stderr") == 88

    def test_dispatch_defaults_stay_none(self, tmp_path):
        kwargs = self._captured_kwargs(tmp_path, capture_output=False)
        assert kwargs.get("stdout") is None
        assert kwargs.get("stderr") is None


@pytest.mark.darwin_native
def test_seatbelt_run_honours_stdout_redirect(tmp_path):
    """Live twin (real Darwin kernel, real sandbox-exec): a
    non-capturing run with stdout= pointed at a file must land the
    child's output in that file."""
    from core.sandbox import context
    out_file = tmp_path / "redirected.txt"
    fd = os.open(out_file, os.O_WRONLY | os.O_CREAT, 0o600)
    try:
        r = context.run(["/bin/sh", "-c", "echo seatbelt-redirect"],
                        target=str(tmp_path), output=str(tmp_path),
                        capture_output=False, stdout=fd, timeout=60)
    finally:
        os.close(fd)
    assert r.returncode == 0
    assert "seatbelt-redirect" in out_file.read_text()


pytestmark_linux = pytest.mark.skipif(
    sys.platform != "linux",
    reason="Landlock-audit spawn path is Linux-only")


def _ptrace_ready() -> bool:
    from core.sandbox.ptrace_probe import check_ptrace_available
    from core.sandbox.seccomp import check_seccomp_available
    return check_ptrace_available() and check_seccomp_available()


@pytestmark_linux
def test_landlock_audit_forwards_stdout_stderr(tmp_path):
    """Live: run_landlock_audit with capture_output=False must honour
    int-fd stdout=/stderr= redirects (the shape run_untrusted's
    write-only reopen passes) instead of leaking the parent's fds."""
    if not _ptrace_ready():
        pytest.skip("ptrace/libseccomp unavailable")
    from core.sandbox import _landlock_audit as mod
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    out_file = tmp_path / "out.txt"
    err_file = tmp_path / "err.txt"
    out_fd = os.open(out_file, os.O_WRONLY | os.O_CREAT, 0o600)
    err_fd = os.open(err_file, os.O_WRONLY | os.O_CREAT, 0o600)
    try:
        r = mod.run_landlock_audit(
            ["sh", "-c", "echo la-out; echo la-err >&2"],
            audit_run_dir=str(run_dir),
            writable_paths=[str(tmp_path), "/tmp"],
            capture_output=False,
            stdout=out_fd, stderr=err_fd,
            timeout=60,
        )
    finally:
        os.close(out_fd)
        os.close(err_fd)
    assert r.returncode == 0
    assert "la-out" in out_file.read_text()
    assert "la-err" in err_file.read_text()


@pytestmark_linux
def test_landlock_audit_stderr_merges_to_stdout(tmp_path):
    """subprocess.STDOUT for stderr merges onto the redirected fd 1 —
    same contract as _spawn's mount-ns child."""
    if not _ptrace_ready():
        pytest.skip("ptrace/libseccomp unavailable")
    from core.sandbox import _landlock_audit as mod
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    out_file = tmp_path / "merged.txt"
    out_fd = os.open(out_file, os.O_WRONLY | os.O_CREAT, 0o600)
    try:
        r = mod.run_landlock_audit(
            ["sh", "-c", "echo m-out; echo m-err >&2"],
            audit_run_dir=str(run_dir),
            writable_paths=[str(tmp_path), "/tmp"],
            capture_output=False,
            stdout=out_fd, stderr=subprocess.STDOUT,
            timeout=60,
        )
    finally:
        os.close(out_fd)
    assert r.returncode == 0
    merged = out_file.read_text()
    assert "m-out" in merged
    assert "m-err" in merged


def test_landlock_audit_dispatch_forwards_source_pin():
    """Source pin (live twin above): the context dispatch for the
    Landlock-only audit lane threads stdout=/stderr= through to
    run_landlock_audit exactly like the Linux spawn dispatch does."""
    src = (_REPO_ROOT / "core" / "sandbox" / "context.py").read_text(
        encoding="utf-8")
    call_at = src.index("_la.run_landlock_audit(")
    block = src[call_at:src.index("start_new_session=", call_at)]
    assert 'stdout=kwargs.get("stdout")' in block
    assert 'stderr=kwargs.get("stderr")' in block
