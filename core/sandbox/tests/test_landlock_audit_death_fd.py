"""Death-pipe plumbing through the Landlock-audit spawn path.

The non-audit ``need_unshare`` branch in context.py hands the pid1
shim a liveness pipe (``_RAPTOR_DEATH_FD``) so a hard-killed
orchestrator still cascades the pid-ns down. The Landlock-audit path
(``_landlock_audit.run_landlock_audit``) had no such plumbing — a
shim spawned via ``--audit`` on a namespace-less host outlived a dead
orchestrator.

``install_death_fd=True`` now mirrors the non-audit branch: the READ
end is inherited by the target chain and advertised via
``_RAPTOR_DEATH_FD``; the parent holds the sole surviving WRITE end.
"""

from __future__ import annotations

import sys

import pytest

from core.sandbox import _landlock_audit as mod

pytestmark = pytest.mark.skipif(
    sys.platform != "linux",
    reason="Landlock-audit spawn path is Linux-only",
)

_CHILD = (
    "import os\n"
    "fd = os.environ.get('_RAPTOR_DEATH_FD')\n"
    "if fd is None:\n"
    "    print('NOFD')\n"
    "else:\n"
    "    os.fstat(int(fd))\n"           # raises if the fd is not open
    "    print('FD-OK', fd)\n"
)


def _ptrace_ready() -> bool:
    from core.sandbox.ptrace_probe import check_ptrace_available
    from core.sandbox.seccomp import check_seccomp_available
    return check_ptrace_available() and check_seccomp_available()


def test_install_death_fd_requires_env(tmp_path):
    with pytest.raises(ValueError, match="_RAPTOR_DEATH_FD"):
        mod.run_landlock_audit(
            ["true"],
            audit_run_dir=str(tmp_path),
            install_death_fd=True,
            env=None,
        )


def test_death_fd_reaches_child_open(tmp_path):
    """The child must see _RAPTOR_DEATH_FD in its env AND find the fd
    open across the exec (inheritable read end)."""
    if not _ptrace_ready():
        pytest.skip("ptrace/libseccomp unavailable")
    result = mod.run_landlock_audit(
        [sys.executable, "-c", _CHILD],
        audit_run_dir=str(tmp_path),
        env={"PATH": "/usr/bin:/bin"},
        install_death_fd=True,
        capture_output=True, text=True, timeout=60,
    )
    assert result.returncode == 0, result.stderr
    assert "FD-OK" in result.stdout, (
        f"death fd did not survive to the child: {result.stdout!r} / "
        f"{result.stderr!r}")


def test_no_death_fd_without_flag(tmp_path):
    if not _ptrace_ready():
        pytest.skip("ptrace/libseccomp unavailable")
    result = mod.run_landlock_audit(
        [sys.executable, "-c", _CHILD],
        audit_run_dir=str(tmp_path),
        env={"PATH": "/usr/bin:/bin"},
        capture_output=True, text=True, timeout=60,
    )
    assert result.returncode == 0, result.stderr
    assert "NOFD" in result.stdout
