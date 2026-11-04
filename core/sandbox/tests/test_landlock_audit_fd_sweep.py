"""The Landlock-audit target child closes fds above the lowered NOFILE.

``run_landlock_audit`` runs ``rlimit_preexec`` (which lowers
RLIMIT_NOFILE) before its pre-exec fd sweep. Lowering NOFILE does not
invalidate descriptors that already exist, so a non-CLOEXEC fd
numbered at/above the reduced soft limit survived the old
``closerange(3, soft)`` sweep and rode the exec into the UNTRUSTED
target as an out-of-policy capability — on the namespace-less lane,
the weakest containment tier, where an inherited fd matters most.
The sweep must enumerate ``/proc/self/fd`` (the shape _spawn's
grandchild sweep uses) so every actually-open fd is closed.
"""

from __future__ import annotations

from contextlib import ExitStack
import fcntl
import os
import resource
import sys

import pytest

from core.sandbox import _landlock_audit as mod

pytestmark = pytest.mark.skipif(
    sys.platform != "linux",
    reason="Landlock-audit spawn path is Linux-only",
)

_PLANT_FD = 300
_LOWERED_SOFT = 256


def _ptrace_ready() -> bool:
    from core.sandbox.ptrace_probe import check_ptrace_available
    from core.sandbox.seccomp import check_seccomp_available
    return check_ptrace_available() and check_seccomp_available()


def test_high_noncloexec_fd_does_not_survive_into_the_target(tmp_path):
    if not _ptrace_ready():
        pytest.skip("ptrace/libseccomp unavailable")
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    if soft <= _PLANT_FD:
        pytest.skip(f"parent NOFILE soft limit {soft} too low to "
                    f"plant fd {_PLANT_FD}")

    # Allocate an unused non-CLOEXEC fd above the child's lowered limit;
    # never overwrite a descriptor another fixture or caller already owns.
    with ExitStack() as cleanup:
        src = os.open(str(tmp_path / "planted"), os.O_CREAT | os.O_RDWR)
        cleanup.callback(os.close, src)
        planted = fcntl.fcntl(src, fcntl.F_DUPFD, _PLANT_FD)
        cleanup.callback(os.close, planted)
        os.set_inheritable(planted, True)

        def _lower_nofile() -> None:
            resource.setrlimit(resource.RLIMIT_NOFILE,
                               (_LOWERED_SOFT, hard))

        probe = (
            "import os\n"
            "try:\n"
            f"    os.fstat({planted})\n"
            "    print('FD-LEAKED')\n"
            "except OSError:\n"
            "    print('FD-CLOSED')\n"
        )
        result = mod.run_landlock_audit(
            [sys.executable, "-c", probe],
            audit_run_dir=str(tmp_path),
            rlimit_preexec=_lower_nofile,
            env={"PATH": "/usr/bin:/bin"},
            capture_output=True, text=True, timeout=60,
        )

    assert result.returncode == 0, result.stderr
    assert "FD-CLOSED" in result.stdout, (
        f"planted fd {planted} (above the lowered NOFILE soft "
        f"limit {_LOWERED_SOFT}) leaked into the audited target:\n"
        f"stdout={result.stdout}\nstderr={result.stderr}"
    )
    assert "FD-LEAKED" not in result.stdout
