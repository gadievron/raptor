"""SysV IPC deny keyed on filesystem confinement, not just
restrict_reads.

The gap: the SysV family deny rode ``deny_fd_exec`` alone, i.e. the
restricted-reads posture — but a TRUSTED read-everywhere lane under a
Landlock write wall (target/output runs with ``restrict_reads=False``)
shares the HOST IPC namespace on the plain subprocess lane, where
same-UID SysV shm segments carry no path for Landlock to evaluate:
``shmget``/``shmat`` against another host process's segment is a
cross-process read AND write primitive that walks straight through the
write wall. The deny therefore keys on the fs-wall engagement
(``seccomp_deny_sysv_ipc``, threaded by context.py) in addition to the
posture key.

Two layers under test:

  * the seccomp builder: ``deny_sysv_ipc=True`` installs the family
    deny live (layer-alone probe, no Landlock in the chain) without
    touching the fileless-exec arms; the default build keeps SysV
    available (wall-less trusted lanes unchanged);
  * context threading: the plain-lane preexec builder receives
    ``seccomp_deny_sysv_ipc=True`` exactly when the composed policy
    confines the filesystem (target/output write wall, a read
    allowlist, or a TCP port allowlist — a port allowlist takes the
    Landlock ruleset out of its net-only shape, so the write wall
    engages even with zero write grants), and falsy for wall-less and
    profile-"none" shapes.

The ns spawn lanes are out of scope by design: they unshare
CLONE_NEWIPC unconditionally (_spawn.py), so SysV objects are
namespace-isolated there regardless of the filter.
"""

from __future__ import annotations

import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[3]
if __name__ == "__main__":
    if str(REPO) not in sys.path:
        sys.path.insert(0, str(REPO))

from core.sandbox import check_seccomp_available  # noqa: E402
from core.sandbox.tests.capability import requires_landlock  # noqa: E402

pytestmark = [
    pytest.mark.skipif(sys.platform != "linux", reason="Linux seccomp"),
    pytest.mark.skipif(
        not check_seccomp_available(),
        reason="libseccomp / seccomp filter unavailable on this host",
    ),
]

# The probe issues shmget via libc and reports the outcome on stdout.
# The deny direction expects EPERM; the allow direction creates a
# private segment and removes it immediately (IPC_RMID) so nothing
# leaks into the host IPC namespace.
_PROBE = textwrap.dedent("""
    import ctypes, ctypes.util, errno, sys
    libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
    libc.shmget.restype = ctypes.c_int
    libc.shmget.argtypes = (ctypes.c_int, ctypes.c_size_t, ctypes.c_int)
    IPC_PRIVATE = 0
    IPC_CREAT = 0o1000
    IPC_RMID = 0
    want_denied = sys.argv[1] == "deny"
    shmid = libc.shmget(IPC_PRIVATE, 4096, IPC_CREAT | 0o600)
    err = ctypes.get_errno()
    if shmid == -1:
        if not want_denied:
            print("FAILURE: shmget denied on wall-less lane errno=%d"
                  % err, flush=True)
            sys.exit(1)
        if err != errno.EPERM:
            print("FAILURE: shmget wrong errno=%d" % err, flush=True)
            sys.exit(1)
        print("shmget DENIED EPERM", flush=True)
    else:
        libc.shmctl(shmid, IPC_RMID, None)
        if want_denied:
            print("FAILURE: shmget SUCCEEDED under deny", flush=True)
            sys.exit(1)
        print("shmget OK", flush=True)
    sys.exit(0)
""")


def _probe_cmd(direction: str) -> list[str]:
    return [sys.executable, "-c", _PROBE, direction]


class TestSeccompLayerAlone:
    """The deny enforced live with no Landlock preexec in the chain —
    the seccomp arm alone must carry it (it exists precisely because
    Landlock cannot see SysV objects)."""

    def _run_under_filter(self, direction: str, **builder_kwargs):
        from core.sandbox.seccomp import _make_seccomp_preexec

        fn = _make_seccomp_preexec("full", **builder_kwargs)
        assert fn is not None
        return subprocess.run(
            _probe_cmd(direction),
            preexec_fn=fn, capture_output=True, text=True, timeout=60,
        )

    def test_deny_sysv_ipc_engages_without_fd_exec(self):
        r = self._run_under_filter("deny", deny_sysv_ipc=True)
        assert r.returncode == 0, r.stdout + r.stderr
        assert "shmget DENIED EPERM" in r.stdout

    def test_default_filter_keeps_sysv_available(self):
        # Neither key set: the wall-less trusted filter is unchanged —
        # shmget still works (private segment, removed immediately).
        r = self._run_under_filter("allow")
        assert r.returncode == 0, r.stdout + r.stderr
        assert "shmget OK" in r.stdout


def _spy_preexec_kwargs(monkeypatch):
    """Capture the kwargs the plain-lane preexec builder receives
    (test_profile_none_sheds_policy pattern)."""
    from core.sandbox import context as _ctx

    captured: dict = {}
    real = _ctx._make_preexec_fn

    def spy(limits, **kw):
        captured.update(kw)
        return real(limits, **kw)

    monkeypatch.setattr(_ctx, "_make_preexec_fn", spy)
    return captured


class TestContextThreading:
    """The fs-wall engagement predicate, pinned at the context layer."""

    @requires_landlock
    def test_trusted_write_wall_threads_the_deny(
            self, tmp_path, monkeypatch):
        """target/output with restrict_reads=False: a trusted
        read-everywhere lane whose writes are confined must carry the
        SysV deny while keeping the fileless-exec arms off."""
        from core.sandbox import context as _ctx

        captured = _spy_preexec_kwargs(monkeypatch)
        tgt = tmp_path / "t"
        out = tmp_path / "o"
        tgt.mkdir()
        out.mkdir()
        with _ctx.sandbox(target=str(tgt), output=str(out)):
            pass
        assert captured, "preexec builder never consulted"
        assert captured.get("seccomp_deny_sysv_ipc") is True
        assert not captured.get("seccomp_deny_fd_exec")

    @requires_landlock
    def test_restricted_reads_threads_the_deny(
            self, tmp_path, monkeypatch):
        from core.sandbox import context as _ctx

        captured = _spy_preexec_kwargs(monkeypatch)
        with _ctx.sandbox(restrict_reads=True):
            pass
        assert captured, "preexec builder never consulted"
        assert captured.get("seccomp_deny_sysv_ipc") is True

    @requires_landlock
    def test_ports_only_wall_threads_the_deny(self, monkeypatch):
        """A TCP port allowlist with ZERO write grants still engages
        the Landlock write wall (the ruleset leaves its net-only shape
        the moment a port allowlist exists), so the SysV deny must
        ride along — writes confined means SysV denied, however the
        wall was engaged."""
        from core.sandbox import context as _ctx

        captured = _spy_preexec_kwargs(monkeypatch)
        with _ctx.sandbox(allowed_tcp_ports=[443],
                          exclude_tmp_baseline=True,
                          block_network=False):
            pass
        assert captured, "preexec builder never consulted"
        assert captured.get("seccomp_deny_sysv_ipc") is True
        assert not captured.get("seccomp_deny_fd_exec")

    def test_wallless_context_keeps_the_filter_unchanged(
            self, monkeypatch):
        """No fs policy at all: the key must stay falsy so wall-less
        trusted lanes build a byte-identical filter."""
        from core.sandbox import context as _ctx

        captured = _spy_preexec_kwargs(monkeypatch)
        # A network block would add an unrelated capability requirement:
        # without namespaces or Landlock it must refuse before preexec.
        with _ctx.sandbox(block_network=False):
            pass
        assert captured, "preexec builder never consulted"
        assert not captured.get("seccomp_deny_sysv_ipc")

    def test_profile_none_sheds_the_deny_with_the_policy(
            self, tmp_path, monkeypatch):
        """'none' must mean none: the profile nulls target/output/
        restrict_reads, and the SysV key must follow the shed policy —
        a surviving True would re-engage a deny the profile promised
        away."""
        from core.sandbox import context as _ctx

        captured = _spy_preexec_kwargs(monkeypatch)
        tgt = tmp_path / "t"
        out = tmp_path / "o"
        tgt.mkdir()
        out.mkdir()
        with _ctx.sandbox(profile="none", target=str(tgt),
                          output=str(out), restrict_reads=True):
            pass
        assert captured, "preexec builder never consulted"
        assert not captured.get("seccomp_deny_sysv_ipc")


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
