"""Landlock fail-closed aborts report through the spawn-lane status pipe.

The fail-closed sites inside ``_make_landlock_preexec``'s closure used
to ``os._exit(126)`` on BOTH lanes. On the preexec_fn lane that is the
only fork-safe option (async-signal-safe write + exit, documented in
exit_codes.py). On the mount-ns spawn lane it bypassed the grandchild's
setup-status pipe — the parent saw an unattributed child exit 126,
indistinguishable from a target that legitimately chose that exit code,
and no SandboxSetupError ever named the layer. ``fail_raise=True`` (the
spawn lane's mode) raises ``LandlockInstallError`` after the stderr
line instead; the grandchild catch-all reports 'L' + reason and
context.run() maps that to a typed SandboxSetupError.
"""

import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[3]

pytestmark = pytest.mark.skipif(
    sys.platform != "linux", reason="Landlock is Linux-only",
)

# Fork-inherited CDLL wrapper that refuses exactly the Landlock
# ruleset-creation syscall; everything else passes through. Same
# injection pattern as test_fresh_procfs_contract's mount refusal —
# the whole real code path runs, only the one syscall is denied.
_FAIL_CREATE_PRELUDE = """
import ctypes, os, sys
sys.path.insert(0, os.environ["RAPTOR_DIR"])
from core.sandbox import landlock as _ll
# Seed the availability probe (ABI query + functional self-test) with
# the REAL libc before the wrapper goes in — context builds the
# Landlock layer only when this probe succeeds, and the wrapper below
# would fail the self-test's own ruleset creation.
_ll.check_landlock_available()
_real_CDLL = ctypes.CDLL
class _FailCreateLibc:
    def __init__(self, real): self._r = real
    def __getattr__(self, n):
        if n == "syscall":
            _real = self._r.syscall
            def _sys(nr, *a):
                # Callers pass the syscall number as int or c_long.
                _n = getattr(nr, "value", nr)
                # The ABI probe passes attr=NULL (0, 0, flags) and must
                # keep working. Refuse only a REAL ruleset creation
                # (attr pointer present).
                if (isinstance(_n, int)
                        and _n == _ll._SYS_LANDLOCK_CREATE
                        and not (a and isinstance(a[0], int) and a[0] == 0)):
                    return -1
                return _real(nr, *a)
            return _sys
        return getattr(self._r, n)
    def __getitem__(self, k): return self._r[k]
def _patched(name=None, *a, **k):
    real = _real_CDLL(name, *a, **k)
    if name is None or "libc" in str(name):
        return _FailCreateLibc(real)
    return real
ctypes.CDLL = _patched
"""


def _run_driver(body: str, extra_env: dict | None = None,
                timeout: int = 150) -> subprocess.CompletedProcess:
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": os.environ.get("HOME", "/tmp"),
        "RAPTOR_DIR": str(_REPO_ROOT),
        **(extra_env or {}),
    }
    return subprocess.run(
        [sys.executable, "-c", _FAIL_CREATE_PRELUDE + textwrap.dedent(body)],
        env=env, capture_output=True, text=True, timeout=timeout,
        check=False,
    )


def _skip_unless_landlock():
    from core.sandbox.landlock import check_landlock_available
    if not check_landlock_available():
        pytest.skip("Landlock unavailable on this kernel")


def test_fail_raise_mode_raises_typed_error():
    """fail_raise=True: the create-failure site raises
    LandlockInstallError (after its stderr line) instead of exiting."""
    _skip_unless_landlock()
    r = _run_driver("""
        from core.sandbox.landlock import (
            LandlockInstallError, _make_landlock_preexec,
        )
        fn = _make_landlock_preexec(["/tmp"], fail_raise=True)
        try:
            fn()
        except LandlockInstallError as e:
            print("TYPED-RAISE:", str(e)[:80])
    """)
    assert r.returncode == 0, r.stderr
    assert "TYPED-RAISE: Landlock ruleset creation failed" in r.stdout
    assert "SYS_landlock_create_ruleset failed post-fork" in r.stderr


def test_fail_raise_message_truthful_when_probe_failed():
    """The builder is invoked on kernels whose probe FAILED too — when
    the resolved containment floor requires the Landlock layer, _spawn
    builds the ruleset regardless so the spawn fails closed instead of
    delivering an unconsented weaker tier. The create-failure message
    must tell that story: pre-fix it unconditionally claimed the
    failure happened on 'a kernel whose probe succeeded', misdirecting
    the operator toward a kernel anomaly on every Landlock-less host
    (the no-Landlock lane shape) instead of naming the actual
    fail-closed contract and its remedies."""
    r = _run_driver("""
        from core.sandbox import state as _state
        from core.sandbox.landlock import (
            LandlockInstallError, _make_landlock_preexec,
        )
        # This kernel's availability verdict: unavailable. On a host
        # WITH Landlock the CDLL wrapper still fails the creation the
        # same way the ENOSYS lane's kernel does; on a host without
        # it, creation fails naturally.
        _state._landlock_cache = -1
        fn = _make_landlock_preexec(["/tmp"], fail_raise=True)
        try:
            fn()
        except LandlockInstallError as e:
            msg = str(e)
            assert "probe succeeded" not in msg, msg
            assert "containment floor requires" in msg, msg
            assert "ns-only tier" in msg, msg
            print("TRUTHFUL-PROBE-FAILED-MESSAGE")
    """)
    assert r.returncode == 0, r.stderr + r.stdout
    assert "TRUTHFUL-PROBE-FAILED-MESSAGE" in r.stdout
    assert "SYS_landlock_create_ruleset failed post-fork" in r.stderr


def test_fail_closed_message_names_the_wsl_consent_on_wsl():
    """On a WSL host the fail-closed create-failure message
    additionally names the standing host-scoped consent ceremony —
    the refusal is the boundary where a WSL operator learns the
    documented way out. The hint is resolved in the PARENT at build
    time (fork-safety), so patching the detection before the builder
    runs is exactly the real WSL shape."""
    r = _run_driver("""
        import core.startup.wsl as _wsl
        _wsl.is_wsl = lambda kernel_id=None: True
        from core.sandbox import state as _state
        from core.sandbox.landlock import (
            LandlockInstallError, _make_landlock_preexec,
        )
        _state._landlock_cache = -1
        fn = _make_landlock_preexec(["/tmp"], fail_raise=True)
        try:
            fn()
        except LandlockInstallError as e:
            msg = str(e)
            assert "wsl-consent grant" in msg, msg
            assert "TTY-gated" in msg, msg
            assert "docs/wsl.md" in msg, msg
            print("WSL-HINT-PRESENT")
    """)
    assert r.returncode == 0, r.stderr + r.stdout
    assert "WSL-HINT-PRESENT" in r.stdout


def test_fail_closed_message_has_no_wsl_hint_off_wsl():
    """Off WSL the message keeps its exact generic shape — no
    misdirecting consent hint on ordinary Landlock-less hosts."""
    r = _run_driver("""
        import core.startup.wsl as _wsl
        _wsl.is_wsl = lambda kernel_id=None: False
        from core.sandbox import state as _state
        from core.sandbox.landlock import (
            LandlockInstallError, _make_landlock_preexec,
        )
        _state._landlock_cache = -1
        fn = _make_landlock_preexec(["/tmp"], fail_raise=True)
        try:
            fn()
        except LandlockInstallError as e:
            msg = str(e)
            assert "wsl-consent" not in msg, msg
            assert msg.endswith("admits the ns-only tier."), msg
            print("NO-WSL-HINT")
    """)
    assert r.returncode == 0, r.stderr + r.stdout
    assert "NO-WSL-HINT" in r.stdout


def test_default_mode_keeps_fork_safe_exit():
    """fail_raise omitted (preexec_fn lane): the same failure keeps the
    documented os._exit(126) + one-line stderr shape."""
    _skip_unless_landlock()
    r = _run_driver("""
        from core.sandbox.landlock import _make_landlock_preexec
        fn = _make_landlock_preexec(["/tmp"])
        fn()
        print("UNREACHED")
    """)
    assert r.returncode == 126, (r.returncode, r.stdout, r.stderr)
    assert "UNREACHED" not in r.stdout
    assert "SYS_landlock_create_ruleset failed post-fork" in r.stderr


@pytest.mark.integration
def test_spawn_lane_reports_L_status(tmp_path):
    """End-to-end: a Landlock install failure inside the spawn
    grandchild surfaces as a typed SandboxSetupError with category 'L'
    — not as an unattributed child exit 126."""
    _skip_unless_landlock()
    r = _run_driver("""
        from core.sandbox.context import run_untrusted
        from core.sandbox.errors import SandboxSetupError
        try:
            r = run_untrusted(["true"], target=%r, output=%r, cwd=%r,
                              timeout=90, capture_output=True, text=True)
            print("NO-RAISE rc=%%d" %% r.returncode)
        except SandboxSetupError as e:
            print("RAISED category=%%s: %%s"
                  %% (e.setup_category, str(e)[:120].replace("\\n", " ")))
    """ % (str(tmp_path), str(tmp_path), str(tmp_path)))
    if r.returncode != 0:
        pytest.skip(f"driver failed: {r.stderr[-300:]}")
    if "NO-RAISE" in r.stdout:
        # Mount-ns spawn lane not taken on this host (the Landlock-only
        # fallback ran and was itself refused Landlock, or the sandbox
        # degraded) — the lane under test never engaged.
        pytest.skip(f"spawn lane not reached: {r.stdout!r}")
    assert "RAISED category=L" in r.stdout, (
        f"Landlock install failure was not reported through the "
        f"setup-status pipe: {r.stdout!r} stderr={r.stderr[-300:]!r}")
    assert "Landlock" in r.stdout
