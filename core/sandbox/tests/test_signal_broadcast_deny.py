"""Broadcast-signal deny: kill(-1, sig) / rt_sigqueueinfo(-1, ...) are
refused in every seccomp profile; targeted and own-group signalling is
untouched.

The gap: on the Landlock-only containment floor (no pid namespace —
unprivileged user namespaces blocked) a sandboxed payload shares the
host pid view, so kill(-1, SIGKILL/SIGSTOP/SIGTERM) fans out to every
same-UID host process: the operator's whole session, the sandbox
supervisor (SIGSTOP freezes it so timeouts never fire), every logger.
Landlock ABI v6 signal scoping (kernel >= 6.12) is the primary,
domain-semantic fix; the seccomp arg-filter under test here is the
pre-v6 tier and belt-and-braces above it. See seccomp.py's
_SIGNAL_BROADCAST_SYSCALLS for the full rationale including the
deliberately-not-denied neighbours (kill(0,·), negative pgids,
tkill/tgkill, pidfd_send_signal).

Two directions, per the deny doctrine:
  * broadcast forms denied: libc kill(-1, 0) (sign-extended), the
    zero-extended raw spelling (low-32 all-ones garnish the kernel
    truncates back to -1), and rt_sigqueueinfo(-1, ...) all get EPERM
    — in full AND the instrumentation profiles (debug/frida: debuggers
    signal specific pids, never the whole host) AND under audit mode
    (hard_deny — executing the broadcast to observe it is the harm);
  * legitimate signalling keeps working: the payload signals its own
    forked child, its own process group (kill(0,·) and the killpg
    negative-pgid spelling), itself, and rt_sigqueueinfo to a specific
    pid.

SAFETY SHAPE for future editors: every broadcast probe uses SIGNAL 0 —
the kernel's existence/permission check that delivers nothing — so a
filter miss (the very bug the deny direction hunts) makes the probe
FAIL LOUDLY without harming any host process. Never change the probes
to a real signal number; a regression plus a real broadcast SIGTERM
would kill the operator's session.
"""

from __future__ import annotations

import errno
import platform
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[3]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from core.sandbox import check_seccomp_available  # noqa: E402
from core.sandbox.tests.capability import (  # noqa: E402
    requires_landlock,
    requires_userns,
)

pytestmark = [
    pytest.mark.skipif(sys.platform != "linux", reason="Linux seccomp"),
    pytest.mark.skipif(
        not check_seccomp_available(),
        reason="libseccomp / seccomp filter unavailable on this host",
    ),
]

# kill / rt_sigqueueinfo syscall numbers for the arches the sandbox
# supports (the probe issues raw syscalls so the zero-extended pid
# spelling and the siginfo-carrying call don't depend on libc wrappers).
_SIGNAL_NR = {
    "x86_64": {"kill": 62, "rt_sigqueueinfo": 129},
    "aarch64": {"kill": 129, "rt_sigqueueinfo": 138},
}


def _nrs() -> dict[str, int] | None:
    return _SIGNAL_NR.get(platform.machine())


requires_signal_nrs = pytest.mark.skipif(
    _nrs() is None,
    reason="kill/rt_sigqueueinfo syscall numbers not tabulated for this arch",
)

_PROBE = textwrap.dedent("""
    import ctypes, errno, os, signal, sys
    libc = ctypes.CDLL(None, use_errno=True)
    kill_nr = int(sys.argv[1])
    rtsq_nr = int(sys.argv[2])
    failures = []

    # ALL broadcast probes use signal 0 (existence/permission check,
    # delivers nothing) so a filter miss cannot harm host processes —
    # see the module-docstring safety shape.

    # 1. libc spelling: kill(-1, 0) — pid_t -1 sign-extends to
    #    0xFFFFFFFFFFFFFFFF in the syscall register.
    try:
        os.kill(-1, 0)
        failures.append("kill(-1,0) PERMITTED (broadcast reachable)")
    except OSError as e:
        if e.errno != errno.EPERM:
            failures.append("kill(-1,0) wrong errno=%d" % e.errno)
        else:
            print("kill-broadcast DENIED EPERM", flush=True)

    # 2. zero-extended raw spelling: low 32 bits all-ones, high bits
    #    zero — the kernel truncates the pid to 32-bit -1, so an exact
    #    64-bit equality rule would miss it (the MASKED_EQ direction).
    ctypes.set_errno(0)
    r = libc.syscall(kill_nr, 0xFFFFFFFF, 0)
    e = ctypes.get_errno()
    if r == -1 and e == errno.EPERM:
        print("kill-broadcast-low32 DENIED EPERM", flush=True)
    else:
        failures.append("raw kill(0xFFFFFFFF,0) rc=%d errno=%d" % (r, e))

    # 3. rt_sigqueueinfo(-1, 0, info). si_code must be SI_QUEUE (-1):
    #    a si_code >= 0 from userspace is refused by the kernel with
    #    its own EPERM *before* pid handling, which would make this
    #    assertion vacuous.
    class SigInfo(ctypes.Structure):
        _fields_ = [("si_signo", ctypes.c_int),
                    ("si_errno", ctypes.c_int),
                    ("si_code", ctypes.c_int),
                    ("pad", ctypes.c_char * 116)]
    info = SigInfo(si_signo=0, si_errno=0, si_code=-1)
    ctypes.set_errno(0)
    r = libc.syscall(rtsq_nr, -1, 0, ctypes.byref(info))
    e = ctypes.get_errno()
    if r == -1 and e == errno.EPERM:
        print("rt_sigqueueinfo-broadcast DENIED EPERM", flush=True)
    else:
        failures.append("rt_sigqueueinfo(-1) rc=%d errno=%d" % (r, e))

    # 4. Legitimate direction: signal own forked child (a real
    #    SIGTERM — targeted at a pid we own, inside the sandbox tree).
    pid = os.fork()
    if pid == 0:
        import time
        time.sleep(30)
        os._exit(0)
    try:
        os.kill(pid, signal.SIGTERM)
        _, st = os.waitpid(pid, 0)
        if os.WIFSIGNALED(st) and os.WTERMSIG(st) == signal.SIGTERM:
            print("child-signal OK", flush=True)
        else:
            failures.append("child did not die of SIGTERM: %r" % st)
    except OSError as ex:
        failures.append("kill(child) denied errno=%d" % ex.errno)

    # 5. Legitimate direction: own process group, both spellings —
    #    kill(0, 0) and the negative-pgid killpg form. Runners MUST
    #    session the probe (start_new_session=True — the shape
    #    core.sandbox.run gives payloads by default) so getpgrp() is the
    #    probe's own pid: in an init-less container (docker without
    #    --init, e.g. the feature-matrix lanes) the inherited pgid
    #    is 1, and killpg(1, 0) IS kill(-1, 0) — the broadcast
    #    constant. Process group 1 is unaddressable via the
    #    negative-pid spelling even without the filter (the kernel
    #    reads -1 as broadcast, never as a pgid), so an unsessioned
    #    probe measures the container's process-group shape, not the
    #    filter. (sig 0 throughout regardless — module-docstring
    #    safety shape.)
    try:
        os.kill(0, 0)
        print("own-group-kill OK", flush=True)
    except OSError as ex:
        failures.append("kill(0,0) denied errno=%d" % ex.errno)
    try:
        os.killpg(os.getpgrp(), 0)
        print("negative-pgid-kill OK", flush=True)
    except OSError as ex:
        failures.append("killpg(pgrp,0) denied errno=%d" % ex.errno)

    # 6. Legitimate direction: self, and rt_sigqueueinfo to a
    #    specific pid.
    os.kill(os.getpid(), 0)
    print("self-kill OK", flush=True)
    ctypes.set_errno(0)
    r = libc.syscall(rtsq_nr, os.getpid(), 0, ctypes.byref(info))
    if r == 0:
        print("rt_sigqueueinfo-self OK", flush=True)
    else:
        failures.append("rt_sigqueueinfo(self) rc=%d errno=%d"
                        % (r, ctypes.get_errno()))

    for f in failures:
        print("FAILURE: " + f, flush=True)
    sys.exit(1 if failures else 0)
""")

_ALL_MARKERS = (
    "kill-broadcast DENIED EPERM",
    "kill-broadcast-low32 DENIED EPERM",
    "rt_sigqueueinfo-broadcast DENIED EPERM",
    "child-signal OK",
    "own-group-kill OK",
    "negative-pgid-kill OK",
    "self-kill OK",
    "rt_sigqueueinfo-self OK",
)


def _probe_cmd() -> list[str]:
    nrs = _nrs()
    assert nrs is not None
    return [sys.executable, "-c", _PROBE,
            str(nrs["kill"]), str(nrs["rt_sigqueueinfo"])]


def _py_tool_paths() -> list[str] | None:
    # Non-system interpreter installs (venv, pyenv) need their runtime
    # dirs granted; None when the interpreter is fully under the
    # system prefixes (test_e2e_sandbox pattern).
    from core.sandbox import python_runtime_tool_paths
    return python_runtime_tool_paths() or None


@requires_signal_nrs
class TestSeccompLayerAlone:
    """The seccomp filter applied directly (no Landlock, no pid-ns in
    the chain) — the exact shape of the pre-v6-Landlock degraded tier
    where this deny is the only broadcast barrier."""

    def _run_under_filter(self, profile: str):
        from core.sandbox.seccomp import _make_seccomp_preexec

        fn = _make_seccomp_preexec(profile)
        assert fn is not None
        # start_new_session: the probe's step-5 killpg(getpgrp(), 0)
        # needs a pgid > 1 — in an init-less container the inherited
        # pgid is 1 and killpg(1, 0) is kill(-1, 0), the broadcast
        # constant itself (see the probe's step-5 comment). setsid
        # also matches how core.sandbox.run spawns payloads by
        # default (child is a new session leader), so the raw-filter
        # shape under test stays faithful to the product's default
        # spawn shape.
        return subprocess.run(
            _probe_cmd(),
            preexec_fn=fn, capture_output=True, text=True, timeout=60,
            start_new_session=True,
        )

    @pytest.mark.parametrize("profile", ["full", "debug", "frida"])
    def test_broadcast_denied_targeted_intact(self, profile: str):
        # debug/frida included: the ptrace-granting instrumentation
        # profiles must NOT relax the broadcast deny — debuggers
        # signal specific pids, never every process on the host.
        r = self._run_under_filter(profile)
        assert r.returncode == 0, r.stdout + r.stderr
        for marker in _ALL_MARKERS:
            assert marker in r.stdout, (profile, marker, r.stdout)


@requires_signal_nrs
class TestAuditModeHardDeny:
    """Escape primitives never downgrade to allow-and-log: with
    audit_mode=True the broadcast rules keep the ERRNO action —
    allow-and-log would EXECUTE the broadcast while recording it.
    Probed with a fork child that only issues raw/direct syscalls
    after the filter engages (the audit filter's TRACE rules would
    SIGSYS without an attached tracer; kill/waitpid/write/_exit are
    not in the trace set), same discipline as test_fd_exec_deny."""

    def test_hard_deny_under_audit_filter(self):
        import os as _os

        from core.sandbox.seccomp import _make_seccomp_preexec

        fn = _make_seccomp_preexec("full", audit_mode=True)
        assert fn is not None
        r, w = _os.pipe()
        pid = _os.fork()
        if pid == 0:
            try:
                _os.close(r)
                fn()
                code = 0
                try:
                    _os.kill(-1, 0)   # sig 0: delivers nothing either way
                    code = 4          # permitted under audit = downgrade
                except OSError as e:
                    if e.errno != errno.EPERM:
                        code = 3      # denied, but not the hard_deny errno
                if code == 0:
                    try:
                        _os.kill(_os.getpid(), 0)
                    except OSError:
                        code = 5      # targeted self-signal broke
                _os.write(w, bytes([code]))
            except BaseException:
                try:
                    _os.write(w, bytes([9]))
                except OSError:
                    pass
            _os._exit(0)
        _os.close(w)
        try:
            data = _os.read(r, 1)
        finally:
            _os.close(r)
            _os.waitpid(pid, 0)
        assert data == b"\x00", f"audit hard-deny probe code={data!r}"


@requires_signal_nrs
@requires_landlock
@requires_userns
class TestLandlockFloorPosture:
    """End-to-end through core.sandbox.run on the pid-ns-less shape
    (skip_pid_ns: the payload shares the host pid view — exactly the
    posture where an unfiltered kill(-1) reaches the operator's
    session). Broadcast denied, own-child signalling intact."""

    def test_broadcast_denied_on_pidns_less_lane(self, tmp_path):
        from core.sandbox import run

        out = tmp_path / "o"
        out.mkdir()
        r = run(
            _probe_cmd(),
            skip_pid_ns=True,
            skip_mount_ns=True,
            fake_home=True,
            block_network=True,
            target=str(tmp_path),
            output=str(out),
            tool_paths=_py_tool_paths(),
            capture_output=True, text=True, timeout=120,
        )
        assert r.returncode == 0, r.stdout + r.stderr
        for marker in _ALL_MARKERS:
            assert marker in r.stdout, (marker, r.stdout)
