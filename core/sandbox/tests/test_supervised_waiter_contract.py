"""Shared contract battery for ns-init waiter implementations.

The waiter contract (mirrored between ``core.sandbox.supervised.
_run_ns_init_waiter`` and ``core/sandbox/_spawn.py``'s
``_pid1_split_for_waiter``): fork the target, forward SIGTERM/SIGINT/
SIGHUP/SIGQUIT to it, reap orphans that reparent to init, and mirror
the target's fate — exit status verbatim, 128+signum for a signal
death. Plus the supervised waiter's fail-closed boot arms: prctl
refusal and supervisor-already-gone.

DELIBERATELY parametrized over a launcher registry so a sibling waiter
implementation (e.g. a netns forwarder's duplicate) can be appended to
``LAUNCHERS`` and inherit every assertion here unchanged.

Hermetic: no pid namespace is created. The launcher's forked host
process sets ``PR_SET_CHILD_SUBREAPER`` on itself (test-only prctl via
ctypes) so orphaned grandchildren reparent to the waiter exactly as
they would to a real pid-ns init — the orphan-reap contract is
exercised without unshare permission.

Fleet-kill doctrine: every signalled pid comes from a fork this file
performed, every wait is deadline-bounded, and a timed-out child is
SIGKILLed and reaped before the test fails.
"""

import ctypes
import ctypes.util
import os
import signal
import sys
import time
import warnings

import pytest

pytestmark = pytest.mark.skipif(
    sys.platform != "linux",
    reason="waiter contract is Linux-only (fork/prctl/procfs)",
)

if sys.platform == "linux":
    from core.sandbox import supervised as sup

_PR_SET_CHILD_SUBREAPER = 36
_WAIT_S = 20.0


def _set_subreaper() -> None:
    """Test-only prctl: make the CALLING process a child subreaper so
    orphans reparent to it (stand-in for being a pid-ns init)."""
    libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6",
                       use_errno=True)
    if libc.prctl(_PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != 0:
        os._exit(96)


def _sh_target(script: str, extra_close: tuple = ()):
    def _target():
        for fd in extra_close:
            try:
                os.close(fd)
            except OSError:
                pass
        os.execvp("/bin/sh", ["/bin/sh", "-c", script])
        os._exit(127)
    return _target


def _launch_supervised_waiter(script: str, *, live_w_preclosed: bool = False):
    """Fork a subreaper host that runs ``_run_ns_init_waiter`` over a
    ``/bin/sh -c script`` target. Returns (waiter_pid, live_w_fd|None).

    The liveness pipe's write end stays open in the test process
    (playing the supervisor role) unless ``live_w_preclosed`` — the
    parent-already-gone boot arm.
    """
    live_r, live_w = os.pipe()
    if live_w_preclosed:
        os.close(live_w)
    with warnings.catch_warnings():
        warnings.filterwarnings(
            "ignore", category=DeprecationWarning,
            message=r".*fork.*may lead to deadlocks.*",
        )
        pid = os.fork()
    if pid == 0:
        try:
            if not live_w_preclosed:
                os.close(live_w)
            _set_subreaper()
            sup._run_ns_init_waiter(live_r, _sh_target(script))
        except BaseException:
            pass
        os._exit(97)  # the waiter must never fall through
    os.close(live_r)
    return pid, (None if live_w_preclosed else live_w)


def _wait_forwarders_installed(pid: int, timeout: float = _WAIT_S) -> None:
    """Readiness handshake: poll /proc/<pid>/status SigCgt until every
    forwarded signal has a handler installed — the observable edge of
    the waiter's forwarder installation. (A fixed sleep here once lost
    this race under load: the signal arrived pre-install and took the
    waiter itself.)"""
    want = 0
    for s in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP,
              signal.SIGQUIT):
        want |= 1 << (int(s) - 1)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with open(f"/proc/{pid}/status", "rb") as f:
                for line in f:
                    if line.startswith(b"SigCgt:"):
                        if int(line.split()[1], 16) & want == want:
                            return
                        break
        except OSError:
            break  # waiter gone — the caller's reap will surface it
        time.sleep(0.01)
    pytest.fail(f"waiter {pid} never installed its forwarders "
                f"(SigCgt handshake timed out)")


def _wait_target_execed(waiter: int, comm: bytes,
                        timeout: float = _WAIT_S) -> None:
    """Second handshake edge: the waiter forks the target BEFORE
    installing forwarders, so SigCgt alone does not prove the target
    has exec'd — poll /proc for a child of ``waiter`` whose comm is
    already ``comm`` so the forwarded signal lands on the real target,
    not a pre-exec fork child."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        for entry in os.listdir("/proc"):
            if not entry.isdigit():
                continue
            try:
                with open(f"/proc/{entry}/stat", "rb") as f:
                    raw = f.read()
                name = raw.split(b"(", 1)[1].rsplit(b")", 1)[0]
                ppid = int(raw.rsplit(b")", 1)[1].split()[1])
            except (OSError, IndexError, ValueError):
                continue
            if ppid == waiter and name == comm:
                return
        time.sleep(0.01)
    pytest.fail(f"waiter {waiter}'s target never exec'd into "
                f"{comm!r} (handshake timed out)")


# Registry: name -> launcher. Sibling waiter implementations append
# here and inherit the whole battery.
LAUNCHERS = {
    "supervised": _launch_supervised_waiter,
}


@pytest.fixture(params=sorted(LAUNCHERS))
def launch(request):
    return LAUNCHERS[request.param]


@pytest.fixture
def reap():
    """Deadline-bounded waitpid; SIGKILLs and reaps on timeout so no
    test can leave a live waiter behind."""
    spawned: list[int] = []

    def _reap(pid: int, timeout: float = _WAIT_S) -> int:
        spawned.append(pid)
        deadline = time.monotonic() + timeout
        while True:
            done, status = os.waitpid(pid, os.WNOHANG)
            if done == pid:
                spawned.remove(pid)
                assert os.WIFEXITED(status), (
                    f"waiter died by signal "
                    f"{os.WTERMSIG(status) if os.WIFSIGNALED(status) else '?'}"
                )
                return os.WEXITSTATUS(status)
            if time.monotonic() > deadline:
                os.kill(pid, signal.SIGKILL)
                os.waitpid(pid, 0)
                spawned.remove(pid)
                pytest.fail(f"waiter {pid} still running after "
                            f"{timeout}s — killed and reaped")
            time.sleep(0.02)

    yield _reap
    for pid in list(spawned):
        try:
            os.kill(pid, signal.SIGKILL)
            os.waitpid(pid, 0)
        except (ProcessLookupError, ChildProcessError):
            pass


class TestFateMirror:
    def test_exit_status_mirrored_verbatim(self, launch, reap):
        pid, live_w = launch("exit 9")
        try:
            assert reap(pid) == 9
        finally:
            os.close(live_w)

    def test_exit_zero_mirrored(self, launch, reap):
        pid, live_w = launch("exit 0")
        try:
            assert reap(pid) == 0
        finally:
            os.close(live_w)

    def test_signal_death_mirrored_as_128_plus_signum(self, launch,
                                                      reap):
        pid, live_w = launch("kill -9 $$")
        try:
            assert reap(pid) == 128 + signal.SIGKILL
        finally:
            os.close(live_w)


class TestOrphanReaping:
    def test_orphan_exit_does_not_hijack_the_mirror(self, launch, reap):
        # A double-forked orphan reparents to the (subreaper) waiter
        # and exits 3 FIRST; the waiter must reap-and-discard it and
        # still mirror the real target's 7.
        pid, live_w = launch(
            "( (sleep 0.2; exit 3) & ) ; sleep 1.0; exit 7")
        try:
            assert reap(pid) == 7
        finally:
            os.close(live_w)


class TestSignalForwarding:
    @pytest.mark.parametrize("sig", [signal.SIGTERM, signal.SIGINT,
                                     signal.SIGHUP, signal.SIGQUIT])
    def test_signal_forwarded_to_target(self, launch, reap, sig):
        # `exec` so the target IS sleep, not a shell: sh catches
        # SIGINT and defers acting on it until its foreground child
        # finishes (observed live: SigCgt bit 2 on /bin/sh), which
        # would test shell job semantics instead of the forwarding.
        pid, live_w = launch("exec sleep 30")
        try:
            _wait_forwarders_installed(pid)
            _wait_target_execed(pid, b"sleep")
            os.kill(pid, sig)
            # The waiter itself survives the signal (handler, not
            # death) and mirrors the TARGET's signal death.
            assert reap(pid) == 128 + int(sig)
        finally:
            os.close(live_w)


class TestFailClosedBoot:
    def test_prctl_failure_exits_distinctly_before_target(
            self, launch, reap, monkeypatch, tmp_path):
        # An unarmed pid-ns init would be an immortal namespace: the
        # waiter must _exit(118) WITHOUT ever forking the target.
        marker = tmp_path / "target-ran"
        monkeypatch.setattr(sup, "_arm_pdeathsig", lambda: False)
        pid, live_w = launch(f"touch {marker}")
        try:
            assert reap(pid) == sup.NS_INIT_EXIT_PRCTL_FAILED
        finally:
            os.close(live_w)
        time.sleep(0.2)
        assert not marker.exists(), (
            "target ran despite the fail-closed prctl arm")

    def test_supervisor_already_gone_exits_distinctly(
            self, launch, reap, tmp_path):
        # Liveness-pipe POLLHUP at boot (sole write end already
        # closed): the fork-to-prctl race window arm — getppid() can
        # not serve a pid-ns init, whose parent reads as 0.
        marker = tmp_path / "target-ran"
        pid, live_w = launch(f"touch {marker}", live_w_preclosed=True)
        assert live_w is None
        assert reap(pid) == sup.NS_INIT_EXIT_PARENT_GONE
        time.sleep(0.2)
        assert not marker.exists(), (
            "target ran despite the supervisor being gone at boot")

    def test_arm_pdeathsig_reports_prctl_result_honestly(
            self, monkeypatch):
        # The two fail-closed tests above stub _arm_pdeathsig, so the
        # predicate's own honesty needs a direct pin: a prctl that
        # returns nonzero (or a missing libc) MUST read as False — an
        # arm that lies True would boot an immortal namespace init.
        class _FakeLibc:
            def __init__(self, rc: int) -> None:
                self.rc = rc

            def prctl(self, *_args: object) -> int:
                return self.rc

        monkeypatch.setattr(sup, "_get_libc", lambda: _FakeLibc(-1))
        assert sup._arm_pdeathsig() is False
        monkeypatch.setattr(sup, "_get_libc", lambda: None)
        assert sup._arm_pdeathsig() is False
        monkeypatch.setattr(sup, "_get_libc", lambda: _FakeLibc(0))
        assert sup._arm_pdeathsig() is True

    def test_boot_exit_codes_are_distinct(self):
        codes = {sup.NS_INIT_EXIT_PRCTL_FAILED,
                 sup.NS_INIT_EXIT_PARENT_GONE,
                 sup.NS_INIT_EXIT_TARGET_FORK_FAILED}
        assert len(codes) == 3
        # And distinct from the mirror-space values the supervisor
        # reads for post-boot exits it synthesizes (137 collapse).
        assert 137 not in codes
