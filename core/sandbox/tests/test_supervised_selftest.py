"""Real pid-namespace boundary tests for core.sandbox.supervised.

Everything here needs the ACTUAL kernel behaviour — PID 1 semantics,
namespace-empty collapse, PDEATHSIG chains — so the module is gated on
the same probe the spawn path consults
(``check_pidns_supervision_available``): hosts where the tier cannot
engage skip cleanly (CI-hermeticity doctrine — probe, skip, never
error). Unit-level behaviour that does not need a namespace lives in
test_supervised.py.

Fleet-kill doctrine: every signalled pid/pidfd comes from a spawn this
file performed, no pid or pgid <= 1 is ever a sentinel, waits are
deadline-bounded, and teardown is verified (pidfd poll / kill-0 /
ProcessLookupError), never assumed.
"""

import ctypes
import ctypes.util
import os
import select
import signal
import struct
import subprocess
import sys
import time
import warnings

import pytest

pytestmark = pytest.mark.skipif(
    sys.platform != "linux",
    reason="pid-namespace supervision is Linux-only",
)

if sys.platform == "linux":
    from core.sandbox.probes import check_pidns_supervision_available
    from core.sandbox.supervised import spawn_supervised

_ENV = {"PATH": "/usr/bin:/bin"}
_WAIT_S = 20.0


@pytest.fixture(scope="module", autouse=True)
def _pidns_gate():
    """Skip the module unless the pidns tier genuinely engages here,
    and unless this process's procfs view matches its pid namespace
    (a skewed view — e.g. a container with a bind-mounted host /proc —
    would make every /proc-based assertion below lie)."""
    if sys.platform != "linux":
        return  # module-level skipif already handles it
    verdict, reason = check_pidns_supervision_available()
    if verdict is not True:
        pytest.skip(f"pidns supervision tier unavailable: {reason}")
    try:
        skew = int(os.readlink("/proc/self")) != os.getpid()
    except OSError:
        skew = True
    if skew:
        pytest.skip("procfs pid view is skewed against this process's "
                    "pid namespace — /proc-based assertions unreliable")


def _read_exact(fd: int, n: int, timeout: float = _WAIT_S) -> bytes:
    """Bounded exact-length pipe read. EXACT length, not read-to-EOF:
    the supervised tree inherits the caller's write end of the handoff
    pipe, so EOF only arrives when the whole tree dies — waiting for
    it would deadlock the very tests that keep the tree alive."""
    buf = b""
    poller = select.poll()
    poller.register(fd, select.POLLIN)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not poller.poll(200):
            continue
        chunk = os.read(fd, n - len(buf))
        if chunk == b"":
            raise AssertionError(
                f"handoff pipe closed after {len(buf)}/{n} bytes")
        buf += chunk
        if len(buf) == n:
            return buf
    raise TimeoutError("pipe read timed out")


def _assert_dead(pid: int, timeout: float = _WAIT_S) -> None:
    """kill-0 confirmation loop — never trusts a teardown claim.
    State Z counts as dead: under a non-reaping init (pytest as PID 1
    of a battery namespace) an adopted orphan stays a kill-visible
    zombie forever, but it is provably dead."""
    assert pid > 1, f"refusing to probe pid {pid}"
    deadline = time.monotonic() + timeout
    while True:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return
        try:
            with open(f"/proc/{pid}/stat", "rb") as f:
                if f.read().rsplit(b")", 1)[1].split()[0] == b"Z":
                    return
        except (OSError, IndexError):
            return  # vanished between the probe and the read
        assert time.monotonic() < deadline, f"pid {pid} still alive"
        time.sleep(0.05)


def _pidfd_dead(pidfd: int, timeout: float = _WAIT_S) -> bool:
    poller = select.poll()
    poller.register(pidfd, select.POLLIN)
    return bool(poller.poll(timeout * 1000))


def _stat_fields(pid: int) -> list[str]:
    """/proc/<pid>/stat fields AFTER the comm — comm can carry spaces
    and parens, so split on the LAST ')'. Returned list starts at
    field 3 (state); ppid=index 1, pgrp=index 2, session=index 3."""
    with open(f"/proc/{pid}/stat") as f:
        raw = f.read()
    return raw.rsplit(")", 1)[1].split()


class TestNamespaceShape:
    def test_target_is_pid_2_in_its_namespace(self, tmp_path):
        out = tmp_path / "pid.txt"
        with open(out, "wb") as f:
            h = spawn_supervised(["/bin/sh", "-c", "echo $$"],
                                 on_parent_death="kill", env=_ENV,
                                 stdout=f)
            assert h.wait(timeout=_WAIT_S) == 0
        assert out.read_bytes().strip() == b"2", (
            "target is not PID 2 — the ns-init waiter is not PID 1 of "
            "a fresh pid namespace")

    def test_tier_and_diagnostics(self):
        h = spawn_supervised(["/bin/sleep", "30"],
                             on_parent_death="kill", env=_ENV)
        try:
            assert h.tier == "pidns"
            assert h.confinement == "none"
            assert h.ns_init_pid is not None and h.ns_init_pid > 1
            assert h.ns_init_pidfd is not None
            tp = int(h.target_pid)
            assert tp > 1
            os.kill(tp, 0)  # the reported outside pid is live
        finally:
            assert h.terminate(grace_s=2.0) == 143
        _assert_dead(int(h.target_pid))

    def test_net_ns_loopback_is_up_and_private(self, tmp_path):
        # NOTE /proc/self/net, never /sys/class/net: sysfs reflects
        # the netns of the MOUNT (the host's — there is deliberately
        # no mount namespace here), while /proc/<pid>/net reflects the
        # netns of the process. Loopback is proven functionally: a
        # 127.0.0.1 TCP round-trip inside the namespace.
        script = tmp_path / "netcheck.py"
        script.write_text(
            "import socket, sys\n"
            "ifaces = [l.split(':')[0].strip()\n"
            "          for l in open('/proc/self/net/dev')\n"
            "          if ':' in l]\n"
            "if ifaces != ['lo']:\n"
            "    print('leaked:', ifaces); sys.exit(2)\n"
            "srv = socket.socket()\n"
            "srv.bind(('127.0.0.1', 0)); srv.listen(1)\n"
            "cli = socket.socket(); cli.connect(srv.getsockname())\n"
            "conn, _ = srv.accept()\n"
            "cli.sendall(b'ping'); assert conn.recv(4) == b'ping'\n"
            "sys.exit(0)\n"
        )
        out = tmp_path / "net.txt"
        with open(out, "wb") as f:
            h = spawn_supervised(
                [sys.executable, str(script)],
                on_parent_death="kill", env=_ENV, net_ns=True,
                stdout=f, stderr=f)
            rc = h.wait(timeout=_WAIT_S)
        assert rc == 0, (
            f"netns check failed (rc {rc}): {out.read_bytes()!r}")


class TestNamespaceCollapse:
    def test_ns_init_death_collapses_the_whole_tree(self, tmp_path):
        # SIGKILL the waiter directly (via the handle's pidfd — the
        # only signalling route): PID 1 death must take every
        # namespace member with it, including backgrounded children.
        out = tmp_path / "grandchild.txt"
        with open(out, "wb") as f:
            h = spawn_supervised(
                ["/bin/sh", "-c", "sleep 300 & echo $!; sleep 300"],
                on_parent_death="kill", env=_ENV, stdout=f)
            time.sleep(0.3)
            tp = int(h.target_pid)
            target_pidfd = os.pidfd_open(tp)
            try:
                signal.pidfd_send_signal(h.ns_init_pidfd, signal.SIGKILL)
                assert h.wait(timeout=_WAIT_S) == 137
                assert _pidfd_dead(target_pidfd), (
                    "target survived its namespace init's death")
            finally:
                os.close(target_pidfd)
        _assert_dead(tp)

    def test_terminate_reaps_backgrounded_descendants(self, tmp_path):
        # The namespace-empty proof: terminate() returning at all
        # means A reaped B, whose exit the kernel gates on every
        # member being gone. Corroborate against the target's host pid.
        h = spawn_supervised(
            ["/bin/sh", "-c",
             "sleep 300 & (sleep 300 & sleep 300) & sleep 300"],
            on_parent_death="kill", env=_ENV,
            stdout=subprocess.DEVNULL)
        time.sleep(0.3)
        tp = int(h.target_pid)
        rc = h.terminate(grace_s=2.0)
        assert rc in (143, 137)
        _assert_dead(tp)
        assert h.returncode == rc


class TestCallerDeathContract:
    def test_kill_mode_caller_death_collapses_tree(self):
        # Fork a disposable "caller" that spawns a kill-mode tree,
        # hands the pids over a pipe, waits for our ACK, then dies
        # WITHOUT any teardown call. The death pipe must collapse the
        # tree. Subreaper so A reparents to us and its exit status is
        # observable (the 137 collapse-path pin).
        libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6",
                           use_errno=True)
        assert libc.prctl(36, 1, 0, 0, 0) == 0  # PR_SET_CHILD_SUBREAPER
        try:
            info_r, info_w = os.pipe()
            ack_r, ack_w = os.pipe()
            with warnings.catch_warnings():
                warnings.filterwarnings(
                    "ignore", category=DeprecationWarning,
                    message=r".*fork.*may lead to deadlocks.*",
                )
                caller = os.fork()
            if caller == 0:
                try:
                    os.close(info_r)
                    os.close(ack_w)
                    h = spawn_supervised(["/bin/sleep", "300"],
                                         on_parent_death="kill",
                                         env=_ENV)
                    os.write(info_w, struct.pack(
                        "qq", h.pid, int(h.target_pid)))
                    os.close(info_w)
                    os.read(ack_r, 1)  # wait for the test's ACK
                except BaseException:
                    os._exit(98)
                os._exit(0)  # caller dies; NO teardown call
            os.close(info_w)
            os.close(ack_r)
            a_pid, target_pid = struct.unpack(
                "qq", _read_exact(info_r, 16))
            os.close(info_r)
            assert a_pid > 1 and target_pid > 1
            a_pidfd = os.pidfd_open(a_pid)
            try:
                os.write(ack_w, b"x")
                os.close(ack_w)
                os.waitpid(caller, 0)
                # A reparented to us (subreaper): reap it and pin the
                # collapse-path exit code.
                assert _pidfd_dead(a_pidfd), (
                    "supervisor survived its caller's death in kill "
                    "mode")
                _, status = os.waitpid(a_pid, 0)
                assert os.WIFEXITED(status)
                assert os.WEXITSTATUS(status) == 137
            finally:
                os.close(a_pidfd)
            _assert_dead(target_pid)
        finally:
            assert libc.prctl(36, 0, 0, 0, 0) == 0

    def test_survive_mode_tree_outlives_caller(self):
        # Same disposable-caller shape, survive mode: the tree must
        # still be running after the caller is gone.
        info_r, info_w = os.pipe()
        ack_r, ack_w = os.pipe()
        with warnings.catch_warnings():
            warnings.filterwarnings(
                "ignore", category=DeprecationWarning,
                message=r".*fork.*may lead to deadlocks.*",
            )
            caller = os.fork()
        if caller == 0:
            try:
                os.close(info_r)
                os.close(ack_w)
                h = spawn_supervised(["/bin/sleep", "300"],
                                     on_parent_death="survive",
                                     env=_ENV)
                os.write(info_w, struct.pack(
                    "qq", h.pid, int(h.target_pid)))
                os.close(info_w)
                os.read(ack_r, 1)
            except BaseException:
                os._exit(98)
            os._exit(0)
        os.close(info_w)
        os.close(ack_r)
        a_pid, target_pid = struct.unpack("qq", _read_exact(info_r, 16))
        os.close(info_r)
        assert a_pid > 1 and target_pid > 1
        a_pidfd = None
        try:
            a_pidfd = os.pidfd_open(a_pid)
            os.write(ack_w, b"x")
            os.close(ack_w)
            os.waitpid(caller, 0)
            time.sleep(1.0)
            os.kill(a_pid, 0)       # supervisor still alive
            os.kill(target_pid, 0)  # target still alive
        finally:
            # Verified cleanup of the deliberately-surviving tree:
            # TERM the supervisor (it forwards down the chain), then
            # confirm both ends died.
            if a_pidfd is not None:
                signal.pidfd_send_signal(a_pidfd, signal.SIGTERM)
                assert _pidfd_dead(a_pidfd)
                os.close(a_pidfd)
        _assert_dead(target_pid)
        _assert_dead(a_pid)


class TestSessionPosture:
    def test_survive_mode_supervisor_leads_its_own_session(self):
        h = spawn_supervised(["/bin/sleep", "30"],
                             on_parent_death="survive", env=_ENV)
        try:
            fields = _stat_fields(h.pid)
            session = int(fields[3])
            assert session == h.pid, (
                "survive-mode supervisor did not setsid — session-"
                "scoped teardown of the caller could reap a tree the "
                "caller asked to outlive it")
        finally:
            assert h.terminate(grace_s=2.0) == 143

    def test_kill_mode_supervisor_stays_in_callers_group(self):
        own_pgrp = os.getpgrp()
        if own_pgrp <= 1:
            pytest.skip("test process's own pgrp <= 1 — the in-group "
                        "pin cannot be asserted safely here")
        h = spawn_supervised(["/bin/sleep", "30"],
                             on_parent_death="kill", env=_ENV)
        try:
            fields = _stat_fields(h.pid)
            pgrp = int(fields[2])
            assert pgrp == own_pgrp, (
                "kill-mode supervisor left the caller's process group "
                "— group-directed teardown aimed at the caller would "
                "miss the tree")
        finally:
            assert h.terminate(grace_s=2.0) == 143
