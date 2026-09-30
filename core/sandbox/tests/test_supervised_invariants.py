"""Adversarial invariant battery for core.sandbox.supervised —
hermetic on any Linux host.

Each test pins one load-bearing contract of the supervised-tree
machinery from the outside: the ready-protocol acceptance predicate,
the PDEATHSIG identities, the group-tier refusal/corroboration ladder,
the boot-report channel, fd custody, and the loud-failure paths. The
tests follow test_supervised.py's conventions: the pidns-tier topology
runs REAL processes with ``_ns_setup`` no-opped, so no unshare
permission is needed.

Fleet-kill doctrine: no test signals a pid or pgid <= 1, every pid
signalled here came from a spawn this test performed, and every
teardown is verified (kill-0 / ProcessLookupError / state Z) rather
than assumed.
"""

import builtins
import contextlib
import io
import os
import signal
import socket
import sys
import time

import pytest

pytestmark = pytest.mark.skipif(
    sys.platform != "linux",
    reason="supervised trees are Linux-only (fork/pidfd/procfs)",
)

if sys.platform == "linux":
    from core.sandbox import state
    from core.sandbox import supervised as sup
    from core.sandbox.errors import SandboxSetupError
    from core.sandbox.supervised import (
        SupervisedTeardownError,
        spawn_supervised,
    )

_ENV = {"PATH": "/usr/bin:/bin"}
_WAIT_S = 15.0


def _spawn_fake(monkeypatch):
    """Real A/B/C topology minus the actual unshare (mirrors
    test_supervised.py)."""
    monkeypatch.setattr(sup, "_ns_setup", lambda net_ns: None)
    monkeypatch.setattr(state, "_pidns_supervision_cache", (True, ""))


def _proc_state(pid: int) -> bytes | None:
    try:
        with open(f"/proc/{pid}/stat", "rb") as f:
            return f.read().rsplit(b")", 1)[1].split()[0]
    except (OSError, IndexError):
        return None


def _assert_dies(pid: int, why: str, timeout: float = _WAIT_S) -> None:
    """Bounded proof of death: gone, or a held zombie (state Z) under a
    non-reaping init. Never signals; pure observation."""
    assert pid > 1
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        st = _proc_state(pid)
        if st is None or st == b"Z":
            return
        time.sleep(0.05)
    pytest.fail(f"{why}: pid {pid} still alive (state {_proc_state(pid)})")


def _reap_stray(pid: int) -> None:
    """Verified cleanup of a process this test created (fake-backend
    trees have no namespace, so C can outlive B)."""
    assert pid > 1, f"refusing to signal pid {pid}"
    deadline = time.monotonic() + _WAIT_S
    while True:
        try:
            os.kill(pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            return  # gone, or pid already recycled to a foreign process
        st = _proc_state(pid)
        if st is None or st == b"Z":
            return
        if time.monotonic() > deadline:
            pytest.fail(f"stray pid {pid} would not die")
        time.sleep(0.05)


def _live_pgrp_members(pgid: int) -> list[int]:
    """Test-local /proc scan (independent of the product helper):
    non-zombie members of ``pgid``."""
    live = []
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        try:
            with open(f"/proc/{entry}/stat", "rb") as f:
                rest = f.read().rsplit(b")", 1)[1].split()
        except (OSError, IndexError):
            continue
        if int(rest[2]) == pgid and rest[0] != b"Z":
            live.append(int(entry))
    return live


class TestReadyProtocolStrict:
    """The _recv_ready acceptance predicate is strict: only a
    well-formed ready message WITH its pidfd mints a handle."""

    def _sleeper(self):
        pid = os.fork()
        if pid == 0:  # stand-in for A; only ever signalled by product code
            with contextlib.suppress(BaseException):
                time.sleep(300)
            os._exit(0)
        return pid

    def test_recv_ready_rejects_missing_pidfd(self):
        # A well-formed line WITHOUT the SCM_RIGHTS pidfd must be
        # refused as malformed — the pidfd is the only pid-reuse-safe
        # signalling route, so a handle without one is a forgery.
        p_sock, a_sock = socket.socketpair(socket.AF_UNIX,
                                           socket.SOCK_SEQPACKET)
        fake_a = self._sleeper()
        try:
            a_sock.sendmsg([b"ok pidns 5 7"])  # no ancillary fds
            with pytest.raises(SandboxSetupError):
                sup._recv_ready(p_sock, fake_a, None)
        finally:
            _reap_stray(fake_a)
            with contextlib.suppress(OSError):
                os.waitpid(fake_a, os.WNOHANG)
            p_sock.close()
            a_sock.close()

    def test_recv_ready_rejects_garbled_verb(self):
        # Right shape, right fd count, wrong verb: still malformed.
        p_sock, a_sock = socket.socketpair(socket.AF_UNIX,
                                           socket.SOCK_SEQPACKET)
        fake_a = self._sleeper()
        null_fd = os.open("/dev/null", os.O_RDONLY)
        try:
            socket.send_fds(a_sock, [b"zz pidns 5 7"], [null_fd])
            with pytest.raises(SandboxSetupError):
                sup._recv_ready(p_sock, fake_a, None)
        finally:
            os.close(null_fd)
            _reap_stray(fake_a)
            with contextlib.suppress(OSError):
                os.waitpid(fake_a, os.WNOHANG)
            p_sock.close()
            a_sock.close()

    def test_recv_ready_rejects_wrong_tier_word(self):
        # This reader mints a pidns-tier handle; a ready line claiming
        # any other tier must not stamp it.
        p_sock, a_sock = socket.socketpair(socket.AF_UNIX,
                                           socket.SOCK_SEQPACKET)
        fake_a = self._sleeper()
        null_fd = os.open("/dev/null", os.O_RDONLY)
        try:
            socket.send_fds(a_sock, [b"ok group 5 7"], [null_fd])
            with pytest.raises(SandboxSetupError):
                sup._recv_ready(p_sock, fake_a, None)
        finally:
            os.close(null_fd)
            _reap_stray(fake_a)
            with contextlib.suppress(OSError):
                os.waitpid(fake_a, os.WNOHANG)
            p_sock.close()
            a_sock.close()


class TestPdeathsigIdentity:
    """The waiter's parent-death signal is SIGKILL, not something
    catchable."""

    def test_waiter_pdeathsig_is_sigkill_not_catchable(self, monkeypatch):
        # If the waiter's parent-death signal were catchable (SIGTERM),
        # B would just FORWARD it to a TERM-immune target and keep
        # waiting — the tree would outlive its supervisor. Only SIGKILL
        # makes supervisor death collapse B unconditionally.
        _spawn_fake(monkeypatch)
        h = spawn_supervised(["/bin/sh", "-c", 'trap "" TERM; sleep 300'],
                             on_parent_death="kill", env=_ENV)
        b_pid, c_pid = h.ns_init_pid, h.target_pid
        try:
            assert b_pid is not None and b_pid > 1
            os.kill(h.pid, signal.SIGKILL)  # A: this test's direct child
            with contextlib.suppress(OSError):
                os.waitpid(h.pid, 0)
            _assert_dies(b_pid, "ns-init waiter survived supervisor death")
        finally:
            if c_pid and c_pid > 1:
                _reap_stray(c_pid)  # no namespace in fake mode: C strays
            if b_pid and b_pid > 1:
                _reap_stray(b_pid)


class TestGroupTeardownProofs:
    """The group-tier refusal/corroboration ladder: refusals gate the
    killpg call sites, and success claims require a death proof."""

    def test_group_teardown_honors_refusal_at_killpg_call_site(
            self, monkeypatch):
        # The predicate result must gate the killpg ladder: when the
        # captured pgid IS the caller's own group, terminate() refuses
        # loudly and no killpg is ever issued.
        h = spawn_supervised(["/bin/sleep", "300"], on_parent_death="kill",
                             pid_ns="off", env=_ENV)
        try:
            pgid = os.getpgid(h.pid)
            calls = []

            def recording_killpg(p, s):
                calls.append((p, s))
                raise ProcessLookupError  # suppressed by product code

            monkeypatch.setattr(os, "getpgrp", lambda: pgid)
            monkeypatch.setattr(os, "killpg", recording_killpg)
            with pytest.raises(SupervisedTeardownError) as exc:
                h.terminate(grace_s=0.2)
            assert "own process group" in str(exc.value)
            assert calls == [], (
                f"killpg issued despite refusal predicate: {calls}")
        finally:
            monkeypatch.undo()
            h.terminate(grace_s=0.5)

    def test_group_terminate_never_reports_success_with_live_member(self):
        # Leader dies on the graceful SIGTERM rung; a TERM-immune
        # non-leader member lingers past it. The corroboration may only
        # RETURN once every member is provably dead (zombies count as
        # dead; live members must be escalated with its in-loop
        # SIGKILL, never waved through). The member is forked while
        # TERM is ignored (inherits the disposition); the leader resets
        # TERM to default before exec, so the graceful rung takes it.
        h = spawn_supervised(
            ["/bin/sh", "-c",
             'trap "" TERM; sleep 300 & trap - TERM; exec sleep 300'],
            on_parent_death="kill", pid_ns="off", env=_ENV)
        pgid = os.getpgid(h.pid)
        try:
            time.sleep(0.4)  # let the background member start
            rc = h.terminate(grace_s=5.0)
            assert rc is not None
            live = _live_pgrp_members(pgid)
            assert live == [], (
                f"terminate() returned success while group {pgid} still "
                f"has live members {live} — teardown proof forged")
        finally:
            for pid in _live_pgrp_members(pgid):
                _reap_stray(pid)

    def test_group_sighted_members_none_on_unlistable_proc(
            self, monkeypatch):
        # No /proc, no death proof: the scan must report "no view"
        # (None) — a shape the corroboration can only refuse on — never
        # an all-dead claim (and never anything pid-shaped).
        def broken_listdir(path):
            raise OSError(5, "proc unavailable")

        monkeypatch.setattr(os, "listdir", broken_listdir)
        assert sup._group_sighted_members(999999) is None

    def test_group_sighted_members_vanished_entry_not_sighted(
            self, monkeypatch):
        # An entry that vanishes between listdir and the stat read is
        # GONE — sighting it as a live member would turn the
        # corroboration into a false refusal loop (and SIGKILL spam at
        # the group). The fabricated listing also omits this process's
        # own pid, which the scan must independently flag as occlusion:
        # a listing that cannot show US can never prove absence.
        monkeypatch.setattr(os, "listdir", lambda path: ["999999999"])
        view = sup._group_sighted_members(999999)
        assert view.members == ()
        assert view.occlusion is not None

    def test_group_sighted_members_eacces_entry_is_occlusion(
            self, monkeypatch):
        # Present-but-unreadable (EACCES — the hidepid=1 shape) is NOT
        # "vanished mid-scan": the entry cannot be attributed to any
        # group, so the whole view is untrustworthy for absence claims.
        # Simulated by denying the read of this process's own stat.
        blocked = f"/proc/{os.getpid()}/stat"
        real_open = builtins.open

        def denying_open(file, *args, **kwargs):
            if str(file) == blocked:
                raise PermissionError(13, "Permission denied", blocked)
            return real_open(file, *args, **kwargs)

        monkeypatch.setattr(builtins, "open", denying_open)
        view = sup._group_sighted_members(os.getpgrp())
        monkeypatch.undo()
        assert view is not None
        assert view.occlusion is not None
        assert os.getpid() not in [m.pid for m in view.members]

    def test_group_sighted_members_reread_declarations_after_scan(
            self, monkeypatch):
        # The mounts table is read BEFORE the listing: a filter (or
        # per-pid overmount) landing in that window is applied to the
        # scan yet undeclared by the pre-read. The scan must re-read
        # the declarations once it is complete, so a mount present at
        # EITHER end of the scan window occludes the view. Simulated
        # at the detector seam: clean on the first read, declared on
        # the second; the listing is pinned to this process only so no
        # per-entry condition can set occlusion first.
        calls = {"n": 0}

        def racing_detector(*_table):
            calls["n"] += 1
            return (None if calls["n"] == 1
                    else "hidepid=2 (mounted mid-scan)")

        own = str(os.getpid())
        real_listdir = os.listdir
        monkeypatch.setattr(sup, "_proc_pid_view_filtered",
                            racing_detector)
        monkeypatch.setattr(
            os, "listdir",
            lambda path: ([own] if str(path) == "/proc"
                          else real_listdir(path)))
        view = sup._group_sighted_members(os.getpgrp())
        monkeypatch.undo()
        assert view is not None
        assert calls["n"] >= 2, (
            "mount declarations never re-read after the listing — a "
            "filter mounted mid-scan goes undeclared")
        assert view.occlusion == "hidepid=2 (mounted mid-scan)"

    def test_group_sighted_members_foreign_pid_view_is_occlusion(
            self, monkeypatch):
        # The own-pid-in-listing tell passes COINCIDENTALLY when a
        # small-numbered namespace pid scans a foreign /proc (pid 1/2
        # are always listed). The strictly stronger tell: the pid
        # /proc/self/stat reports must equal os.getpid() — a mismatch
        # means the mounted /proc belongs to a different pid namespace
        # and its listing proves nothing about absence.
        own = str(os.getpid())
        real_listdir = os.listdir
        monkeypatch.setattr(sup, "_proc_self_stat_pid",
                            lambda: os.getpid() + 1, raising=False)
        monkeypatch.setattr(
            os, "listdir",
            lambda path: ([own] if str(path) == "/proc"
                          else real_listdir(path)))
        view = sup._group_sighted_members(os.getpgrp())
        monkeypatch.undo()
        assert view is not None
        assert view.occlusion is not None and "foreign" in view.occlusion

    def test_group_sighted_members_unreadable_self_stat_is_occlusion(
            self, monkeypatch):
        # /proc/self/stat unreadable: the view cannot be confirmed as
        # this pid namespace's — occlusion, the refuse direction.
        own = str(os.getpid())
        real_listdir = os.listdir
        monkeypatch.setattr(sup, "_proc_self_stat_pid",
                            lambda: None, raising=False)
        monkeypatch.setattr(
            os, "listdir",
            lambda path: ([own] if str(path) == "/proc"
                          else real_listdir(path)))
        view = sup._group_sighted_members(os.getpgrp())
        monkeypatch.undo()
        assert view is not None
        assert view.occlusion is not None

    def test_proc_self_stat_pid_reads_own_pid(self):
        # Shape pin against the kernel's own answer: on this (own)
        # /proc view the cross-check helper must agree with getpid.
        assert sup._proc_self_stat_pid() == os.getpid()

    def test_group_sighted_members_carry_kernel_identity(self):
        # Sighted members carry (pid, start_time) — the identity pair
        # the natural-exit anchor matches on. Pin it against the
        # kernel's own answer for this process.
        with open(f"/proc/{os.getpid()}/stat", "rb") as f:
            expected = int(f.read().rsplit(b")", 1)[1].split()[19])
        view = sup._group_sighted_members(os.getpgrp())
        assert view is not None
        me = [m for m in view.members if m.pid == os.getpid()]
        assert me, "own process not sighted in its own pgrp"
        assert me[0].start_time == expected
        assert me[0].start_time > 0


class TestPidnsCollapseProof:
    """The pidns tier's verified-teardown claim is kernel-witnessed:
    A's own exit paths prove the namespace emptied (A reaps B, whose
    exit the kernel gates on zap_pid_ns_processes draining every
    member), but an EXTERNAL kill of A records A's death without that
    gate. The handle must then demand the kernel's direct witness —
    B's (PID 1's) pidfd turning readable — before reporting a verified
    teardown. B's pidfd is simulated by a pipe read end: never
    readable = a namespace that has not collapsed; readable = the
    kernel's namespace-empty proof."""

    def _external_kill_handle(self, witness_fd):
        child = os.posix_spawn("/bin/sleep", ["/bin/sleep", "30"], {})
        h = sup.SupervisedHandle(
            tier="pidns", pid=child, target_pid=-1,
            on_parent_death="kill", name="collapse-pin",
            ns_init_pid=None, ns_init_pidfd=witness_fd)
        os.kill(child, signal.SIGKILL)  # the external kill of A
        deadline = time.monotonic() + _WAIT_S
        while h.poll() is None:
            assert time.monotonic() < deadline, "child never reaped"
            time.sleep(0.02)
        assert h.returncode == -signal.SIGKILL
        return h

    def test_external_kill_of_supervisor_demands_collapse_proof(
            self, monkeypatch):
        # Witness never readable (write end held open, nothing
        # written): the namespace is NOT proven empty, so terminate()
        # after the externally-killed supervisor was reaped must refuse
        # loudly — never return the recorded -9 as a verified teardown
        # over a possibly-draining (e.g. D-state) member.
        r, w = os.pipe()
        try:
            h = self._external_kill_handle(r)
            monkeypatch.setattr(sup, "_KILL_REAP_BUDGET_S", 0.5)
            with pytest.raises(SupervisedTeardownError):
                h.terminate(grace_s=0.1)
        finally:
            os.close(w)
            with contextlib.suppress(OSError):
                os.close(r)

    def test_external_kill_with_collapse_proof_verifies(self):
        # Witness readable: the kernel's namespace-empty proof is in,
        # so the same externally-killed shape verifies and terminate()
        # returns the recorded status (idempotently thereafter).
        r, w = os.pipe()
        try:
            os.write(w, b"x")  # the witness: B exited, namespace empty
            h = self._external_kill_handle(r)
            assert h.terminate(grace_s=0.1) == -signal.SIGKILL
            assert h.terminate(grace_s=0.1) == -signal.SIGKILL
        finally:
            os.close(w)
            with contextlib.suppress(OSError):
                os.close(r)


class TestProcViewFilterDetection:
    """The mount-declared procfs filter detector: hidepid=/subset=
    options on the /proc mount make the pid view untrustworthy as
    death evidence; a clean mount reads as unfiltered."""

    @staticmethod
    def _with_mounts(monkeypatch, table: bytes):
        real_open = builtins.open

        def fake_open(file, *args, **kwargs):
            if str(file) == "/proc/self/mounts":
                return io.BytesIO(table)
            return real_open(file, *args, **kwargs)

        monkeypatch.setattr(builtins, "open", fake_open)

    def test_hidepid_mount_detected(self, monkeypatch):
        self._with_mounts(
            monkeypatch,
            b"proc /proc proc rw,nosuid,nodev,noexec,relatime,"
            b"hidepid=2 0 0\n")
        verdict = sup._proc_pid_view_filtered()
        assert verdict is not None and "hidepid=2" in verdict

    def test_hidepid_named_value_detected(self, monkeypatch):
        self._with_mounts(
            monkeypatch,
            b"proc /proc proc rw,relatime,hidepid=invisible 0 0\n")
        assert sup._proc_pid_view_filtered() is not None

    def test_subset_mount_detected(self, monkeypatch):
        self._with_mounts(
            monkeypatch,
            b"proc /proc proc rw,relatime,subset=pid 0 0\n")
        verdict = sup._proc_pid_view_filtered()
        assert verdict is not None and "subset=pid" in verdict

    def test_clean_mount_is_unfiltered(self, monkeypatch):
        self._with_mounts(
            monkeypatch,
            b"sysfs /sys sysfs rw 0 0\n"
            b"proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0\n")
        assert sup._proc_pid_view_filtered() is None

    def test_hidepid_off_is_unfiltered(self, monkeypatch):
        self._with_mounts(
            monkeypatch,
            b"proc /proc proc rw,relatime,hidepid=off 0 0\n")
        assert sup._proc_pid_view_filtered() is None

    def test_last_proc_mount_wins(self, monkeypatch):
        # A later /proc mount shadows an earlier one: the verdict must
        # come from the mount that actually backs the path.
        self._with_mounts(
            monkeypatch,
            b"proc /proc proc rw,relatime,hidepid=2 0 0\n"
            b"proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0\n")
        assert sup._proc_pid_view_filtered() is None

    def test_pid_overmount_detected(self, monkeypatch):
        # A mount DECLARED over /proc/<pid> shadows that pid's entries:
        # its stat reads ENOENT while the process lives, so the scan
        # would classify a live member "vanished mid-scan — gone". The
        # declaration is right there in the table the detector parses —
        # it must read as occlusion, exactly like hidepid=/subset=.
        self._with_mounts(
            monkeypatch,
            b"proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0\n"
            b"/dev/root /proc/7 ext4 rw,relatime 0 0\n")
        verdict = sup._proc_pid_view_filtered()
        assert verdict is not None and "/proc/7" in verdict

    def test_pid_overmount_subpath_detected(self, monkeypatch):
        # A mount BELOW a pid dir (/proc/<pid>/task, .../stat, ...)
        # shadows part of that pid's view — same occlusion verdict.
        self._with_mounts(
            monkeypatch,
            b"proc /proc proc rw,relatime 0 0\n"
            b"tmpfs /proc/12345/task tmpfs rw 0 0\n")
        verdict = sup._proc_pid_view_filtered()
        assert verdict is not None and "/proc/12345" in verdict

    def test_nonpid_proc_masks_are_unfiltered(self, monkeypatch):
        # Standard container runtimes mask NON-pid /proc paths
        # (/proc/sys, /proc/acpi, /proc/kcore, ...). Those shadow no
        # pid entries and must not read as occlusion — the pid-dir
        # match is exact, not a /proc-prefix match.
        self._with_mounts(
            monkeypatch,
            b"proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0\n"
            b"tmpfs /proc/sys tmpfs ro 0 0\n"
            b"tmpfs /proc/acpi tmpfs ro 0 0\n"
            b"/dev/null /proc/kcore devtmpfs rw 0 0\n"
            b"tmpfs /proc/scsi tmpfs ro 0 0\n"
            b"tmpfs /proc/asound tmpfs ro 0 0\n")
        assert sup._proc_pid_view_filtered() is None

    def test_pid_overmount_survives_later_proc_mount(self, monkeypatch):
        # The last-/proc-line-wins rule exists for the standard shape
        # of a stale filtered /proc line under a fresh --mount-proc.
        # A /proc/<pid> overmount line has no standard-runtime source,
        # so it is NOT reset by a later /proc mount: the conservative
        # reading errs toward refusal, never verification.
        self._with_mounts(
            monkeypatch,
            b"/dev/root /proc/7 ext4 rw,relatime 0 0\n"
            b"proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0\n")
        assert sup._proc_pid_view_filtered() is not None

    def test_unreadable_mounts_is_occlusion(self, monkeypatch):
        real_open = builtins.open

        def denying_open(file, *args, **kwargs):
            if str(file) == "/proc/self/mounts":
                raise OSError(5, "mounts unavailable")
            return real_open(file, *args, **kwargs)

        monkeypatch.setattr(builtins, "open", denying_open)
        assert sup._proc_pid_view_filtered() is not None

    def test_real_mount_table_parses(self):
        # Whatever this environment's real mount table says, the
        # detector must parse it without raising and answer in-shape.
        verdict = sup._proc_pid_view_filtered()
        assert verdict is None or isinstance(verdict, str)


class TestBootReportChannel:
    """The boot-report read primitive: oversized data is data, and the
    read is deadline-bounded."""

    def test_oversized_report_line_is_not_clean_eof(self):
        # >512 bytes with no newline must surface AS DATA: on the
        # exec-status pipe b"" means "exec succeeded", so returning b""
        # would misread a long exec-failure diagnostic as success.
        r, w = os.pipe()
        try:
            payload = b"x" * 600
            os.write(w, payload)
            got = sup._read_line_deadline(r, 5.0)
            assert got, "oversized report read back as clean EOF"
            # The reader returns what has arrived once the oversize arm
            # trips (chunked reads: the first boundary past 512), so
            # assert a truncated-but-real prefix, never b"".
            assert len(got) > 512 and payload.startswith(got)
        finally:
            os.close(r)
            os.close(w)

    def test_read_line_deadline_bounded_on_silent_fd(self):
        # A silent fd must produce None at the deadline — never an
        # unbounded block (a wedged boot would hang A, and with it the
        # caller's 15s spawn budget, forever). Proven in a fork child
        # so a regression cannot hang the suite.
        r, w = os.pipe()
        child = os.fork()
        if child == 0:
            try:
                os.close(w)
                got = sup._read_line_deadline(r, 0.5)
                os._exit(0 if got is None else 1)
            except BaseException:
                os._exit(2)
        os.close(r)
        try:
            deadline = time.monotonic() + 10.0
            while time.monotonic() < deadline:
                done, status = os.waitpid(child, os.WNOHANG)
                if done == child:
                    assert os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0
                    return
                time.sleep(0.05)
            os.kill(child, signal.SIGKILL)  # own child, verified above
            os.waitpid(child, 0)
            pytest.fail("_read_line_deadline did not honor its deadline")
        finally:
            os.close(w)


class TestFdCustody:
    """B holds no status-socket fd after the fork split."""

    @staticmethod
    def _own_socket_links() -> set[str]:
        links: set[str] = set()
        for entry in os.listdir("/proc/self/fd"):
            with contextlib.suppress(OSError):
                ln = os.readlink(f"/proc/self/fd/{entry}")
                if ln.startswith("socket:"):
                    links.add(ln)
        return links

    def test_ns_init_holds_no_status_socket(self, monkeypatch):
        # B must drop A's status socket at fork: a leaked copy keeps
        # the socket open after A dies, so the caller's EOF-based
        # "supervisor died before reporting" detection goes blind for
        # as long as any tree member survives.
        #
        # The assertion is snapshot-relative, not "no sockets at all":
        # B never execs, so sockets the TEST process already held
        # (e.g. an xdist worker's execnet channel) legitimately ride
        # every fork. The status socketpair is created inside
        # spawn_supervised(), so a leaked copy is always a socket
        # inode that did not exist in this process before the spawn.
        _spawn_fake(monkeypatch)
        inherited = self._own_socket_links()
        h = spawn_supervised(["/bin/sleep", "300"],
                             on_parent_death="kill", env=_ENV)
        try:
            b_pid = h.ns_init_pid
            assert b_pid is not None and b_pid > 1
            links = []
            for entry in os.listdir(f"/proc/{b_pid}/fd"):
                with contextlib.suppress(OSError):
                    links.append(os.readlink(f"/proc/{b_pid}/fd/{entry}"))
            leaked = [ln for ln in links
                      if ln.startswith("socket:") and ln not in inherited]
            assert leaked == [], (
                f"ns-init waiter holds a leaked socket fd: {links}")
        finally:
            tp = h.target_pid
            h.kill()
            if tp and tp > 1:
                _reap_stray(tp)  # fake mode: no namespace to collapse C


class TestExternalReapIsLoud:
    """A supervisor reaped outside the handle surfaces loudly."""

    def test_externally_reaped_supervisor_is_loud(self, monkeypatch):
        # A broad os.wait()/waitpid elsewhere in the process stealing
        # A's exit status must surface as SupervisedTeardownError —
        # poll() lying None forever would strand the owner on a tree
        # whose state is unverifiable.
        _spawn_fake(monkeypatch)
        h = spawn_supervised(["/bin/sleep", "0"],
                             on_parent_death="kill", env=_ENV)
        os.waitpid(h.pid, 0)  # the "someone else reaped A" event
        with pytest.raises(SupervisedTeardownError):
            h.poll()


class TestCallerDeathGroupTier:
    """kill mode on the group tier: the leader dies with the caller."""

    def test_group_kill_mode_leader_dies_with_caller(self):
        # kill mode's whole contract: the tree must not outlive the
        # caller — on the group tier that is carried by PDEATHSIG on
        # the leader. Disposable caller, SIGKILLed post-spawn.
        info_r, info_w = os.pipe()
        caller = os.fork()
        if caller == 0:
            try:
                os.close(info_r)
                h = spawn_supervised(["/bin/sleep", "300"],
                                     on_parent_death="kill", pid_ns="off",
                                     env=_ENV)
                os.write(info_w, str(h.pid).encode())
                os.close(info_w)
                time.sleep(300)
            except BaseException:
                os._exit(98)
            os._exit(99)
        os.close(info_w)
        try:
            buf = os.read(info_r, 32)
            assert buf, "disposable caller failed to spawn"
            leader = int(buf)
            os.kill(caller, signal.SIGKILL)  # own child, verified pid
            os.waitpid(caller, 0)
            try:
                _assert_dies(leader,
                             "group-tier leader outlived its kill-mode "
                             "caller (PDEATHSIG not armed)")
            finally:
                if leader > 1:
                    _reap_stray(leader)
        finally:
            os.close(info_r)


class TestSupervisorForwarderSet:
    """A's forwarder set covers SIGINT."""

    def test_sigint_to_supervisor_forwards_not_kills(self, monkeypatch):
        # SIGINT aimed at A must forward down the chain (target dies,
        # waiter mirrors 128+15, A exits with it) — an unhandled SIGINT
        # would kill A itself (-2) and strand the tree.
        _spawn_fake(monkeypatch)
        h = spawn_supervised(["/bin/sleep", "300"],
                             on_parent_death="kill", env=_ENV)
        tp = h.target_pid
        try:
            os.kill(h.pid, signal.SIGINT)  # forwarders armed pre-ready
            assert h.wait(timeout=_WAIT_S) == 143
        finally:
            if tp and tp > 1:
                _reap_stray(tp)  # only strays under a broken forwarder
