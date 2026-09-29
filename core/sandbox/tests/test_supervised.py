"""Unit tests for core.sandbox.supervised — hermetic on any Linux host.

Nothing here needs a real pid namespace: the handle/lifecycle tests run
the REAL supervisor topology (fork A → fork B → fork C, pidfd transfer,
status protocol) with ``_ns_setup`` monkeypatched to a no-op, so the
tree is real processes without requiring unshare permission. The
namespace-boundary assertions live in test_supervised_selftest.py
(probe-gated); the waiter contract battery in
test_supervised_waiter_contract.py.

Fleet-kill doctrine: no test signals a pid or pgid <= 1, every pid
signalled here came from a spawn this test performed, and every
teardown is verified (kill-0 / ProcessLookupError) rather than assumed.
"""

import builtins
import contextlib
import ctypes
import ctypes.util
import errno
import inspect
import io
import logging
import os
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(
    sys.platform != "linux",
    reason="supervised trees are Linux-only (fork/pidfd/procfs)",
)

if sys.platform == "linux":
    from core.sandbox import probes, state
    from core.sandbox import supervised as sup
    from core.sandbox.errors import SandboxSetupError
    from core.sandbox.supervised import (
        SupervisedHandle,
        SupervisedTeardownError,
        spawn_supervised,
    )

# Explicit env for spawns: hermetic (no dependence on the test shell's
# environment) and exercises the caller-env-verbatim contract.
_ENV = {"PATH": "/usr/bin:/bin"}
_WAIT_S = 15.0


def _spawn_fake(monkeypatch):
    """Route the pidns tier through the real topology minus the actual
    unshare: A/B/C are real processes, just not in a namespace."""
    monkeypatch.setattr(sup, "_ns_setup", lambda net_ns: None)
    monkeypatch.setattr(state, "_pidns_supervision_cache", (True, ""))


def _reap_stray(pid: int) -> None:
    """Verified cleanup of a process this test created (fake-backend
    kill() has no namespace, so C can outlive B). Guarded: never a
    pid <= 1, and death is confirmed, not assumed.

    Death is EITHER ProcessLookupError OR state Z: when the suite runs
    under a non-reaping init (pytest as PID 1 of a battery namespace),
    the orphaned stray is adopted but never reaped, so it stays a
    kill-visible zombie forever — provably dead all the same."""
    assert pid > 1, f"refusing to signal pid {pid}"
    deadline = time.monotonic() + _WAIT_S
    while True:
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            return
        try:
            with open(f"/proc/{pid}/stat", "rb") as f:
                state = f.read().rsplit(b")", 1)[1].split()[0]
        except (OSError, IndexError):
            return  # vanished between kill and read
        if state == b"Z":
            return  # dead, held un-reaped by a non-reaping init
        if time.monotonic() > deadline:
            pytest.fail(f"stray pid {pid} would not die")
        time.sleep(0.05)


def _pgrp_members_with_state(pgid: int) -> list[tuple[int, bytes]]:
    """Test-local (deliberately independent of the product helper)
    /proc scan: (pid, state) for every process whose pgrp is ``pgid``.
    Splits /proc/<pid>/stat on the LAST ')' — comm can carry spaces."""
    members = []
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        try:
            with open(f"/proc/{entry}/stat", "rb") as f:
                rest = f.read().rsplit(b")", 1)[1].split()
        except (OSError, IndexError):
            continue
        if int(rest[2]) == pgid:
            members.append((int(entry), rest[0]))
    return members


def _pgrp_members(pgid: int) -> list[int]:
    return [pid for pid, _state in _pgrp_members_with_state(pgid)]


def _live_pgrp_members(pgid: int) -> list[int]:
    """Members of ``pgid`` that are not zombies (state Z)."""
    return [pid for pid, state in _pgrp_members_with_state(pgid)
            if state != b"Z"]


def _pgrp_live_tasks(pgid: int) -> list[tuple[int, int]]:
    """(pid, tid) for every non-zombie TASK of every ``pgid`` member.

    A process whose thread-group leader called pthread_exit() reads
    state Z in /proc/<pid>/stat while its worker threads run on — the
    process-level scan alone would call it dead. This helper looks
    through /proc/<pid>/task to catch exactly that."""
    tasks: list[tuple[int, int]] = []
    for pid, _state in _pgrp_members_with_state(pgid):
        try:
            tids = os.listdir(f"/proc/{pid}/task")
        except OSError:
            continue  # member vanished mid-scan
        for tid in tids:
            try:
                with open(f"/proc/{pid}/task/{tid}/stat", "rb") as f:
                    tstate = f.read().rsplit(b")", 1)[1].split()[0]
            except (OSError, IndexError):
                continue
            if tstate != b"Z":
                tasks.append((pid, int(tid)))
    return tasks


class TestValidation:
    def test_str_cmd_rejected(self):
        with pytest.raises(TypeError, match="argv list"):
            spawn_supervised("echo hi", on_parent_death="kill")

    def test_bytes_cmd_rejected(self):
        with pytest.raises(TypeError, match="argv list"):
            spawn_supervised(b"echo hi", on_parent_death="kill")

    def test_empty_cmd_rejected(self):
        with pytest.raises(ValueError, match="non-empty list"):
            spawn_supervised([], on_parent_death="kill")

    def test_non_str_argv_rejected(self):
        with pytest.raises(ValueError, match="non-empty list of str"):
            spawn_supervised(["/bin/echo", 42], on_parent_death="kill")

    def test_on_parent_death_is_required_keyword_without_default(self):
        # The caller must own the fate decision explicitly — no
        # default may ever be added.
        param = inspect.signature(spawn_supervised).parameters[
            "on_parent_death"]
        assert param.kind is inspect.Parameter.KEYWORD_ONLY
        assert param.default is inspect.Parameter.empty
        with pytest.raises(TypeError):
            spawn_supervised(["/bin/true"])

    def test_on_parent_death_value_validated(self):
        with pytest.raises(ValueError, match="on_parent_death"):
            spawn_supervised(["/bin/true"], on_parent_death="maybe")

    def test_pid_ns_value_validated(self):
        with pytest.raises(ValueError, match="pid_ns"):
            spawn_supervised(["/bin/true"], on_parent_death="kill",
                             pid_ns="yes-please")

    @pytest.mark.parametrize("pid_ns", ["off", "auto"])
    @pytest.mark.parametrize("stream", [subprocess.PIPE, subprocess.STDOUT])
    def test_pipe_and_stdout_rejected_on_both_tiers(self, stream, pid_ns):
        with pytest.raises(ValueError, match="not supported"):
            spawn_supervised(["/bin/true"], on_parent_death="kill",
                             pid_ns=pid_ns, stdout=stream)
        with pytest.raises(ValueError, match="not supported"):
            spawn_supervised(["/bin/true"], on_parent_death="kill",
                             pid_ns=pid_ns, stderr=stream)

    def test_negative_fd_rejected(self):
        with pytest.raises(ValueError, match="negative fd"):
            spawn_supervised(["/bin/true"], on_parent_death="kill",
                             stdout=-5)

    def test_non_file_object_rejected(self):
        with pytest.raises(TypeError, match="expected fd"):
            spawn_supervised(["/bin/true"], on_parent_death="kill",
                             stdout=object())


class TestTierSelection:
    """Matrix over pid_ns x probe verdict, with both spawn backends
    replaced by recorders — no processes are created."""

    @pytest.fixture
    def backends(self, monkeypatch):
        calls = {"pidns": [], "group": []}

        def fake_pidns(cmd, env, cwd, stdout, stderr, net_ns, kill_mode,
                       name):
            calls["pidns"].append(
                {"net_ns": net_ns, "kill_mode": kill_mode})
            return "PIDNS-HANDLE"

        def fake_group(cmd, env, cwd, stdout, stderr, kill_mode, name):
            calls["group"].append({"kill_mode": kill_mode})
            return "GROUP-HANDLE"

        monkeypatch.setattr(sup, "_spawn_pidns_tier", fake_pidns)
        monkeypatch.setattr(sup, "_spawn_group_tier", fake_group)
        return calls

    def _seed(self, monkeypatch, verdict):
        monkeypatch.setattr(state, "_pidns_supervision_cache", verdict)

    def test_off_selects_group_without_consulting_probe(
            self, backends, monkeypatch):
        def boom():
            pytest.fail("probe consulted despite pid_ns='off'")
        monkeypatch.setattr(probes, "check_pidns_supervision_available",
                            boom)
        h = spawn_supervised(["/bin/true"], on_parent_death="kill",
                             pid_ns="off", env=_ENV)
        assert h == "GROUP-HANDLE"
        assert backends["pidns"] == []

    def test_probe_true_auto_selects_pidns(self, backends, monkeypatch):
        self._seed(monkeypatch, (True, ""))
        h = spawn_supervised(["/bin/true"], on_parent_death="kill",
                             env=_ENV)
        assert h == "PIDNS-HANDLE"

    def test_probe_false_auto_degrades_to_group(self, backends,
                                                monkeypatch):
        self._seed(monkeypatch, (False, "userns restricted"))
        h = spawn_supervised(["/bin/true"], on_parent_death="kill",
                             env=_ENV)
        assert h == "GROUP-HANDLE"
        assert backends["pidns"] == []

    def test_probe_false_auto_degrade_warns(self, backends, monkeypatch,
                                            caplog):
        # The degrade is honest in the handle (tier="group") but must
        # also be LOUD: a caller who never inspects .tier still gets an
        # operator-visible warning naming the reason and the weaker
        # teardown scope.
        self._seed(monkeypatch, (False, "userns restricted"))
        with caplog.at_level(logging.WARNING,
                             logger="core.sandbox.supervised"):
            h = spawn_supervised(["/bin/true"], on_parent_death="kill",
                                 env=_ENV)
        assert h == "GROUP-HANDLE"
        degrade_records = [r for r in caplog.records
                           if "group tier" in r.getMessage()
                           and "userns restricted" in r.getMessage()]
        assert degrade_records, (
            "pidns->group degrade emitted no warning — the degrade "
            "must be loud, not merely handle-visible")

    def test_probe_false_require_refuses(self, backends, monkeypatch):
        self._seed(monkeypatch, (False, "userns restricted"))
        with pytest.raises(SandboxSetupError, match="userns restricted"):
            spawn_supervised(["/bin/true"], on_parent_death="kill",
                             pid_ns="require", env=_ENV)
        assert backends["pidns"] == [] and backends["group"] == []

    def test_probe_indeterminate_auto_attempts_pidns(
            self, backends, monkeypatch):
        # Infra-failure probe (None) is not a verdict: the live spawn's
        # own unshare is the authoritative test, so attempt the tier.
        self._seed(monkeypatch, None)
        monkeypatch.setattr(
            probes, "check_pidns_supervision_available",
            lambda: (None, "probe could not run"))
        h = spawn_supervised(["/bin/true"], on_parent_death="kill",
                             env=_ENV)
        assert h == "PIDNS-HANDLE"

    def test_net_ns_with_pid_ns_off_refuses(self, backends):
        with pytest.raises(SandboxSetupError, match="net_ns"):
            spawn_supervised(["/bin/true"], on_parent_death="kill",
                             pid_ns="off", net_ns=True, env=_ENV)
        assert backends["group"] == []

    def test_net_ns_with_refused_pidns_refuses_not_degrades(
            self, backends, monkeypatch):
        self._seed(monkeypatch, (False, "userns restricted"))
        with pytest.raises(SandboxSetupError, match="net_ns"):
            spawn_supervised(["/bin/true"], on_parent_death="kill",
                             net_ns=True, env=_ENV)
        assert backends["group"] == []

    @pytest.mark.parametrize("mode,expected", [("kill", True),
                                               ("survive", False)])
    def test_kill_mode_reaches_backend(self, backends, monkeypatch,
                                       mode, expected):
        self._seed(monkeypatch, (True, ""))
        spawn_supervised(["/bin/true"], on_parent_death=mode, env=_ENV)
        assert backends["pidns"][-1]["kill_mode"] is expected


class TestRuntimeRefusalFlipsCache:
    """A live 'U' refusal from A is authoritative: it re-caches the
    probe verdict and (auto) degrades / (require) raises."""

    @pytest.fixture
    def refusing_ns(self, monkeypatch):
        monkeypatch.setattr(state, "_pidns_supervision_cache", (True, ""))

        def deny(net_ns):
            raise OSError(errno.EPERM, "Operation not permitted")
        monkeypatch.setattr(sup, "_ns_setup", deny)

    def test_auto_degrades_and_flips_cache(self, refusing_ns,
                                           monkeypatch):
        h = spawn_supervised(["/bin/sh", "-c", "exit 4"],
                             on_parent_death="kill", env=_ENV)
        assert h.tier == "group"
        assert h.wait(timeout=_WAIT_S) == 4
        cached = state._pidns_supervision_cache
        assert cached is not None and cached[0] is False
        assert "refused" in cached[1]
        # Subsequent auto spawns must not re-attempt the doomed tier.
        monkeypatch.setattr(
            sup, "_spawn_pidns_tier",
            lambda *a, **k: pytest.fail("pidns tier re-attempted "
                                        "after cached refusal"))
        h2 = spawn_supervised(["/bin/sh", "-c", "exit 5"],
                              on_parent_death="kill", env=_ENV)
        assert h2.tier == "group"
        assert h2.wait(timeout=_WAIT_S) == 5

    def test_live_refusal_degrade_warns(self, refusing_ns, caplog):
        # The runtime-refusal degrade must be as loud as the
        # probe-verdict one: a live 'U' that lands the caller on the
        # group tier logs a warning naming the refusal.
        with caplog.at_level(logging.WARNING,
                             logger="core.sandbox.supervised"):
            h = spawn_supervised(["/bin/sh", "-c", "exit 3"],
                                 on_parent_death="kill", env=_ENV)
        assert h.tier == "group"
        assert h.wait(timeout=_WAIT_S) == 3
        degrade_records = [r for r in caplog.records
                           if "group tier" in r.getMessage()]
        assert degrade_records, (
            "live-refusal degrade emitted no warning — the degrade "
            "must be loud, not merely handle-visible")

    def test_require_raises_and_flips_cache(self, refusing_ns):
        with pytest.raises(SandboxSetupError) as exc:
            spawn_supervised(["/bin/true"], on_parent_death="kill",
                             pid_ns="require", env=_ENV)
        assert exc.value.setup_category == "U"
        cached = state._pidns_supervision_cache
        assert cached is not None and cached[0] is False

    def test_net_ns_never_silently_dropped_on_runtime_refusal(
            self, refusing_ns):
        with pytest.raises(SandboxSetupError):
            spawn_supervised(["/bin/true"], on_parent_death="kill",
                             net_ns=True, env=_ENV)


class TestHandleLifecycle:
    """Real A/B/C topology, no-op namespace setup."""

    @pytest.fixture(autouse=True)
    def fake_backend(self, monkeypatch):
        _spawn_fake(monkeypatch)

    def test_exit_code_mirrors(self):
        h = spawn_supervised(["/bin/sh", "-c", "exit 7"],
                             on_parent_death="kill", env=_ENV)
        assert h.tier == "pidns"
        assert h.wait(timeout=_WAIT_S) == 7
        assert h.returncode == 7

    def test_signal_death_in_tree_mirrors_128_plus_signum(self):
        h = spawn_supervised(["/bin/sh", "-c", "kill -9 $$"],
                             on_parent_death="kill", env=_ENV)
        assert h.wait(timeout=_WAIT_S) == 137

    def test_poll_running_then_exit(self):
        h = spawn_supervised(["/bin/sh", "-c", "sleep 0.3; exit 3"],
                             on_parent_death="kill", env=_ENV)
        assert h.poll() is None
        assert h.wait(timeout=_WAIT_S) == 3
        assert h.poll() == 3

    def test_wait_timeout_leaves_state_unchanged(self):
        h = spawn_supervised(["/bin/sleep", "30"],
                             on_parent_death="kill", env=_ENV)
        try:
            with pytest.raises(TimeoutError):
                h.wait(timeout=0.2)
            assert h.returncode is None
            assert h.poll() is None  # still waitable
        finally:
            assert h.terminate(grace_s=2.0) == 143

    def test_terminate_idempotent(self):
        h = spawn_supervised(["/bin/sleep", "30"],
                             on_parent_death="kill", env=_ENV)
        rc = h.terminate(grace_s=2.0)
        assert rc == 143
        assert h.terminate() == rc
        assert h.kill() == rc

    def test_kill_skips_grace(self):
        h = spawn_supervised(
            ["/bin/sh", "-c", "trap '' TERM; sleep 30"],
            on_parent_death="kill", env=_ENV)
        time.sleep(0.2)
        tp = int(h.target_pid)
        try:
            assert h.kill() == 137
        finally:
            # No namespace under the fake backend, so C survives B's
            # SIGKILL — clean up the deliberate stray, verified.
            _reap_stray(tp)

    def test_context_manager_terminates(self):
        with spawn_supervised(["/bin/sleep", "30"],
                              on_parent_death="kill", env=_ENV) as h:
            assert h.poll() is None
        assert h.returncode == 143

    def test_signal_to_supervisor_forwards_down_the_chain(self):
        h = spawn_supervised(["/bin/sleep", "30"],
                             on_parent_death="kill", env=_ENV)
        os.kill(h.pid, signal.SIGTERM)  # h.pid: our direct child A
        assert h.wait(timeout=_WAIT_S) == 143

    def test_forwarders_armed_before_ready_report(self, monkeypatch):
        # Regression (caught by the in-namespace battery under load):
        # A must arm its TERM/INT forwarders BEFORE reporting ready —
        # the caller may signal the instant spawn returns. Widen the
        # report-to-supervise window deterministically by delaying
        # _supervise (the monkeypatch rides into A, which runs post-
        # fork in this process's memory image): with installation
        # inside _supervise (the bug), the TERM below lands on default
        # disposition and A dies -15 instead of forwarding to 143.
        real_supervise = sup._supervise

        def delayed(b_pid, b_pidfd, death_r):
            time.sleep(1.0)
            real_supervise(b_pid, b_pidfd, death_r)

        monkeypatch.setattr(sup, "_supervise", delayed)
        h = spawn_supervised(["/bin/sleep", "30"],
                             on_parent_death="kill", env=_ENV)
        os.kill(h.pid, signal.SIGTERM)  # inside the widened window
        assert h.wait(timeout=_WAIT_S) == 143

    def test_supervisor_outlives_signal_while_target_ignores_it(self):
        # Exit-path invariant: a signal at A never makes A abandon a
        # live B — A forwards and keeps supervising.
        h = spawn_supervised(
            ["/bin/sh", "-c", "trap '' TERM; sleep 30"],
            on_parent_death="kill", env=_ENV)
        time.sleep(0.2)
        tp = int(h.target_pid)
        try:
            os.kill(h.pid, signal.SIGTERM)
            time.sleep(0.5)
            assert h.poll() is None, (
                "supervisor died while its tree was still alive")
        finally:
            assert h.kill() == 137
            _reap_stray(tp)

    def test_exec_failure_is_typed_X(self):
        with pytest.raises(SandboxSetupError) as exc:
            spawn_supervised(["/nonexistent-raptor-test-binary"],
                             on_parent_death="kill", env=_ENV)
        assert exc.value.setup_category == "X"
        assert "nonexistent-raptor-test-binary" in str(exc.value)

    def test_stdout_and_cwd_plumbing(self, tmp_path):
        out = tmp_path / "out.txt"
        with open(out, "wb") as f:
            h = spawn_supervised(["/bin/sh", "-c", "pwd"],
                                 on_parent_death="kill", env=_ENV,
                                 cwd=str(tmp_path), stdout=f)
            assert h.wait(timeout=_WAIT_S) == 0
        assert out.read_bytes().strip() == str(tmp_path).encode()

    def test_devnull_stdout(self):
        h = spawn_supervised(["/bin/echo", "swallowed"],
                             on_parent_death="kill", env=_ENV,
                             stdout=subprocess.DEVNULL)
        assert h.wait(timeout=_WAIT_S) == 0

    def test_caller_env_used_verbatim(self, tmp_path):
        out = tmp_path / "env.txt"
        with open(out, "wb") as f:
            h = spawn_supervised(
                ["/bin/sh", "-c", "echo ${RAPTOR_SUP_TEST:-absent}"],
                on_parent_death="kill",
                env={**_ENV, "RAPTOR_SUP_TEST": "verbatim"}, stdout=f)
            assert h.wait(timeout=_WAIT_S) == 0
        assert out.read_bytes().strip() == b"verbatim"

    def test_default_env_is_safe_env_snapshot(self, tmp_path,
                                              monkeypatch):
        # env=None must NOT leak the caller's environment.
        monkeypatch.setenv("RAPTOR_SUP_POISON", "leaked")
        out = tmp_path / "env.txt"
        with open(out, "wb") as f:
            h = spawn_supervised(
                ["/bin/sh", "-c", "echo ${RAPTOR_SUP_POISON:-absent}"],
                on_parent_death="kill", stdout=f)
            assert h.wait(timeout=_WAIT_S) == 0
        assert out.read_bytes().strip() == b"absent"

    def test_handle_metadata(self):
        h = spawn_supervised(["/bin/sleep", "30"],
                             on_parent_death="survive", env=_ENV)
        try:
            assert h.tier == "pidns"
            assert h.confinement == "none"
            assert h.on_parent_death == "survive"
            assert h.ns_init_pid is not None and h.ns_init_pid > 1
            assert h.ns_init_pidfd is not None
            assert int(h.target_pid) > 1
            os.kill(int(h.target_pid), 0)  # diagnostic pid is live
        finally:
            assert h.terminate(grace_s=2.0) == 143


class TestGroupTier:
    def test_exit_code(self):
        h = spawn_supervised(["/bin/sh", "-c", "exit 6"],
                             on_parent_death="kill", pid_ns="off",
                             env=_ENV)
        assert h.tier == "group"
        assert h.confinement == "none"
        assert h.wait(timeout=_WAIT_S) == 6

    def test_terminate_reports_popen_convention(self):
        # Group tier: signal death of the leader is Popen's -signum
        # (vs the pidns tier's 128+signum waiter mirror) — a
        # documented divergence.
        h = spawn_supervised(["/bin/sleep", "30"],
                             on_parent_death="kill", pid_ns="off",
                             env=_ENV)
        assert h.terminate(grace_s=2.0) == -signal.SIGTERM

    def test_terminate_takes_descendants_via_group(self):
        h = spawn_supervised(
            ["/bin/sh", "-c", "sleep 30 & sleep 30"],
            on_parent_death="kill", pid_ns="off", env=_ENV)
        time.sleep(0.2)
        pgid = os.getpgid(h.pid)
        assert pgid == h.pid  # start_new_session leader
        h.terminate(grace_s=2.0)
        # Corroborate independently of the product helper. Dead ==
        # ProcessLookupError, or every remaining pgrp member is a
        # zombie (adopted-but-unreaped under a non-reaping init, e.g.
        # pytest as PID 1 of a battery namespace).
        deadline = time.monotonic() + _WAIT_S
        while True:
            try:
                os.killpg(pgid, 0)
            except ProcessLookupError:
                break  # whole group gone — corroborated
            if not _live_pgrp_members(pgid):
                break  # only zombies left — dead, held un-reaped
            assert time.monotonic() < deadline, "group survived teardown"
            time.sleep(0.05)

    def test_group_corroboration_treats_held_zombies_as_dead(self):
        # Regression (caught by the in-namespace battery): under an
        # init that never reaps adopted orphans (pytest as PID 1 of a
        # battery namespace), killed descendants stay kill-visible
        # zombies and killpg-0 alone would refuse forever. Make THIS
        # process the adopter (test-only PR_SET_CHILD_SUBREAPER, and
        # deliberately do not reap until afterwards) so the scenario is
        # deterministic on any host: terminate() must still verify
        # death via the zombie disambiguation instead of raising
        # SupervisedTeardownError at the corroboration budget.
        libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6",
                           use_errno=True)
        assert libc.prctl(36, 1, 0, 0, 0) == 0  # PR_SET_CHILD_SUBREAPER
        pgid = None
        try:
            h = spawn_supervised(
                ["/bin/sh", "-c", "sleep 30 & sleep 30"],
                on_parent_death="kill", pid_ns="off", env=_ENV)
            time.sleep(0.3)
            pgid = os.getpgid(h.pid)
            rc = h.terminate(grace_s=1.0)
            assert rc in (-signal.SIGTERM, -signal.SIGKILL)
            assert _live_pgrp_members(pgid) == []
        finally:
            # Reap the zombies this test deliberately adopted (they
            # are our children now); per-pid waitpid, never wait(-1) —
            # a -1 reap could steal another fixture's child.
            if pgid is not None and pgid > 1:
                deadline = time.monotonic() + _WAIT_S
                while time.monotonic() < deadline:
                    members = _pgrp_members(pgid)
                    if not members:
                        break
                    for z in members:
                        with contextlib.suppress(ChildProcessError,
                                                 OSError):
                            os.waitpid(z, os.WNOHANG)
                    time.sleep(0.05)
            assert libc.prctl(36, 0, 0, 0, 0) == 0

    def test_group_terminate_refuses_on_skewed_proc_pid_view(
            self, monkeypatch):
        # A /proc whose pid view disagrees with the killpg pid view
        # (e.g. /proc mounted from a different pid namespace than the
        # one the signals travel in: unshare without --mount-proc) lets
        # the scan sight ZERO members while killpg-0 still sees the
        # group. Zero sighted is absence of proof, and killpg-0
        # succeeding at the same time is a positive contradiction —
        # terminate() must keep escalating and refuse loudly at its
        # deadline, never report the teardown verified. Hold the
        # zombies via a test-only subreaper so the contradiction
        # persists to the deadline on any host (a promptly-reaping init
        # would turn the escalated kills into honest killpg-0 ESRCH
        # verification and mask the skew).
        libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6",
                           use_errno=True)
        assert libc.prctl(36, 1, 0, 0, 0) == 0  # PR_SET_CHILD_SUBREAPER
        pgid = None
        try:
            # TERM-immune non-leader member: forked while TERM is
            # ignored (inherits the disposition); the leader resets
            # TERM before exec so the graceful rung takes it.
            h = spawn_supervised(
                ["/bin/sh", "-c",
                 'trap "" TERM; sleep 30 & trap - TERM; exec sleep 30'],
                on_parent_death="kill", pid_ns="off", env=_ENV)
            time.sleep(0.4)  # let the background member start
            pgid = os.getpgid(h.pid)
            real_listdir = os.listdir

            def skewed_listdir(path):
                if str(path) == "/proc":
                    return []  # the skewed pid view: nobody visible
                return real_listdir(path)

            monkeypatch.setattr(sup, "_KILL_REAP_BUDGET_S", 2.0)
            monkeypatch.setattr(os, "listdir", skewed_listdir)
            with pytest.raises(SupervisedTeardownError):
                h.terminate(grace_s=0.5)
            monkeypatch.undo()
            # The refusal must be loud AND the escalation real: by the
            # time the deadline raised, the in-loop SIGKILLs must have
            # taken the TERM-immune member down (held zombies count as
            # dead).
            assert _live_pgrp_members(pgid) == []
        finally:
            monkeypatch.undo()
            if pgid is not None and pgid > 1:
                for pid in _live_pgrp_members(pgid):
                    _reap_stray(pid)
                deadline = time.monotonic() + _WAIT_S
                while time.monotonic() < deadline:
                    members = _pgrp_members(pgid)
                    if not members:
                        break
                    for z in members:
                        with contextlib.suppress(ChildProcessError,
                                                 OSError):
                            os.waitpid(z, os.WNOHANG)
                    time.sleep(0.05)
            assert libc.prctl(36, 0, 0, 0, 0) == 0

    def test_group_terminate_kills_live_worker_behind_zombie_leader(
            self, tmp_path):
        # A member whose thread-group leader pthread_exit()ed reads
        # state Z in /proc/<pid>/stat while a worker thread runs on:
        # the process is alive, killable, and killpg-visible. A death
        # proof that reads the process-level Z as "dead" verifies a
        # teardown that left a running thread behind — the proof must
        # consult /proc/<pid>/task before counting a Z member dead.
        script = tmp_path / "zleader.py"
        script.write_text(
            "import ctypes, signal, threading, time\n"
            "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
            "threading.Thread(target=time.sleep, args=(30,)).start()\n"
            "ctypes.CDLL(None).pthread_exit(None)\n")
        h = spawn_supervised(
            ["/bin/sh", "-c",
             f'"{sys.executable}" "{script}" & exec sleep 30'],
            on_parent_death="kill", pid_ns="off", env=_ENV)
        pgid = os.getpgid(h.pid)
        try:
            # Bounded wait for the member to reach the split state:
            # process-level Z with a live worker task.
            deadline = time.monotonic() + _WAIT_S
            while True:
                live_task_pids = {p for p, _t in _pgrp_live_tasks(pgid)}
                if any(st == b"Z" and pid in live_task_pids
                       for pid, st in _pgrp_members_with_state(pgid)):
                    break
                assert time.monotonic() < deadline, (
                    "member never reached the zombie-leader state")
                time.sleep(0.05)
            rc = h.terminate(grace_s=1.0)
            assert rc is not None
            live_tasks = _pgrp_live_tasks(pgid)
            assert live_tasks == [], (
                f"terminate() verified group {pgid} dead while tasks "
                f"{live_tasks} were still running")
        finally:
            for pid in _pgrp_members(pgid):
                _reap_stray(pid)
            deadline = time.monotonic() + _WAIT_S
            while time.monotonic() < deadline:
                members = _pgrp_members(pgid)
                if not members:
                    break
                for z in members:
                    with contextlib.suppress(ChildProcessError, OSError):
                        os.waitpid(z, os.WNOHANG)
                time.sleep(0.05)

    def test_group_terminate_after_natural_leader_exit_corroborates(self):
        # The leader exiting on its own is NOT a teardown proof: a
        # descendant may linger in the group. The first terminate()
        # after a natural leader exit must corroborate — and escalate —
        # the group instead of returning the leader's returncode over
        # a live member.
        h = spawn_supervised(
            ["/bin/sh", "-c", "sleep 30 & exit 0"],
            on_parent_death="kill", pid_ns="off", env=_ENV)
        pgid = h.pid  # start_new_session leader
        try:
            assert h.wait(timeout=_WAIT_S) == 0  # natural leader exit
            assert _live_pgrp_members(pgid), (
                "background member should outlive the leader")
            rc = h.terminate(grace_s=2.0)
            assert rc == 0  # the leader's recorded returncode
            assert _live_pgrp_members(pgid) == []
            # Only now is the teardown verified — and idempotent.
            assert h.terminate(grace_s=0.1) == 0
        finally:
            for pid in _live_pgrp_members(pgid):
                _reap_stray(pid)
            deadline = time.monotonic() + _WAIT_S
            while time.monotonic() < deadline:
                members = _pgrp_members(pgid)
                if not members:
                    break
                for z in members:
                    with contextlib.suppress(ChildProcessError, OSError):
                        os.waitpid(z, os.WNOHANG)
                time.sleep(0.05)

    def test_group_natural_exit_zero_sighted_refuses_without_signal(
            self, monkeypatch):
        # After the whole group is gone its pgid may be RECYCLED by an
        # unrelated process, so the natural-exit verification must
        # never signal on killpg-0 evidence alone: zero sighted members
        # plus killpg-0 success refuses loudly with NO signal sent
        # (unlike the post-kill corroboration, which owns its
        # freshly-signalled group and keeps escalating).
        h = spawn_supervised(["/bin/true"], on_parent_death="kill",
                             pid_ns="off", env=_ENV)
        assert h.wait(timeout=_WAIT_S) == 0
        sent = []

        def stub_killpg(pgid, sig):
            sent.append((pgid, sig))
            return None  # "the group exists" — skew or recycled pgid

        real_listdir = os.listdir
        monkeypatch.setattr(os, "killpg", stub_killpg)
        monkeypatch.setattr(
            os, "listdir",
            lambda path: [] if str(path) == "/proc"
            else real_listdir(path))
        with pytest.raises(SupervisedTeardownError):
            h.terminate(grace_s=0.5)
        real_signals = [s for s in sent if s[1] != 0]
        assert real_signals == [], (
            f"signal sent at an unowned, possibly recycled pgid: "
            f"{real_signals}")

    def test_group_corroboration_zero_sighted_contradiction_refuses(
            self, monkeypatch):
        # Unit pin at the corroboration seam itself: killpg-0
        # SUCCEEDING while the /proc scan sights zero group members is
        # a contradiction (a skewed pid view), not a death proof. The
        # corroboration must keep escalating SIGKILL and refuse loudly
        # at its deadline — never return "verified".
        h = spawn_supervised(["/bin/true"], on_parent_death="kill",
                             pid_ns="off", env=_ENV)
        assert h.wait(timeout=_WAIT_S) == 0
        kills = []

        def stub_killpg(pgid, sig):
            if sig == signal.SIGKILL:
                kills.append(pgid)
            return None  # sig 0 included: "the group exists"

        real_listdir = os.listdir
        monkeypatch.setattr(os, "killpg", stub_killpg)
        monkeypatch.setattr(
            os, "listdir",
            lambda path: [] if str(path) == "/proc"
            else real_listdir(path))
        monkeypatch.setattr(sup, "_KILL_REAP_BUDGET_S", 1.0)
        with pytest.raises(SupervisedTeardownError):
            h._corroborate_group_dead_locked(h.pid)
        assert kills, "refusal without escalation: no SIGKILL issued"

    def test_group_corroboration_unlistable_proc_refuses(
            self, monkeypatch):
        # No /proc view at the corroboration seam is no death proof:
        # while killpg-0 keeps seeing the group, an unlistable /proc
        # must refuse at the deadline — never read as "nobody there,
        # all dead".
        h = spawn_supervised(["/bin/true"], on_parent_death="kill",
                             pid_ns="off", env=_ENV)
        assert h.wait(timeout=_WAIT_S) == 0

        def stub_killpg(pgid, sig):
            return None  # the group "exists" throughout

        def broken_listdir(path):
            if str(path) == "/proc":
                raise OSError(5, "proc unavailable")
            return real_listdir(path)

        real_listdir = os.listdir
        monkeypatch.setattr(os, "killpg", stub_killpg)
        monkeypatch.setattr(os, "listdir", broken_listdir)
        monkeypatch.setattr(sup, "_KILL_REAP_BUDGET_S", 1.0)
        with pytest.raises(SupervisedTeardownError):
            h._corroborate_group_dead_locked(h.pid)

    def test_group_corroboration_occluded_view_refuses(self, monkeypatch):
        # Occlusion pin at the corroboration seam: the held-zombies
        # scenario (killpg-0 sees the group, every sighted member is
        # Z-through-tasks) VERIFIES on a clean view — but a filtered
        # /proc mount can hide a live member while showing the zombies,
        # so under a mount-declared filter the same evidence proves
        # only what was sighted, never absence. The corroboration must
        # keep escalating (it owns its freshly-signalled group) and
        # refuse loudly at its deadline instead of verifying.
        libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6",
                           use_errno=True)
        assert libc.prctl(36, 1, 0, 0, 0) == 0  # PR_SET_CHILD_SUBREAPER
        pgid = None
        try:
            h = spawn_supervised(
                ["/bin/sh", "-c", "sleep 30 & sleep 30"],
                on_parent_death="kill", pid_ns="off", env=_ENV)
            time.sleep(0.3)
            pgid = os.getpgid(h.pid)
            monkeypatch.setattr(
                sup, "_proc_pid_view_filtered",
                lambda: "hidepid=2 (simulated)", raising=False)
            monkeypatch.setattr(sup, "_KILL_REAP_BUDGET_S", 1.5)
            with pytest.raises(SupervisedTeardownError, match="occluded"):
                h.terminate(grace_s=0.5)
            monkeypatch.undo()
            # The refusal must not have abandoned the escalation: the
            # members are down (held zombies count), only the VERIFY
            # claim was withheld.
            assert _live_pgrp_members(pgid) == []
        finally:
            monkeypatch.undo()
            self._drain_group(pgid)
            assert libc.prctl(36, 0, 0, 0, 0) == 0

    def _held_zombie_plus_live_member(self):
        """Natural-exit topology for the occluded-view pins: the leader
        exits on its own, leaving one held zombie (the short sleep,
        adopted by this test's subreaper and deliberately unreaped) and
        one live member (the long sleep) in the group. Returns
        ``(handle, pgid, hidden_live_pid)``; the caller owns cleanup."""
        h = spawn_supervised(
            ["/bin/sh", "-c", "sleep 0.2 & sleep 30 & exit 0"],
            on_parent_death="kill", pid_ns="off", env=_ENV)
        pgid = h.pid  # start_new_session leader
        assert h.wait(timeout=_WAIT_S) == 0  # natural leader exit
        deadline = time.monotonic() + _WAIT_S
        while True:
            members = _pgrp_members_with_state(pgid)
            live = [p for p, s in members if s != b"Z"]
            zombies = [p for p, s in members if s == b"Z"]
            if len(live) == 1 and zombies:
                return h, pgid, live[0]
            assert time.monotonic() < deadline, (
                f"never reached the zombie+live topology: {members}")
            time.sleep(0.05)

    def _drain_group(self, pgid):
        """Verified cleanup of a test-owned group: kill live members,
        then per-pid reap of the zombies this test's subreaper holds."""
        if pgid is None or pgid <= 1:
            return
        for pid in _live_pgrp_members(pgid):
            _reap_stray(pid)
        deadline = time.monotonic() + _WAIT_S
        while time.monotonic() < deadline:
            members = _pgrp_members(pgid)
            if not members:
                return
            for z in members:
                with contextlib.suppress(ChildProcessError, OSError):
                    os.waitpid(z, os.WNOHANG)
            time.sleep(0.05)

    def test_group_natural_exit_filtered_proc_view_refuses_unsignalled(
            self, monkeypatch):
        # A hidepid-class procfs filter can hide a live member from the
        # scan while a held zombie stays visible. The natural-exit
        # verification then sees "one sighted member, Z-through-tasks"
        # plus killpg-0 success — but that killpg-0 success is
        # AMBIGUOUS between "only held zombies" and "a live member this
        # /proc cannot show". A mount-declared filtered view makes the
        # scan's sightings insufficient death evidence: refuse loudly,
        # signal nothing. The filter declaration is simulated at the
        # detector seam (a hidepid procfs cannot be mounted portably
        # mid-test); the hidden member by omitting exactly its pid from
        # the listing, the same way the shipped skew tests simulate a
        # partial pid view.
        libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6",
                           use_errno=True)
        assert libc.prctl(36, 1, 0, 0, 0) == 0  # PR_SET_CHILD_SUBREAPER
        pgid = None
        sent: list[tuple[int, int]] = []
        try:
            h, pgid, hidden = self._held_zombie_plus_live_member()
            real_listdir = os.listdir
            real_killpg = os.killpg

            def filtered_listdir(path):
                entries = real_listdir(path)
                if str(path) == "/proc":
                    return [e for e in entries if e != str(hidden)]
                return entries

            def recording_killpg(kpgid, sig):
                if sig == 0:
                    return real_killpg(kpgid, sig)
                sent.append((kpgid, sig))
                return None  # swallowed: the hidden member must stay up

            monkeypatch.setattr(
                sup, "_proc_pid_view_filtered",
                lambda: "hidepid=2 (simulated)", raising=False)
            monkeypatch.setattr(os, "listdir", filtered_listdir)
            monkeypatch.setattr(os, "killpg", recording_killpg)
            with pytest.raises(SupervisedTeardownError):
                h.terminate(grace_s=0.5)
            monkeypatch.undo()
            assert sent == [], (
                f"signal sent through a declared-filtered /proc view: "
                f"{sent}")
            assert _live_pgrp_members(pgid) == [hidden], (
                "the hidden member must survive unsignalled — a "
                "filtered view is a refusal, not an escalation")
        finally:
            monkeypatch.undo()
            self._drain_group(pgid)
            assert libc.prctl(36, 0, 0, 0, 0) == 0

    def test_group_natural_exit_unreadable_member_refuses_unsignalled(
            self, monkeypatch):
        # The hidepid=1 shape: a group member is LISTED in /proc but
        # its stat is unreadable (EACCES — e.g. a member that exec'd a
        # setuid binary under hidepid=1). Present-but-unreadable is
        # occlusion, not "vanished mid-scan": the scan must not treat
        # the member as gone, and the natural-exit verification must
        # refuse (unsignalled) rather than verify off the remaining
        # zombie sighting — the same ENOENT/EACCES distinction its
        # sibling _member_provably_dead already draws.
        libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6",
                           use_errno=True)
        assert libc.prctl(36, 1, 0, 0, 0) == 0  # PR_SET_CHILD_SUBREAPER
        pgid = None
        sent: list[tuple[int, int]] = []
        try:
            h, pgid, hidden = self._held_zombie_plus_live_member()
            blocked = f"/proc/{hidden}/stat"
            real_open = builtins.open
            real_killpg = os.killpg

            def guarded_open(file, *args, **kwargs):
                if str(file) == blocked:
                    raise PermissionError(
                        errno.EACCES, "Permission denied", blocked)
                return real_open(file, *args, **kwargs)

            def recording_killpg(kpgid, sig):
                if sig == 0:
                    return real_killpg(kpgid, sig)
                sent.append((kpgid, sig))
                return None  # swallowed: the hidden member must stay up

            monkeypatch.setattr(builtins, "open", guarded_open)
            monkeypatch.setattr(os, "killpg", recording_killpg)
            with pytest.raises(SupervisedTeardownError):
                h.terminate(grace_s=0.5)
            monkeypatch.undo()
            assert sent == [], (
                f"signal sent past an unreadable (EACCES) member: {sent}")
            assert _live_pgrp_members(pgid) == [hidden], (
                "the unreadable member must survive unsignalled — "
                "EACCES is occlusion, not death")
        finally:
            monkeypatch.undo()
            self._drain_group(pgid)
            assert libc.prctl(36, 0, 0, 0, 0) == 0

    # Runs as PID 1 of its own user+mount+pid namespaces (root-mapped:
    # bind-mounting over a /proc pid dir needs CAP_SYS_ADMIN over the
    # mount namespace, which a plain current-user mapping does not
    # grant for this operation). Spawns a group-tier tree, waits for
    # the natural leader exit leaving one held zombie plus one live
    # member, then bind-mounts an empty dir over /proc/<live_member>:
    # the mount is DECLARED in /proc/self/mounts, yet the member's
    # stat reads ENOENT. A sound terminate() must refuse (occluded
    # view); returning VERIFIED while the member lives is the
    # false-verify this leg exists to catch. Every signal issued here
    # stays inside this leg's own kill-child pid namespace.
    _OVERMOUNT_LEG = r'''
import ctypes
import ctypes.util
import os
import sys
import tempfile
import time

sys.path.insert(0, sys.argv[1])

from core.sandbox.supervised import (  # noqa: E402
    SupervisedTeardownError,
    spawn_supervised,
)

libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6",
                   use_errno=True)
MS_BIND = 4096

h = spawn_supervised(["/bin/sh", "-c", "sleep 0.2 & sleep 300 & exit 0"],
                     on_parent_death="kill", pid_ns="off",
                     env={"PATH": "/usr/bin:/bin"})
pgid = h.pid
assert h.wait(timeout=10) == 0

# We are PID 1 here: the group's orphans reparent to us, the short
# sleep becomes a held zombie, the long sleep is the live member.
deadline = time.monotonic() + 10
zombie = live = None
while time.monotonic() < deadline:
    zs, ls = [], []
    for e in os.listdir("/proc"):
        if not e.isdigit() or int(e) == os.getpid():
            continue
        try:
            with open(f"/proc/{e}/stat", "rb") as f:
                rest = f.read().rsplit(b")", 1)[1].split()
        except OSError:
            continue
        if int(rest[2]) == pgid:
            (zs if rest[0] == b"Z" else ls).append(int(e))
    if zs and len(ls) == 1:
        zombie, live = zs[0], ls[0]
        break
    time.sleep(0.05)
assert zombie is not None and live is not None, "topology never reached"

empty = tempfile.mkdtemp()
r = libc.mount(empty.encode(), f"/proc/{live}".encode(), None,
               MS_BIND, None)
if r != 0:
    err = ctypes.get_errno()
    if err == 1:  # EPERM: environment cannot create the vector
        print(f"MOUNT-EPERM errno={err}")
        sys.exit(0)
    raise OSError(err, os.strerror(err), f"/proc/{live}")

try:
    try:
        rc2 = h.terminate(grace_s=0.5)
    except SupervisedTeardownError as e:
        print(f"REFUSED: {e}")
    else:
        try:
            os.kill(live, 0)
            alive = True
        except ProcessLookupError:
            alive = False
        print(f"FALSE-VERIFY rc={rc2} overmounted-member-alive={alive}")
        sys.exit(1)
finally:
    libc.umount2(f"/proc/{live}".encode(), 0)
    try:
        os.kill(live, 9)  # own spawn, own pid namespace
        os.waitpid(live, 0)
    except (ProcessLookupError, ChildProcessError, OSError):
        pass
'''

    def test_group_natural_exit_overmounted_member_refuses(
            self, tmp_path):
        # Mount-declared PER-PID occlusion: a bind mount over
        # /proc/<live_member> appears in the very mounts table the
        # detector parses, while the member's stat reads ENOENT
        # ("vanished"). The natural-exit verification must refuse, not
        # verify off the remaining zombie sighting. The vector needs a
        # root-mapped user namespace, so the leg runs as a subprocess
        # under its own unshare; an environment that cannot build the
        # vector skips loudly with the reason, never silently passes.
        unshare = shutil.which("unshare")
        if unshare is None:
            pytest.skip("unshare(1) not available")
        script = tmp_path / "overmount_leg.py"
        script.write_text(self._OVERMOUNT_LEG)
        repo_root = Path(sup.__file__).resolve().parents[2]
        proc = subprocess.run(
            [unshare, "-r", "--mount", "--pid", "--fork",
             "--mount-proc", "--kill-child",
             sys.executable, str(script), str(repo_root)],
            capture_output=True, text=True, timeout=120)
        out = proc.stdout + proc.stderr
        if ("REFUSED" not in out and "FALSE-VERIFY" not in out
                and "MOUNT-EPERM" not in out and proc.returncode != 0):
            pytest.skip(
                "cannot build the overmount vector here (root-mapped "
                f"userns unavailable): {proc.stderr.strip()[:200]}")
        if "MOUNT-EPERM" in out:
            pytest.skip(
                "bind mount over /proc/<pid> refused (EPERM) — the "
                "vector needs CAP_SYS_ADMIN over the mount namespace")
        assert "FALSE-VERIFY" not in out, (
            f"terminate() verified through a mount-declared per-pid "
            f"occlusion:\n{out}")
        assert proc.returncode == 0 and "REFUSED" in out, out
        assert "overmount" in out or "mount is declared over" in out, out

    def test_group_natural_exit_never_signals_unanchored_pgid(
            self, monkeypatch):
        # After the whole group is gone its pgid may be RECYCLED by an
        # unrelated process. Sighting a live member with a matching
        # pgrp proves the pgid is held NOW — not that it was held
        # continuously since this tree owned it — so a live sighting
        # that cannot be tied to the tree's own reap-time view must
        # refuse, never killpg. The stranger is simulated by forging
        # this test process's OWN stat to read as a live member of the
        # dead group's pgid (the pid is real and listed; only its group
        # membership and start time are forged).
        h = spawn_supervised(["/bin/true"], on_parent_death="kill",
                             pid_ns="off", env=_ENV)
        assert h.wait(timeout=_WAIT_S) == 0  # group fully gone
        pgid = h.pid
        imposter = os.getpid()
        forged = (f"{imposter} (stranger) S 1 {pgid} {pgid} 0 -1 "
                  f"4194304 " + "0 " * 12 + "424242 0 0 0 0").encode()
        real_open = builtins.open
        sent: list[tuple[int, int]] = []

        def forging_open(file, *args, **kwargs):
            if str(file) == f"/proc/{imposter}/stat":
                return io.BytesIO(forged)
            return real_open(file, *args, **kwargs)

        def stub_killpg(kpgid, sig):
            if sig != 0:
                sent.append((kpgid, sig))
            return None  # "the group exists" — the stranger holds it

        monkeypatch.setattr(builtins, "open", forging_open)
        monkeypatch.setattr(os, "killpg", stub_killpg)
        monkeypatch.setattr(sup, "_KILL_REAP_BUDGET_S", 1.0)
        with pytest.raises(SupervisedTeardownError):
            h.terminate(grace_s=0.3)
        monkeypatch.undo()
        assert sent == [], (
            f"signal sent at a possibly-recycled pgid with no identity "
            f"anchor: {sent}")

    def test_wait_timeout(self):
        h = spawn_supervised(["/bin/sleep", "30"],
                             on_parent_death="kill", pid_ns="off",
                             env=_ENV)
        try:
            with pytest.raises(TimeoutError):
                h.wait(timeout=0.2)
            assert h.returncode is None
        finally:
            h.kill()

    @pytest.mark.parametrize("pgid,refused", [
        (0, True), (1, True), (-1, True), (-12345, True),
    ])
    def test_group_refusal_predicate_low_pgids(self, pgid, refused):
        assert (_refusal(pgid, os.getpgrp()) is not None) is refused

    def test_group_refusal_predicate_own_group(self):
        own = os.getpgrp()
        if own <= 1:
            pytest.skip("test process's own pgid <= 1 — covered by "
                        "the low-pgid arm")
        assert _refusal(own, own) is not None
        assert "own process group" in _refusal(own, own)

    def test_group_refusal_predicate_allows_other_group(self):
        own = os.getpgrp()
        assert _refusal(own + 1 if own + 1 != 1 else 2, own) is None


def _refusal(pgid, own):
    return sup._group_signal_refusal(pgid, own)


class TestProbeCache:
    def test_definitive_false_is_cached(self, monkeypatch):
        monkeypatch.setattr(state, "_pidns_supervision_cache", None)
        calls = []

        def probe():
            calls.append(1)
            return (False, "denied by test")
        monkeypatch.setattr(probes, "_probe_pidns_supervision", probe)
        assert probes.check_pidns_supervision_available() == (
            False, "denied by test")
        assert probes.check_pidns_supervision_available() == (
            False, "denied by test")
        assert len(calls) == 1

    def test_true_is_cached(self, monkeypatch):
        monkeypatch.setattr(state, "_pidns_supervision_cache", None)
        calls = []

        def probe():
            calls.append(1)
            return (True, "")
        monkeypatch.setattr(probes, "_probe_pidns_supervision", probe)
        assert probes.check_pidns_supervision_available() == (True, "")
        assert probes.check_pidns_supervision_available() == (True, "")
        assert len(calls) == 1

    def test_indeterminate_is_never_cached(self, monkeypatch):
        monkeypatch.setattr(state, "_pidns_supervision_cache", None)
        calls = []

        def probe():
            calls.append(1)
            return (None, "under load")
        monkeypatch.setattr(probes, "_probe_pidns_supervision", probe)
        assert probes.check_pidns_supervision_available()[0] is None
        assert probes.check_pidns_supervision_available()[0] is None
        assert len(calls) == 2
        assert state._pidns_supervision_cache is None

    def test_runtime_refusal_note_overwrites(self, monkeypatch):
        monkeypatch.setattr(state, "_pidns_supervision_cache",
                            (True, ""))
        probes.note_pidns_supervision_refused("live EPERM")
        assert probes.check_pidns_supervision_available() == (
            False, "live EPERM")

    def test_real_probe_returns_shape(self):
        # The real probe on this host: any verdict is acceptable, the
        # contract is the shape and that it never raises.
        verdict, reason = probes._probe_pidns_supervision()
        assert verdict in (True, False, None)
        assert isinstance(reason, str)
        if verdict is not True:
            assert reason  # non-engaged verdicts must carry a reason

    def test_selfmap_write_refusal_is_definitive_false(self, monkeypatch):
        # Probe/live-path fidelity fence: hosts exist (Ubuntu's AppArmor
        # unprivileged-userns restriction) where the combined unshare
        # succeeds and the identity self-map WRITE is what gets denied
        # — the live spawn fails closed there, so the probe must say
        # False, not True. The monkeypatched os functions are inherited
        # by the probe's forked child: unshare is a no-op (hermetic on
        # hosts that deny userns creation) and the three self-map opens
        # raise the venue's EACCES.
        _MAP_PATHS = ("/proc/self/setgroups", "/proc/self/gid_map",
                      "/proc/self/uid_map")
        real_open = os.open

        def deny_selfmap_open(path, flags, *args, **kwargs):
            if path in _MAP_PATHS:
                raise PermissionError(errno.EACCES, "Permission denied",
                                      path)
            return real_open(path, flags, *args, **kwargs)

        monkeypatch.setattr(os, "unshare", lambda flags: None)
        monkeypatch.setattr(os, "open", deny_selfmap_open)
        verdict, reason = probes._probe_pidns_supervision()
        assert verdict is False
        assert "self-map write" in reason


class TestGuardrails:
    """Not-a-sandbox pins: these strings and shapes are load-bearing —
    they are what keeps this primitive from being mistaken for (or
    drifting into) a confinement surface."""

    def test_module_docstring_disclaims_confinement(self):
        assert "NOT a sandbox" in sup.__doc__
        assert "NO security confinement" in sup.__doc__

    def test_spawn_docstring_disclaims_confinement(self):
        assert "NOT a sandbox" in spawn_supervised.__doc__

    def test_handle_docstring_disclaims_confinement(self):
        assert "NOT a sandbox" in SupervisedHandle.__doc__

    def test_exit_path_invariant_pinned(self):
        # The invariant is scoped honestly: A's OWN exit paths carry
        # it; an unhandled fatal signal kills A with its default
        # disposition and the tree collapses via PDEATHSIG — a
        # collapse, never abandonment.
        doc = " ".join(sup.__doc__.split())
        assert ("on its own code paths A exits only because B exited"
                in doc)
        assert "never abandonment of a live B" in doc
        assert "default disposition" in doc

    def test_confinement_attribute_is_none_string(self, monkeypatch):
        h = spawn_supervised(["/bin/true"], on_parent_death="kill",
                             pid_ns="off", env=_ENV)
        assert h.confinement == "none"
        h.wait(timeout=_WAIT_S)

    def test_no_run_named_public_surface(self):
        offenders = [n for n in vars(sup)
                     if n.startswith("run_") or n.startswith("Run")]
        # _run_ns_init_waiter is private plumbing, not a run_* API.
        assert offenders == [], offenders

    def test_handle_has_no_finalizer(self):
        # Fleet-kill lesson: no __del__ — a gc-timed signal from a
        # stale handle is exactly the broadcast-kill hazard class.
        assert "__del__" not in SupervisedHandle.__dict__

    def test_teardown_error_is_recoverable_exception(self):
        # Recoverable condition (the handle stays live), so Exception
        # family — unlike SandboxSetupError's deliberate BaseException.
        assert issubclass(SupervisedTeardownError, RuntimeError)
