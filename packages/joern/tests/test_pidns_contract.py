"""Contract pins for the pid-namespace supervision tier.

Each test nails one guarantee of the supervision contract to its
observable behaviour — waiter fail-closed arming, orphan reaping,
signal forwarding, tier-report integrity, single-call unshare shape,
bounded stop waits, loud uncorroborated-refusal, and the RAPTOR-death
path of the in-namespace orphan watchdog. They complement
``test_pidns_forwarder.py`` / ``test_pidns_tier.py``: those exercise
the flows, these pin the individual clauses an implementation could
quietly weaken.

No test asserts process-group properties; every signalled pid is our
own fork/Popen or a ``pgrep -P`` walk of it (zombie-aware — see the
authorship note in ``test_pidns_forwarder.py``).
"""
from __future__ import annotations

import os
import select
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

from packages.joern import netns_forwarder as nf
from packages.joern import server as server_mod

_SCRIPT = Path(nf.__file__).resolve()
_REPO_ROOT = _SCRIPT.parents[2]


def _pidns_available() -> bool:
    try:
        return subprocess.run(
            [sys.executable, str(_SCRIPT), "--self-probe-pidns"],
            capture_output=True, timeout=30, check=False,
        ).returncode == 0
    except (subprocess.TimeoutExpired, OSError):
        return False


needs_pidns = pytest.mark.skipif(
    not _pidns_available(),
    reason="single-call unshare(USER|NET|PID) unavailable on this host",
)


@pytest.fixture
def restore_signal_handlers():
    saved = {s: signal.getsignal(s)
             for s in (signal.SIGTERM, signal.SIGINT)}
    yield
    for sig, handler in saved.items():
        signal.signal(sig, handler)


# ── waiter prctl failure must fail CLOSED (exit 96, no arm) ──────────

_PRCTL_FAIL_DRIVER = r"""
import os, sys
sys.path.insert(0, sys.argv[1])
import packages.joern.netns_forwarder as nf

class _BrokenLibc:
    def prctl(self, *a):
        return -1

live_r, live_w = os.pipe2(os.O_CLOEXEC)
arm_r, arm_w = os.pipe2(os.O_CLOEXEC)
pid = os.fork()
if pid != 0:
    os.close(live_r); os.close(arm_w)
    got_arm = os.read(arm_r, 1)
    _, status = os.waitpid(pid, 0)
    rc = os.WEXITSTATUS(status) if os.WIFEXITED(status) else 128
    # fail-closed contract: NO arm byte and the distinct unarmed code
    sys.exit(90 if (got_arm == b"" and rc == 96) else 91)
os.close(live_w); os.close(arm_r)
nf._LIBC = _BrokenLibc()
nf._ns_init_split(live_r, arm_w)
os._exit(7)  # only reachable if the broken prctl was ignored
"""


def test_waiter_prctl_failure_fails_closed_without_arming():
    """A PR_SET_PDEATHSIG failure must abort the waiter with
    _WAITER_EXIT_PRCTL_FAILED before the arm byte — never
    arm-and-continue with the safety net absent."""
    rc = subprocess.run(
        [sys.executable, "-c", _PRCTL_FAIL_DRIVER, str(_REPO_ROOT)],
        timeout=30, check=False,
    ).returncode
    assert rc == 90


# ── P dead before prctl → waiter collapses, never arms ───────────────

_PARENT_DEAD_DRIVER = r"""
import os, sys
sys.path.insert(0, sys.argv[1])
import packages.joern.netns_forwarder as nf

live_r, live_w = os.pipe2(os.O_CLOEXEC)
arm_r, arm_w = os.pipe2(os.O_CLOEXEC)
pid = os.fork()
if pid != 0:
    os.close(live_r); os.close(arm_w)
    got_arm = os.read(arm_r, 1)
    _, status = os.waitpid(pid, 0)
    rc = os.WEXITSTATUS(status) if os.WIFEXITED(status) else 128
    sys.exit(90 if (got_arm == b"" and rc == 95) else 91)
os.close(live_w); os.close(arm_r)
# Simulate P dying in the fork->prctl window: the liveness pipe's sole
# write end is already gone when the waiter starts.
os.close(live_r)
r2, w2 = os.pipe2(os.O_CLOEXEC)
os.close(w2)  # a pipe that is already HUP, as live_r would read
nf._ns_init_split(r2, arm_w)
os._exit(7)  # only reachable if the liveness probe was skipped
"""


def test_waiter_detects_parent_death_in_prearm_window():
    """With the liveness pipe already HUP at waiter entry (P died
    before PDEATHSIG armed), the waiter must exit
    _WAITER_EXIT_PARENT_DIED without arming — not supervise an
    orphaned tree."""
    rc = subprocess.run(
        [sys.executable, "-c", _PARENT_DEAD_DRIVER, str(_REPO_ROOT)],
        timeout=30, check=False,
    ).returncode
    assert rc == 90


# ── reparented orphans are REAPED, not left as zombies ───────────────

_ZOMBIE_DRIVER = r"""
import os, sys, time
sys.path.insert(0, sys.argv[1])
from packages.joern.netns_forwarder import _ns_init_split

live_r, live_w = os.pipe2(os.O_CLOEXEC)
arm_r, arm_w = os.pipe2(os.O_CLOEXEC)
pid = os.fork()
if pid != 0:
    os.close(live_r); os.close(arm_w)
    if os.read(arm_r, 1) != b"A":
        sys.exit(96)
    _, status = os.waitpid(pid, 0)
    sys.exit(os.WEXITSTATUS(status) if os.WIFEXITED(status) else 128)
os.close(live_w); os.close(arm_r)
decoy = os.fork()
if decoy == 0:
    time.sleep(0.1)
    os._exit(1)  # dies while C is still alive; the waiter must reap it
_ns_init_split(live_r, arm_w)
# --- C: wait for the waiter to fully reap the dead decoy ---
deadline = time.monotonic() + 10
while time.monotonic() < deadline:
    try:
        # /proc entry present = alive, or dead-but-unreaped (zombie).
        # Only a completed reap removes it.
        open(f"/proc/{decoy}/stat").close()
    except OSError:
        os._exit(90)  # decoy fully reaped: contract holds
    time.sleep(0.1)
os._exit(91)  # never reaped within the window (zombie squatter)
"""


def test_waiter_reaps_orphans_while_supervised_child_lives():
    """A child that dies while C is still running must be reaped and
    discarded by the waiter (pid-ns init duty) — a waitpid(child)-only
    loop accumulates zombies for the namespace's whole life."""
    rc = subprocess.run(
        [sys.executable, "-c", _ZOMBIE_DRIVER, str(_REPO_ROOT)],
        timeout=30, check=False,
    ).returncode
    assert rc == 90


# ── the waiter forwards INT/HUP/QUIT, not only TERM ──────────────────

_SIGNAL_FORWARD_DRIVER = r"""
import os, signal, sys, time
sys.path.insert(0, sys.argv[1])
from packages.joern.netns_forwarder import _ns_init_split

signum = getattr(signal, sys.argv[2])
live_r, live_w = os.pipe2(os.O_CLOEXEC)
arm_r, arm_w = os.pipe2(os.O_CLOEXEC)
pid = os.fork()
if pid != 0:
    os.close(live_r); os.close(arm_w)
    if os.read(arm_r, 1) != b"A":
        sys.exit(96)
    time.sleep(0.3)  # let C install its trap
    os.kill(pid, signum)  # our own just-forked child, unreaped
    _, status = os.waitpid(pid, 0)
    if os.WIFEXITED(status):
        sys.exit(os.WEXITSTATUS(status))
    sys.exit(128 + os.WTERMSIG(status))
os.close(live_w); os.close(arm_r)
_ns_init_split(live_r, arm_w)
# --- C: the forwarded signal must arrive here ---
signal.signal(signum, lambda *_: os._exit(44))
for _ in range(600):
    time.sleep(0.1)
os._exit(9)
"""


@pytest.mark.parametrize("signame", ["SIGINT", "SIGHUP", "SIGQUIT"])
def test_waiter_forwards_every_contract_signal(signame):
    """The ns-init contract names TERM/INT/HUP/QUIT; a waiter that
    only forwards TERM dies to the default action instead, collapsing
    the namespace without the graceful hop."""
    rc = subprocess.run(
        [sys.executable, "-c", _SIGNAL_FORWARD_DRIVER,
         str(_REPO_ROOT), signame],
        timeout=30, check=False,
    ).returncode
    assert rc == 44, f"{signame} did not forward through the waiter"


# ── the arm wait is BOUNDED ──────────────────────────────────────────


def test_arm_timeout_is_actually_bounded(restore_signal_handlers):
    """A waiter that never arms must be refused within the configured
    budget, not whenever it happens to die on its own."""
    arm_r, arm_w = os.pipe()
    gone_r, gone_w = os.pipe()
    pid = os.fork()
    if pid == 0:  # never arms; exits on its own well past the budget
        time.sleep(20)
        os._exit(0)
    os.close(arm_w)
    try:
        t0 = time.monotonic()
        rc = nf._supervise_ns_init(
            pid, arm_r, gone_w, None,
            poll_s=0.05, arm_timeout_s=0.5,
        )
        elapsed = time.monotonic() - t0
        assert rc == nf.EXIT_PIDNS_WAITER_UNARMED
        assert elapsed < 5.0, (
            f"arm refusal took {elapsed:.1f}s — the timeout is not "
            f"enforced")
    finally:
        for fd in (gone_r, gone_w):
            try:
                os.close(fd)
            except OSError:
                pass
        try:
            os.kill(pid, signal.SIGKILL)
            os.waitpid(pid, 0)
        except (ProcessLookupError, ChildProcessError):
            pass


# ── P never signals the ns-init pid after reaping it ─────────────────


def test_supervisor_never_forwards_to_a_reaped_pid(
    monkeypatch, restore_signal_handlers,
):
    """Once the ns-init is reaped its pid is recyclable; the forward
    handler must be a no-op from then on."""
    arm_r, arm_w = os.pipe()
    gone_r, gone_w = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.write(arm_w, b"A")
        os._exit(0)
    os.close(arm_w)
    try:
        rc = nf._supervise_ns_init(pid, arm_r, gone_w, None, poll_s=0.05)
        assert rc == 0
        kills: list[tuple[int, int]] = []
        monkeypatch.setattr(
            nf.os, "kill", lambda p, s: kills.append((p, s)))
        # the handler installed by _supervise_ns_init is still live
        signal.raise_signal(signal.SIGTERM)
        assert kills == [], (
            f"forward handler signalled {kills} after the ns-init was "
            f"reaped (pid-recycle hazard)")
    finally:
        for fd in (gone_r, gone_w):
            try:
                os.close(fd)
            except OSError:
                pass


# ── a group boot must report group ───────────────────────────────────


def test_group_boot_reports_group_tier(
    monkeypatch, uds_dir: str, restore_signal_handlers,
):
    """The achieved-tier report on a boot without --pidns must be the
    group tier — a forwarder-side misstamp would make the server skip
    the kill ladder with no namespace behind it."""
    monkeypatch.setattr(nf, "enter_private_netns", lambda **kw: None)
    monkeypatch.setattr(nf, "bring_loopback_up", lambda: None)
    ready_r, ready_w = os.pipe()
    try:
        rc = nf.main([
            "--ready-fd", str(ready_w),
            "--socket", os.path.join(uds_dir, "j.sock"),
            "--port", "47101", "--", "true",
        ])
        assert rc == 0
        readable, _, _ = select.select([ready_r], [], [], 5)
        assert readable, "no tier report on a group boot"
        assert os.read(ready_r, 64) == b"supervision_tier=group\n"
    finally:
        for fd in (ready_r, ready_w):
            try:
                os.close(fd)
            except OSError:
                pass


# ── the unshare is ONE combined call ─────────────────────────────────


def test_pidns_unshare_is_a_single_combined_call(monkeypatch):
    """CLONE_NEWPID must ride the SAME unshare call as USER|NET —
    staged second calls are refused on restricted hosts even where
    the combined call succeeds (the documented staged-refusal
    class)."""
    calls: list[int] = []

    def record(flags: int) -> None:
        calls.append(flags)
        raise RuntimeError("stop before /proc writes")

    monkeypatch.setattr(nf.os, "unshare", record)
    with pytest.raises(RuntimeError, match="stop before"):
        nf.enter_private_netns(include_pid=True)
    assert len(calls) == 1, f"expected ONE unshare call, saw {calls}"
    assert calls[0] & nf._CLONE_NEWPID
    assert calls[0] & nf._CLONE_NEWUSER
    assert calls[0] & nf._CLONE_NEWNET


# ── the ready-report pipe is unreachable below P ─────────────────────


@needs_pidns
def test_ready_fd_not_held_below_supervisor(tmp_path, uds_dir: str):
    """Only P may hold the achieved-tier report channel; a write end
    surviving into B/C keeps the parent's EOF fallback from firing
    and widens the stamp surface."""
    marker = tmp_path / "up"
    body = (
        f"import os, time; open({str(marker)!r}, 'w').write('x'); "
        "time.sleep(600)"
    )
    r, w = os.pipe()
    os.set_inheritable(w, True)
    proc = subprocess.Popen(
        [sys.executable, str(_SCRIPT), "--pidns",
         "--ready-fd", str(w),
         "--socket", os.path.join(uds_dir, "j.sock"), "--port", "47103",
         "--", sys.executable, "-c", body],
        pass_fds=(w,),
    )
    os.close(w)
    try:
        line = b""
        while not line.endswith(b"\n"):
            chunk = os.read(r, 64)
            if not chunk:
                break
            line += chunk
        assert line == b"supervision_tier=pidns\n"
        deadline = time.monotonic() + 30
        while not marker.exists():
            assert time.monotonic() < deadline, "stack never came up"
            time.sleep(0.1)
        # P closed its copy after reporting; ours is the read end. If
        # nothing below P leaked a write end, the pipe is now
        # write-endless and read() returns EOF promptly.
        readable, _, _ = select.select([r], [], [], 10)
        assert readable, (
            "ready pipe still has a live write end below P "
            "(no EOF within 10s)")
        assert os.read(r, 64) == b""
    finally:
        os.close(r)
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=15)


# ── pidns-tier orphan watchdog fires on RAPTOR death ─────────────────


@needs_pidns
def test_pidns_orphan_watchdog_reaps_after_raptor_death(
    tmp_path, uds_dir: str,
):
    """On the pidns tier the in-namespace watchdog cannot see RAPTOR
    die via getppid(); the supervisor must signal it down the gone
    pipe, or an orphaned idle JVM squats forever — the exact
    stranded-multi-GB class the watchdog exists to reap."""
    marker = tmp_path / "up"
    shim = (
        "import subprocess, sys, time\n"
        "p = subprocess.Popen(sys.argv[1:])\n"
        "print(p.pid, flush=True)\n"
        "time.sleep(600)\n"
    )
    body = (
        f"import os, time; open({str(marker)!r}, 'w').write('x'); "
        "time.sleep(600)"
    )
    raptor = subprocess.Popen(
        [sys.executable, "-c", shim,
         sys.executable, str(_SCRIPT), "--pidns",
         "--orphan-idle-ttl", "1",
         "--socket", os.path.join(uds_dir, "j.sock"), "--port", "47102",
         "--", sys.executable, "-c", body],
        stdout=subprocess.PIPE, text=True,
    )
    try:
        assert raptor.stdout is not None
        forwarder_pid = int(raptor.stdout.readline())
        deadline = time.monotonic() + 30
        while not marker.exists():
            assert time.monotonic() < deadline, "stack never came up"
            time.sleep(0.1)

        def kids(pid: int) -> list[int]:
            out = subprocess.run(["pgrep", "-P", str(pid)],
                                 capture_output=True, text=True,
                                 check=False)
            return [int(x) for x in out.stdout.split()]

        members, frontier = [forwarder_pid], [forwarder_pid]
        for _ in range(4):
            frontier = [k for p in frontier for k in kids(p)]
            members.extend(frontier)
        # kill-0-gated kill of OUR OWN shim child only
        os.kill(raptor.pid, 0)
        raptor.kill()
        raptor.wait(timeout=10)

        def gone(p: int) -> bool:
            try:
                os.kill(p, 0)
            except ProcessLookupError:
                return True
            except OSError:
                return False
            # zombies count as gone: when this test runs as a pid-ns
            # init (kill-containment idiom) collapsed orphans reparent
            # here unreaped; kill-0 still succeeds on them.
            try:
                with open(f"/proc/{p}/stat") as f:
                    return f.read().rsplit(")", 1)[1].split()[0] == "Z"
            except OSError:
                return True

        def all_gone() -> bool:
            return all(gone(p) for p in members)

        # watchdog poll (5s) + ttl (1s) + escalation grace, bounded
        deadline = time.monotonic() + 30
        while not all_gone():
            assert time.monotonic() < deadline, (
                "orphaned idle pidns tree was never reaped — the "
                "RAPTOR-death signal did not reach the in-namespace "
                "watchdog")
            time.sleep(0.5)
    finally:
        if raptor.poll() is None:
            raptor.kill()
            raptor.wait(timeout=10)
        for p in locals().get("members", []):
            try:
                os.kill(p, 0)
            except (ProcessLookupError, OSError):
                continue
            try:
                os.kill(p, signal.SIGKILL)
            except OSError:
                pass


# ── only the FIRST report line may stamp the tier ────────────────────


class TestStampFirstLineWins:
    def _read(self, payload: bytes) -> str:
        r, w = os.pipe()
        try:
            os.write(w, payload)
            os.close(w)
            return server_mod._read_achieved_tier(r, timeout_s=5.0)
        finally:
            os.close(r)

    def test_pidns_on_a_later_line_reads_group(self):
        """Bytes after the first line are not the forwarder's
        arm-gated report and must never stamp the strong tier."""
        assert self._read(
            b"garbage\nsupervision_tier=pidns\n") == "group"

    def test_first_line_pidns_with_trailing_noise_reads_pidns(self):
        assert self._read(
            b"supervision_tier=pidns\ntrailing noise\n") == "pidns"


# ── pidns stop paths keep their BOUNDED waits ────────────────────────


def _pidns_server_with_proc():
    from unittest.mock import MagicMock
    srv = server_mod.JoernServer()
    proc = MagicMock()
    proc.pid = 2_000_000_000  # inert: beyond pid_max
    proc.poll.return_value = None
    proc.wait = MagicMock(return_value=0)
    srv._proc = proc
    srv._pgid = proc.pid
    srv._supervision_tier = "pidns"
    return srv, proc


def test_stop_pidns_first_wait_is_bounded():
    """stop() on the strong tier must pass the shutdown grace to
    wait() — an unbounded wait turns a stalled collapse into a hung
    teardown."""
    from unittest.mock import patch
    srv, proc = _pidns_server_with_proc()
    with patch("packages.joern.server._ensure_group_dead"), \
         patch("packages.joern.server.os.killpg",
               side_effect=ProcessLookupError):
        srv.stop()
    (_args, kwargs) = proc.wait.call_args_list[0]
    assert kwargs.get("timeout") == server_mod._SHUTDOWN_GRACE_S, (
        f"stop() first wait not bounded: {proc.wait.call_args_list[0]}")


def test_stop_fast_pidns_wait_is_bounded():
    """The forced-exit path is about to os._exit — its single wait
    must carry the caller's grace."""
    srv, proc = _pidns_server_with_proc()
    assert srv.stop_fast(grace_s=1.25) is True
    (_args, kwargs) = proc.wait.call_args_list[0]
    assert kwargs.get("timeout") == 1.25, (
        f"stop_fast() wait not bounded: {proc.wait.call_args_list[0]}")


# ── pidns never engages without the netns tier ───────────────────────


def test_pidns_requires_netns_tier(monkeypatch):
    """Without the forwarder there is no --pidns boot; a bare-JVM exit
    code that happens to be 97 must ride the ordinary
    died-during-boot path, never the tier relaunch."""
    from unittest.mock import MagicMock, patch

    from packages.joern.netns_forwarder import EXIT_PIDNS_UNSHARE_REFUSED

    srv = server_mod.JoernServer()
    procs = []

    def fake_popen(cmd, **kwargs):
        proc = MagicMock()
        proc.pid = 2_000_000_000
        proc.poll.return_value = EXIT_PIDNS_UNSHARE_REFUSED
        proc.stderr = MagicMock()
        procs.append((list(cmd), proc))
        return proc

    with (
        patch("packages.joern.prereqs._java_version", return_value=21),
        patch("packages.joern.server._netns_isolation_available",
              return_value=False),
        patch("packages.joern.server._pidns_supervision_available",
              return_value=True),
        patch("packages.joern.server._server_auth_supported",
              return_value=True),
        patch("packages.joern.server._repl_bridge_path",
              return_value="/opt/joern/repl-bridge"),
        patch("packages.joern.server.subprocess.Popen",
              side_effect=fake_popen),
        patch("packages.joern.server.os.killpg",
              side_effect=ProcessLookupError),
        patch("packages.joern.server._invalidate_pidns_probe")
            as invalidate,
        patch.object(srv, "_wait_for_ready", side_effect=[False, False]),
        pytest.raises(RuntimeError, match="failed to start"),
    ):
        srv.start()
    invalidate.assert_not_called()
    for cmd, _proc in procs:
        assert "--pidns" not in cmd


# ── the uncorroborated-refusal branch must be LOUD ───────────────────


def test_uncorroborated_refusal_is_loud(caplog):
    """Refusing to escalate into an uncorroborated group is correct,
    but it leaks whatever genuinely survived — the refusal must WARN
    so an operator learns the group is neither dead nor being
    killed."""
    import logging

    proc = subprocess.Popen(
        [sys.executable, "-c",
         "import time; print('ready', flush=True); time.sleep(300)"],
        stdout=subprocess.PIPE, text=True, start_new_session=True,
    )
    try:
        assert proc.stdout is not None
        proc.stdout.readline()
        with caplog.at_level(logging.WARNING,
                             logger=server_mod.logger.name):
            assert server_mod._ensure_group_dead(
                proc.pid, label="uncorroborated survivor") is False
        assert proc.poll() is None, "refusal must not signal the group"
        msgs = [r.getMessage() for r in caplog.records
                if r.levelno >= logging.WARNING]
        assert any("corroborates" in m for m in msgs), (
            f"uncorroborated refusal was silent (warnings: {msgs})")
    finally:
        try:
            proc.kill()  # our own Popen child, handle-gated
        except OSError:
            pass
        proc.wait(timeout=10)


# ── parent-side ready_w closed once it crossed the spawn ─────────────


def test_parent_ready_write_end_closed_after_boot():
    """The parent's copy of the ready-report write end must be closed
    once the fd went across the spawn — a leaked copy means the read
    end can never see POLLHUP after the forwarder dies (one leaked fd
    per boot, and every tier read on a dead forwarder degrades to the
    full report timeout)."""
    from unittest.mock import MagicMock, patch

    srv = server_mod.JoernServer()
    passed: list[int] = []

    def fake_popen(cmd, **kwargs):
        fds = kwargs.get("pass_fds") or ()
        passed.extend(fds)
        if fds:
            os.write(fds[0], b"supervision_tier=pidns\n")
        proc = MagicMock()
        proc.pid = 2_000_000_000  # inert: beyond pid_max
        proc.poll.return_value = None
        proc.stderr = MagicMock()
        return proc

    closed: list[int] = []
    real_close = os.close

    def recording_close(fd):
        closed.append(fd)
        real_close(fd)

    with (
        patch("packages.joern.prereqs._java_version", return_value=21),
        patch("packages.joern.server._netns_isolation_available",
              return_value=True),
        patch("packages.joern.server._pidns_supervision_available",
              return_value=True),
        patch("packages.joern.server._server_auth_supported",
              return_value=True),
        patch("packages.joern.server._repl_bridge_path",
              return_value="/opt/joern/repl-bridge"),
        patch("packages.joern.server.subprocess.Popen",
              side_effect=fake_popen),
        patch("packages.joern.server.os.close",
              side_effect=recording_close),
        patch("packages.joern.server.os.killpg",
              side_effect=ProcessLookupError),
        patch.object(srv, "_wait_for_ready", return_value=True),
        patch.object(srv, "_warmup_imports"),
        patch("packages.joern.server._find_jvm_member",
              return_value=None),
    ):
        srv.start()
        try:
            assert passed, "no ready fd crossed the spawn"
            assert passed[0] in closed, (
                f"parent-side ready_w fd {passed[0]} never closed "
                f"(closed so far: {closed})")
        finally:
            srv.stop()
