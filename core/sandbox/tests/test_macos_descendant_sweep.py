"""macOS post-wait descendant sweep.

Process-group teardown (death-pipe → sandbox pgrp SIGKILL; killpg of
the shim session as backstop) cannot reach a fork+setsid descendant —
the allow-default seatbelt profile permits setsid — and pre-fix,
NORMAL completion performed no teardown at all, so such a descendant
outlived the run, the timeout path, and the orchestrator.

The fix is a proc-table sweep (ps -axo pid,ppid,pgid; macOS has no
/proc) applied on all exit paths, in both _macos_spawn (parent side)
and libexec/raptor-seatbelt-shim (which owns the normal-completion
path, where it still sees the live tree). The collection logic is a
pure function — (pid, ppid, pgid) table in, kill list out — so it is
fully testable on this Linux CI host; the shim additionally gets a
real-subprocess test using Linux setsid(1) as a stand-in escapee.
"""

import os
import shutil
import signal
import subprocess
import sys
import time
from importlib.machinery import SourceFileLoader
from importlib.util import module_from_spec, spec_from_loader
from pathlib import Path

import pytest

from core.sandbox import _macos_spawn
from core.testing.module_bindings import patch_module_attribute

SHIM_PATH = (
    Path(__file__).resolve().parents[3] / "libexec" / "raptor-seatbelt-shim"
)

# A pid far above anything this test host allocates in practice; only
# ever handed to fakes/recorders, never signalled for real.
FAKE_SHIM_PID = 4190100


# --- pure collection logic (parent-side copy) --------------------------

class TestCollectDescendants:
    # Table model: shim 100 (session leader, pgid 100) forked
    # sandbox-exec 101 (own pgrp 101), which execs into the target;
    # the target forks children.
    BASE = [
        (100, 50, 100),    # the shim itself
        (101, 100, 101),   # sandbox-exec / target
        (102, 101, 101),   # target's forked child, still in the group
    ]

    def test_direct_descendants_collected(self):
        got = _macos_spawn.collect_descendants(self.BASE, 100)
        assert got == {101, 102}

    def test_setsid_escapee_still_collected_via_ppid_chain(self):
        # setsid changes pgid/session, NOT ppid: while its ancestors
        # live, the ppid walk still finds it.
        table = self.BASE + [(103, 102, 103)]  # fork+setsid escapee
        got = _macos_spawn.collect_descendants(table, 100)
        assert 103 in got

    def test_escapee_children_collected_transitively(self):
        table = self.BASE + [(103, 102, 103), (104, 103, 103)]
        got = _macos_spawn.collect_descendants(table, 100)
        assert {103, 104} <= got

    def test_unrelated_processes_never_collected(self):
        table = self.BASE + [
            (200, 1, 200),     # unrelated daemon
            (201, 200, 200),   # its child
            (50, 1, 50),       # the shim's own parent
        ]
        got = _macos_spawn.collect_descendants(table, 100)
        assert got == {101, 102}

    def test_root_itself_never_collected(self):
        assert 100 not in _macos_spawn.collect_descendants(self.BASE, 100)

    def test_reparented_group_member_collected_via_extra_pgids(self):
        # ppid chain broken (reparented to launchd/pid 1) but still in
        # the sandbox process group.
        table = self.BASE + [(105, 1, 101)]
        without = _macos_spawn.collect_descendants(table, 100)
        assert 105 not in without  # honest: ppid walk alone cannot see it
        with_pg = _macos_spawn.collect_descendants(
            table, 100, extra_pgids=(101,))
        assert 105 in with_pg

    def test_extra_pgid_member_descendants_collected(self):
        table = self.BASE + [(105, 1, 101), (106, 105, 106)]
        got = _macos_spawn.collect_descendants(
            table, 100, extra_pgids=(101,))
        assert {105, 106} <= got

    def test_reparented_setsid_orphan_invisible_post_exit(self):
        # THE documented blind spot: after the whole tree died, a
        # fork+setsid orphan shows (pid, 1, own-pgid) — no ppid path,
        # no group membership. A post-exit table alone cannot
        # attribute it; bridging needs the while-alive snapshot
        # (covered in TestSweepDescendants below).
        table = [(100, 50, 100), (103, 1, 103), (200, 1, 200)]
        got = _macos_spawn.collect_descendants(table, 100)
        assert got == set()

    def test_protect_set_honoured(self):
        got = _macos_spawn.collect_descendants(
            self.BASE, 100, protect={102})
        assert got == {101}

    def test_pid_one_never_collected(self):
        table = self.BASE + [(1, 100, 1)]  # garbage table claiming init
        got = _macos_spawn.collect_descendants(table, 100)
        assert 1 not in got

    def test_cyclic_garbage_table_terminates(self):
        table = [(100, 50, 100), (300, 301, 300), (301, 300, 300)]
        got = _macos_spawn.collect_descendants(table, 100)
        assert got == set()

    def test_unparseable_ps_lines_skipped(self):
        text = " 100  50 100\ngarbage line\n 101 100 101\n 12 x 9\n"
        assert _macos_spawn._parse_ps_table(text) == [
            (100, 50, 100), (101, 100, 101)]


class TestSweepDescendants:
    # Every direct sweep call passes protect=frozenset(): the sweep's
    # default protect set is {os.getpid(), os.getppid()}, and inside a
    # container pid namespace a pytest worker can genuinely run AS pid
    # 101/103 — silently exempting that synthetic pid from the verdict
    # and flipping these assertions on whichever worker drew the pid.
    @pytest.fixture(autouse=True)
    def _record_kills(self, monkeypatch):
        self.killed = []
        monkeypatch.setattr(
            _macos_spawn, "_kill_pid", self.killed.append)

    def test_live_descendants_swept(self):
        tables = [[(100, 50, 100), (101, 100, 101), (103, 101, 103)], []]
        swept = _macos_spawn._sweep_descendants(
            100, snapshot_fn=lambda: tables.pop(0),
            protect=frozenset())
        assert swept == {101, 103}
        assert sorted(self.killed) == [101, 103]

    def test_reparented_orphan_bridged_by_live_snapshot(self):
        # While alive: escapee 103 parented inside the tree, pgid 103.
        live = [(100, 50, 100), (101, 100, 101), (103, 101, 103)]
        # Post-exit: tree gone, 103 reparented to pid 1 — unreachable
        # from the root in this table.
        post = [(100, 50, 100), (103, 1, 103), (200, 1, 200)]
        tables = [post, []]
        swept = _macos_spawn._sweep_descendants(
            100, live_snapshot=live, snapshot_fn=lambda: tables.pop(0),
            protect=frozenset())
        assert swept == {103}
        assert 200 not in self.killed

    def test_orphan_without_live_snapshot_escapes_honestly(self):
        # The documented blind spot: no while-alive snapshot → the
        # reparented orphan cannot be attributed and is NOT killed.
        post = [(100, 50, 100), (103, 1, 103)]
        tables = [post, []]
        swept = _macos_spawn._sweep_descendants(
            100, snapshot_fn=lambda: tables.pop(0),
            protect=frozenset())
        assert swept == set()
        assert self.killed == []

    def test_pid_reuse_guard_checks_pgid(self):
        # 103 was a descendant while alive (pgid 103); post-exit a
        # process with the same pid sits in a DIFFERENT group —
        # recycled pid, must not be signalled.
        live = [(100, 50, 100), (101, 100, 101), (103, 101, 103)]
        post = [(100, 50, 100), (103, 1, 777)]
        tables = [post, []]
        swept = _macos_spawn._sweep_descendants(
            100, live_snapshot=live, snapshot_fn=lambda: tables.pop(0),
            protect=frozenset())
        assert swept == set()

    def test_sweep_is_bounded(self):
        # A target that keeps re-forking: every snapshot shows a live
        # descendant. The sweep must stop after max_passes rounds.
        calls = {"n": 0}

        def snapshot():
            calls["n"] += 1
            return [(100, 50, 100), (101, 100, 101)]

        _macos_spawn._sweep_descendants(100, snapshot_fn=snapshot,
                                        protect=frozenset())
        assert calls["n"] == _macos_spawn._SWEEP_MAX_PASSES

    def test_snapshot_failure_is_quiet_noop(self):
        swept = _macos_spawn._sweep_descendants(
            100, snapshot_fn=lambda: None, protect=frozenset())
        assert swept == set()
        assert self.killed == []


# --- wiring: the sweep runs on every exit path of run_sandboxed --------

class _FakePopen:
    """Stand-in for the seatbelt shim process — never spawns."""

    behaviour = "normal"

    def __init__(self, cmd, **kwargs):
        self.cmd = cmd
        self.pid = FAKE_SHIM_PID

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def communicate(self, input=None, timeout=None):
        if self.behaviour == "timeout":
            raise subprocess.TimeoutExpired(cmd="fake", timeout=1)
        if self.behaviour == "raise":
            raise RuntimeError("mid-run abort")
        return ("", "")

    def poll(self):
        return 0

    def wait(self, timeout=None):
        return 0

    def kill(self):
        pass


class TestRunSandboxedSweepWiring:
    LIVE_SENTINEL = [(FAKE_SHIM_PID, 1, FAKE_SHIM_PID)]

    def _invoke(self, monkeypatch, behaviour):
        monkeypatch.setattr(_FakePopen, "behaviour", behaviour)
        patch_module_attribute(monkeypatch, _macos_spawn, "subprocess", "Popen", _FakePopen)
        monkeypatch.setattr(
            _macos_spawn, "_ps_snapshot", lambda: list(self.LIVE_SENTINEL))
        killpgs = []
        patch_module_attribute(monkeypatch, _macos_spawn, "os", "killpg",
            lambda pid, sig: killpgs.append((pid, sig)))
        sweeps = []

        def record_sweep(root_pid, **kwargs):
            sweeps.append((root_pid, kwargs))
            return set()

        monkeypatch.setattr(
            _macos_spawn, "_sweep_descendants", record_sweep)
        return sweeps, killpgs

    def test_sweep_runs_on_normal_completion(self, monkeypatch):
        sweeps, _ = self._invoke(monkeypatch, "normal")
        result = _macos_spawn.run_sandboxed(["/usr/bin/true"], env={})
        assert result.returncode == 0
        assert [pid for pid, _kw in sweeps] == [FAKE_SHIM_PID]

    def test_sweep_runs_on_timeout(self, monkeypatch):
        sweeps, killpgs = self._invoke(monkeypatch, "timeout")
        with pytest.raises(subprocess.TimeoutExpired):
            _macos_spawn.run_sandboxed(
                ["/usr/bin/true"], env={}, timeout=1)
        assert [pid for pid, _kw in sweeps] == [FAKE_SHIM_PID]
        # Timeout teardown snapshots the tree while alive and hands the
        # snapshot to the sweep (post-kill, setsid escapees reparent
        # and become unattributable without it).
        assert sweeps[0][1].get("live_snapshot") == self.LIVE_SENTINEL
        # ... and the killpg backstop still fired.
        assert (FAKE_SHIM_PID, signal.SIGKILL) in killpgs

    def test_sweep_runs_on_exception(self, monkeypatch):
        sweeps, _ = self._invoke(monkeypatch, "raise")
        with pytest.raises(RuntimeError, match="mid-run abort"):
            _macos_spawn.run_sandboxed(["/usr/bin/true"], env={})
        assert [pid for pid, _kw in sweeps] == [FAKE_SHIM_PID]
        assert sweeps[0][1].get("live_snapshot") == self.LIVE_SENTINEL

    def test_sweep_failure_does_not_break_the_run(self, monkeypatch):
        sweeps, _ = self._invoke(monkeypatch, "normal")

        def boom(root_pid, **kwargs):
            raise OSError("ps exploded")

        monkeypatch.setattr(_macos_spawn, "_sweep_descendants", boom)
        result = _macos_spawn.run_sandboxed(["/usr/bin/true"], env={})
        assert result.returncode == 0


# --- the shim's inline copy ---------------------------------------------

@pytest.fixture(scope="module")
def shim_mod():
    """Import the shim as a module (it is a script; its trust-marker
    gate sys.exit(2)s without the env marker)."""
    old = os.environ.get("_RAPTOR_TRUSTED")
    os.environ["_RAPTOR_TRUSTED"] = "1"
    try:
        loader = SourceFileLoader(
            "raptor_seatbelt_shim_under_test", str(SHIM_PATH))
        spec = spec_from_loader(loader.name, loader)
        mod = module_from_spec(spec)
        loader.exec_module(mod)
        return mod
    finally:
        if old is None:
            os.environ.pop("_RAPTOR_TRUSTED", None)
        else:
            os.environ["_RAPTOR_TRUSTED"] = old


class TestShimSweep:
    def test_collect_matches_parent_side_semantics(self, shim_mod):
        table = [(100, 50, 100), (101, 100, 101), (103, 101, 103),
                 (200, 1, 200)]
        assert shim_mod._collect_descendants(table, 100) == {101, 103}
        assert shim_mod._collect_descendants(
            [(105, 1, 101)] + table, 100, extra_pgids=(101,),
        ) == {101, 103, 105}

    def test_sweep_orphans_kills_reparented_escapee(
            self, shim_mod, monkeypatch):
        self_pid = os.getpid()
        child = FAKE_SHIM_PID + 1
        escapee = FAKE_SHIM_PID + 2
        patch_module_attribute(monkeypatch, shim_mod, "os", "killpg", lambda pid, sig: None)
        live = [(child, self_pid, child), (escapee, child, escapee)]
        post = [(escapee, 1, escapee), (200, 1, 200)]
        tables = [post, []]
        killed = []
        swept = shim_mod._sweep_orphans(
            child, live, snapshot_fn=lambda: tables.pop(0),
            kill_fn=killed.append)
        assert swept == {escapee}
        assert killed == [escapee]

    def test_sweep_orphans_kills_group_member_without_live_table(
            self, shim_mod, monkeypatch):
        # A group member with a broken ppid chain is reachable via the
        # sandbox pgid even from a post-exit snapshot.
        child = FAKE_SHIM_PID + 1
        member = FAKE_SHIM_PID + 3
        patch_module_attribute(monkeypatch, shim_mod, "os", "killpg", lambda pid, sig: None)
        post = [(member, 1, child)]
        tables = [post, []]
        killed = []
        swept = shim_mod._sweep_orphans(
            child, None, snapshot_fn=lambda: tables.pop(0),
            kill_fn=killed.append)
        assert swept == {member}

    def test_sweep_orphans_never_touches_unrelated(
            self, shim_mod, monkeypatch):
        child = FAKE_SHIM_PID + 1
        patch_module_attribute(monkeypatch, shim_mod, "os", "killpg", lambda pid, sig: None)
        post = [(200, 1, 200), (201, 200, 200)]
        tables = [post, []]
        killed = []
        swept = shim_mod._sweep_orphans(
            child, None, snapshot_fn=lambda: tables.pop(0),
            kill_fn=killed.append)
        assert swept == set()
        assert killed == []

    def test_sweep_orphans_signals_the_sandbox_group(
            self, shim_mod, monkeypatch):
        child = FAKE_SHIM_PID + 1
        killpgs = []
        patch_module_attribute(monkeypatch, shim_mod, "os", "killpg", lambda pid, sig: killpgs.append((pid, sig)))
        shim_mod._sweep_orphans(
            child, None, snapshot_fn=lambda: [], kill_fn=lambda p: None)
        assert killpgs == [(child, signal.SIGKILL)]


# --- real-subprocess integration (Linux stand-in) -----------------------

needs_linux_setsid = pytest.mark.skipif(
    sys.platform != "linux" or shutil.which("setsid") is None,
    reason="needs Linux + util-linux setsid(1) as the escapee stand-in",
)


def _alive(pid):
    try:
        st = open(f"/proc/{pid}/stat").read().split(")")[1].split()[0]
    except (OSError, IndexError):
        return False
    return "Z" not in st


def _wait_dead(pid, timeout=5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not _alive(pid):
            return True
        time.sleep(0.05)
    return False


def _shim_env(**extra):
    return dict(os.environ, _RAPTOR_TRUSTED="1", **extra)


@needs_linux_setsid
class TestShimSweepIntegration:
    """Run the real shim: a target forks a setsid daemon (leaves the
    process group AND the session) and exits. Pre-fix the daemon
    outlived the run; the sweep must SIGKILL it."""

    def test_normal_completion_sweeps_setsid_escapee(self):
        # Target: fork the escapee, print its pid, keep the tree alive
        # long enough for the shim's 0.5s-interval snapshot thread to
        # capture the escapee's ppid chain while intact, then exit 0.
        # The window is several snapshot cycles wide: under whole-suite
        # parallel load the snapshot thread can be descheduled well past
        # one interval, and a missed capture fails the test on a starved
        # precondition rather than on the sweep behaviour under test.
        script = ("setsid sleep 300 </dev/null >/dev/null 2>&1 & "
                  "echo $!; sleep 3; exit 0")
        argv = [sys.executable, "-I", str(SHIM_PATH),
                "/bin/sh", "-c", script]
        proc = subprocess.run(
            argv, env=_shim_env(), capture_output=True, text=True,
            timeout=30,
        )
        daemon = int(proc.stdout.strip().splitlines()[0])
        try:
            assert proc.returncode == 0
            assert _wait_dead(daemon), (
                "setsid escapee survived normal completion")
        finally:
            if _alive(daemon):
                os.kill(daemon, signal.SIGKILL)

    def test_death_pipe_teardown_sweeps_setsid_escapee(self):
        script = ("setsid sleep 300 </dev/null >/dev/null 2>&1 & "
                  "echo $!; sleep 300")
        death_r, death_w = os.pipe()
        argv = [sys.executable, "-I", str(SHIM_PATH),
                "/bin/sh", "-c", script]
        proc = subprocess.Popen(
            argv, env=_shim_env(_RAPTOR_DEATH_FD=str(death_r)),
            pass_fds=(death_r,), stdout=subprocess.PIPE, text=True,
        )
        os.close(death_r)
        daemon = None
        try:
            daemon = int(proc.stdout.readline().strip())
            # Several snapshot cycles, for the same under-load reason as
            # the normal-completion test above.
            time.sleep(3)   # let the shim snapshot the live tree
            os.close(death_w)  # orchestrator "dies"
            assert proc.wait(timeout=30) == 137
            assert _wait_dead(daemon), (
                "setsid escapee survived death-pipe teardown")
        finally:
            try:
                os.close(death_w)
            except OSError:
                pass
            if proc.poll() is None:
                proc.kill()
            proc.stdout.close()
            proc.wait(timeout=10)
            if daemon is not None and _alive(daemon):
                os.kill(daemon, signal.SIGKILL)


# --- cumulative lineage ledger (shim watcher) ----------------------------

class TestShimSweepLineageLedger:
    """The watcher's cumulative pid/pgid lineage ledger: descendants
    attributed in ANY while-alive snapshot stay sweepable after they
    reparent, and process groups led by attributed descendants (their
    pid, once they setsid) attribute members even when the leader —
    the classic double-fork intermediate — is already dead. Pre-ledger,
    only the LATEST snapshot fed the sweep, so both classes escaped."""

    def test_ledger_bridges_descendant_forgotten_by_latest_table(
            self, shim_mod, monkeypatch):
        child = FAKE_SHIM_PID + 1
        escapee = FAKE_SHIM_PID + 2
        patch_module_attribute(monkeypatch, shim_mod, "os", "killpg", lambda pid, sig: None)
        # The latest live table no longer attributes the escapee (its
        # link broke before the final snapshot) — only the ledger,
        # accumulated from an EARLIER snapshot, still knows it.
        post = [(escapee, 1, escapee)]
        tables = [post, []]
        killed = []
        swept = shim_mod._sweep_orphans(
            child, None, snapshot_fn=lambda: tables.pop(0),
            kill_fn=killed.append,
            known_pids={escapee: escapee})
        assert swept == {escapee}
        assert killed == [escapee]

    def test_dead_intermediate_group_attributes_daemon(
            self, shim_mod, monkeypatch):
        # Double-fork shape: intermediate A (seen alive once, now dead)
        # setsid'd, forked daemon B (pgid == A), exited. B is
        # unreachable via ppid (1) and via the sandbox group — only A's
        # pid-as-candidate-pgid attributes it.
        child = FAKE_SHIM_PID + 1
        intermediate = FAKE_SHIM_PID + 4
        daemon = FAKE_SHIM_PID + 5
        patch_module_attribute(monkeypatch, shim_mod, "os", "killpg", lambda pid, sig: None)
        post = [(daemon, 1, intermediate), (200, 1, 200)]
        killed = []
        tables = [list(post), []]
        swept = shim_mod._sweep_orphans(
            child, None, snapshot_fn=lambda: tables.pop(0),
            kill_fn=killed.append,
            extra_pgids={intermediate})
        assert swept == {daemon}
        assert killed == [daemon]
        # Control: without the candidate group the daemon is honestly
        # unattributable (this is the pre-ledger behaviour).
        tables = [list(post), []]
        killed = []
        swept = shim_mod._sweep_orphans(
            child, None, snapshot_fn=lambda: tables.pop(0),
            kill_fn=killed.append)
        assert swept == set()

    def test_ledger_pid_reuse_guard_checks_pgid(
            self, shim_mod, monkeypatch):
        # A recycled pid lands in a different process group: the ledger
        # kills a known pid only while it still carries the recorded
        # pgid.
        child = FAKE_SHIM_PID + 1
        recycled = FAKE_SHIM_PID + 6
        patch_module_attribute(monkeypatch, shim_mod, "os", "killpg", lambda pid, sig: None)
        post = [(recycled, 1, 777)]  # different group now
        tables = [post, []]
        killed = []
        swept = shim_mod._sweep_orphans(
            child, None, snapshot_fn=lambda: tables.pop(0),
            kill_fn=killed.append,
            known_pids={recycled: recycled})
        assert swept == set()
        assert killed == []

    def test_shim_own_ps_children_never_attributed(self, shim_mod,
                                                    monkeypatch):
        """The shim's transient ps snapshot helpers list themselves in
        the very table they produce (ppid = shim). They must never be
        attributed — rooting at the shim would feed them into the
        cumulative candidate-group ledger, turning recycled pids into
        false-kill candidates for unrelated processes."""
        self_pid = os.getpid()
        child = FAKE_SHIM_PID + 1
        ps_child = FAKE_SHIM_PID + 7
        patch_module_attribute(monkeypatch, shim_mod, "os", "killpg", lambda pid, sig: None)
        # The ps helper appears as a live child of the SHIM, outside
        # the sandbox group.
        post = [(child, self_pid, child), (ps_child, self_pid, self_pid)]
        tables = [post, []]
        killed = []
        swept = shim_mod._sweep_orphans(
            child, None, snapshot_fn=lambda: tables.pop(0),
            kill_fn=killed.append)
        assert ps_child not in swept
        assert killed == []
        # And the lineage derivation (rooted at the sandbox leader)
        # never records it either.
        collected = shim_mod._collect_descendants(
            post, child, extra_pgids=(child,))
        assert ps_child not in collected

    def test_note_lineage_accumulates_across_snapshots(self, shim_mod):
        # Drive the ledger derivation the watcher uses: attribute via
        # the ppid chain in snapshot 1; the pid stays known (and
        # becomes a candidate group) even though snapshot 2 can no
        # longer attribute it. Uses the same _collect_descendants the
        # watcher calls, rooted at the sandbox LEADER exactly like the
        # watcher — this pins the accumulation CONTRACT, not the
        # watcher's closure (exercised by the integration test below).
        self_pid = 100
        child = 101
        intermediate = 102
        lineage = {"pids": {}, "pgids": set()}

        def note(table):
            cur = {pid: pgid for pid, _pp, pgid in table}
            extra = (child, *tuple(lineage["pgids"]))
            for pid in shim_mod._collect_descendants(
                    table, child, extra_pgids=extra):
                lineage["pids"][pid] = cur.get(pid)
                lineage["pgids"].add(pid)

        # Snapshot 1: intermediate alive, attributed via ppid=child
        # (the walk roots at child; the shim itself and its ps helpers
        # sit outside it).
        note([(child, self_pid, child), (intermediate, child,
                                         intermediate)])
        assert intermediate in lineage["pids"]
        assert intermediate in lineage["pgids"]
        # Snapshot 2: intermediate dead; its daemon (pgid ==
        # intermediate) attributes through the candidate group.
        daemon = 103
        note([(child, self_pid, child), (daemon, 1, intermediate)])
        assert daemon in lineage["pids"]


@needs_linux_setsid
class TestShimDoubleForkIntegration:
    """Real shim, double-fork daemoniser with an intermediate that
    stays alive across snapshot ticks: the intermediate setsids, waits
    long enough to be seen, forks the daemon, and dies. The daemon
    (ppid 1, pgid = dead intermediate) was unattributable pre-ledger
    and survived normal completion; the candidate-group lineage now
    sweeps it. The fully-in-between variant (intermediate born and
    dead within one snapshot interval) remains the documented
    residual and is NOT asserted here."""

    def test_normal_completion_sweeps_double_fork_daemon(self, tmp_path):
        bpid = tmp_path / "bpid"
        # Intermediate: new session (setsid(1)), visible for ~1.5s,
        # then forks the daemon into its session's group and exits.
        # Target stays alive 3s so the watcher's 0.5s snapshots
        # attribute the intermediate while its ppid link is intact.
        script = (
            f'setsid /bin/sh -c \'sleep 1.5; '
            f'sleep 300 </dev/null >/dev/null 2>&1 & '
            f'echo $! > "{bpid}"\' & '
            f'sleep 3; exit 0'
        )
        argv = [sys.executable, "-I", str(SHIM_PATH),
                "/bin/sh", "-c", script]
        proc = subprocess.run(
            argv, env=_shim_env(), capture_output=True, text=True,
            timeout=30,
        )
        daemon = None
        try:
            assert proc.returncode == 0, proc.stderr
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline and not bpid.exists():
                time.sleep(0.05)
            daemon = int(bpid.read_text().strip())
            assert _wait_dead(daemon), (
                "double-fork daemon (dead intermediate's group) "
                "survived normal completion — lineage ledger regressed")
        finally:
            if daemon is not None and _alive(daemon):
                os.kill(daemon, signal.SIGKILL)


class TestParentBackstopGroupReport:
    """The parent's normal-completion backstop sweep consumes the
    watcher's G sandbox-group report from the status channel, so it
    can killpg-attribute group members even after the shim died
    without sweeping (the ppid walk from a dead shim pid attributes
    nothing)."""

    def test_group_report_threaded_into_backstop_sweep(
            self, monkeypatch):
        reported_group = 4242

        class _ReportingPopen(_FakePopen):
            def __init__(self, cmd, **kwargs):
                super().__init__(cmd, **kwargs)
                # Stand in for the watcher: write the group report and
                # the readiness byte through the real status pipe the
                # spawn wired into our env.
                fd = int(kwargs["env"]["_RAPTOR_STATUS_FD"])
                os.write(fd, b"G%d\n" % reported_group)
                os.write(fd, b"K")

        patch_module_attribute(monkeypatch, _macos_spawn, "subprocess", "Popen", _ReportingPopen)
        monkeypatch.setattr(_macos_spawn, "_ps_snapshot", lambda: [])
        sweeps = []

        def record_sweep(root_pid, **kwargs):
            sweeps.append((root_pid, kwargs))
            return set()

        monkeypatch.setattr(
            _macos_spawn, "_sweep_descendants", record_sweep)
        result = _macos_spawn.run_sandboxed(["/usr/bin/true"], env={})
        assert result.returncode == 0
        assert getattr(result, "_setup_status", "missing") is None
        assert [pid for pid, _kw in sweeps] == [FAKE_SHIM_PID]
        assert sweeps[0][1].get("extra_pgids") == (reported_group,)
