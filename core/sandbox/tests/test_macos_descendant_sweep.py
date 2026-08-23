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
import types
from importlib.machinery import SourceFileLoader
from importlib.util import module_from_spec, spec_from_loader
from pathlib import Path

import pytest

from core.sandbox import _macos_spawn

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
    @pytest.fixture(autouse=True)
    def _record_kills(self, monkeypatch):
        self.killed = []
        monkeypatch.setattr(
            _macos_spawn, "_kill_pid", self.killed.append)

    def test_live_descendants_swept(self):
        tables = [[(100, 50, 100), (101, 100, 101), (103, 101, 103)], []]
        swept = _macos_spawn._sweep_descendants(
            100, snapshot_fn=lambda: tables.pop(0))
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
            100, live_snapshot=live, snapshot_fn=lambda: tables.pop(0))
        assert swept == {103}
        assert 200 not in self.killed

    def test_orphan_without_live_snapshot_escapes_honestly(self):
        # The documented blind spot: no while-alive snapshot → the
        # reparented orphan cannot be attributed and is NOT killed.
        post = [(100, 50, 100), (103, 1, 103)]
        tables = [post, []]
        swept = _macos_spawn._sweep_descendants(
            100, snapshot_fn=lambda: tables.pop(0))
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
            100, live_snapshot=live, snapshot_fn=lambda: tables.pop(0))
        assert swept == set()

    def test_sweep_is_bounded(self):
        # A target that keeps re-forking: every snapshot shows a live
        # descendant. The sweep must stop after max_passes rounds.
        calls = {"n": 0}

        def snapshot():
            calls["n"] += 1
            return [(100, 50, 100), (101, 100, 101)]

        _macos_spawn._sweep_descendants(100, snapshot_fn=snapshot)
        assert calls["n"] == _macos_spawn._SWEEP_MAX_PASSES

    def test_snapshot_failure_is_quiet_noop(self):
        swept = _macos_spawn._sweep_descendants(
            100, snapshot_fn=lambda: None)
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
        fake_subprocess = types.SimpleNamespace(
            Popen=_FakePopen,
            TimeoutExpired=subprocess.TimeoutExpired,
            CompletedProcess=subprocess.CompletedProcess,
            PIPE=subprocess.PIPE,
        )
        monkeypatch.setattr(_FakePopen, "behaviour", behaviour)
        monkeypatch.setattr(_macos_spawn, "subprocess", fake_subprocess)
        monkeypatch.setattr(
            _macos_spawn, "_ps_snapshot", lambda: list(self.LIVE_SENTINEL))
        killpgs = []
        monkeypatch.setattr(
            os, "killpg",
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
        monkeypatch.setattr(
            os, "killpg", lambda pid, sig: None)
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
        monkeypatch.setattr(os, "killpg", lambda pid, sig: None)
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
        monkeypatch.setattr(os, "killpg", lambda pid, sig: None)
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
        monkeypatch.setattr(
            os, "killpg", lambda pid, sig: killpgs.append((pid, sig)))
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
