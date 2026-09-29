"""No-namespace (Landlock-only) teardown sweep.

Battery-proven escapes pinned here: on the Landlock-only path there is
no pid namespace, so a payload could leave survivors behind that
outlived run() teardown with full host access —

- setsid double-fork daemons,
- SIGSTOP-parked children,
- delayed writers that create files AFTER teardown,
- stragglers surviving a run timeout.

The fix is layered: the composed preexec forks a
PR_SET_CHILD_SUBREAPER sweeper (every orphaned descendant reparents to
it; it SIGKILL-sweeps on payload exit or death-pipe EOF and mirrors
the payload's exit status), plus a parent-side marked-process backstop
(each run injects a random `_SBX_RUN_ID` token into the child env;
after the run, any /proc process still carrying it is killed — this
covers the timeout path, where subprocess kills the sweeper itself).
"""

import os
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
import uuid
from unittest.mock import patch

import pytest
from core.sandbox.tests.capability import requires_landlock

pytestmark = pytest.mark.skipif(
    sys.platform != "linux", reason="Landlock-only posture is Linux-only",
)

_SYS_PY = "/usr/bin/python3"

# Payload template: double-fork a setsid daemon whose argv carries the
# per-test marker, exactly the battery's shape.
_DAEMON = textwrap.dedent("""
    import os, sys, time
    MARK = {mark!r}
    def daemon(extra=""):
        pid = os.fork()
        if pid == 0:
            os.setsid()
            if os.fork() == 0:
                os.execv("/bin/sh",
                         ["sh", "-c", extra + "sleep 30", MARK])
            os._exit(0)
        os.waitpid(pid, 0)
""")


def _survivors(mark: str) -> list:
    out = []
    for name in os.listdir("/proc"):
        if not name.isdigit():
            continue
        try:
            with open(f"/proc/{name}/cmdline", "rb") as f:
                cmdline = f.read()
        except OSError:
            continue
        if mark.encode() in cmdline:
            out.append(int(name))
    return out


def _kill_survivors(mark: str) -> None:
    for pid in _survivors(mark):
        try:
            os.kill(pid, 9)
        except OSError:
            pass


@requires_landlock
class TestLandlockOnlyTeardownSweep(unittest.TestCase):
    def setUp(self):
        self._out = tempfile.TemporaryDirectory(prefix="raptor-sweep-")
        self.addCleanup(self._out.cleanup)
        self.out = os.path.realpath(self._out.name)
        self.mark = "RAPTORSWEEPTEST" + uuid.uuid4().hex[:12]
        self.addCleanup(_kill_survivors, self.mark)
        if not os.path.exists(_SYS_PY):
            self.skipTest("system python3 not present")

    def _ll_run(self, payload, timeout=30, **kw):
        from core.sandbox import sandbox
        with patch("core.sandbox.context.check_net_available",
                   return_value=False), \
             patch("core.sandbox.context.check_mount_available",
                   return_value=False):
            with sandbox(target=self.out, output=self.out,
                         block_network=False, restrict_reads=True) as run:
                return run([_SYS_PY, "-c", payload],
                           capture_output=True, text=True,
                           timeout=timeout, **kw)

    def test_setsid_daemon_swept(self):
        r = self._ll_run(_DAEMON.format(mark=self.mark) + "daemon()\n")
        self.assertTrue(r.sandbox_info.get("teardown_sweep"),
                        "no-namespace run must stamp teardown_sweep")
        time.sleep(0.3)
        self.assertEqual(_survivors(self.mark), [],
                         "setsid double-fork daemon survived teardown "
                         "on the no-namespace path")

    def test_sigstop_parked_swept(self):
        r = self._ll_run(_DAEMON.format(mark=self.mark)
                         + 'daemon("kill -STOP $$; ")\n')
        self.assertEqual(r.sandbox_info.get("teardown_sweep"), True)
        time.sleep(0.3)
        self.assertEqual(_survivors(self.mark), [],
                         "SIGSTOP-parked daemon survived teardown")

    def test_post_teardown_write_prevented(self):
        """Late-writer shape: a daemon scheduled to create a file
        seconds after run() returns must be dead before it writes.
        The canary targets the OUTPUT dir (writable in-policy) so the
        test isolates teardown from the write-surface fixes."""
        canary = os.path.join(self.out, "late-canary")
        payload = (_DAEMON.format(mark=self.mark)
                   + f'daemon("sleep 2; echo late > {canary}; ")\n')
        self._ll_run(payload)
        # Sweep-then-write ordering, without waiting out the write
        # horizon: once no marked process survives (the same 0.3s
        # settle grace the sibling tests use), nothing can write the
        # canary later — a dead daemon has no pending 2s write. The
        # canary check then pins the write-surface half: a survivor
        # that already wrote is caught even if it died between the
        # sweep and the scan. Widen the grace (or re-lengthen the
        # daemon's delay) only if the settle ever races the sweep;
        # never assert the canary alone without the survivor scan, or
        # the test degrades back to a wall-clock wait.
        time.sleep(0.3)
        self.assertEqual(_survivors(self.mark), [],
                         "late-writer daemon survived teardown")
        self.assertFalse(os.path.exists(canary),
                         "post-teardown host write landed — late "
                         "writer survived the sweep")

    def test_timeout_stragglers_swept(self):
        """Timeout kills Popen.pid (the sweeper) — the marked-process
        backstop must still reap the daemon and the payload."""
        # The run timeout is this test's wall-time floor: it must fire
        # (the payload idles far past it), but only AFTER the daemon
        # is staged. The staged-marker assert keeps the shrunken value
        # honest — a timeout that beats the daemon spawn now fails
        # loudly as inconclusive instead of passing vacuously with
        # nothing to sweep. Raise the timeout if that assert ever
        # fires on a loaded runner; don't shrink it further without
        # widening the daemon-spawn margin some other way.
        staged = os.path.join(self.out, "daemon-staged")
        payload = (_DAEMON.format(mark=self.mark)
                   + "daemon()\n"
                   + f"open({staged!r}, 'w').close()\n"
                   + "time.sleep(60)\n")
        with self.assertRaises(subprocess.TimeoutExpired):
            self._ll_run(payload, timeout=2)
        self.assertTrue(os.path.exists(staged),
                        "run timed out before the daemon was staged — "
                        "sweep never exercised, test inconclusive")
        time.sleep(0.5)
        self.assertEqual(_survivors(self.mark), [],
                         "daemon survived a run timeout")

    def test_env_scrubbed_daemon_still_swept(self):
        """Variant family: a daemon that execs with a CLEAN environment
        defeats the marker backstop — the subreaper sweeper must catch
        it by pid tracking alone."""
        payload = textwrap.dedent(f"""
            import os
            pid = os.fork()
            if pid == 0:
                os.setsid()
                if os.fork() == 0:
                    os.execve("/bin/sh",
                              ["sh", "-c", "sleep 30", {self.mark!r}],
                              {{}})
                os._exit(0)
            os.waitpid(pid, 0)
        """)
        self._ll_run(payload)
        time.sleep(0.3)
        self.assertEqual(_survivors(self.mark), [],
                         "env-scrubbed daemon survived — subreaper "
                         "sweep must not depend on the env marker")

    def test_env_scrubbed_daemon_swept_even_on_timeout(self):
        """Composed timeout + env-scrub shape: a run TIMEOUT used to SIGKILL
        Popen.pid — the sweeper itself — before it could sweep, and an
        env-scrubbed daemon is invisible to the marker backstop, so the
        composition escaped teardown entirely. The teardown-first
        timeout closes the death pipe before any kill, so the sweeper
        reaps by pid tracking even on the timeout path."""
        # Same shrunken-timeout doctrine as test_timeout_stragglers_
        # swept: the timeout is the wall floor, the staged marker
        # keeps it honest against a vacuous early expiry.
        staged = os.path.join(self.out, "daemon-staged")
        payload = textwrap.dedent(f"""
            import os, time
            pid = os.fork()
            if pid == 0:
                os.setsid()
                if os.fork() == 0:
                    os.execve("/bin/sh",
                              ["sh", "-c", "sleep 30", {self.mark!r}],
                              {{}})
                os._exit(0)
            os.waitpid(pid, 0)
            open({staged!r}, "w").close()
            time.sleep(60)
        """)
        with self.assertRaises(subprocess.TimeoutExpired):
            self._ll_run(payload, timeout=2)
        self.assertTrue(os.path.exists(staged),
                        "run timed out before the daemon was staged — "
                        "sweep never exercised, test inconclusive")
        time.sleep(0.5)
        self.assertEqual(_survivors(self.mark), [],
                         "env-scrubbed daemon survived a run timeout — "
                         "the sweeper must be allowed to sweep before "
                         "it is killed")

    def test_exit_status_mirrored(self):
        r = self._ll_run("import sys; sys.exit(7)")
        self.assertEqual(r.returncode, 7,
                         "sweeper must mirror the payload's exit code")

    def test_signal_death_mirrored(self):
        r = self._ll_run(
            "import os, signal; os.kill(os.getpid(), signal.SIGSEGV)")
        self.assertIn(r.returncode, (-11, 128 + 11),
                      f"signal death must stay observable "
                      f"(got rc={r.returncode})")

    def test_stdout_still_captured(self):
        r = self._ll_run("print('payload-output')")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("payload-output", r.stdout)


class TestSweeperSignalScopeStamp(unittest.TestCase):
    """Per-run visibility of the killable-sweeper arm: on kernels
    without Landlock signal scoping (ABI < 6) — or when no Landlock
    ruleset engages for the payload at all — a hostile same-UID
    payload can SIGKILL the sweeper before spawning daemons, leaving
    only the env-scrub-able marker backstop. That arm is a kernel
    limitation; what the sandbox CAN do is stamp the degraded
    envelope per run (``teardown_sweep_signal_unscoped``) instead of
    letting ``teardown_sweep=True`` read as full coverage."""

    def _build_cell(self, *, abi: int, available: bool = True,
                    writable: bool = True) -> dict:
        from core.sandbox import preexec as preexec_mod
        cell: dict = {"death_fd": None}
        with patch.object(preexec_mod, "check_landlock_available",
                          return_value=available), \
             patch.object(preexec_mod, "_get_landlock_abi",
                          return_value=abi):
            preexec_mod._make_preexec_fn(
                {}, writable_paths=["/tmp"] if writable else None,
                reaper_cell=cell)
        return cell

    def test_scoped_on_abi6_with_ruleset(self):
        cell = self._build_cell(abi=6)
        self.assertIs(cell.get("signal_scoped"), True)

    def test_unscoped_below_abi6(self):
        cell = self._build_cell(abi=5)
        self.assertIs(cell.get("signal_scoped"), False)

    def test_unscoped_without_landlock(self):
        cell = self._build_cell(abi=0, available=False)
        self.assertIs(cell.get("signal_scoped"), False)

    def test_unscoped_without_any_ruleset(self):
        # ABI is modern but nothing engages Landlock for the payload
        # (no writable paths, no ports, no read restriction, no
        # connect deny): the payload never enters a Landlock domain,
        # so scoping cannot protect the sweeper either.
        cell = self._build_cell(abi=8, writable=False)
        self.assertIs(cell.get("signal_scoped"), False)

    def test_cell_always_stamped_none_cell_safe(self):
        # Every cell-carrying build must record the posture key
        # (a bool, never absent), so the stamp site can trust
        # `.get("signal_scoped")` to mean "unscoped" only for
        # genuinely unscoped builds; reaper_cell=None (namespace
        # paths) must build without touching cell state.
        cell = self._build_cell(abi=8)
        self.assertIsInstance(cell.get("signal_scoped"), bool)
        from core.sandbox import preexec as preexec_mod
        fn = preexec_mod._make_preexec_fn({}, writable_paths=["/tmp"],
                                          reaper_cell=None)
        self.assertTrue(callable(fn))

    def _run_true(self):
        from core.sandbox import sandbox
        out = tempfile.mkdtemp(prefix="raptor-sweep-stamp-")
        self.addCleanup(__import__("shutil").rmtree, out,
                        ignore_errors=True)
        with patch("core.sandbox.context.check_net_available",
                   return_value=False), \
             patch("core.sandbox.context.check_mount_available",
                   return_value=False):
            with sandbox(target=out, output=out,
                         block_network=False,
                         restrict_reads=True) as run:
                return run([_SYS_PY, "-c", "pass"],
                           capture_output=True, text=True, timeout=30)

    @requires_landlock
    def test_stamp_matches_host_scoping(self):
        """Hermetic across hosts: the stamp must be present exactly
        when this host cannot scope signals for the sweeper."""
        if not os.path.exists(_SYS_PY):
            self.skipTest("system python3 not present")
        from core.sandbox.landlock import (
            _get_landlock_abi,
            check_landlock_available,
        )
        r = self._run_true()
        if not r.sandbox_info.get("teardown_sweep"):
            self.skipTest("run did not take the no-namespace posture")
        host_scoped = (check_landlock_available()
                       and _get_landlock_abi() >= 6)
        if host_scoped:
            self.assertNotIn("teardown_sweep_signal_unscoped",
                             r.sandbox_info)
        else:
            self.assertIs(
                r.sandbox_info.get("teardown_sweep_signal_unscoped"),
                True)

    @requires_landlock
    def test_stamp_present_when_scoping_forced_off(self):
        """Force the ABI<6 view at the preexec seam: the run must
        carry the degraded-envelope stamp."""
        if not os.path.exists(_SYS_PY):
            self.skipTest("system python3 not present")
        with patch("core.sandbox.preexec._get_landlock_abi",
                   return_value=5):
            r = self._run_true()
        if not r.sandbox_info.get("teardown_sweep"):
            self.skipTest("run did not take the no-namespace posture")
        self.assertIs(
            r.sandbox_info.get("teardown_sweep_signal_unscoped"),
            True)


class TestSweepBackstopUnit(unittest.TestCase):
    def test_sweep_marked_processes_kills_only_marked(self):
        from core.sandbox.context import _sweep_marked_processes
        token = uuid.uuid4().hex
        marked = subprocess.Popen(
            ["sleep", "30"],
            env={"_SBX_RUN_ID": token, "PATH": "/usr/bin:/bin"},
        )
        unmarked = subprocess.Popen(["sleep", "30"])
        try:
            time.sleep(0.1)
            killed = _sweep_marked_processes(token)
            self.assertIn(marked.pid, killed)
            self.assertNotIn(unmarked.pid, killed)
            self.assertIsNone(unmarked.poll(),
                              "unmarked process must be untouched")
            marked.wait(timeout=5)
            self.assertEqual(marked.returncode, -9)
        finally:
            for p in (marked, unmarked):
                try:
                    p.kill()
                    p.wait(timeout=5)
                except OSError:
                    pass


@requires_landlock
class TestNamespacePathUnaffected(unittest.TestCase):
    def test_spawn_path_does_not_stamp_teardown_sweep(self):
        import shutil
        from core.sandbox import check_mount_available, sandbox
        if not (check_mount_available() and shutil.which("newuidmap")):
            self.skipTest("mount-ns unavailable")
        with tempfile.TemporaryDirectory(prefix="raptor-sweep-ns-") as out:
            with sandbox(target=out, output=out) as run:
                r = run(["/bin/true"], capture_output=True, timeout=30)
        self.assertEqual(r.returncode, 0)
        if r.sandbox_info.get("mount_ns_active"):
            self.assertNotIn("teardown_sweep", r.sandbox_info)


if __name__ == "__main__":
    unittest.main()
