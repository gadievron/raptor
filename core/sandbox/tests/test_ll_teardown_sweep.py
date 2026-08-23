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
(each run injects a random `_RAPTOR_SBX_RUN` token into the child env;
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
        time.sleep(3)
        self.assertFalse(os.path.exists(canary),
                         "post-teardown host write landed — late "
                         "writer survived the sweep")

    def test_timeout_stragglers_swept(self):
        """Timeout kills Popen.pid (the sweeper) — the marked-process
        backstop must still reap the daemon and the payload."""
        payload = (_DAEMON.format(mark=self.mark)
                   + "daemon()\ntime.sleep(60)\n")
        with self.assertRaises(subprocess.TimeoutExpired):
            self._ll_run(payload, timeout=3)
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
            time.sleep(60)
        """)
        with self.assertRaises(subprocess.TimeoutExpired):
            self._ll_run(payload, timeout=3)
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


class TestSweepBackstopUnit(unittest.TestCase):
    def test_sweep_marked_processes_kills_only_marked(self):
        from core.sandbox.context import _sweep_marked_processes
        token = uuid.uuid4().hex
        marked = subprocess.Popen(
            ["sleep", "30"],
            env={"_RAPTOR_SBX_RUN": token, "PATH": "/usr/bin:/bin"},
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
