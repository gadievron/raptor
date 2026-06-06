"""Direct unit tests for libexec/raptor-pid1-shim.

The shim is normally invoked inside the subprocess-path sandbox to insulate
targets from Linux's pid-ns init-signal filter (see `docs/sandbox.md` →
"Crash signals across the pid-ns boundary"). These tests exercise it
WITHOUT the surrounding `unshare` chain, so a failure here points at a
shim-level bug rather than the wider sandbox integration.

The full stack — shim + unshare + Landlock + seccomp — is covered by
`test_e2e_sandbox.py::TestE2ECrashObservability`.

Contract tested:
  - normal-exit rc pass-through (0, 1, arbitrary)
  - signal death → `128 + sig` exit-code encoding (bash/unix convention)
  - exec failure → rc 127 (FileNotFoundError) / rc 126 (PermissionError)
  - missing target argv → rc 2 + stderr message
  - orphan reap does NOT replace the target's exit status
  - stdout / stderr pass-through
"""

import sys as _sys
import pytest as _pytest
pytestmark = _pytest.mark.skipif(
    _sys.platform != "linux",
    reason="Linux-only sandbox internals (mount-ns / Landlock / seccomp / ptrace tracer / pid1 shim) — see core/sandbox/_macos_spawn.py for the macOS path",
)


import os  # noqa: E402
import signal  # noqa: E402
import subprocess  # noqa: E402
import tempfile  # noqa: E402
import unittest  # noqa: E402
from pathlib import Path  # noqa: E402

# Shim path resolved from repo root — test file lives at
# core/sandbox/tests/test_pid1_shim.py, so parents[3] is the repo root.
SHIM_PATH = Path(__file__).resolve().parents[3] / "libexec" / "raptor-pid1-shim"


class TestPid1ShimContract(unittest.TestCase):
    """Caller-visible behaviour that context.py depends on."""

    def setUp(self):
        if not SHIM_PATH.is_file():
            self.skipTest(f"shim not found at {SHIM_PATH}")
        if not os.access(SHIM_PATH, os.X_OK):
            self.skipTest(f"shim not executable: {SHIM_PATH}")

    def _run_shim(self, *target_argv, timeout=5):
        """Run the shim with `target_argv` and return CompletedProcess."""
        return subprocess.run(
            [str(SHIM_PATH), *target_argv],
            capture_output=True, text=True, timeout=timeout,
        )

    # --- normal-exit rc pass-through ---------------------------------

    def test_normal_exit_rc_0(self):
        """/bin/true exits 0; shim must too."""
        self.assertEqual(self._run_shim("/bin/true").returncode, 0)

    def test_normal_exit_rc_1(self):
        """/bin/false exits 1; shim must too."""
        self.assertEqual(self._run_shim("/bin/false").returncode, 1)

    def test_normal_exit_rc_42(self):
        """Arbitrary rc must round-trip — observe.py relies on exit
        codes being preserved exactly, not clamped or re-signed."""
        self.assertEqual(
            self._run_shim("/bin/sh", "-c", "exit 42").returncode, 42,
        )

    # --- signal death encoded as 128+sig -----------------------------

    def test_signal_death_sigterm(self):
        """Target killed by SIGTERM (15) → shim exits 128+15=143.
        The shim can't re-raise the signal on itself from pid-1 of a
        pid-ns (filter), so it encodes death via 128+sig; the direct
        test here (no pid-ns) still takes the same code path because
        the grandchild is reaped by the intermediate which always
        uses `_exit(128+sig)` for signal death, regardless of whether
        it's actually in a pid-ns.
        """
        r = self._run_shim("/bin/sh", "-c", "kill -TERM $$")
        self.assertEqual(r.returncode, 128 + int(signal.SIGTERM))

    def test_signal_death_sigkill(self):
        """Target killed by SIGKILL (9) → shim exits 128+9=137."""
        r = self._run_shim("/bin/sh", "-c", "kill -KILL $$")
        self.assertEqual(r.returncode, 128 + int(signal.SIGKILL))

    def test_signal_death_sigabrt_via_c_probe(self):
        """abort() self-sends SIGABRT (6). This is the specific case
        the shim exists to handle — without it, the pid-ns filter drops
        the raise() silently when the target is pid-1."""
        import shutil
        if not shutil.which("gcc"):
            self.skipTest("gcc not installed")
        with tempfile.TemporaryDirectory() as d:
            src = Path(d) / "abrt.c"
            src.write_text('#include <stdlib.h>\nint main(){abort();return 0;}')
            binary = Path(d) / "abrt"
            subprocess.run(
                ["gcc", "-o", str(binary), str(src)],
                capture_output=True, timeout=10, check=True,
            )
            r = self._run_shim(str(binary))
        self.assertEqual(r.returncode, 128 + int(signal.SIGABRT))

    # --- missing argv -------------------------------------------------

    def test_missing_target_argv(self):
        """Shim with no target argv → rc 2, usage message on stderr."""
        r = subprocess.run(
            [str(SHIM_PATH)],
            capture_output=True, text=True, timeout=5,
        )
        self.assertEqual(r.returncode, 2)
        self.assertIn("missing target argv", r.stderr)

    # --- exec failure -------------------------------------------------

    def test_exec_failure_not_found(self):
        """Non-existent target → rc 127 (convention for
        FileNotFoundError on exec, matches bash's `command not found`)."""
        r = self._run_shim("/nonexistent/raptor/shim/test/binary")
        self.assertEqual(r.returncode, 127)

    def test_exec_failure_not_executable(self):
        """File exists but has no exec bit and no shebang → rc 126
        (convention for PermissionError on exec, matches bash)."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False,
        ) as f:
            f.write("not a script, no exec bit")
            non_exec_path = f.name
        try:
            os.chmod(non_exec_path, 0o644)  # no x
            r = self._run_shim(non_exec_path)
            self.assertEqual(r.returncode, 126)
        finally:
            os.unlink(non_exec_path)

    # --- orphan reap doesn't replace target status -------------------

    def test_orphan_reap_preserves_target_status(self):
        """Target backgrounds a short-lived process then exits 17. The
        orphan's eventual reap must NOT overwrite the target's status —
        the shim's `waitpid(-1)` loop discards non-target statuses."""
        r = self._run_shim(
            "/bin/sh", "-c",
            # Background child lives longer than the shell. Under the
            # double-fork layout, the orphan is reparented to the shim
            # (or intermediate, depending on timing). Either way the
            # shim must only mirror the target shell's exit (17), not
            # the orphan's (99).
            "(sleep 0.2; exit 99) & exit 17",
        )
        self.assertEqual(r.returncode, 17)

    # --- stdout / stderr pass-through --------------------------------

    def test_target_stdout_passthrough(self):
        r = self._run_shim("/bin/echo", "hello")
        self.assertEqual(r.stdout.strip(), "hello")

    def test_target_stderr_passthrough(self):
        r = self._run_shim("/bin/sh", "-c", "echo err >&2")
        self.assertEqual(r.stderr.strip(), "err")

    def test_target_does_not_inherit_trust_marker(self):
        """The shim strips _RAPTOR_TRUSTED before exec'ing the target. The
        trust marker authorizes RAPTOR's own dispatch scripts (this shim
        included) and must not leak into the untrusted target's env."""
        probe = ("import os;"
                 "print('TRUST=' + os.environ.get('_RAPTOR_TRUSTED', '<unset>'))")
        r = subprocess.run(
            [str(SHIM_PATH), _sys.executable, "-c", probe],
            capture_output=True, text=True, timeout=5,
            env=dict(os.environ, _RAPTOR_TRUSTED="1"),
        )
        self.assertEqual(r.returncode, 0)
        self.assertIn("TRUST=<unset>", r.stdout)


if __name__ == "__main__":
    unittest.main()


class TestPid1ShimDeathPipe(unittest.TestCase):
    """Orphan-teardown: the shim watches an orchestrator-liveness ('death')
    pipe and tears the pid-ns down when the orchestrator dies — covering the
    SIGKILL/OOM/crash case that no graceful cleanup can."""

    def setUp(self):
        if not SHIM_PATH.is_file() or not os.access(SHIM_PATH, os.X_OK):
            self.skipTest("shim missing/not executable")

    def test_death_pipe_eof_exits_shim(self):
        """Direct (no pid-ns): when the death-pipe write end closes (EOF),
        the shim stops waiting on its long target and exits with the
        teardown code. The kernel cascade to the target is covered by the
        integration test below."""
        marker = "raptor_shimdeath_7271"
        death_r, death_w = os.pipe()
        env = dict(os.environ, _RAPTOR_TRUSTED="1",
                   _RAPTOR_DEATH_FD=str(death_r))
        proc = subprocess.Popen(
            [str(SHIM_PATH), "/bin/sleep", marker.split("_")[-1]],
            pass_fds=(death_r,), env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        try:
            os.close(death_r)  # parent holds only the write end
            import time
            time.sleep(0.5)    # let the shim fork the target + enter watch
            os.close(death_w)  # EOF → shim must tear down
            try:
                rc = proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.fail("shim did not exit after death-pipe EOF")
            self.assertEqual(rc, 137,  # _DEATH_TEARDOWN_EXIT
                             "shim should exit with the teardown code on EOF")
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait()
            subprocess.run(["pkill", "-9", "-f", marker.split("_")[-1]],
                           capture_output=True)

    def test_orphan_teardown_on_orchestrator_kill(self):
        """Integration: an orchestrator running a long target through the
        subprocess/shim sandbox path, then SIGKILLed mid-run (OOM/crash
        simulation), must leave NO lingering sandbox processes — the shim
        reads EOF and the kernel cascade-SIGKILLs the pid-ns."""
        import time
        marker = "313339"

        def lineage():
            out = subprocess.run(["pgrep", "-af", marker],
                                 capture_output=True, text=True).stdout
            return [ln for ln in out.splitlines() if "pgrep" not in ln]

        orch = subprocess.Popen(
            ["python3", "-c",
             "from core.sandbox import sandbox\n"
             "with sandbox(block_network=True) as run:\n"
             "    run(['/bin/sleep','%s'], capture_output=True, text=True)\n"
             % marker],
            cwd=str(Path(__file__).resolve().parents[3]),
            env=dict(os.environ, _RAPTOR_TRUSTED="1"),
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        try:
            # Only proceed once the SHIM actually wraps the target — i.e. the
            # subprocess/pid-ns path engaged. On a no-namespace runner the
            # target would run bare (no shim, no death-pipe), which has no
            # teardown guarantee and isn't what this test covers → skip.
            for _ in range(150):
                time.sleep(0.1)
                if any("raptor-pid1-shim" in p and marker in p
                       for p in lineage()):
                    break
            else:
                self.skipTest("subprocess/shim sandbox path did not engage "
                              "here (namespaces unavailable)")
            orch.send_signal(signal.SIGKILL)
            orch.wait()
            # Poll up to 5s for full teardown.
            for _ in range(50):
                time.sleep(0.1)
                if not lineage():
                    break
            self.assertEqual(lineage(), [],
                             "sandbox lineage leaked after orchestrator kill")
        finally:
            if orch.poll() is None:
                orch.kill()
                orch.wait()
            subprocess.run(["pkill", "-9", "-f", marker], capture_output=True)
