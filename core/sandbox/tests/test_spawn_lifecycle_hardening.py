"""Spawn lifecycle hardening: teardown, fd hygiene, helper resolution.

- _kill_and_reap killpg'd whatever process group the child was in;
  with the supported start_new_session=False shape that is RAPTOR's
  OWN group — a timeout the target provoked SIGKILLed the
  orchestrator (confused deputy).
- A subprocess timeout SIGKILLs the setup child (the death-pipe
  watcher) first; nothing then killed the pid-ns init, so the target
  tree survived the timeout and kept executing. The grandchild now
  ties its lifetime to the setup child via PR_SET_PDEATHSIG.
- The grandchild fd sweep derived its ceiling from the ALREADY
  LOWERED RLIMIT_NOFILE soft limit, so a pre-existing inheritable fd
  numbered at/above it survived execvpe as an out-of-policy
  capability.
- newuidmap/newgidmap/getcap resolved via the inherited PATH in the
  unsandboxed parent, contra the pinned-resolver doctrine.
"""

import os
import shutil
import stat
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(
    sys.platform != "linux", reason="Linux spawn backend",
)


def _mount_ns_usable() -> bool:
    if not shutil.which("newuidmap") or not shutil.which("newgidmap"):
        return False
    sysctl = Path("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
    return not (sysctl.exists() and sysctl.read_text().strip() == "1")


_WT = str(Path(__file__).resolve().parents[3])


class TestKillpgConfusedDeputyGuard(unittest.TestCase):
    def test_kill_and_reap_never_signals_its_own_group(self):
        """Driver process (own session) spawns a same-group child and
        calls _kill_and_reap on it — pre-fix the killpg took out the
        driver itself."""
        driver = textwrap.dedent(f"""
            import os, subprocess, sys
            sys.path.insert(0, {_WT!r})
            os.environ.setdefault("RAPTOR_DIR", {_WT!r})
            from core.sandbox._spawn import _kill_and_reap
            child = subprocess.Popen(["/bin/sleep", "300"],
                                     start_new_session=False)
            _kill_and_reap(child.pid)
            print("DRIVER-SURVIVED")
        """)
        r = subprocess.run(
            ["/usr/bin/python3", "-c", driver],
            capture_output=True, text=True, timeout=60,
            start_new_session=True,
        )
        self.assertIn("DRIVER-SURVIVED", r.stdout, (
            f"_kill_and_reap SIGKILLed its own process group "
            f"(confused deputy): rc={r.returncode} "
            f"stderr={r.stderr[-300:]!r}"
        ))
        self.assertEqual(r.returncode, 0)


class TestTimeoutKillsTargetTree(unittest.TestCase):
    def setUp(self):
        if not _mount_ns_usable():
            self.skipTest("mount-ns unusable here")
        from core.sandbox._spawn import mount_ns_available
        if not mount_ns_available():
            self.skipTest("mount-ns not available on this host")

    def test_no_post_timeout_execution(self):
        """A target that outlives the run timeout must be killed with
        the sandbox teardown, not keep mutating output afterwards."""
        from core.sandbox._spawn import run_sandboxed
        out = tempfile.mkdtemp(prefix="raptor-pdsig-")
        beat = os.path.join(out, "beat")
        prog = textwrap.dedent(f"""
            import os, time
            # leave the captured process group — the surviving shape:
            # killpg on the setup child's group no longer reaches us
            try:
                os.setsid()
            except OSError:
                pass
            while True:
                with open({beat!r}, "a") as f:
                    f.write("b")
                time.sleep(0.2)
        """)
        with self.assertRaises(subprocess.TimeoutExpired):
            run_sandboxed(
                ["/usr/bin/python3", "-c", prog],
                target=out, output=out,
                block_network=True,
                writable_paths=[out, "/tmp"],
                nproc_limit=1024,
                limits={"memory_mb": 0, "max_file_mb": 10240,
                        "cpu_seconds": 300},
                readable_paths=None, allowed_tcp_ports=None,
                seccomp_profile="full", seccomp_block_udp=False,
                env=None, cwd=None, timeout=3,
                capture_output=True, text=True,
            )
        time.sleep(1.5)
        size_a = os.path.getsize(beat) if os.path.exists(beat) else 0
        time.sleep(2.5)
        size_b = os.path.getsize(beat) if os.path.exists(beat) else 0
        self.assertEqual(size_a, size_b, (
            "target kept executing (heartbeat file still growing) "
            "after the run timeout — the sandbox tree survived "
            "teardown"
        ))


class TestHighFdSweep(unittest.TestCase):
    def setUp(self):
        if not _mount_ns_usable():
            self.skipTest("mount-ns unusable here")
        from core.sandbox._spawn import mount_ns_available
        if not mount_ns_available():
            self.skipTest("mount-ns not available on this host")

    def test_inheritable_fd_above_lowered_limit_is_closed(self):
        import resource
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        want = 5000  # above the sandbox's default 4096 NOFILE cap
        if hard != resource.RLIM_INFINITY and hard <= want:
            self.skipTest("hard NOFILE limit too low to stage the fd")
        raised = False
        if soft <= want:
            resource.setrlimit(resource.RLIMIT_NOFILE, (want + 16, hard))
            raised = True
        try:
            r_end, w_end = os.pipe()
            os.dup2(r_end, want, inheritable=True)
            os.close(r_end)
            self.addCleanup(os.close, w_end)
            self.addCleanup(lambda: os.close(want)
                            if os.path.exists(f"/proc/self/fd/{want}")
                            else None)
            from core.sandbox._spawn import run_sandboxed
            out = tempfile.mkdtemp(prefix="raptor-hifd-")
            prog = textwrap.dedent(f"""
                import os
                try:
                    os.fstat({want})
                    print("FD-SURVIVED")
                except OSError:
                    print("FD-CLOSED")
            """)
            r = run_sandboxed(
                ["/usr/bin/python3", "-c", prog],
                target=out, output=out,
                block_network=True,
                writable_paths=[out, "/tmp"],
                nproc_limit=1024,
                limits={"memory_mb": 0, "max_file_mb": 10240,
                        "cpu_seconds": 300},
                readable_paths=None, allowed_tcp_ports=None,
                seccomp_profile="full", seccomp_block_udp=False,
                env=None, cwd=None, timeout=30,
                capture_output=True, text=True,
            )
            self.assertEqual(r.returncode, 0, r.stderr[-300:])
            self.assertIn("FD-CLOSED", r.stdout, (
                f"inheritable fd {want} (above the lowered NOFILE "
                f"soft limit) survived into the sandboxed child: "
                f"{r.stdout!r}"
            ))
        finally:
            if raised:
                import resource as _res
                _res.setrlimit(_res.RLIMIT_NOFILE, (soft, hard))


class TestPinnedHelperResolution(unittest.TestCase):
    def test_trusted_resolver_ignores_inherited_path(self):
        from core.sandbox.probes import _SAFE_BIN_DIRS, _find_sandbox_binary
        with tempfile.TemporaryDirectory(prefix="raptor-path-") as d:
            fake = os.path.join(d, "newuidmap")
            with open(fake, "w") as f:
                f.write("#!/bin/sh\nexit 0\n")
            os.chmod(fake, os.stat(fake).st_mode | stat.S_IXUSR)
            old_path = os.environ.get("PATH", "")
            os.environ["PATH"] = d
            try:
                got = _find_sandbox_binary("newuidmap")
            finally:
                os.environ["PATH"] = old_path
            self.assertNotEqual(got, fake,
                                "poisoned PATH entry was resolved")
            if got is not None:
                self.assertTrue(
                    any(got.startswith(sd + "/")
                        for sd in _SAFE_BIN_DIRS),
                    f"resolved outside the pinned dirs: {got}")


if __name__ == "__main__":
    unittest.main()
