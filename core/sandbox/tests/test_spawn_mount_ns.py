"""Tests for the mount-ns path: core.sandbox._spawn and core.sandbox.mount_ns.

These tests skip gracefully when prerequisites are missing (newuidmap, or
kernel.apparmor_restrict_unprivileged_userns=1), so they're safe to ship
in CI. When prerequisites ARE present — as on a dev's machine after
flipping the sysctl and installing uidmap — they exercise the full
fork+newuidmap+mount+pivot_root+Landlock+seccomp+pid-ns chain.

Without these, the mount-ns path gets zero direct coverage on Ubuntu
24.04's default (sysctl=1) and regressions would only surface when a
developer manually flips the sysctl.
"""

from __future__ import annotations

import sys as _sys
import pytest as _pytest
pytestmark = _pytest.mark.skipif(
    _sys.platform != "linux",
    reason="Linux-only sandbox internals (mount-ns / Landlock / seccomp / ptrace tracer / pid1 shim) — see core/sandbox/_macos_spawn.py for the macOS path",
)


import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path


def _mount_ns_usable() -> bool:
    """True iff mount-ns actually works here (both prerequisites)."""
    if not shutil.which("newuidmap") or not shutil.which("newgidmap"):
        return False
    sysctl = Path("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
    if sysctl.exists() and sysctl.read_text().strip() == "1":
        return False
    return True


class TestMountNSAvailableProbe(unittest.TestCase):
    """mount_ns_available() — correctness of the runtime probe."""

    def setUp(self):
        from core.sandbox import state
        state._mount_ns_available_cache = None

    def test_returns_bool(self):
        from core.sandbox._spawn import mount_ns_available
        self.assertIsInstance(mount_ns_available(), bool)

    def test_cached(self):
        from core.sandbox import state
        from core.sandbox._spawn import mount_ns_available
        first = mount_ns_available()
        state._mount_ns_available_cache = not first  # fake a cache flip
        self.assertEqual(mount_ns_available(), not first,
                         "mount_ns_available should honour the cache")


class TestSyscallNumberTable(unittest.TestCase):
    """pivot_root syscall number lookup must cover the host arch or raise
    NotImplementedError with a clear message.

    The syscall number IS architecture-specific — a silent fallback to
    the x86_64 number on e.g. aarch64 would make pivot_root invoke the
    wrong syscall entirely (different op, possibly unsafe). The table
    in mount_ns.py is load-bearing."""

    @unittest.skipUnless(sys.platform == "linux", "pivot_root is Linux-only")
    def test_host_arch_is_mapped(self):
        import platform
        from core.sandbox.mount_ns import _PIVOT_ROOT_SYSCALL_NR
        arch = platform.machine()
        self.assertIn(arch, _PIVOT_ROOT_SYSCALL_NR,
                      f"host arch {arch!r} not in pivot_root syscall table "
                      f"— will raise NotImplementedError at run time. "
                      f"Add it to core/sandbox/mount_ns.py.")

    @unittest.skipUnless(sys.platform == "linux", "pivot_root is Linux-only")
    def test_lookup_helper(self):
        from core.sandbox.mount_ns import _pivot_root_nr
        nr = _pivot_root_nr()
        self.assertIsInstance(nr, int)
        self.assertGreater(nr, 0)


class TestRunSandboxedSmokeTest(unittest.TestCase):
    """End-to-end smoke of _spawn.run_sandboxed() against a trivial
    command. Skips on systems where mount-ns prerequisites are absent."""

    def setUp(self):
        if not _mount_ns_usable():
            self.skipTest(
                "mount-ns unusable here (needs uidmap package + "
                "kernel.apparmor_restrict_unprivileged_userns=0)"
            )
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def test_basic_execvp(self):
        """Fork+newuidmap+mount+Landlock+seccomp+exec chain runs. The
        child sees itself as PID 1 (pid-ns) and uid 0 (user-ns-mapped)."""
        from core.sandbox._spawn import run_sandboxed
        r = run_sandboxed(
            ["sh", "-c", "echo pid=$$; id -u"],
            target=self.tmp.name, output=self.tmp.name,
            block_network=True,
            nproc_limit=1024,
            limits={"memory_mb": 0, "max_file_mb": 10240, "cpu_seconds": 300},
            writable_paths=[self.tmp.name, "/tmp"],
            readable_paths=None,
            allowed_tcp_ports=None,
            seccomp_profile=None,
            seccomp_block_udp=False,
            env=None, cwd=None, timeout=15,
            capture_output=True, text=True,
        )
        self.assertEqual(r.returncode, 0, f"stderr: {r.stderr!r}")
        # PID 1 inside the pid-ns, uid 0 inside the user-ns.
        self.assertIn("pid=1", r.stdout)
        self.assertIn("0", r.stdout.splitlines()[-1])

    def test_target_visible_at_original_path(self):
        """Caller's target dir is bind-mounted at its original absolute
        path inside the sandbox, so argv referring to the host path
        resolves identically in the child. No caller-side rewriting."""
        from core.sandbox._spawn import run_sandboxed
        marker = Path(self.tmp.name) / "marker.txt"
        marker.write_text("MARKER-CONTENT\n")
        r = run_sandboxed(
            ["cat", str(marker)],
            target=self.tmp.name, output=self.tmp.name,
            block_network=True,
            nproc_limit=1024,
            limits={"memory_mb": 0, "max_file_mb": 10240, "cpu_seconds": 300},
            writable_paths=[self.tmp.name, "/tmp"],
            readable_paths=None,
            allowed_tcp_ports=None,
            seccomp_profile=None, seccomp_block_udp=False,
            env=None, cwd=None, timeout=15,
            capture_output=True, text=True,
        )
        self.assertEqual(r.returncode, 0, f"stderr: {r.stderr!r}")
        self.assertIn("MARKER-CONTENT", r.stdout)

    def test_output_writable_inside_sandbox(self):
        """A file created in output by the child survives the sandbox."""
        from core.sandbox._spawn import run_sandboxed
        out_file = os.path.join(self.tmp.name, "proof")
        r = run_sandboxed(
            ["touch", out_file],
            target=self.tmp.name, output=self.tmp.name,
            block_network=True,
            nproc_limit=1024,
            limits={"memory_mb": 0, "max_file_mb": 10240, "cpu_seconds": 300},
            writable_paths=[self.tmp.name, "/tmp"],
            readable_paths=None,
            allowed_tcp_ports=None,
            seccomp_profile=None, seccomp_block_udp=False,
            env=None, cwd=None, timeout=15,
            capture_output=True, text=True,
        )
        self.assertEqual(r.returncode, 0, f"stderr: {r.stderr!r}")
        self.assertTrue(os.path.exists(out_file),
                        "file created by sandboxed child should persist "
                        "because output is bind-mounted writable")

    def test_tmp_is_fresh_per_sandbox(self):
        """Per-sandbox tmpfs /tmp — content the caller placed in host
        /tmp is NOT visible inside the sandbox (except the bind-mounted
        target/output path). This is the main isolation win over
        Landlock-only mode."""
        from core.sandbox._spawn import run_sandboxed
        canary = f"/tmp/.raptor-canary-{os.getpid()}"
        Path(canary).write_text("SHOULD-NOT-BE-VISIBLE\n")
        try:
            r = run_sandboxed(
                ["sh", "-c", f"cat {canary} 2>&1 || echo GONE"],
                target=self.tmp.name, output=self.tmp.name,
                block_network=True,
                nproc_limit=1024,
                limits={"memory_mb": 0, "max_file_mb": 10240, "cpu_seconds": 300},
                writable_paths=[self.tmp.name, "/tmp"],
                readable_paths=None,
                allowed_tcp_ports=None,
                seccomp_profile=None, seccomp_block_udp=False,
                env=None, cwd=None, timeout=15,
                capture_output=True, text=True,
            )
            self.assertEqual(r.returncode, 0, f"stderr: {r.stderr!r}")
            self.assertIn("GONE", r.stdout,
                          "/tmp canary leaked into sandboxed view — "
                          "per-sandbox tmpfs isolation broken")
        finally:
            os.unlink(canary)

    def test_stub_dir_cleaned_up_after_run(self):
        """The parent-created tempfile.mkdtemp stub must be removed
        after the child exits. Without cleanup, /tmp accumulates
        empty .raptor-sbx-* dirs across runs.

        Order-independent: monkey-patches tempfile.mkdtemp inside
        _spawn to capture OUR specific stub path, then asserts only
        THAT path got cleaned up. Previous version snapshotted the
        whole .raptor-sbx-* prefix globally, which intermittently
        flaked when concurrent sandbox activity in other tests
        materialised stubs in the gap (memory: project_test_spawn_
        mount_ns_flake.md). Fix: per-run path tracking via
        monkey-patch.
        """
        from core.sandbox import _spawn
        from core.sandbox._spawn import run_sandboxed
        captured_stubs = []
        # _spawn.run_sandboxed imports tempfile internally as _tempfile.
        # Monkey-patch the module-level tempfile.mkdtemp to record the
        # stub path before passing through.
        import tempfile as _tf
        real_mkdtemp = _tf.mkdtemp

        def recording_mkdtemp(*args, **kwargs):
            path = real_mkdtemp(*args, **kwargs)
            if kwargs.get("prefix", "").startswith(".raptor-sbx-"):
                captured_stubs.append(path)
            return path

        # Patch on the tempfile module — _spawn imports tempfile as
        # _tempfile inside the function, so module-level patch wins.
        from unittest.mock import patch
        with patch("tempfile.mkdtemp", side_effect=recording_mkdtemp):
            r = run_sandboxed(
                ["true"],
                target=self.tmp.name, output=self.tmp.name,
                block_network=True,
                nproc_limit=1024,
                limits={"memory_mb": 0, "max_file_mb": 10240,
                        "cpu_seconds": 300},
                writable_paths=[self.tmp.name, "/tmp"],
                readable_paths=None,
                allowed_tcp_ports=None,
                seccomp_profile=None, seccomp_block_udp=False,
                env=None, cwd=None, timeout=15,
                capture_output=False, text=False,
            )

        self.assertEqual(r.returncode, 0)
        self.assertEqual(len(captured_stubs), 1, (
            f"expected exactly 1 stub creation, got {captured_stubs}"
        ))
        # The specific stub we created must be cleaned up. Ignore any
        # other .raptor-sbx-* dirs in /tmp (could be from concurrent
        # test runs; not our responsibility to assert about).
        our_stub = captured_stubs[0]
        self.assertFalse(
            os.path.exists(our_stub),
            f"this test's mkdtemp stub leaked: {our_stub}"
        )


if __name__ == "__main__":
    unittest.main()
