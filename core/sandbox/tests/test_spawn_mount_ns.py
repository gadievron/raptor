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


import os  # noqa: E402
import shutil  # noqa: E402
import sys  # noqa: E402
import tempfile  # noqa: E402
import unittest  # noqa: E402
from pathlib import Path  # noqa: E402


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
        # The canary must live in the HOST /tmp root: this test proves the
        # per-sandbox tmpfs shadows /tmp *itself*, so a nested tmp_path
        # wouldn't exercise the mount. NamedTemporaryFile gives a
        # collision-free name and cleans up even when an assert fails —
        # no hand-rolled os.getpid() name or try/finally unlink.
        with tempfile.NamedTemporaryFile(
            dir="/tmp", prefix=".raptor-canary-", mode="w",
        ) as cf:
            cf.write("SHOULD-NOT-BE-VISIBLE\n")
            cf.flush()
            canary = cf.name
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


class TestEtcOverlayMissingHostTarget(unittest.TestCase):
    """etc_overlay when the target path doesn't exist on the host.

    Baron Samedit (CVE-2021-3156) needs /etc/pam.d/sudoedit overlay'd into
    the sandbox, but that file doesn't exist on the host.  On kernel ≥5.12
    the bind mount of /etc is MNT_LOCKED (can't remount RW), and the
    namespace uid can't create files on the host FS anyway (EACCES).

    The fix mounts a tmpfs on {root}/etc, shallow-copies host /etc into it,
    and pre-creates mount-point stubs for missing targets.  This test
    exercises that path end-to-end: the child reads the overlaid content
    through a path that doesn't exist on the host.
    """

    def setUp(self):
        if not _mount_ns_usable():
            self.skipTest(
                "mount-ns unusable here (needs uidmap package + "
                "kernel.apparmor_restrict_unprivileged_userns=0)"
            )
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def test_overlay_file_visible_at_missing_host_path(self):
        """A file overlay'd to a path that doesn't exist on the host
        is readable inside the sandbox with the correct content."""
        from core.sandbox._spawn import run_sandboxed

        # Pick a target path that definitely doesn't exist on the host.
        overlay_target = "/etc/raptor_test_overlay_missing.conf"
        assert not os.path.exists(overlay_target), (
            f"test assumption violated: {overlay_target} exists on host"
        )

        # Create the overlay source file in our temp dir.
        overlay_source = os.path.join(self.tmp.name, "overlay.conf")
        sentinel = "RAPTOR-OVERLAY-SENTINEL-42"
        with open(overlay_source, "w") as f:
            f.write(sentinel + "\n")

        r = run_sandboxed(
            ["cat", overlay_target],
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
            etc_overlay={overlay_target: overlay_source},
        )
        self.assertEqual(r.returncode, 0,
                         f"cat failed inside sandbox; stderr: {r.stderr!r}")
        self.assertIn(sentinel, r.stdout,
                      "overlay content not visible at the missing-host path")

    def test_host_etc_files_still_visible_with_tmpfs_overlay(self):
        """When tmpfs+copy is used for /etc, pre-existing host files
        (e.g. /etc/hostname) remain visible inside the sandbox."""
        from core.sandbox._spawn import run_sandboxed

        overlay_target = "/etc/raptor_test_overlay_missing2.conf"
        assert not os.path.exists(overlay_target)

        overlay_source = os.path.join(self.tmp.name, "overlay2.conf")
        with open(overlay_source, "w") as f:
            f.write("OVERLAY2\n")

        # Read /etc/hostname — a file that exists on any Linux host.
        r = run_sandboxed(
            ["sh", "-c",
             f"cat /etc/hostname && cat {overlay_target}"],
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
            etc_overlay={overlay_target: overlay_source},
        )
        self.assertEqual(r.returncode, 0,
                         f"sandbox cmd failed; stderr: {r.stderr!r}")
        # Host /etc/hostname content should be present (shallow-copied).
        host_hostname = open("/etc/hostname").read().strip()
        self.assertIn(host_hostname, r.stdout,
                      "host /etc/hostname not preserved after tmpfs+copy")
        # Overlay content should also be present.
        self.assertIn("OVERLAY2", r.stdout,
                      "overlay file not visible alongside host /etc")


class TestGidmapAllowProbe(unittest.TestCase):
    """_gidmap_allow_available() — detection of the raptor-gidmap-allow helper."""

    def setUp(self):
        from core.sandbox import state
        state._gidmap_allow_cache = None

    def tearDown(self):
        from core.sandbox import state
        state._gidmap_allow_cache = None

    def test_returns_none_when_binary_missing(self):
        """When the helper binary doesn't exist, returns None."""
        from unittest.mock import patch
        from core.sandbox._spawn import _gidmap_allow_available
        with patch("core.sandbox._spawn.GIDMAP_ALLOW_PATH") as mock_path:
            mock_path.is_file.return_value = False
            self.assertIsNone(_gidmap_allow_available())

    def test_returns_none_when_no_cap_setgid(self):
        """Binary exists but getcap doesn't show cap_setgid → None."""
        from unittest.mock import patch, MagicMock
        from core.sandbox._spawn import _gidmap_allow_available
        mock_run = MagicMock(return_value=MagicMock(stdout="", returncode=0))
        with patch("core.sandbox._spawn.GIDMAP_ALLOW_PATH") as mock_path:
            mock_path.is_file.return_value = True
            with (
                patch("core.sandbox._spawn.shutil.which",
                      return_value="/usr/sbin/getcap"),
                patch("core.sandbox._spawn.subprocess.run", mock_run),
            ):
                self.assertIsNone(_gidmap_allow_available())

    def test_returns_path_when_cap_present(self):
        """Binary exists and getcap confirms cap_setgid → returns path."""
        from unittest.mock import patch, MagicMock
        from core.sandbox._spawn import _gidmap_allow_available
        mock_run = MagicMock(return_value=MagicMock(
            stdout="/path/to/raptor-gidmap-allow cap_setgid=ep",
            returncode=0,
        ))
        with patch("core.sandbox._spawn.GIDMAP_ALLOW_PATH") as mock_path:
            mock_path.is_file.return_value = True
            mock_path.__str__ = lambda _: "/path/to/raptor-gidmap-allow"
            with (
                patch("core.sandbox._spawn.shutil.which",
                      return_value="/usr/sbin/getcap"),
                patch("core.sandbox._spawn.subprocess.run", mock_run),
            ):
                result = _gidmap_allow_available()
                self.assertEqual(result, "/path/to/raptor-gidmap-allow")

    def test_cached_after_first_probe(self):
        """Second call returns the cached value without re-probing."""
        from unittest.mock import patch
        from core.sandbox import state
        from core.sandbox._spawn import _gidmap_allow_available
        with patch("core.sandbox._spawn.GIDMAP_ALLOW_PATH") as mock_path:
            mock_path.is_file.return_value = False
            _gidmap_allow_available()
        # Cache should be set to False (not None).
        self.assertFalse(state._gidmap_allow_cache)
        # Second call should still return None — cache is already decided.
        self.assertIsNone(_gidmap_allow_available())


class TestDeathPipeOrphanTeardown(unittest.TestCase):
    """Death-pipe mechanism: intermediate child exits 137 when the
    parent's write end closes (simulating orchestrator SIGKILL/OOM).

    Tests the core select-loop mechanism without needing mount-ns;
    the loop logic is architecture-independent.
    """

    def test_death_pipe_eof_exits_child(self):
        """Fork a child that watches death_r while waiting on a
        long-running grandchild. Close death_w → child must SIGKILL
        the grandchild and exit 137."""
        import signal as _signal
        import time
        import warnings
        death_r, death_w = os.pipe()
        with warnings.catch_warnings():
            warnings.filterwarnings(
                "ignore", category=DeprecationWarning,
                message=r".*fork.*may lead to deadlocks.*",
            )
            pid = os.fork()
        if pid == 0:
            os.close(death_w)
            grand = os.fork()
            if grand == 0:
                os.close(death_r)
                time.sleep(300)
                os._exit(0)
            import select as _sel
            while True:
                try:
                    p, _st = os.waitpid(grand, os.WNOHANG)
                except ChildProcessError:
                    break
                if p != 0:
                    break
                try:
                    ready, _, _ = _sel.select([death_r], [], [], 0.05)
                except (OSError, ValueError):
                    time.sleep(0.05)
                    continue
                if ready:
                    try:
                        os.kill(grand, _signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    try:
                        os.waitpid(grand, 0)
                    except ChildProcessError:
                        pass
                    os._exit(137)
            os._exit(0)

        os.close(death_r)
        import time
        time.sleep(0.3)
        os.close(death_w)
        _, status = os.waitpid(pid, 0)
        self.assertTrue(os.WIFEXITED(status))
        self.assertEqual(os.WEXITSTATUS(status), 137)

    def test_normal_exit_no_death_pipe(self):
        """When the grandchild exits normally, the intermediate child
        mirrors the exit code and death_r stays open (no false trigger)."""
        import warnings
        death_r, death_w = os.pipe()
        with warnings.catch_warnings():
            warnings.filterwarnings(
                "ignore", category=DeprecationWarning,
                message=r".*fork.*may lead to deadlocks.*",
            )
            pid = os.fork()
        if pid == 0:
            os.close(death_w)
            grand = os.fork()
            if grand == 0:
                os.close(death_r)
                os._exit(42)
            import select as _sel
            import time
            st = 9
            while True:
                try:
                    p, st = os.waitpid(grand, os.WNOHANG)
                except ChildProcessError:
                    break
                if p != 0:
                    break
                try:
                    ready, _, _ = _sel.select([death_r], [], [], 0.05)
                except (OSError, ValueError):
                    time.sleep(0.05)
                    continue
                if ready:
                    try:
                        os.kill(grand, 9)
                    except ProcessLookupError:
                        pass
                    try:
                        os.waitpid(grand, 0)
                    except ChildProcessError:
                        pass
                    os._exit(137)
            if os.WIFEXITED(st):
                os._exit(os.WEXITSTATUS(st))
            os._exit(255)

        os.close(death_r)
        _, status = os.waitpid(pid, 0)
        os.close(death_w)
        self.assertTrue(os.WIFEXITED(status))
        self.assertEqual(os.WEXITSTATUS(status), 42)


if __name__ == "__main__":
    unittest.main()
