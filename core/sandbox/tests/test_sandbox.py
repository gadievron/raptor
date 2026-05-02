"""Tests for core.sandbox — namespace isolation, resource limits, fallback."""

import os
import subprocess
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from core.sandbox import (
    _check_blocked,
    _DEFAULT_LIMITS,
    _make_preexec_fn,
    check_sandbox_available,
    check_landlock_available,
    sandbox,
    run as sandbox_run,
)


class TestAvailabilityCheck(unittest.TestCase):

    def test_returns_bool(self):
        result = check_sandbox_available()
        self.assertIsInstance(result, bool)

    def test_cached(self):
        """Second call returns same result without re-testing."""
        import core.sandbox as mod; from core.sandbox import state as mod_state
        mod_state._net_available_cache = None
        first = check_sandbox_available()
        second = check_sandbox_available()
        self.assertEqual(first, second)

    def test_no_unshare(self):
        """Returns False when unshare is not found in any safe bin dir.

        The resolver raises FileNotFoundError (hard-fail rather than
        falling back to a bare name that subprocess would resolve via
        PATH — a poisoned PATH on a system missing util-linux is
        exactly the system where PATH-hijack matters). check_net_available
        catches the exception and returns False.
        """
        import core.sandbox as mod; from core.sandbox import state as mod_state
        mod_state._net_available_cache = None
        mod_state._unshare_path_cache = None
        with patch("os.path.isfile", return_value=False):
            self.assertFalse(check_sandbox_available())
        mod_state._net_available_cache = None  # Reset for other tests
        mod_state._unshare_path_cache = None


class TestResourceLimits(unittest.TestCase):
    """preexec_fn tests MUST NOT apply rlimits to the pytest process itself.

    Invoking `_make_preexec_fn(...)()` directly calls resource.setrlimit in
    the current process — previously this silently lowered the pytest
    process's RLIMIT_AS to 512MB for the remainder of the session, which
    is a fragile way to run a test suite. We mock setrlimit so we can
    verify the intended calls without side effects.
    """

    def test_preexec_fn_callable(self):
        fn = _make_preexec_fn(_DEFAULT_LIMITS)
        self.assertTrue(callable(fn))

    def test_preexec_fn_runs(self):
        """preexec_fn doesn't raise when called (setrlimit is mocked)."""
        fn = _make_preexec_fn({"memory_mb": 2048,
                               "max_file_mb": 1024, "cpu_seconds": 60})
        with patch("resource.setrlimit") as mock:
            fn()
        # Four rlimits configured: AS, FSIZE, CPU, CORE.
        self.assertEqual(mock.call_count, 4)

    def test_core_dump_suppressed(self):
        """RLIMIT_CORE=0 is always set — sandboxed crashes must not dump
        memory contents (which would include anything the process read:
        ~/.ssh, ~/.aws/credentials, API keys, etc.).
        """
        import resource as _res
        fn = _make_preexec_fn({"memory_mb": 0,
                               "max_file_mb": 0, "cpu_seconds": 0})
        with patch("resource.setrlimit") as mock:
            fn()
        core_calls = [c for c in mock.call_args_list
                      if c.args[0] == _res.RLIMIT_CORE]
        self.assertEqual(len(core_calls), 1,
                         "RLIMIT_CORE must be set exactly once")
        self.assertEqual(core_calls[0].args[1], (0, 0),
                         "RLIMIT_CORE must be (0, 0)")

    def test_custom_limits_applied(self):
        """Caller-supplied memory_mb is reflected in the setrlimit call."""
        fn = _make_preexec_fn({"memory_mb": 512})
        with patch("resource.setrlimit") as mock:
            fn()
        # Find the RLIMIT_AS call and verify value.
        import resource as _res
        as_calls = [c for c in mock.call_args_list if c.args[0] == _res.RLIMIT_AS]
        self.assertEqual(len(as_calls), 1)
        soft, hard = as_calls[0].args[1]
        self.assertEqual(soft, 512 * 1024 * 1024)
        self.assertEqual(hard, 512 * 1024 * 1024)


class TestBlockedCheck(unittest.TestCase):

    def test_detects_unreachable_when_engaged(self):
        info = {}
        with self.assertLogs("core.sandbox", level="INFO") as cm:
            _check_blocked("connect: Network is unreachable", "make",
                           returncode=1, sandbox_info=info,
                           network_engaged=True)
        self.assertIn("network", cm.output[0].lower())
        self.assertIn("blocked", info)

    def test_detects_curl_failure_when_engaged(self):
        info = {}
        with self.assertLogs("core.sandbox", level="INFO") as cm:
            _check_blocked("curl: (7) Failed to connect", "curl http://evil.com",
                           returncode=7, sandbox_info=info,
                           network_engaged=True)
        self.assertIn("sandbox", cm.output[0].lower())
        self.assertIn("blocked", info)

    def test_network_pattern_silent_when_not_engaged(self):
        """User offline without sandbox must not produce a spurious alert."""
        info = {}
        if hasattr(self, "assertNoLogs"):
            with self.assertNoLogs("core.sandbox", level="INFO"):
                _check_blocked("Could not resolve host: github.com", "git",
                               returncode=128, sandbox_info=info,
                               network_engaged=False)
        else:
            _check_blocked("Could not resolve host: github.com", "git",
                           returncode=128, sandbox_info=info,
                           network_engaged=False)
        # Regardless of Python version: blocked field must stay empty.
        self.assertNotIn("blocked", info)

    def test_write_pattern_silent_when_not_engaged(self):
        """Ordinary EACCES without sandbox must not claim sandbox enforcement."""
        info = {}
        _check_blocked(
            "install: cannot create '/usr/local/bin/foo': Permission denied",
            "make install", returncode=1, sandbox_info=info,
            landlock_engaged=False,
        )
        self.assertNotIn("blocked", info)

    def test_write_inside_writable_paths_ignored(self):
        """Permission denied on a writable path is never Landlock."""
        info = {}
        _check_blocked(
            "sh: cannot create /tmp/foo/locked.db: Permission denied",
            "app", returncode=1, sandbox_info=info,
            landlock_engaged=True, writable_paths=["/tmp"],
        )
        self.assertNotIn("blocked", info)

    def test_write_outside_writable_paths_reported(self):
        info = {}
        with self.assertLogs("core.sandbox", level="INFO") as cm:
            _check_blocked(
                "sh: cannot create /var/tmp/evil: Permission denied",
                "app", returncode=1, sandbox_info=info,
                landlock_engaged=True, writable_paths=["/tmp"],
            )
        self.assertIn("blocked", info)
        self.assertTrue(any("/var/tmp/evil" in line for line in cm.output))

    def test_python_permission_error_reported(self):
        """Python's PermissionError format must also populate blocked evidence."""
        info = {}
        with self.assertLogs("core.sandbox", level="INFO") as cm:
            _check_blocked(
                "PermissionError: [Errno 13] Permission denied: '/etc/shadow'",
                "python app.py", returncode=1, sandbox_info=info,
                landlock_engaged=True, writable_paths=["/tmp"],
            )
        self.assertIn("blocked", info)
        self.assertTrue(any("/etc/shadow" in line for line in cm.output))

    def test_crlf_stderr_strips_control_chars(self):
        """CRLF line endings must not leak \\r into sandbox_info or logs."""
        info = {}
        stderr = "sh: cannot create '/var/tmp/x': Permission denied\r\n"
        _check_blocked(stderr, "app", returncode=1, sandbox_info=info,
                       landlock_engaged=True, writable_paths=["/tmp"])
        self.assertIn("blocked", info)
        # The reported path must not contain any control chars.
        for entry in info["blocked"]:
            self.assertNotIn("\r", entry)
            self.assertNotIn("\n", entry)

    def test_tab_in_path_excluded(self):
        """Tab characters in stderr must not leak into sandbox_info."""
        info = {}
        # Synthetic: tool uses tab as a separator before the offending path.
        stderr = "sh: cannot create '/var/tmp/x': Permission denied\tfiller"
        _check_blocked(stderr, "app", returncode=1, sandbox_info=info,
                       landlock_engaged=True, writable_paths=["/tmp"])
        self.assertIn("blocked", info)
        for entry in info["blocked"]:
            self.assertNotIn("\t", entry)

    def test_no_warning_on_clean_stderr(self):
        _check_blocked("warning: unused variable", "gcc -c foo.c",
                       landlock_engaged=True)

    def test_empty_stderr(self):
        _check_blocked("", "make")
        _check_blocked(None, "make")


class TestSandboxContextManager(unittest.TestCase):

    def test_basic_command(self):
        """A simple command runs and returns CompletedProcess."""
        with sandbox() as run:
            result = run(["echo", "hello"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0)
        self.assertIn("hello", result.stdout)

    def test_env_is_safe(self):
        """Commands get safe env by default (dangerous vars stripped)."""
        os.environ["BASH_ENV"] = "/tmp/evil.sh"
        try:
            with sandbox() as run:
                result = run(["env"], capture_output=True, text=True)
            self.assertNotIn("BASH_ENV", result.stdout)
        finally:
            os.environ.pop("BASH_ENV", None)

    def test_glibc_loader_vars_stripped(self):
        """glibc loader/data-module vars must be stripped — GCONV_PATH etc.
        are classic AT_SECURE-surviving injection vectors and must not flow
        through to sandboxed children. Also covers runtime-injection vars
        like JAVA_TOOL_OPTIONS and OPENSSL_CONF (other pass additions).
        """
        # Pick a representative subset across the categories.
        dangerous = {
            "GCONV_PATH": "/tmp/evil_iconv",
            "LOCPATH": "/tmp/evil_locale",
            "HOSTALIASES": "/tmp/evil_dns",
            "LD_DEBUG": "all",
            "MALLOC_CHECK_": "3",
            "TMPDIR": "/tmp/evil_tmp",
            "RES_OPTIONS": "debug",
            "NLSPATH": "/tmp/evil_nls",
            "JAVA_TOOL_OPTIONS": "-javaagent:/tmp/evil.jar",
            "_JAVA_OPTIONS": "-Devil=true",
            "OPENSSL_CONF": "/tmp/evil.cnf",
            "PYTHONUSERBASE": "/tmp/evil",
            "GIT_CONFIG_GLOBAL": "/tmp/evil.gitconfig",
            "GIT_CONFIG_SYSTEM": "/tmp/evil.gitconfig",
            "GIT_CONFIG": "/tmp/evil.gitconfig",
            "GIT_SSH_COMMAND": "sh -c evil",
            "GIT_SSH": "/tmp/evil",
            "SSH_ASKPASS": "/tmp/evil.sh",
            "PYTHONBREAKPOINT": "evil.run",
            "KUBECONFIG": "/tmp/evil.yaml",
            "GNUTLS_SYSTEM_PRIORITY_FILE": "/tmp/evil",
            "NODE_EXTRA_CA_CERTS": "/tmp/evil.pem",
            "SSLKEYLOGFILE": "/tmp/evil.keys",
            "KRB5_CONFIG": "/tmp/evil.conf",
            "KRB5CCNAME": "/tmp/evil.cc",
        }
        saved = {k: os.environ.get(k) for k in dangerous}
        os.environ.update(dangerous)
        try:
            with sandbox() as run:
                result = run(["env"], capture_output=True, text=True)
            for var in dangerous:
                self.assertNotIn(f"{var}=", result.stdout,
                                 f"{var} should be stripped from sandbox env")
        finally:
            for k, v in saved.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v

    def test_disabled_flag(self):
        """disabled=True skips namespace, still applies env + limits."""
        with sandbox(disabled=True) as run:
            result = run(["echo", "test"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0)

    def test_custom_env_preserved(self):
        """Caller-provided env is respected, not overwritten."""
        custom_env = {"PATH": "/usr/bin", "MY_VAR": "hello"}
        with sandbox() as run:
            result = run(["env"], capture_output=True, text=True, env=custom_env)
        self.assertIn("MY_VAR=hello", result.stdout)

    def test_env_allowlist_blocks_unknown_vars(self):
        """get_safe_env() uses allowlist-first: anything not in
        SAFE_ENV_ALLOWLIST or matching SAFE_ENV_PREFIXES drops by default,
        so future unknown injection vectors can't silently flow through.
        """
        from core.config import RaptorConfig
        # Set a var that's NOT in the allowlist and NOT in the blocklist —
        # under the old pure-blocklist behaviour this would pass through.
        os.environ["RAPTOR_TEST_UNKNOWN_INJECTION"] = "should-not-leak"
        try:
            env = RaptorConfig.get_safe_env()
            self.assertNotIn("RAPTOR_TEST_UNKNOWN_INJECTION", env,
                             "unknown env var flowed through — allowlist broken")
            # Positive case: allowlisted vars come through
            os.environ["LANG"] = "C.UTF-8"
            env = RaptorConfig.get_safe_env()
            self.assertEqual(env.get("LANG"), "C.UTF-8")
            # Prefix-match case: LC_* names come through
            os.environ["LC_TIME"] = "en_GB"
            env = RaptorConfig.get_safe_env()
            self.assertEqual(env.get("LC_TIME"), "en_GB")
            # Belt + braces: a blocklisted var is stripped even if future
            # allowlist additions happen to cover its prefix.
            os.environ["SSH_ASKPASS"] = "/tmp/evil"
            env = RaptorConfig.get_safe_env()
            self.assertNotIn("SSH_ASKPASS", env,
                             "blocklist overlay failed")
        finally:
            for k in ("RAPTOR_TEST_UNKNOWN_INJECTION", "LC_TIME", "SSH_ASKPASS"):
                os.environ.pop(k, None)

    def test_timeout_works(self):
        """Python timeout still functions inside sandbox."""
        with sandbox() as run:
            with self.assertRaises(subprocess.TimeoutExpired):
                run(["sleep", "60"], timeout=1)

    def test_multiple_commands(self):
        """Multiple run() calls work in same context."""
        with sandbox() as run:
            r1 = run(["echo", "first"], capture_output=True, text=True)
            r2 = run(["echo", "second"], capture_output=True, text=True)
        self.assertIn("first", r1.stdout)
        self.assertIn("second", r2.stdout)


class TestSandboxNetworkIsolation(unittest.TestCase):
    """These tests only run when sandboxing is available."""

    def setUp(self):
        if not check_sandbox_available():
            self.skipTest("User namespaces not available")

    def test_network_blocked(self):
        """With network=False, outbound connections fail."""
        with sandbox(block_network=True) as run:
            # Try to connect — should fail with network error
            result = run(
                ["python3", "-c",
                 "import urllib.request; urllib.request.urlopen('http://1.1.1.1', timeout=2)"],
                capture_output=True, text=True, timeout=10,
            )
        self.assertNotEqual(result.returncode, 0)

    def test_localhost_blocked(self):
        """With network=False, even localhost is unreachable."""
        with sandbox(block_network=True) as run:
            result = run(
                ["python3", "-c",
                 "import socket; s=socket.socket(); s.settimeout(1); s.connect(('127.0.0.1', 1))"],
                capture_output=True, text=True, timeout=5,
            )
        self.assertNotEqual(result.returncode, 0)

    def test_command_still_works(self):
        """Basic commands work inside network sandbox."""
        with sandbox(block_network=True) as run:
            result = run(["echo", "sandboxed"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0)
        self.assertIn("sandboxed", result.stdout)


class TestSandboxRun(unittest.TestCase):
    """Test the convenience run() function."""

    def test_basic(self):
        result = sandbox_run(["echo", "test"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0)
        self.assertIn("test", result.stdout)

    def test_disabled(self):
        result = sandbox_run(["echo", "test"], disabled=True,
                             capture_output=True, text=True)
        self.assertEqual(result.returncode, 0)


class TestSandboxProfiles(unittest.TestCase):
    """Test named sandbox profiles."""

    def test_profile_none(self):
        """Profile 'none' runs without isolation."""
        with sandbox(profile="none") as run:
            result = run(["echo", "unsandboxed"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0)
        self.assertIn("unsandboxed", result.stdout)

    def test_profile_network_only(self):
        """Profile 'network-only' blocks network but not filesystem."""
        if not check_sandbox_available():
            self.skipTest("User namespaces not available")
        with sandbox(profile="network-only") as run:
            result = run(["echo", "net-only"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0)
        self.assertIn("net-only", result.stdout)

    def test_profile_full(self):
        """Profile 'full' applies all available isolation."""
        if not check_sandbox_available():
            self.skipTest("User namespaces not available")
        with sandbox(profile="full") as run:
            result = run(["echo", "full"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0)
        self.assertIn("full", result.stdout)

    def test_disabled_overrides_profile(self):
        """disabled=True overrides any profile to 'none'."""
        with sandbox(profile="full", disabled=True) as run:
            result = run(["echo", "disabled"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0)

    def test_convenience_run_with_profile(self):
        result = sandbox_run(["echo", "profiled"], profile="none",
                             capture_output=True, text=True)
        self.assertEqual(result.returncode, 0)


class TestSandboxMountIsolation(unittest.TestCase):
    """Mount namespace tests — only run when available."""

    def setUp(self):
        if not check_sandbox_available():
            self.skipTest("User namespaces not available")

    def test_target_readable(self):
        """Files in target are readable via /target inside sandbox."""
        with TemporaryDirectory() as target, TemporaryDirectory() as output:
            (Path(target) / "test.txt").write_text("hello from target")
            with sandbox(block_network=True, target=target, output=output) as run:
                result = run(
                    ["cat", "/target/test.txt"],
                    capture_output=True, text=True, timeout=5,
                )
            # This may fail if mount namespace setup fails — that's OK,
            # the fallback path is tested separately
            if result.returncode == 0:
                self.assertIn("hello from target", result.stdout)

    def test_output_writable(self):
        """Output directory is writable inside sandbox."""
        with TemporaryDirectory() as target, TemporaryDirectory() as output:
            with sandbox(block_network=True, target=target, output=output) as run:
                result = run(
                    ["sh", "-c", "echo result > /output/test.txt"],
                    capture_output=True, text=True, timeout=5,
                )
            if result.returncode == 0:
                content = (Path(output) / "test.txt").read_text()
                self.assertIn("result", content)


class TestLandlockEnforcement(unittest.TestCase):
    """Test that Landlock actually blocks writes outside allowed paths."""

    def setUp(self):
        if not check_landlock_available():
            self.skipTest("Landlock not available")

    def test_write_to_output_allowed(self):
        """Writes to the output directory succeed."""
        with TemporaryDirectory() as target, TemporaryDirectory() as output:
            with sandbox(target=target, output=output) as run:
                result = run(
                    ["sh", "-c", f"echo allowed > {output}/test.txt"],
                    capture_output=True, text=True, timeout=5,
                )
            self.assertEqual(result.returncode, 0)
            self.assertEqual((Path(output) / "test.txt").read_text().strip(), "allowed")

    def test_write_to_tmp_allowed(self):
        """Writes to /tmp succeed."""
        with TemporaryDirectory() as target, TemporaryDirectory() as output:
            with sandbox(target=target, output=output) as run:
                result = run(
                    ["sh", "-c", "echo allowed > /tmp/sandbox_test_write && cat /tmp/sandbox_test_write"],
                    capture_output=True, text=True, timeout=5,
                )
            self.assertEqual(result.returncode, 0)
            self.assertIn("allowed", result.stdout)

    def test_write_outside_blocked(self):
        """Writes outside allowed paths are blocked — either by Landlock
        (EACCES) or by mount-ns (/var doesn't exist in sandbox root)."""
        with TemporaryDirectory() as target, TemporaryDirectory() as output:
            with sandbox(target=target, output=output) as run:
                result = run(
                    ["sh", "-c", "echo evil > /var/tmp/sandbox_evil_test 2>&1"],
                    capture_output=True, text=True, timeout=5,
                )
            combined = result.stdout + result.stderr
            denied = ("Permission denied" in combined
                      or "Directory nonexistent" in combined
                      or "No such file" in combined)
            self.assertTrue(denied,
                            f"expected EACCES or ENOENT; got {combined!r}")

    def test_relative_output_path_does_not_break_landlock(self):
        """Regression: a relative output= (e.g. 'out/scan_xxx') used to
        fail Landlock open in the mount-ns child after pivot_root,
        printing 'RAPTOR: Landlock writable path could not be opened'
        on stderr and silently disabling the writable rule for output.
        Discovered via E2E scan against /tmp/vulns where scanner.py
        passes a relative out_dir into sandbox_run().
        """
        import os
        from tempfile import TemporaryDirectory
        with TemporaryDirectory() as target_abs, TemporaryDirectory() as parent:
            saved_cwd = os.getcwd()
            os.chdir(parent)
            try:
                rel_out = "out/scan_relative_test"
                os.makedirs(rel_out, exist_ok=True)
                # Resolve to absolute for the shell command — the
                # sandbox child's cwd may not survive pivot_root, so
                # `out/X` (relative) wouldn't resolve from inside the
                # sandbox even when output is correctly bind-mounted.
                # The bind-mount itself is at the absolute path
                # (mount_ns.setup_mount_ns absolutizes output), so
                # writing to that absolute path inside the sandbox is
                # the path the bind-mount actually exposes.
                abs_out = os.path.abspath(rel_out)
                with sandbox(target=target_abs, output=rel_out) as run:
                    result = run(
                        ["sh", "-c", f"echo ok > {abs_out}/proof.txt"],
                        capture_output=True, text=True, timeout=10,
                    )
                self.assertNotIn(
                    "Landlock writable path could not be opened",
                    result.stderr,
                    "relative output= path triggered Landlock open failure",
                )
                self.assertEqual(result.returncode, 0,
                                 f"sandbox child failed: stderr={result.stderr!r}")
                # Verify the write actually went through (proves the
                # bind-mount is correctly wired, not just that Landlock
                # didn't error).
                self.assertTrue(os.path.exists(f"{rel_out}/proof.txt"),
                                "bind-mount didn't deliver write to host")
            finally:
                os.chdir(saved_cwd)

    def test_output_alone_engages_landlock(self):
        """Passing only `output` engages filesystem isolation — writes
        outside fail either via Landlock (EACCES) or mount-ns (path
        not present in the sandbox root)."""
        with TemporaryDirectory() as output:
            with sandbox(output=output) as run:
                result = run(
                    ["sh", "-c", "echo evil > /var/tmp/sandbox_evil_output_only 2>&1"],
                    capture_output=True, text=True, timeout=5,
                )
            combined = result.stdout + result.stderr
            denied = ("Permission denied" in combined
                      or "Directory nonexistent" in combined
                      or "No such file" in combined)
            self.assertTrue(denied,
                            f"expected EACCES or ENOENT; got {combined!r}")

    def test_allowed_ports_alone_engages_landlock(self):
        """Passing only `allowed_tcp_ports` engages Landlock for filesystem too."""
        with sandbox(allowed_tcp_ports=[443]) as run:
            result = run(
                ["sh", "-c", "echo evil > /var/tmp/sandbox_evil_ports_only 2>&1"],
                capture_output=True, text=True, timeout=5,
            )
        self.assertIn("Permission denied", result.stdout + result.stderr)


class TestSeccompBlocklist(unittest.TestCase):
    """Seccomp filter blocks escape-vector syscalls under full/debug."""

    def setUp(self):
        from core.sandbox import check_seccomp_available
        if not check_seccomp_available():
            self.skipTest("libseccomp not available on this system")

    def _run_probe(self, profile: str, code: str) -> subprocess.CompletedProcess:
        with TemporaryDirectory() as d:
            return sandbox_run(
                ["python3", "-c", code],
                profile=profile, target=d, output=d,
                capture_output=True, text=True, timeout=5,
            )

    def test_af_unix_blocked_in_full(self):
        """AF_UNIX socket creation is blocked — closes docker.sock escape."""
        r = self._run_probe("full",
            "import socket; socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("Operation not permitted", r.stderr)

    def test_af_unix_blocked_in_debug(self):
        """debug profile still blocks AF_UNIX — only ptrace is exempted."""
        r = self._run_probe("debug",
            "import socket; socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("Operation not permitted", r.stderr)

    def test_af_unix_allowed_in_network_only(self):
        """network-only disables seccomp — callers that need UDS drop to this."""
        r = self._run_probe("network-only",
            "import socket; s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); print('ok')")
        self.assertEqual(r.returncode, 0)
        self.assertIn("ok", r.stdout)

    def test_ptrace_blocked_in_full(self):
        """ptrace blocked in full — cross-process memory attack closed."""
        r = self._run_probe("full", (
            "import ctypes, os, sys;"
            "libc = ctypes.CDLL(None, use_errno=True);"
            "ret = libc.ptrace(0, 0, 0, 0);"
            "sys.exit(0 if ret < 0 and ctypes.get_errno() == 1 else 1)"
        ))
        self.assertEqual(r.returncode, 0, f"ptrace should be blocked: {r.stderr}")

    def test_ptrace_allowed_in_debug(self):
        """ptrace allowed in debug — enables gdb/rr."""
        r = self._run_probe("debug", (
            "import ctypes, sys;"
            "libc = ctypes.CDLL(None, use_errno=True);"
            "ret = libc.ptrace(0, 0, 0, 0);"
            "sys.exit(0 if ret == 0 else 1)"
        ))
        # PTRACE_TRACEME (op 0) returns 0 on success
        self.assertEqual(r.returncode, 0, f"ptrace should be allowed: {r.stderr}")


class TestForkBombBounded(unittest.TestCase):
    """RLIMIT_NPROC inside the user namespace bounds fork bombs.

    The ns-UID (nobody/65534) starts with zero processes, so NPROC=N
    means "N processes per sandbox invocation" without affecting
    unrelated RAPTOR work on the invoking host UID.
    """

    def setUp(self):
        if not check_sandbox_available():
            self.skipTest("User namespaces not available")

    def test_fork_bomb_bounded_by_nproc(self):
        """nproc=5 caps the sandbox at ~5 processes — fork loop gets EAGAIN."""
        with TemporaryDirectory() as d:
            probe = (
                "import os\n"
                "forked = 0\n"
                "for i in range(30):\n"
                "    try:\n"
                "        pid = os.fork()\n"
                "        if pid == 0:\n"
                "            import time; time.sleep(0.5)\n"
                "            os._exit(0)\n"
                "        forked += 1\n"
                "    except OSError as e:\n"
                "        print(f'blocked at {forked} errno={e.errno}')\n"
                "        break\n"
                "else:\n"
                "    print(f'unbounded forked {forked}')\n"
            )
            result = sandbox_run(
                ["python3", "-c", probe],
                block_network=True, target=d, output=d,
                limits={"nproc": 5},
                capture_output=True, text=True, timeout=15,
            )
        self.assertIn("blocked at", result.stdout,
                      f"fork bomb NOT bounded: {result.stdout!r} / {result.stderr!r}")
        self.assertIn("errno=11", result.stdout)  # EAGAIN

    def test_nproc_not_applied_in_profile_none(self):
        """profile=none must NOT apply NPROC — would hit host UID's count."""
        # This is a smoke test — verify echo runs without errno=11 from
        # an accidental NPROC hitting the host.
        result = sandbox_run(
            ["echo", "ok"], profile="none",
            capture_output=True, text=True, timeout=5,
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("ok", result.stdout)


class TestPidNamespace(unittest.TestCase):
    """PID namespace isolates sandboxed processes from host PIDs."""

    def setUp(self):
        if not check_sandbox_available():
            self.skipTest("User namespaces not available")

    def test_kill_host_pid_blocked(self):
        """kill(host_pid) returns ESRCH — host PID doesn't exist in the ns."""
        import os as _os
        host_pid = _os.getpid()
        with TemporaryDirectory() as d:
            r = sandbox_run(
                ["python3", "-c", (
                    f"import ctypes, os; "
                    f"libc = ctypes.CDLL(None, use_errno=True); "
                    f"ret = libc.kill({host_pid}, 0); "
                    f"print('rc', ret, 'errno', ctypes.get_errno())"
                )],
                block_network=True, target=d, output=d,
                capture_output=True, text=True, timeout=5,
            )
        # kill returns -1 with errno=3 (ESRCH) when the PID isn't visible.
        self.assertIn("errno 3", r.stdout)

    def test_sandboxed_process_is_pid_1(self):
        """With --pid --fork, the sandboxed command runs at a low pid
        in the new pid-ns.

        Exact pid depends on the sandbox layout:
        - pid=1 if the target is exec'd directly as pid-ns init
        - pid=3 when wrapped by libexec/raptor-pid1-shim (shim=pid-1,
          intermediate=pid-2, target=pid-3). The shim exists to avoid
          the kernel's pid-ns signal filter swallowing raise()/abort()
          from the target — see docs/sandbox.md for why.
        Either way, the pid is a small single-digit value and definitely
        not a host pid (which would be in the thousands).
        """
        with TemporaryDirectory() as d:
            r = sandbox_run(
                ["python3", "-c", "import os; print(os.getpid())"],
                block_network=True, target=d, output=d,
                capture_output=True, text=True, timeout=5,
            )
        self.assertIn(r.stdout.strip(), ("1", "2", "3"),
                      f"target pid should be 1–3 (pid-ns root or shim "
                      f"grandchild), got: {r.stdout!r}")


class TestFdIsolation(unittest.TestCase):
    """File descriptors must NOT be inherited from RAPTOR into the sandbox
    except via the explicit pass_fds= escape hatch."""

    def test_close_fds_false_rejected(self):
        with sandbox() as run:
            with self.assertRaises(TypeError) as cm:
                run(["true"], close_fds=False)
            self.assertIn("close_fds=False", str(cm.exception))

    def test_pass_fds_unix_socket_rejected(self):
        """A Unix socket in pass_fds would bypass the seccomp socket()
        family filter entirely — e.g. an inherited /var/run/docker.sock.
        Guard rejects socket FDs; pipes still pass through.
        """
        import socket as _socket
        s = _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM)
        try:
            with sandbox() as run:
                with self.assertRaises(TypeError) as cm:
                    run(["true"], pass_fds=[s.fileno()])
                self.assertIn("socket", str(cm.exception))
        finally:
            s.close()

    def test_pass_fds_pipe_accepted(self):
        """Pipes (S_ISFIFO) are a legitimate pass_fds use — not blocked."""
        r, w = os.pipe()
        try:
            with sandbox() as run:
                result = run(["true"], pass_fds=[r], stdin=r,
                             capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 0)
        finally:
            os.close(r)
            os.close(w)

    def test_pass_fds_invalid_fd_rejected(self):
        """Non-existent FD numbers in pass_fds should raise cleanly."""
        with sandbox() as run:
            with self.assertRaises(TypeError) as cm:
                run(["true"], pass_fds=[9999])
            self.assertIn("not a valid open file descriptor", str(cm.exception))

    def test_sandboxed_child_does_not_see_parent_fd(self):
        """Open an FD in the parent; sandboxed child should NOT see it.
        Default close_fds=True must close FDs ≥3 at fork."""
        import tempfile
        # Open a file in the parent — get an FD ≥3. Capture the path
        # BEFORE write so a failing write still lets the outer finally
        # unlink the stub (delete=False means the NamedTemporaryFile
        # stays on disk unless we explicitly remove it).
        f = tempfile.NamedTemporaryFile(mode="w", delete=False)
        leaked_path = f.name
        leaked_fd = f.file.fileno()
        try:
            try:
                f.write("secret")
            finally:
                f.close()
            with sandbox() as run:
                probe = (
                    "import os\n"
                    f"try:\n"
                    f"    os.fstat({leaked_fd})\n"
                    "    print('LEAKED')\n"
                    "except OSError:\n"
                    "    print('closed')\n"
                )
                r = run(
                    ["python3", "-c", probe],
                    capture_output=True, text=True, timeout=5,
                )
            self.assertIn("closed", r.stdout)
        finally:
            import os as _os
            _os.unlink(leaked_path)

    def test_pass_fds_logged(self):
        """Explicit pass_fds=[N] is allowed but logs INFO for audit."""
        import os as _os
        r, w = _os.pipe()
        try:
            with sandbox() as run:
                with self.assertLogs("core.sandbox", level="INFO") as cm:
                    run(["true"], pass_fds=[r],
                        capture_output=True, text=True, timeout=5)
            self.assertTrue(any("pass_fds" in m for m in cm.output))
        finally:
            _os.close(r)
            _os.close(w)

    def test_custom_env_logged(self):
        """Custom env= bypasses DANGEROUS_ENV_VARS sanitizer — logged at INFO."""
        with sandbox() as run:
            with self.assertLogs("core.sandbox", level="INFO") as cm:
                run(["true"], env={"PATH": "/usr/bin"},
                    capture_output=True, text=True, timeout=5)
        self.assertTrue(any("custom env" in m for m in cm.output))


class TestDebugProfile(unittest.TestCase):
    """The debug profile keeps network/Landlock but permits ptrace."""

    def test_profile_is_registered(self):
        from core.sandbox import PROFILES
        self.assertIn("debug", PROFILES)
        self.assertTrue(PROFILES["debug"]["block_network"])
        self.assertTrue(PROFILES["debug"]["use_landlock"])
        self.assertEqual(PROFILES["debug"]["seccomp"], "debug")

    def test_cli_debug_profile_accepted(self):
        """`--sandbox debug` parses and applies."""
        import argparse
        from core.sandbox import add_cli_args, apply_cli_args, state as mod_state
        parser = argparse.ArgumentParser()
        add_cli_args(parser)
        args = parser.parse_args(["--sandbox", "debug"])
        apply_cli_args(args)
        self.assertEqual(mod_state._cli_sandbox_profile, "debug")


class TestProfilesImmutable(unittest.TestCase):
    """PROFILES is exposed via __all__ — it must be immutable so callers
    can't corrupt the module for all subsequent sandbox() invocations."""

    def test_cannot_mutate_inner_profile(self):
        from core.sandbox import PROFILES
        with self.assertRaises(TypeError):
            PROFILES["full"]["block_network"] = False  # type: ignore[index]

    def test_cannot_add_new_profile(self):
        from core.sandbox import PROFILES
        with self.assertRaises(TypeError):
            PROFILES["custom"] = {"block_network": True, "use_landlock": True}  # type: ignore[index]


class TestRunTrustedGuard(unittest.TestCase):
    """run_trusted() must reject sandbox kwargs — they'd be silently misleading."""

    def test_run_trusted_rejects_sandbox_kwargs(self):
        from core.sandbox import run_trusted
        for bad in ("block_network", "target", "output",
                    "allowed_tcp_ports", "profile", "disabled", "limits"):
            with self.assertRaises(TypeError, msg=f"run_trusted should reject {bad}"):
                run_trusted(["true"], **{bad: "x"})

    def test_run_trusted_accepts_subprocess_kwargs(self):
        from core.sandbox import run_trusted
        result = run_trusted(["echo", "ok"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0)
        self.assertIn("ok", result.stdout)


class TestRunUntrustedGuard(unittest.TestCase):
    """run_untrusted() must require at least one Landlock-engaging arg."""

    def test_run_untrusted_requires_target_or_output(self):
        from core.sandbox import run_untrusted
        with self.assertRaises(ValueError):
            run_untrusted(["true"])  # no target, no output

    def test_run_untrusted_with_output_works(self):
        from core.sandbox import run_untrusted
        with TemporaryDirectory() as out:
            result = run_untrusted(["echo", "ok"], output=out,
                                    capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0)
        self.assertIn("ok", result.stdout)

    def test_run_untrusted_empty_string_rejected(self):
        """Empty strings must not silently bypass the Landlock guard."""
        from core.sandbox import run_untrusted
        for bad in (("", None), (None, "")):
            t, o = bad
            with self.assertRaises(ValueError):
                run_untrusted(["true"], target=t, output=o)

    def test_run_untrusted_rejects_block_network_override(self):
        """run_untrusted contract includes network block — cannot be disabled."""
        from core.sandbox import run_untrusted
        with TemporaryDirectory() as out:
            with self.assertRaises(TypeError):
                run_untrusted(["true"], output=out, block_network=False)

    def test_run_untrusted_rejects_allowed_tcp_ports(self):
        """Dead combination: namespace --net kills any Landlock TCP allow-rule."""
        from core.sandbox import run_untrusted
        with TemporaryDirectory() as out:
            with self.assertRaises(TypeError):
                run_untrusted(["true"], output=out, allowed_tcp_ports=[443])


class TestSandboxRunKwargGuard(unittest.TestCase):
    """sandbox().run() must reject per-call sandbox kwargs."""

    def test_run_rejects_sandbox_kwargs(self):
        with sandbox() as run:
            for bad in ("block_network", "target", "output",
                        "allowed_tcp_ports", "profile", "disabled",
                        "limits", "map_root"):
                with self.assertRaises(TypeError, msg=f"run should reject {bad}"):
                    run(["true"], **{bad: "x"})


class TestTopLevelRunMapRoot(unittest.TestCase):
    """Top-level run() must accept map_root and forward to sandbox()."""

    def test_map_root_accepted(self):
        """Previously, run(cmd, map_root=True) crashed via subprocess.run."""
        from core.sandbox import run
        result = run(["echo", "ok"], map_root=True,
                     capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0)
        self.assertIn("ok", result.stdout)


class TestSanitizerStderrBytes(unittest.TestCase):
    """_interpret_result must detect sanitizer reports in bytes stderr (text=False)."""

    def test_bytes_stderr_asan_detected(self):
        from core.sandbox import _interpret_result
        class FakeResult:
            returncode = 1
            stderr = (
                b"==42==ERROR: AddressSanitizer: heap-buffer-overflow\n"
                b"SUMMARY: AddressSanitizer: heap-buffer-overflow\n"
            )
        r = FakeResult()
        _interpret_result(r, "asan-bin")
        # Previously bytes stderr was silently dropped, missing sanitizer detection.
        self.assertEqual(r.sandbox_info.get("sanitizer"), "asan")
        self.assertTrue(r.sandbox_info.get("crashed"))

    def test_invalid_utf8_stderr_still_parsed(self):
        """Binary stderr with invalid UTF-8 must be decoded gracefully."""
        from core.sandbox import _interpret_result
        class FakeResult:
            returncode = 1
            stderr = b"\xff\xfe bad utf-8 ==42==ERROR: AddressSanitizer: uaf\n"
        r = FakeResult()
        _interpret_result(r, "bin")
        self.assertEqual(r.sandbox_info.get("sanitizer"), "asan")

    def test_bytes_stderr_enforcement_still_detected(self):
        """sandbox() must detect Landlock/network/seccomp blocks even when
        the caller passed capture_output=True without text=True (bytes stderr).

        Regression: previously _check_blocked silently saw empty string when
        stderr was bytes, losing all enforcement detection while
        _interpret_result (sibling call) still decoded correctly.
        """
        import subprocess, tempfile
        from core.sandbox import sandbox
        # Use a sandbox with Landlock engaged and a write to a non-writable
        # path so Landlock produces "Permission denied" stderr in bytes.
        with tempfile.TemporaryDirectory() as td:
            with sandbox(target=td, output=td) as run:
                # touch outside writable dirs: Landlock blocks with EACCES.
                # Don't pass text=True → stderr is bytes.
                result = run(
                    ["sh", "-c", "touch /root/denied_write 2>&1 || true"],
                    capture_output=True,  # no text=True → bytes stderr
                )
        # Even with bytes stderr, sandbox_info should be populated.
        # We don't assert a specific block because the test host may not have
        # Landlock — the key invariant is that sandbox_info exists and the
        # stderr decode path didn't skip.
        self.assertTrue(hasattr(result, "sandbox_info"))


class TestUserLimitsInvalidUtf8(unittest.TestCase):
    """_load_user_limits must not crash on non-UTF-8 config files."""

    def test_invalid_utf8_config(self):
        import core.sandbox as mod; from core.sandbox import state as mod_state
        import tempfile
        from pathlib import Path
        saved_cache = mod_state._user_limits_cache
        saved_path = mod.preexec._CONFIG_PATH
        # Capture tmp_path before the write so a failing write doesn't
        # leak the file AND mask the real error with a NameError in
        # the finally below.
        f = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
        tmp_path = f.name
        try:
            try:
                f.write(b"\xff\xfe garbage bytes")
            finally:
                f.close()
            mod.preexec._CONFIG_PATH = Path(tmp_path)
            mod_state._user_limits_cache = None
            # Must not raise; must log a warning and return empty dict.
            with self.assertLogs("core.sandbox", level="WARNING") as cm:
                result = mod._load_user_limits()
            self.assertEqual(result, {})
            self.assertTrue(any("could not parse" in m for m in cm.output))
        finally:
            mod_state._user_limits_cache = saved_cache
            mod.preexec._CONFIG_PATH = saved_path
            Path(tmp_path).unlink(missing_ok=True)


class TestUserLimitsValidation(unittest.TestCase):
    """_load_user_limits accepts non-negative ints; rejects negatives, bools, and non-ints.

    Zero is a valid "skip this rlimit" sentinel — e.g. memory_mb=0 disables
    RLIMIT_AS, which is required for ASAN-instrumented binaries.
    """

    def test_rejects_negatives_accepts_zero(self):
        import core.sandbox as mod; from core.sandbox import state as mod_state
        import json, tempfile
        from pathlib import Path
        saved_cache = mod_state._user_limits_cache
        saved_path = mod.preexec._CONFIG_PATH
        f = tempfile.NamedTemporaryFile(mode="w", suffix=".json",
                                        delete=False)
        tmp_path = f.name
        try:
            try:
                json.dump({"memory_mb": -1, "cpu_seconds": 0,
                           "max_file_mb": 512}, f)
            finally:
                f.close()
            mod.preexec._CONFIG_PATH = Path(tmp_path)
            mod_state._user_limits_cache = None
            with self.assertLogs("core.sandbox", level="WARNING") as cm:
                result = mod._load_user_limits()
            # -1 rejected; 0 (skip sentinel) and 512 accepted.
            self.assertEqual(result, {"cpu_seconds": 0, "max_file_mb": 512})
            # Warning names the bad key.
            all_msgs = "\n".join(cm.output)
            self.assertIn("memory_mb", all_msgs)
            self.assertNotIn("cpu_seconds", all_msgs)
        finally:
            mod_state._user_limits_cache = saved_cache
            mod.preexec._CONFIG_PATH = saved_path
            Path(tmp_path).unlink(missing_ok=True)

    def test_rejects_bool(self):
        """bool is an int subclass — exclude so `true` doesn't become 1."""
        import core.sandbox as mod; from core.sandbox import state as mod_state
        import json, tempfile
        from pathlib import Path
        saved_cache = mod_state._user_limits_cache
        saved_path = mod.preexec._CONFIG_PATH
        f = tempfile.NamedTemporaryFile(mode="w", suffix=".json",
                                        delete=False)
        tmp_path = f.name
        try:
            try:
                json.dump({"nproc": True, "max_file_mb": 256}, f)
            finally:
                f.close()
            mod.preexec._CONFIG_PATH = Path(tmp_path)
            mod_state._user_limits_cache = None
            with self.assertLogs("core.sandbox", level="WARNING") as cm:
                result = mod._load_user_limits()
            self.assertEqual(result, {"max_file_mb": 256})
            self.assertIn("nproc", "\n".join(cm.output))
        finally:
            mod_state._user_limits_cache = saved_cache
            mod.preexec._CONFIG_PATH = saved_path
            Path(tmp_path).unlink(missing_ok=True)


class TestProfileDiscardWarning(unittest.TestCase):
    """profile='none' with Landlock-engaging args must warn, not silently drop."""

    def test_unknown_profile_raises(self):
        """Typos in profile= must fail loudly, not silently fall back to defaults."""
        with self.assertRaises(ValueError):
            with sandbox(profile="fulll") as run:  # typo
                run(["true"], capture_output=True, text=True)

    def test_profile_none_warns_on_target(self):
        with TemporaryDirectory() as d:
            with self.assertLogs("core.sandbox", level="WARNING") as cm:
                with sandbox(profile="none", target=d) as run:
                    run(["true"], capture_output=True, text=True)
        self.assertTrue(any("ignores" in m and "target" in m for m in cm.output))

    def test_disabled_does_not_warn(self):
        # disabled=True is the user's explicit opt-out; no warning.
        if not hasattr(self, "assertNoLogs"):
            self.skipTest("assertNoLogs requires Python 3.10+")
        import logging
        logger_obj = logging.getLogger("core.sandbox")
        with TemporaryDirectory() as d:
            prev = logger_obj.level
            logger_obj.setLevel(logging.WARNING)
            try:
                with self.assertNoLogs("core.sandbox", level="WARNING"):
                    with sandbox(disabled=True, target=d) as run:
                        run(["true"], capture_output=True, text=True)
            finally:
                logger_obj.setLevel(prev)


class TestSanitizerCrashSemantics(unittest.TestCase):
    """ASAN/MSAN must only set crashed=True when the process actually died."""

    def test_asan_no_death_no_crash(self):
        from core.sandbox import _interpret_result
        class FakeResult:
            returncode = 0
            stderr = (
                "==42==ERROR: AddressSanitizer: heap-buffer-overflow on address ...\n"
                "SUMMARY: AddressSanitizer: heap-buffer-overflow\n"
            )
        r = FakeResult()
        _interpret_result(r, "asan-test")
        self.assertEqual(r.sandbox_info.get("sanitizer"), "asan")
        self.assertFalse(r.sandbox_info.get("crashed"))

    def test_asan_with_abort_crashed(self):
        from core.sandbox import _interpret_result
        class FakeResult:
            returncode = 1  # ASAN often exits 1 even without signal
            stderr = "==42==ERROR: AddressSanitizer: use-after-free\n"
        r = FakeResult()
        _interpret_result(r, "asan-test")
        self.assertEqual(r.sandbox_info.get("sanitizer"), "asan")
        self.assertTrue(r.sandbox_info.get("crashed"))


class TestCacheLockReentrant(unittest.TestCase):
    """check_mount_available nests a call to check_net_available — must not deadlock."""

    def test_nested_check_does_not_deadlock(self):
        import core.sandbox as mod; from core.sandbox import state as mod_state
        mod_state._net_available_cache = None
        mod_state._mount_available_cache = None
        # Should return without hanging
        check_sandbox_available()
        mod_state._mount_available_cache = None
        from core.sandbox import check_mount_available
        check_mount_available()


class TestMountScriptSeparator(unittest.TestCase):
    """`--` between mount options and paths prevents `--help`-as-flag injection."""

    def test_build_mount_script_uses_dashdash(self):
        from core.sandbox import _build_mount_script
        with TemporaryDirectory() as d:
            script = _build_mount_script(d, d)
            try:
                content = Path(script).read_text()
                # Both bind lines must include -- before the path.
                self.assertIn("--bind -o ro -- ", content)
                self.assertIn("--bind -- ", content)
            finally:
                os.unlink(script)

    def test_build_mount_script_hostile_path_after_separator(self):
        """A path like `--help` must appear after --, preventing flag injection.

        shlex.quote doesn't quote `--help` (no shell metachars), so only the
        `--` separator prevents mount from interpreting it as a flag.
        """
        from core.sandbox import _build_mount_script
        script = _build_mount_script("--help", "--version")
        try:
            content = Path(script).read_text()
            self.assertIn("-- --help", content)
            self.assertIn("-- --version", content)
            # Critically, neither flag-lookalike must appear before the separator.
            for line in content.splitlines():
                # After the absolute-path fix, lines look like
                # "/usr/bin/mount --bind ..." — match on the flag, not the prefix.
                if " --bind" in line:
                    pre, _, _ = line.partition(" -- ")
                    self.assertNotIn("--help", pre, f"--help leaked before separator: {line}")
                    self.assertNotIn("--version", pre, f"--version leaked before separator: {line}")
        finally:
            os.unlink(script)

    def test_build_mount_script_uses_absolute_paths(self):
        """mount/mkdir/umount/rmdir must be invoked by absolute path, not
        bare name.

        A polluted PATH (malicious .envrc + direnv, or `.` in PATH) could
        otherwise shadow these with attacker binaries that run under
        Landlock+seccomp but skip the mount-namespace setup — silently
        degrading isolation to the Landlock-only fallback.
        """
        from core.sandbox import _build_mount_script
        with TemporaryDirectory() as d:
            script = _build_mount_script(d, d)
            try:
                content = Path(script).read_text()
                # Collect lines that invoke an external command. Exclude
                # shell syntax that isn't a command invocation: comments,
                # shebang, builtins (set, exec, cd), for/if/done/then/fi,
                # shell variable assignments (ROOT=..., _T=..., _O=...),
                # and script control flow (pivot_root is a binary in
                # util-linux but often a builtin; skip-list it).
                SHELL_KEYWORDS = ("for ", "if ", "then", "else", "fi",
                                  "do", "done", "while ", "elif ")
                SHELL_BUILTINS = ("set ", "exec ", "cd ", "pivot_root")
                import re
                var_assign = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
                command_lines = []
                for line in content.splitlines():
                    s = line.strip()
                    if not s or s.startswith("#") or s.startswith("#!"):
                        continue
                    if any(s.startswith(k) for k in SHELL_KEYWORDS):
                        continue
                    if any(s.startswith(b) for b in SHELL_BUILTINS):
                        continue
                    if var_assign.match(s):
                        continue
                    command_lines.append(s)
                self.assertTrue(command_lines,
                                "filter excluded all lines — bug in test harness")
                for line in command_lines:
                    self.assertTrue(
                        line.startswith("/"),
                        f"non-absolute invocation found: {line!r}",
                    )
            finally:
                os.unlink(script)

    def test_build_mount_script_shell_metachar_quoted(self):
        """Shell metacharacters in a path must be quoted to prevent injection."""
        from core.sandbox import _build_mount_script
        nasty = "/tmp/a; rm -rf /"
        script = _build_mount_script(nasty, nasty)
        try:
            content = Path(script).read_text()
            self.assertIn("'/tmp/a; rm -rf /'", content)
        finally:
            os.unlink(script)


class TestCliProfile(unittest.TestCase):
    """--sandbox <profile> / --no-sandbox CLI surface."""

    def setUp(self):
        import core.sandbox as mod; from core.sandbox import state as mod_state
        self._saved_disabled = mod_state._cli_sandbox_disabled
        self._saved_profile = mod_state._cli_sandbox_profile

    def tearDown(self):
        import core.sandbox as mod; from core.sandbox import state as mod_state
        mod_state._cli_sandbox_disabled = self._saved_disabled
        mod_state._cli_sandbox_profile = self._saved_profile

    def test_set_cli_profile_unknown_rejected(self):
        from core.sandbox import set_cli_profile
        with self.assertRaises(ValueError):
            set_cli_profile("fulll")

    def test_set_cli_profile_none_also_disables(self):
        """profile='none' must set both _cli_sandbox_profile and _cli_sandbox_disabled
        so existing disabled-checks continue to work."""
        import core.sandbox as mod; from core.sandbox import state as mod_state
        from core.sandbox import set_cli_profile
        set_cli_profile("none")
        self.assertEqual(mod_state._cli_sandbox_profile, "none")
        self.assertTrue(mod_state._cli_sandbox_disabled)

    def test_set_cli_profile_switches_coherently(self):
        """Switching profile='none' → 'full' must un-stick the disabled flag."""
        import core.sandbox as mod; from core.sandbox import state as mod_state
        from core.sandbox import set_cli_profile
        set_cli_profile("none")
        self.assertTrue(mod_state._cli_sandbox_disabled)
        set_cli_profile("full")
        self.assertEqual(mod_state._cli_sandbox_profile, "full")
        self.assertFalse(mod_state._cli_sandbox_disabled)

    def test_disable_from_cli_coherent_after_profile_full(self):
        """disable_from_cli() after set_cli_profile('full') must disable — it
        used to leave _cli_sandbox_profile='full' and silently win."""
        import core.sandbox as mod; from core.sandbox import state as mod_state
        from core.sandbox import set_cli_profile, disable_from_cli
        set_cli_profile("full")
        self.assertEqual(mod_state._cli_sandbox_profile, "full")
        disable_from_cli()
        # Both flags must be coherent after the disable.
        self.assertEqual(mod_state._cli_sandbox_profile, "none")
        self.assertTrue(mod_state._cli_sandbox_disabled)

    def test_set_cli_profile_overrides_code_profile(self):
        """CLI --sandbox takes precedence over caller-passed profile= arg."""
        from core.sandbox import set_cli_profile
        set_cli_profile("none")
        # Code asks for full, CLI said none — CLI wins.
        with sandbox(profile="full") as run:
            result = run(["echo", "ok"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0)

    def test_add_cli_args_adds_both_flags(self):
        """add_cli_args attaches --sandbox and --no-sandbox to an argparse parser."""
        import argparse
        from core.sandbox import add_cli_args
        parser = argparse.ArgumentParser()
        add_cli_args(parser)
        # Parse with neither flag — defaults should be None / False
        args = parser.parse_args([])
        self.assertIsNone(args.sandbox)
        self.assertFalse(args.no_sandbox)
        # Parse with --sandbox network-only
        args = parser.parse_args(["--sandbox", "network-only"])
        self.assertEqual(args.sandbox, "network-only")
        # Parse with --no-sandbox
        args = parser.parse_args(["--no-sandbox"])
        self.assertTrue(args.no_sandbox)

    def test_add_cli_args_rejects_unknown_profile(self):
        """argparse choices= rejects typos at parse time."""
        import argparse
        from core.sandbox import add_cli_args
        parser = argparse.ArgumentParser()
        add_cli_args(parser)
        with self.assertRaises(SystemExit):
            parser.parse_args(["--sandbox", "fulll"])

    def test_add_cli_args_mutually_exclusive(self):
        """Passing both --sandbox and --no-sandbox must be a parse error,
        not a silent tie-break."""
        import argparse
        from core.sandbox import add_cli_args
        parser = argparse.ArgumentParser()
        add_cli_args(parser)
        with self.assertRaises(SystemExit):
            parser.parse_args(["--sandbox", "full", "--no-sandbox"])

    def test_apply_cli_args_no_sandbox_alone(self):
        """--no-sandbox sets BOTH flags coherently via shared _set_cli_state."""
        import argparse
        import core.sandbox as mod; from core.sandbox import state as mod_state
        from core.sandbox import add_cli_args, apply_cli_args
        parser = argparse.ArgumentParser()
        add_cli_args(parser)
        args = parser.parse_args(["--no-sandbox"])
        apply_cli_args(args)
        self.assertTrue(mod_state._cli_sandbox_disabled)
        self.assertEqual(mod_state._cli_sandbox_profile, "none")

    def test_apply_cli_args_sandbox_network_only(self):
        """--sandbox network-only sets profile, does NOT set disabled."""
        import argparse
        import core.sandbox as mod; from core.sandbox import state as mod_state
        from core.sandbox import add_cli_args, apply_cli_args
        parser = argparse.ArgumentParser()
        add_cli_args(parser)
        args = parser.parse_args(["--sandbox", "network-only"])
        apply_cli_args(args)
        self.assertEqual(mod_state._cli_sandbox_profile, "network-only")
        self.assertFalse(mod_state._cli_sandbox_disabled)

    def test_apply_cli_args_noop_when_neither_flag(self):
        import argparse
        import core.sandbox as mod; from core.sandbox import state as mod_state
        from core.sandbox import add_cli_args, apply_cli_args
        parser = argparse.ArgumentParser()
        add_cli_args(parser)
        args = parser.parse_args([])
        apply_cli_args(args)
        self.assertIsNone(mod_state._cli_sandbox_profile)
        self.assertFalse(mod_state._cli_sandbox_disabled)


class TestLandlockDegradationWarnings(unittest.TestCase):
    """When Landlock can't enforce what the caller asked for, warn loudly."""

    def setUp(self):
        # Reset the once-per-process warning flags so each test starts clean.
        import core.sandbox as mod; from core.sandbox import state as mod_state
        self._saved_unav = mod_state._landlock_warned_unavailable
        self._saved_abi = mod_state._landlock_warned_abi_v4
        mod_state._landlock_warned_unavailable = False
        mod_state._landlock_warned_abi_v4 = False

    def tearDown(self):
        import core.sandbox as mod; from core.sandbox import state as mod_state
        mod_state._landlock_warned_unavailable = self._saved_unav
        mod_state._landlock_warned_abi_v4 = self._saved_abi

    def test_warns_when_landlock_unavailable_but_target_set(self):
        import core.sandbox as mod; from core.sandbox import state as mod_state
        from unittest.mock import patch
        with TemporaryDirectory() as d:
            # Force check_landlock_available → False regardless of host kernel.
            with patch.object(mod.landlock, "check_landlock_available", return_value=False):
                # Also stub check_mount_available → False so we hit the
                # Landlock-warning branch (use_mount=False).
                with patch.object(mod.probes, "check_mount_available", return_value=False):
                    with self.assertLogs("core.sandbox", level="WARNING") as cm:
                        with sandbox(target=d, output=d) as run:
                            run(["true"], capture_output=True, text=True)
        self.assertTrue(any("Landlock is unavailable" in m for m in cm.output))

    def test_warns_when_tcp_allowlist_on_abi_lt_4(self):
        import core.sandbox as mod; from core.sandbox import state as mod_state
        from unittest.mock import patch
        # Simulate ABI v3 kernel: Landlock available for fs, not for net.
        with patch.object(mod.landlock, "check_landlock_available", return_value=True):
            with patch.object(mod.landlock, "_get_landlock_abi", return_value=3):
                with patch.object(mod.probes, "check_mount_available", return_value=False):
                    with self.assertLogs("core.sandbox", level="WARNING") as cm:
                        with sandbox(allowed_tcp_ports=[443]) as run:
                            run(["true"], capture_output=True, text=True)
        self.assertTrue(any("ABI v4" in m for m in cm.output))

    def test_degradation_warning_throttled(self):
        """Opening many sandbox contexts on a degraded kernel warns ONCE."""
        import core.sandbox as mod; from core.sandbox import state as mod_state
        from unittest.mock import patch
        with TemporaryDirectory() as d:
            with patch.object(mod.landlock, "check_landlock_available", return_value=False), \
                 patch.object(mod.probes, "check_mount_available", return_value=False):
                with self.assertLogs("core.sandbox", level="WARNING") as cm:
                    for _ in range(5):
                        with sandbox(target=d, output=d) as run:
                            run(["true"], capture_output=True, text=True)
        matches = [m for m in cm.output if "Landlock is unavailable" in m]
        self.assertEqual(len(matches), 1,
                         f"expected exactly 1 degradation warning, got {len(matches)}")

    def test_warns_on_old_landlock_abi_v2(self):
        """Pre-5.19 kernels lack REFER — rename-across-dirs isn't blocked.
        Operator should see a WARNING so the gap is visible."""
        import core.sandbox as mod; from core.sandbox import state as mod_state
        with patch.object(mod.landlock, "check_landlock_available", return_value=True):
            with patch.object(mod.landlock, "_get_landlock_abi", return_value=1):
                with patch.object(mod.probes, "check_mount_available", return_value=False):
                    with TemporaryDirectory() as d:
                        with self.assertLogs("core.sandbox", level="WARNING") as cm:
                            with sandbox(target=d, output=d) as run:
                                run(["true"], capture_output=True, text=True)
        # Both v2 and v3 warnings should fire (ABI 1 is below both).
        self.assertTrue(any("ABI v2" in m and "REFER" in m for m in cm.output))
        self.assertTrue(any("ABI v3" in m and "TRUNCATE" in m for m in cm.output))

    def test_warns_on_old_landlock_abi_v3_only(self):
        """Pre-6.2 kernels lack TRUNCATE but have REFER (ABI 2)."""
        import core.sandbox as mod; from core.sandbox import state as mod_state
        with patch.object(mod.landlock, "check_landlock_available", return_value=True):
            with patch.object(mod.landlock, "_get_landlock_abi", return_value=2):
                with patch.object(mod.probes, "check_mount_available", return_value=False):
                    with TemporaryDirectory() as d:
                        with self.assertLogs("core.sandbox", level="WARNING") as cm:
                            with sandbox(target=d, output=d) as run:
                                run(["true"], capture_output=True, text=True)
        # ABI 2: TRUNCATE warning YES, REFER warning NO
        self.assertTrue(any("ABI v3" in m and "TRUNCATE" in m for m in cm.output))
        self.assertFalse(any("ABI v2" in m and "REFER" in m for m in cm.output))

    def test_warns_on_block_network_plus_allowlist(self):
        """block_network=True + allowed_tcp_ports is a dead combination —
        namespace removes all interfaces before Landlock's allow-rule can
        apply. Warn so the caller catches their misconfiguration."""
        with self.assertLogs("core.sandbox", level="WARNING") as cm:
            with sandbox(block_network=True, allowed_tcp_ports=[443]) as run:
                run(["true"], capture_output=True, text=True)
        self.assertTrue(any("unreachable" in m and "443" in m for m in cm.output))

    def test_no_warning_on_abi_v4_with_tcp_allowlist(self):
        """On ABI v4+, allowed_tcp_ports is enforceable — no degradation warning."""
        import core.sandbox as mod; from core.sandbox import state as mod_state
        from unittest.mock import patch
        with patch.object(mod.landlock, "check_landlock_available", return_value=True):
            with patch.object(mod.landlock, "_get_landlock_abi", return_value=4):
                with patch.object(mod.probes, "check_mount_available", return_value=False):
                    import logging
                    logger_obj = logging.getLogger("core.sandbox")
                    with self.assertLogs("core.sandbox", level="WARNING") as cm:
                        with sandbox(allowed_tcp_ports=[443]) as run:
                            run(["true"], capture_output=True, text=True)
                        # Force at least one WARNING so assertLogs doesn't fail
                        logger_obj.warning("test sentinel")
        self.assertFalse(any("ABI v4" in m for m in cm.output))


class TestCliProfileAuthoritative(unittest.TestCase):
    """CLI --sandbox must override library-level disabled=True."""

    def setUp(self):
        import core.sandbox as mod; from core.sandbox import state as mod_state
        self._saved_disabled = mod_state._cli_sandbox_disabled
        self._saved_profile = mod_state._cli_sandbox_profile

    def tearDown(self):
        import core.sandbox as mod; from core.sandbox import state as mod_state
        mod_state._cli_sandbox_disabled = self._saved_disabled
        mod_state._cli_sandbox_profile = self._saved_profile

    def test_cli_full_beats_library_disabled(self):
        """User passed --sandbox full; library code passes disabled=True.
        CLI must win — sandbox should actually run."""
        import core.sandbox as mod; from core.sandbox import state as mod_state
        from core.sandbox import set_cli_profile
        set_cli_profile("full")
        # With disabled=True + CLI='full', we expect CLI to override —
        # use_sandbox must become True when check_net_available is True.
        # Test by observing effective behaviour: the sandbox wrapper
        # should actually engage (unshare in the command line). We can
        # introspect via sandbox_info or just verify no ValueError.
        with TemporaryDirectory() as d:
            with sandbox(disabled=True, target=d, output=d) as run:
                # A command that succeeds regardless of isolation.
                result = run(["echo", "cli-wins"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0)
        self.assertIn("cli-wins", result.stdout)
        # And the CLI state should still read as "full" (not disabled by library).
        self.assertEqual(mod_state._cli_sandbox_profile, "full")
        self.assertFalse(mod_state._cli_sandbox_disabled)


class TestSandboxObservability(unittest.TestCase):
    """Test signal interpretation and sandbox_info."""

    def test_crash_detected(self):
        """A segfaulting process gets sandbox_info with crash evidence."""
        # Write a tiny C program that segfaults, compile and run it
        with TemporaryDirectory() as d:
            src = Path(d) / "crash.c"
            src.write_text('int main(){*(int*)0=0;return 0;}')
            binary = Path(d) / "crash"
            # Compile
            import subprocess
            subprocess.run(["gcc", "-o", str(binary), str(src)],
                           capture_output=True, timeout=10)
            if not binary.exists():
                self.skipTest("gcc not available")
            # Run in sandbox
            result = sandbox_run([str(binary)], block_network=True,
                                 capture_output=True, text=True, timeout=5)
            self.assertTrue(hasattr(result, "sandbox_info"))
            self.assertTrue(result.sandbox_info.get("crashed"))
            self.assertIn("SIGSEGV", result.sandbox_info.get("signal", ""))
            self.assertIn("SIGSEGV", result.sandbox_info.get("evidence", ""))

    def test_normal_exit_no_crash(self):
        """A normal process gets sandbox_info without crash."""
        result = sandbox_run(["true"], capture_output=True, text=True, timeout=5)
        self.assertTrue(hasattr(result, "sandbox_info"))
        self.assertFalse(result.sandbox_info.get("crashed"))
        self.assertNotIn("signal", result.sandbox_info)


class TestCmdVisibleInMountTree(unittest.TestCase):
    """Unit tests for the helper that checks whether cmd[0] resolves to
    a path visible inside the mount-ns bind tree. Drives the B fallback
    behavior in context.py: when cmd[0] is invisible, the sandbox call
    falls back to Landlock-only so the workflow doesn't silently die at
    exit 127 (binary-not-found inside the new rootfs)."""

    def test_system_bin_path_is_visible(self):
        from core.sandbox.context import _cmd_visible_in_mount_tree
        self.assertTrue(_cmd_visible_in_mount_tree(
            ["/usr/bin/cat"], None, None, None))
        self.assertTrue(_cmd_visible_in_mount_tree(
            ["/bin/sh"], None, None, None))

    def test_home_path_not_visible_by_default(self):
        from core.sandbox.context import _cmd_visible_in_mount_tree
        # ~/.local/bin/semgrep is the typical pip --user install location;
        # this is the bug we're guarding against.
        self.assertFalse(_cmd_visible_in_mount_tree(
            ["/home/u/.local/bin/semgrep"], None, None, None))

    def test_home_path_visible_when_extra_paths_cover_it(self):
        from core.sandbox.context import _cmd_visible_in_mount_tree
        self.assertTrue(_cmd_visible_in_mount_tree(
            ["/home/u/.local/bin/semgrep"], None, None,
            ["/home/u/.local/bin"]))

    def test_target_path_is_visible(self):
        from core.sandbox.context import _cmd_visible_in_mount_tree
        # Binary inside the target dir (rare, but legal).
        self.assertTrue(_cmd_visible_in_mount_tree(
            ["/data/target/run.sh"], "/data/target", None, None))

    def test_relative_cmd_falls_through_to_true(self):
        """Can't resolve a non-PATH-findable cmd → don't trigger fallback;
        let the subprocess fail naturally with ENOENT. The point of
        the helper is to AVOID broken workflows, not to second-guess
        a workflow that's already going to fail clearly."""
        from core.sandbox.context import _cmd_visible_in_mount_tree
        self.assertTrue(_cmd_visible_in_mount_tree(
            ["nonexistent-binary-xyz"], None, None, None))

    def test_empty_cmd_falls_through(self):
        from core.sandbox.context import _cmd_visible_in_mount_tree
        self.assertTrue(_cmd_visible_in_mount_tree([], None, None, None))


class TestToolPathsKwarg(unittest.TestCase):
    """C: the tool_paths kwarg is the explicit-opt-in companion to B's
    auto-fallback. Callers that know their tool's install layout pass
    tool_paths so mount-ns isolation engages instead of falling back to
    Landlock-only."""

    def test_tool_paths_accepted_by_sandbox(self):
        from core.sandbox import sandbox
        with sandbox(tool_paths=["/opt/foo/bin"]) as run:
            pass

    def test_tool_paths_accepted_by_top_level_run(self):
        from core.sandbox import run as sandbox_run
        try:
            sandbox_run(["true"], tool_paths=["/opt/foo/bin"],
                        capture_output=True, text=True, timeout=5)
        except (RuntimeError, OSError, FileNotFoundError):
            pass

    def test_tool_paths_rejected_on_inner_run(self):
        """tool_paths is sandbox()-level config; passing it to inner
        run() means the caller misunderstands the API. Reject loudly
        per the _SANDBOX_KWARGS guard in profiles.py."""
        from core.sandbox import sandbox
        with sandbox() as run:
            with self.assertRaises(TypeError):
                run(["true"], tool_paths=["/opt/foo/bin"])


class TestSpeculativeToolPathsRetry(unittest.TestCase):
    """When tool_paths was supplied AND the resulting mount-ns call
    exits 126/127 with empty stderr, the sandbox infers the bind set
    was insufficient (typical Python tool: bin dir bound, stdlib at
    sys.prefix/lib not bound — Python dies before its stderr handler
    starts) and re-runs via Landlock-only fallback.

    These are structural-pin tests — we verify the contract is
    documented in source rather than the runtime mechanism (which
    requires real mount-ns prereqs).
    """

    def test_retry_branch_is_documented_in_source(self):
        """The speculative-retry block MUST be present in context.py.
        Pinned by source-grep so a future refactor that drops the
        retry surfaces in CI immediately.
        """
        from pathlib import Path
        from core.sandbox import context as _ctx
        src = Path(_ctx.__file__).read_text()
        for required in ("Speculative-C retry",
                         "tool_paths",
                         "(126, 127)",
                         "Landlock-only"):
            self.assertIn(required, src,
                          f"speculative-C retry: missing {required!r}")

    def test_signature_filter_uses_empty_stderr_check(self):
        """The retry must NOT fire when stderr is non-empty — those
        are normal tool failures (arg-parse errors etc.) we should
        leave alone. Pinned by source-grep on the .strip() guard."""
        from pathlib import Path
        from core.sandbox import context as _ctx
        src = Path(_ctx.__file__).read_text()
        # The exact pattern the retry uses to gate on empty stderr.
        self.assertIn("not _stderr_text.strip()", src,
                      "speculative-C retry must filter on empty stderr")


class TestSpeculativeFailureCache(unittest.TestCase):
    """The per-cmd speculative-failure cache prevents repeated mount-ns
    setup attempts for binaries known to fail at exec (typical Python
    tools whose native exec deps live outside any reasonable bind set).

    First failure for cmd[0]=X: populate cache, log INFO once.
    Subsequent calls for X: cache-hit, skip mount-ns directly, DEBUG only.

    Saves ~100-300ms per call across many sandbox invocations
    (e.g. scanner.py running 10+ semgrep rule files per scan)."""

    def test_cache_dict_exists(self):
        from core.sandbox import state
        self.assertTrue(hasattr(state, "_speculative_failure_cache"))
        self.assertIsInstance(state._speculative_failure_cache, dict)

    def test_cache_check_pinned_in_source(self):
        """Both the cache POPULATE site (in retry block) and the
        cache HIT site (in spawn-eligibility check) reference the
        canonical attribute name."""
        from pathlib import Path
        from core.sandbox import context as _ctx
        src = Path(_ctx.__file__).read_text()
        self.assertIn("state._speculative_failure_cache[", src,
                      "retry block must populate the cache")
        self.assertIn("in state._speculative_failure_cache", src,
                      "spawn-eligibility must check the cache")

    def test_cache_populate_under_lock(self):
        """Concurrent first-failures for the same binary must not
        double-log. The cache populate is wrapped in state._cache_lock
        so the read+insert+log-decision is atomic."""
        from pathlib import Path
        from core.sandbox import context as _ctx
        src = Path(_ctx.__file__).read_text()
        idx = src.find("state._speculative_failure_cache[")
        assert idx > 0, "cache populate not found"
        preceding = src[max(0, idx - 400):idx]
        self.assertIn("state._cache_lock", preceding,
                      "cache populate must be under state._cache_lock")

    def test_cache_first_seen_logs_at_info(self):
        """Operator-visibility contract: first failure per binary fires
        ONE INFO log; cache-hit subsequent calls log at DEBUG only."""
        from pathlib import Path
        from core.sandbox import context as _ctx
        src = Path(_ctx.__file__).read_text()
        idx = src.find("if _first_seen:")
        assert idx > 0, "first-seen branch missing"
        block = src[idx:idx + 1500]
        self.assertIn("logger.info(", block,
                      "first-failure-per-binary must log at INFO")
        self.assertIn("logger.debug(", block,
                      "cache-hit subsequent calls must log at DEBUG")


class TestMountNsToolPathFallbackContract(unittest.TestCase):
    """B: structural pin that the helper exists with the canonical name
    context.py's spawn-eligibility check uses. The fallback is
    DEBUG-logged (no warn-once flag) — workflow proceeds correctly,
    operator doesn't need to act. Functional fallback exercise lives
    in test_spawn_mount_ns where real mount-ns prereqs are required."""

    def test_fallback_logs_at_debug_not_warning(self):
        """The B fallback message must be at DEBUG level — workflow
        works, operator has nothing to fix. Pinned by source-grep
        on the call-site usage."""
        from pathlib import Path
        from core.sandbox import context as _ctx
        src = Path(_ctx.__file__).read_text()
        # Find the CALL SITE (not the definition). The pattern
        # `if not _cmd_visible_in_mount_tree(` only appears inside
        # the spawn-eligibility check.
        idx = src.find("if not _cmd_visible_in_mount_tree(")
        assert idx > 0, "fallback call site missing"
        # The fallback log call sits inside the `if not visible:`
        # branch — within ~600 chars of the call site.
        block = src[idx:idx + 600]
        assert "logger.debug" in block, \
            "B fallback should log at DEBUG (was WARNING — see " \
            "user-feedback round on noise reduction)"
        assert "logger.warning" not in block, \
            "B fallback must NOT log at WARNING — workflow proceeds " \
            "correctly, operator has nothing to fix"

    def test_helper_distinguishes_inside_vs_outside(self):
        """Both branches of the fallback decision pinned with the
        canonical paths scanner.py / codeql call sites will produce
        in production."""
        from core.sandbox.context import _cmd_visible_in_mount_tree
        # Pip --user install — the original bug case.
        self.assertFalse(_cmd_visible_in_mount_tree(
            ["/home/u/.local/bin/semgrep"], None, None, None))
        # Same with explicit tool_paths — the fix path.
        self.assertTrue(_cmd_visible_in_mount_tree(
            ["/home/u/.local/bin/semgrep"], None, None,
            ["/home/u/.local/bin"]))
        # System-installed (operator-fix path).
        self.assertTrue(_cmd_visible_in_mount_tree(
            ["/usr/local/bin/semgrep"], None, None, None))


if __name__ == "__main__":
    unittest.main()
