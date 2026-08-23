"""Run-surface hardening: capture ceiling, trust-marker plumbing,
SandboxHost preflight, darwin untrusted tmp posture.

- Parent-side output capture concatenated every child chunk with no
  byte ceiling — a hostile target could balloon the trusted parent's
  memory well inside any timeout.
- The pid1 shim honoured a _RAPTOR_KEEP_TRUST_MARKERS key from its
  inherited environment, so any caller-supplied env dict carrying it
  preserved _RAPTOR_TRUSTED/CLAUDECODE for untrusted code; the keep
  decision now travels as a shim argv flag only run() can set.
- SandboxHost (a hostile-target facility) called generic sandbox_run
  with no untrusted preflight, silently degrading on namespace-less
  hosts with the whole-/proc read grant.
- run_untrusted on macOS kept the host-shared /private/tmp write
  baseline; it now defaults to the per-run scratch posture.
"""

import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest.mock import patch

import pytest

pytestmark = pytest.mark.skipif(
    sys.platform != "linux", reason="Linux spawn backend",
)


def _mount_ns_usable() -> bool:
    if not shutil.which("newuidmap") or not shutil.which("newgidmap"):
        return False
    sysctl = Path("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
    return not (sysctl.exists() and sysctl.read_text().strip() == "1")


class TestCaptureCeiling(unittest.TestCase):
    def setUp(self):
        if not _mount_ns_usable():
            self.skipTest("mount-ns unusable here")
        from core.sandbox._spawn import mount_ns_available
        if not mount_ns_available():
            self.skipTest("mount-ns not available on this host")

    def test_stdout_flood_is_bounded_and_marked(self):
        from core.sandbox._spawn import run_sandboxed
        out = tempfile.mkdtemp(prefix="raptor-cap-")
        prog = textwrap.dedent("""
            import os, sys
            chunk = b"x" * (1024 * 1024)
            for _ in range(80):  # 80 MiB > the 64 MiB ceiling
                os.write(1, chunk)
            os.write(2, b"done")
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
            env=None, cwd=None, timeout=120,
            capture_output=True, text=False,
        )
        self.assertEqual(r.returncode, 0, r.stderr[-300:])
        self.assertLessEqual(
            len(r.stdout), 64 * 1024 * 1024 + 4096,
            "parent-side capture exceeded the 64 MiB ceiling")
        self.assertIn(b"capture truncated", r.stdout,
                      "expected the truncation marker")


class TestKeepTrustMarkersOutOfBand(unittest.TestCase):
    def setUp(self):
        if not _mount_ns_usable():
            self.skipTest("mount-ns unusable here")
        self._tgt = tempfile.TemporaryDirectory(prefix="raptor-ktm-")
        self.addCleanup(self._tgt.cleanup)
        self.tgt = os.path.realpath(self._tgt.name)

    def test_poisoned_env_key_does_not_preserve_markers(self):
        """A caller env dict carrying the legacy env key must NOT keep
        the trust markers in the target env — on any backend."""
        from core.config import RaptorConfig
        from core.sandbox import sandbox
        env = {**RaptorConfig.get_safe_env(),
               "_RAPTOR_KEEP_TRUST_MARKERS": "1"}
        prog = ("import os; "
                "print('T=' + os.environ.get('_RAPTOR_TRUSTED', 'none')"
                " + ' K=' + os.environ.get("
                "'_RAPTOR_KEEP_TRUST_MARKERS', 'none'))")
        with sandbox(target=self.tgt, output=self.tgt,
                     restrict_reads=True) as run:
            # input= forces the Landlock-only unshare+shim path, where
            # the shim used to honour the env key
            r = run(["/usr/bin/python3", "-c", prog], env=env,
                    input="", strip_trust_markers=True,
                    capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr[-400:])
        self.assertIn("T=none", r.stdout, (
            f"poisoned _RAPTOR_KEEP_TRUST_MARKERS env key preserved "
            f"the trust marker for the target: {r.stdout!r}"
        ))
        self.assertIn("K=none", r.stdout)


class TestSandboxHostPreflight(unittest.TestCase):
    def test_start_applies_untrusted_preflight(self):
        import core.sandbox.context as ctx
        from core.sandbox.errors import SandboxSetupError
        from core.sandbox.host import SandboxHost

        def _refuse(entry, restrict_reads=True):
            raise SandboxSetupError("nope", "fix")

        with patch.object(ctx, "_require_userns_or_optin", _refuse):
            with self.assertRaises(SandboxSetupError):
                SandboxHost.start(target=tempfile.gettempdir())


class TestDarwinUntrustedTmpPosture(unittest.TestCase):
    def test_run_untrusted_defaults_exclude_tmp_baseline_on_darwin(
            self):
        import core.sandbox.context as ctx
        captured = {}

        def fake_run(cmd, **kw):
            captured.update(kw)
            return subprocess.CompletedProcess(cmd, 0, "", "")

        with patch.object(ctx.sys, "platform", "darwin"), \
             patch.object(ctx, "check_seatbelt_available",
                          return_value=True), \
             patch.object(ctx, "run", fake_run):
            ctx.run_untrusted(["true"], target=tempfile.gettempdir())
        self.assertIs(captured.get("exclude_tmp_baseline"), True, (
            "darwin run_untrusted must default to the per-run "
            "scratch posture (host-shared /private/tmp otherwise "
            "stays writable)"
        ))

    def test_linux_default_unchanged(self):
        import core.sandbox.context as ctx
        captured = {}

        def fake_run(cmd, **kw):
            captured.update(kw)
            return subprocess.CompletedProcess(cmd, 0, "", "")

        with patch.object(ctx, "run", fake_run), \
             patch.object(ctx, "_require_userns_or_optin",
                          lambda *a, **k: False):
            ctx.run_untrusted(["true"], target=tempfile.gettempdir())
        self.assertNotIn("exclude_tmp_baseline", captured)


if __name__ == "__main__":
    unittest.main()
