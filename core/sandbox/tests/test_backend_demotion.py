"""Per-call mount-ns → Landlock-only demotion hardening.

The mount backend is chosen at context construction, but several
PER-CALL conditions demote a run to the Landlock-only subprocess path
(pass_fds=/input= kwarg compat, the B-fallback cmd-visibility check,
the speculative-failure cache, an M/X setup status). Pre-fix, those
demotions (a) bypassed the strict fail-closed contract, which was only
checked at construction, and (b) kept the construction-time writable
grants — computed for the mount backend where /tmp and /dev/shm are
per-sandbox tmpfs — so the demoted call ran with the HOST-SHARED
scratch directories writable despite a restricted posture.

Also pins the related policy-required gates: a Landlock-unavailable
host must refuse restrict_reads (not silently drop it), and the target
remount-ro failure must fail closed when the ro bind is the only
read-only enforcement for the target.
"""

import errno
import os
import shutil
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(
    sys.platform != "linux", reason="mount-ns backend is Linux-only",
)


def _mount_ns_usable() -> bool:
    if not shutil.which("newuidmap") or not shutil.which("newgidmap"):
        return False
    sysctl = Path("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
    return not (sysctl.exists() and sysctl.read_text().strip() == "1")


class _Base(unittest.TestCase):
    def setUp(self):
        if not _mount_ns_usable():
            self.skipTest("mount-ns unusable here")
        from core.sandbox._spawn import mount_ns_available
        if not mount_ns_available():
            self.skipTest("mount-ns not available on this host")
        self._tgt = tempfile.TemporaryDirectory(prefix="raptor-dem-t-")
        self._out = tempfile.TemporaryDirectory(prefix="raptor-dem-o-")
        self.addCleanup(self._tgt.cleanup)
        self.addCleanup(self._out.cleanup)
        self.tgt = os.path.realpath(self._tgt.name)
        self.out = os.path.realpath(self._out.name)


class TestStrictRefusesPerCallDemotion(_Base):
    def test_input_kwarg_demotion_raises_under_strict(self):
        from core.sandbox import sandbox
        from core.sandbox.errors import SandboxSetupError
        with sandbox(profile="strict", target=self.tgt,
                     output=self.out) as run:
            with self.assertRaises(SandboxSetupError):
                run(["cat"], input="x", capture_output=True, text=True,
                    timeout=30)

    def test_pass_fds_demotion_raises_under_strict(self):
        from core.sandbox import sandbox
        from core.sandbox.errors import SandboxSetupError
        r, w = os.pipe()
        self.addCleanup(lambda: (os.close(r), os.close(w)))
        with sandbox(profile="strict", target=self.tgt,
                     output=self.out) as run:
            with self.assertRaises(SandboxSetupError):
                run(["true"], pass_fds=[r], pass_fds_declared=True,
                    capture_output=True, text=True, timeout=30)

    def test_strict_without_demotion_still_runs(self):
        from core.sandbox import sandbox
        with sandbox(profile="strict", target=self.tgt,
                     output=self.out) as run:
            r = run(["/usr/bin/python3", "-c", "print('ALIVE')"],
                    capture_output=True, text=True, timeout=60)
        self.assertIn("ALIVE", r.stdout, r.stderr[-300:])


class TestDemotedCallGetsPrivateScratch(_Base):
    """input= forces the Landlock-only path; under restrict_reads the
    demoted call must NOT keep the mount-time host /tmp / /dev/shm
    grants — it gets a per-call private scratch dir instead."""

    _PROBE = textwrap.dedent("""
        import os, sys
        sys.stdin.read()
        marker = sys.argv[1]
        try:
            with open(marker, "w") as f:
                f.write("ESCAPED")
            print("hosttmp=writable")
        except OSError:
            print("hosttmp=denied")
        td = os.environ.get("TMPDIR", "/tmp")
        try:
            p = os.path.join(td, "scratch-probe")
            with open(p, "w") as f:
                f.write("ok")
            print("scratch=writable")
        except OSError:
            print("scratch=denied")
    """)

    def test_demoted_restricted_call_cannot_write_host_tmp(self):
        from core.sandbox import sandbox
        marker = os.path.join(
            tempfile.gettempdir(),
            f"raptor-demote-marker-{os.getpid()}")
        self.addCleanup(
            lambda: os.path.exists(marker) and os.unlink(marker))
        with sandbox(target=self.tgt, output=self.out,
                     restrict_reads=True) as run:
            r = run(["/usr/bin/python3", "-c", self._PROBE, marker],
                    input="go", capture_output=True, text=True,
                    timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr[-400:])
        self.assertIn("hosttmp=denied", r.stdout, (
            f"demoted restricted call kept the host /tmp grant: "
            f"{r.stdout!r}"
        ))
        self.assertFalse(os.path.exists(marker),
                         "marker file appeared in host /tmp")
        self.assertIn("scratch=writable", r.stdout, (
            f"TMPDIR-steered private scratch must be writable: "
            f"{r.stdout!r} {r.stderr!r}"
        ))
        self.assertTrue(
            (getattr(r, "sandbox_info", None) or {}).get(
                "private_scratch"),
            "demoted restricted call must stamp private_scratch")

    def test_mounted_run_keeps_full_tmp_semantics(self):
        """No demotion → per-sandbox tmpfs /tmp stays writable."""
        from core.sandbox import sandbox
        with sandbox(target=self.tgt, output=self.out,
                     restrict_reads=True) as run:
            r = run(["/usr/bin/python3", "-c",
                     "open('/tmp/x', 'w').write('x'); print('tmp=ok')"],
                    capture_output=True, text=True, timeout=60)
        self.assertIn("tmp=ok", r.stdout,
                      f"{r.stdout!r} {r.stderr[-300:]!r}")


class TestPolicyRequiredGates(unittest.TestCase):
    def test_restrict_reads_alone_builds_landlock_on_spawn_path(self):
        """_spawn's landlock gate must treat a read-restricted spawn
        with no writable paths / TCP ports as policy-bearing."""
        if not _mount_ns_usable():
            self.skipTest("mount-ns unusable here")
        from core.sandbox._spawn import mount_ns_available, run_sandboxed
        if not mount_ns_available():
            self.skipTest("mount-ns not available on this host")
        from core.sandbox.landlock import check_landlock_available
        if not check_landlock_available():
            self.skipTest("Landlock unavailable")
        with tempfile.NamedTemporaryFile(
                dir=os.path.expanduser("~"), prefix=".raptor-dem-",
                mode="w", delete=False) as f:
            f.write("SECRET")
            secret = f.name
        self.addCleanup(os.unlink, secret)
        prog = textwrap.dedent(f"""
            try:
                print("read=" + open({secret!r}).read())
            except OSError:
                print("read=denied")
        """)
        r = run_sandboxed(
            ["/usr/bin/python3", "-c", prog],
            target=None, output=None, skip_mount_ns=True,
            restrict_reads=True,
            readable_paths=["/usr", "/lib", "/lib64", "/bin", "/etc",
                            "/proc", "/dev"],
            writable_paths=[], allowed_tcp_ports=None,
            block_network=True, nproc_limit=1024,
            limits={"memory_mb": 0, "max_file_mb": 10240,
                    "cpu_seconds": 300},
            seccomp_profile="full", seccomp_block_udp=False,
            env=None, cwd=None, timeout=30,
            capture_output=True, text=True,
        )
        self.assertEqual(r.returncode, 0, r.stderr[-400:])
        self.assertIn("read=denied", r.stdout, (
            f"read-restricted spawn without writable paths lost its "
            f"read restriction: {r.stdout!r}"
        ))


class TestTargetRemountRoFailClosed(_Base):
    def test_remount_failure_aborts_when_target_under_writable_grant(
            self):
        """When the target sits under a writable grant, the ro bind is
        the only read-only enforcement — a remount-ro failure must
        abort the spawn, not warn and continue."""
        from unittest.mock import patch

        from core.sandbox import mount_ns as mns
        from core.sandbox._spawn import run_sandboxed

        # target under /tmp, /tmp in the writable grants
        tgt = tempfile.mkdtemp(prefix="raptor-ro-t-", dir="/tmp")
        self.addCleanup(shutil.rmtree, tgt, True)
        orig = mns._ro_remount_flags

        def _failing(inside, _orig=orig, _tgt=tgt):
            if inside.endswith(_tgt):
                raise OSError(errno.EPERM, "simulated remount denial")
            return _orig(inside)

        with patch.object(mns, "_ro_remount_flags", _failing):
            r = run_sandboxed(
                ["/usr/bin/python3", "-c", "print('ALIVE')"],
                target=tgt, output=self.out,
                writable_paths=[self.out, "/tmp"],
                block_network=True, nproc_limit=1024,
                limits={"memory_mb": 0, "max_file_mb": 10240,
                        "cpu_seconds": 300},
                readable_paths=None, allowed_tcp_ports=None,
                seccomp_profile="full", seccomp_block_udp=False,
                env=None, cwd=None, timeout=30,
                capture_output=True, text=True,
            )
        self.assertNotEqual(r.returncode, 0, (
            f"spawn must fail closed when the target's only read-only "
            f"enforcement (the ro bind) could not be established: "
            f"stdout={r.stdout!r}"
        ))
        self.assertNotIn("ALIVE", r.stdout)


if __name__ == "__main__":
    unittest.main()
