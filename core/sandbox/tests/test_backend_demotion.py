"""Per-call mount-ns → Landlock-only demotion hardening.

The mount backend is chosen at context construction, but several
PER-CALL conditions demote a run to the Landlock-only subprocess path
(the B-fallback cmd-visibility check,
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
from unittest.mock import patch

import pytest
from core.sandbox.tests.capability import (
    requires_landlock,
    requires_mount,
    requires_userns,
)

pytestmark = pytest.mark.skipif(
    sys.platform != "linux", reason="mount-ns backend is Linux-only",
)


def _mount_ns_usable() -> bool:
    if not shutil.which("newuidmap") or not shutil.which("newgidmap"):
        return False
    sysctl = Path("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
    return not (sysctl.exists() and sysctl.read_text().strip() == "1")


def _force_spawn_failure():
    return patch("core.sandbox._spawn.run_sandboxed",
                 side_effect=RuntimeError("forced native setup failure"))


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


# Exercises mount-delivered capability; hosts with userns but no mount capability degrade by design -> named SKIP, not a mid-flight mount failure.
@requires_mount
class TestStrictRefusesPerCallDemotion(_Base):
    @requires_landlock
    @requires_userns
    def test_input_kwarg_no_longer_demotes_under_strict(self):
        # input= converts to a private stdin spool and rides the fork
        # backend — strict mode has nothing to refuse: the call runs
        # WITH the mount-ns posture and the bytes arrive on stdin.
        from core.sandbox import sandbox
        with sandbox(profile="strict", target=self.tgt,
                     output=self.out) as run:
            r = run(["cat"], input="witness-x", capture_output=True,
                    text=True, timeout=30)
        self.assertEqual(r.returncode, 0, r.stderr[-300:])
        self.assertIn("witness-x", r.stdout)

    @requires_landlock
    @requires_userns
    def test_input_stdin_spool_is_read_only(self):
        # The converted spool must reach the target with NO write
        # capability on fd 0 — a writable description would let the
        # target grow a host-tmp file to RLIMIT_FSIZE.
        from core.sandbox import sandbox
        probe = ('import os\n'
                 'print("IN=" + os.read(0, 64).decode())\n'
                 'try:\n'
                 '    os.write(0, b"x")\n'
                 '    print("WRITE=allowed")\n'
                 'except OSError:\n'
                 '    print("WRITE=denied")\n')
        with sandbox(profile="strict", target=self.tgt,
                     output=self.out) as run:
            r = run(["sh", "-c", "python3 -c '" + probe + "'"],
                    input="witness-ro", capture_output=True,
                    text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr[-300:])
        self.assertIn("IN=witness-ro", r.stdout)
        self.assertIn("WRITE=denied", r.stdout)

    @requires_userns
    def test_truncated_stdin_spool_fails_loud(self):
        # A spool that silently loses the input= bytes must abort the
        # run: handing the target an empty fd 0 turns a witness-driven
        # run into a clean exit and a wrong verdict downstream.
        import tempfile as _tf
        from unittest import mock

        from core.sandbox import sandbox
        from core.sandbox.errors import SandboxSetupError

        real_temporary_file = _tf.TemporaryFile

        def _lossy_temporary_file(*a, **k):
            f = real_temporary_file(*a, **k)

            class _Lossy:
                def __getattr__(self, name):
                    return getattr(f, name)

                def write(self, data):
                    return len(data)  # claim success, write nothing

            return _Lossy()

        with mock.patch.object(
                _tf, "TemporaryFile", _lossy_temporary_file), \
                sandbox(profile="strict", target=self.tgt,
                        output=self.out) as run:
            with self.assertRaises(SandboxSetupError) as cm:
                run(["cat"], input="witness-x", capture_output=True,
                    text=True, timeout=30)
        self.assertIn("spool integrity", str(cm.exception))

    @requires_userns
    def test_input_and_stdin_together_raise(self):
        # subprocess.run's own contract, kept across the spool
        # conversion instead of silently preferring input=.
        from core.sandbox import sandbox
        _pr, _pw = os.pipe()
        self.addCleanup(lambda: (os.close(_pr), os.close(_pw)))
        with sandbox(profile="strict", target=self.tgt,
                     output=self.out) as run:
            with self.assertRaises(ValueError):
                run(["cat"], input="x", stdin=_pr,
                    capture_output=True, text=True, timeout=30)

    @requires_userns
    def test_pass_fds_keeps_strict_namespace_backend(self):
        from core.sandbox import sandbox
        r, w = os.pipe()
        self.addCleanup(lambda: (os.close(r), os.close(w)))
        with sandbox(profile="strict", target=self.tgt,
                     output=self.out) as run:
            result = run(["true"], pass_fds=[r],
                         capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(result.sandbox_info["mount_ns_active"])

    @requires_landlock
    @requires_userns
    def test_strict_without_demotion_still_runs(self):
        from core.sandbox import sandbox
        with sandbox(profile="strict", target=self.tgt,
                     output=self.out) as run:
            r = run(["/usr/bin/python3", "-c", "print('ALIVE')"],
                    capture_output=True, text=True, timeout=60)
        self.assertIn("ALIVE", r.stdout, r.stderr[-300:])


class TestDemotedCallGetsPrivateScratch(_Base):
    """A failed native setup must not expose host scratch on fallback."""

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

    @requires_landlock
    def test_demoted_restricted_call_cannot_write_host_tmp(self):
        from core.sandbox import sandbox
        marker = os.path.join(
            tempfile.gettempdir(),
            f"raptor-demote-marker-{os.getpid()}")
        self.addCleanup(
            lambda: os.path.exists(marker) and os.unlink(marker))
        # Force a genuine native setup failure; descriptors stay supported.
        _pr, _pw = os.pipe()
        os.write(_pw, b"go")
        os.close(_pw)
        self.addCleanup(lambda: (os.close(_pr) if _pr else None))
        with sandbox(target=self.tgt, output=self.out,
                     restrict_reads=True) as run, _force_spawn_failure():
            r = run(["/usr/bin/python3", "-c", self._PROBE, marker],
                    stdin=_pr, pass_fds=[_pr], pass_fds_declared=True,
                    capture_output=True, text=True,
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

    @requires_landlock
    @requires_userns
    @requires_mount
    def test_spawn_lane_masks_host_cgroup(self):
        # Namespace execution masks host membership; a forced fallback is stamped.
        from core.sandbox import sandbox
        with sandbox(target=self.tgt, output=self.out) as run:
            r = run(["cat", "/proc/self/cgroup"],
                    capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr[-400:])
        self.assertIn("0::/", r.stdout, r.stdout)
        for tell in ("user.slice", "session-", ".scope"):
            self.assertNotIn(tell, r.stdout,
                             f"host cgroup path leaked: {r.stdout!r}")
        # The demoted plain lane still RUNS the same shape (floor
        # BARE for trusted work) — pin the routing, not the mask.
        _pr, _pw = os.pipe()
        os.write(_pw, b"go")
        os.close(_pw)
        self.addCleanup(lambda: os.close(_pr))
        with sandbox(target=self.tgt, output=self.out) as run, _force_spawn_failure():
            r2 = run(["cat", "/proc/self/cgroup"],
                     stdin=_pr, pass_fds=[_pr], pass_fds_declared=True,
                     capture_output=True, text=True, timeout=60)
        self.assertEqual(r2.returncode, 0, r2.stderr[-400:])
        self.assertEqual(r2.sandbox_info.get("containment_tier"),
                         "landlock")

    @requires_landlock
    @requires_userns
    # Exercises mount-delivered capability; hosts with userns but no mount capability degrade by design -> named SKIP, not a mid-flight mount failure.
    @requires_mount
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


@requires_userns
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


@requires_userns
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


class TestDemotionLandlockRecheck(_Base):
    """A per-call mount-ns demotion on a Landlock-less kernel must
    refuse, not run unconfined.

    The construction-time "confinement requested but Landlock
    unavailable" refusal only fires when the mount backend was ruled
    out at setup. A call that chose mount-ns and was then demoted
    (a mid-setup spawn error or an M/X setup status)
    lands on the Landlock-only path — where every byte of the requested
    target/output/allowed_tcp_ports/restrict_reads policy is enforced
    by Landlock alone, and the preexec silently skips its Landlock arm
    when the kernel lacks it. Pre-fix the demoted call returned rc=0
    with NO filesystem or TCP confinement at all.
    """

    def _devnull_fd(self):
        fd = os.open("/dev/null", os.O_RDONLY)
        self.addCleanup(os.close, fd)
        return fd

    def _patch_landlock_unavailable(self):
        from unittest.mock import patch

        import core.sandbox.landlock as _ll
        return patch.object(_ll, "check_landlock_available",
                            return_value=False)

    def _sandbox_run_or_skip(self, **sandbox_kwargs):
        """Enter a mount-backend sandbox context, or skip.

        The demotion chokepoint under test only exists when the context
        actually chose the mount backend. On hosts where it cannot
        engage (no unprivileged userns: the construction-time gates own
        the refusal instead) or where a probe run cannot complete (no
        Landlock: the spawn child fails its install loudly), these
        tests have nothing to exercise — skip with the reason rather
        than asserting against whichever OTHER gate fired first.
        block_network=False keeps the network-deny gates out of the
        picture entirely.
        """
        from core.sandbox import sandbox
        from core.sandbox.errors import SandboxSetupError
        ctx = sandbox(block_network=False, target=self.tgt,
                      output=self.out, **sandbox_kwargs)
        try:
            run = ctx.__enter__()
        except SandboxSetupError as exc:
            self.skipTest(f"sandbox cannot engage here: {exc}")
        self.addCleanup(ctx.__exit__, None, None, None)
        try:
            probe = run(["true"], capture_output=True, timeout=30)
        except SandboxSetupError as exc:
            self.skipTest(f"probe run cannot engage here: {exc}")
        if not (probe.returncode == 0
                and (getattr(probe, "sandbox_info", None) or {})
                .get("mount_ns_active")):
            self.skipTest("mount backend not engaging on this host")
        return run

    def test_pass_fds_demotion_without_landlock_refuses(self):
        from core.sandbox.errors import SandboxSetupError
        run = self._sandbox_run_or_skip()
        fd = self._devnull_fd()
        with self._patch_landlock_unavailable(), _force_spawn_failure():
            with self.assertRaises(SandboxSetupError) as cm:
                run(["true"], pass_fds=(fd,), capture_output=True,
                    timeout=30)
        self.assertIn("Landlock is unavailable", str(cm.exception))
        self.assertIn("demoted", str(cm.exception))

    def test_restrict_reads_demotion_without_landlock_refuses(self):
        from core.sandbox.errors import SandboxSetupError
        run = self._sandbox_run_or_skip(restrict_reads=True)
        fd = self._devnull_fd()
        with self._patch_landlock_unavailable(), _force_spawn_failure():
            with self.assertRaises(SandboxSetupError):
                run(["true"], pass_fds=(fd,), capture_output=True,
                    timeout=30)

    def test_spawn_error_demotion_without_landlock_refuses(self):
        # A mid-setup spawn failure rides the degradation ladder to the
        # Landlock-only path — the recheck must fire there too.
        from unittest.mock import patch

        from core.sandbox import _spawn
        from core.sandbox.errors import SandboxSetupError
        run = self._sandbox_run_or_skip()
        with self._patch_landlock_unavailable(), \
                patch.object(_spawn, "run_sandboxed",
                             side_effect=RuntimeError(
                                 "forced spawn setup failure")):
            with self.assertRaises(SandboxSetupError) as cm:
                run(["true"], capture_output=True, timeout=30)
        self.assertIn("Landlock is unavailable", str(cm.exception))

    def test_demotion_with_landlock_still_degrades(self):
        # Control: with Landlock genuinely available the demoted lane
        # keeps its designed graceful-degradation behaviour.
        from core.sandbox.landlock import check_landlock_available
        if not check_landlock_available():
            self.skipTest("Landlock unavailable")
        run = self._sandbox_run_or_skip()
        fd = self._devnull_fd()
        with _force_spawn_failure():
            r = run(["true"], pass_fds=(fd,), capture_output=True, timeout=30)
        self.assertEqual(r.returncode, 0, r.stderr[-300:])


if __name__ == "__main__":
    unittest.main()
