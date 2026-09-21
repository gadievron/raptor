"""Mount-tree spawns drop the host-custom TMPDIR writable grant.

The context's writable baseline carries ``tempfile.gettempdir()``.
When the host TMPDIR is customised, that path exists only on the host
filesystem — the mount-tree child pivots onto a fresh tmpfs at /tmp —
so the post-pivot Landlock grant-open failed and wrote ``sandbox:
Landlock writable path could not be opened`` into the CHILD's stderr,
where consumers reading a tool's diagnostics (PoC-compile evidence,
build-failure summaries) misattributed it as the tool failing.
"""

import os
import sys
import tempfile
import unittest

import pytest

from core.sandbox._spawn import _drop_host_tmpdir_grants

pytestmark = pytest.mark.skipif(
    sys.platform != "linux", reason="mount-ns / Landlock are Linux-only",
)


class TestDropHostTmpdirGrants(unittest.TestCase):
    def setUp(self):
        self._saved_tempdir = tempfile.tempdir
        self.scratch = tempfile.mkdtemp(prefix="custom-tmp-")

    def tearDown(self):
        tempfile.tempdir = self._saved_tempdir
        import shutil
        shutil.rmtree(self.scratch, ignore_errors=True)

    def test_custom_tmpdir_baseline_entry_dropped(self):
        tempfile.tempdir = self.scratch
        writable = [self.scratch, "/dev/shm", "/tmp", "/out/run"]
        result = _drop_host_tmpdir_grants(
            writable, target="/src/repo", output="/out/run", rootfs=None)
        self.assertNotIn(self.scratch, result)
        self.assertEqual(result, ["/dev/shm", "/tmp", "/out/run"])

    def test_default_tmp_untouched(self):
        tempfile.tempdir = "/tmp"
        writable = ["/tmp", "/dev/shm", "/out/run"]
        result = _drop_host_tmpdir_grants(
            writable, target="/src/repo", output="/out/run", rootfs=None)
        self.assertEqual(result, writable)

    def test_bound_output_equal_to_tmpdir_is_kept(self):
        # output= IS bind-mounted, so it exists post-pivot even when it
        # coincides with the custom tmpdir — dropping it would revoke a
        # caller-requested write surface.
        tempfile.tempdir = self.scratch
        writable = [self.scratch, "/tmp"]
        result = _drop_host_tmpdir_grants(
            writable, target=None, output=self.scratch, rootfs=None)
        self.assertEqual(result, writable)

    def test_paths_under_custom_tmpdir_are_kept(self):
        # Only the exact baseline entry is vestigial; caller-supplied
        # paths beneath it keep their (pre-existing) behaviour.
        tempfile.tempdir = self.scratch
        nested = os.path.join(self.scratch, "sub")
        writable = [self.scratch, nested]
        result = _drop_host_tmpdir_grants(
            writable, target=None, output="/out/run", rootfs=None)
        self.assertEqual(result, [nested])


class TestMountNsChildStderrClean(unittest.TestCase):
    """End-to-end: a custom host TMPDIR no longer leaks a Landlock
    grant-open failure into the sandboxed child's stderr, and the
    write surfaces the baseline promises keep working."""

    def setUp(self):
        from core.sandbox._spawn import mount_ns_available
        from core.sandbox.landlock import check_landlock_available
        if not mount_ns_available():
            self.skipTest("mount-ns backend unavailable on this host")
        if not check_landlock_available():
            # The subject is the Landlock grant-open leak — vacuous
            # without Landlock. And on hosts where mount(2) is ALSO
            # refused at runtime (feature-matrix no-landlock/no-both
            # lanes probe mount_in_userns=fail), the spawn's Landlock-
            # only fallback hits the designed fail-closed refusal
            # (target/output confinement with no layer to enforce it),
            # which is the sandbox working as intended, not a grant
            # regression. Same gate as the sibling classes below.
            self.skipTest("Landlock unavailable — grant semantics "
                          "unobservable")
        self._saved_tempdir = tempfile.tempdir
        # A real host dir so gettempdir() resolves; it will not exist
        # inside the child's fresh /tmp tmpfs.
        self.scratch = tempfile.mkdtemp(prefix="custom-tmp-")
        tempfile.tempdir = self.scratch

    def tearDown(self):
        tempfile.tempdir = self._saved_tempdir
        import shutil
        shutil.rmtree(self.scratch, ignore_errors=True)

    def test_no_grant_open_failure_and_writes_work(self):
        from tempfile import TemporaryDirectory

        from core.sandbox import sandbox
        # Outside /tmp: the per-sandbox tmpfs masks host /tmp, so a
        # /tmp-resident output would prove nothing about bind-mounted
        # write delivery.
        with TemporaryDirectory(dir="/var/tmp") as target, \
                TemporaryDirectory(dir="/var/tmp") as output:
            with sandbox(target=target, output=output,
                         block_network=True) as run:
                result = run(
                    ["sh", "-c",
                     f"touch /tmp/probe && touch {output}/probe"],
                    capture_output=True, text=True, timeout=30,
                )
            self.assertNotIn(
                "Landlock writable path could not be opened",
                result.stderr or "",
                "host-custom TMPDIR grant leaked a Landlock open "
                "failure into the child's stderr",
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(
                os.path.exists(os.path.join(output, "probe")))


if __name__ == "__main__":
    unittest.main()

class TestSymlinkedHostTmp(unittest.TestCase):
    """Hosts where /tmp itself resolves through a symlink: the drop
    must never take the LITERAL /tmp baseline entry with it — that
    entry names the per-sandbox tmpfs, and realpath equality with the
    host tmpdir is an artifact of the symlink, not vestigiality."""

    def setUp(self):
        self._saved_tempdir = tempfile.tempdir
        tempfile.tempdir = "/tmp"

    def tearDown(self):
        tempfile.tempdir = self._saved_tempdir

    def test_literal_tmp_entry_survives_symlinked_tmp(self):
        from unittest.mock import patch

        real = os.path.realpath

        def fake_realpath(path: str) -> str:
            if os.path.abspath(path) == "/tmp":
                return "/fake-resolved-tmp"
            return real(path)

        writable = ["/tmp", "/dev/shm", "/out/run"]
        with patch("os.path.realpath", side_effect=fake_realpath):
            result = _drop_host_tmpdir_grants(
                writable, target=None, output="/out/run", rootfs=None)
        self.assertEqual(result, writable)


class TestMountlessLaneKeepsHostTmpdirGrant(unittest.TestCase):
    """Lane pin: the drop applies ONLY to mount-tree spawns. A
    mountless-ns child (skip_mount_ns) sees the HOST filesystem,
    where the custom-TMPDIR grant is load-bearing — applying the drop
    there would silently revoke the child's temp-dir write surface."""

    def setUp(self):
        from core.sandbox.landlock import check_landlock_available
        if sys.platform != "linux" or not check_landlock_available():
            self.skipTest("Landlock unavailable — grant semantics "
                          "unobservable")
        self._saved_tempdir = tempfile.tempdir
        # Outside /tmp so no other baseline grant masks a revocation.
        self.scratch = tempfile.mkdtemp(prefix="custom-tmp-",
                                        dir="/var/tmp")
        tempfile.tempdir = self.scratch

    def tearDown(self):
        tempfile.tempdir = self._saved_tempdir
        import shutil
        shutil.rmtree(self.scratch, ignore_errors=True)

    def test_skip_mount_ns_child_writes_host_tmpdir(self):
        from tempfile import TemporaryDirectory

        from core.sandbox import sandbox
        probe = os.path.join(self.scratch, "probe")
        with TemporaryDirectory(dir="/var/tmp") as target, \
                TemporaryDirectory(dir="/var/tmp") as output:
            with sandbox(target=target, output=output,
                         block_network=True) as run:
                result = run(
                    ["sh", "-c", f"touch {probe}"],
                    capture_output=True, text=True, timeout=60,
                    skip_mount_ns=True,
                )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(
                os.path.exists(probe),
                "host-TMPDIR write grant revoked on the mountless lane",
            )


class TestGrantOpenFailureNamesPath(unittest.TestCase):
    """A genuinely un-openable writable grant still fails loudly —
    and the failure line names the path, so it is attributable."""

    def test_missing_writable_grant_named_in_stderr(self):
        from tempfile import TemporaryDirectory

        from core.sandbox import sandbox
        from core.sandbox.landlock import check_landlock_available
        if not check_landlock_available():
            self.skipTest("Landlock unavailable")
        missing = "/var/tmp/no-such-grant-dir-e79b1c"
        with TemporaryDirectory(dir="/var/tmp") as target, \
                TemporaryDirectory(dir="/var/tmp") as output:
            with sandbox(target=target, output=output,
                         block_network=True,
                         writable_paths=[missing]) as run:
                result = run(["true"], capture_output=True, text=True,
                             timeout=60)
        self.assertIn(
            f"Landlock writable path could not be opened: {missing}",
            result.stderr or "",
        )
