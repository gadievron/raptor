"""Landlock metadata-op gap: honest stamping of a kernel limitation.

Landlock has no access right covering metadata-only operations —
chmod/chown/utimensat/setxattr on any same-UID file OUTSIDE the
writable allowlist succeed in Landlock-only posture (content
reads/writes stay blocked). Seccomp cannot close it (the path is a
pointer argument classic BPF cannot dereference); mount-ns mode closes
it via read-only binds (EROFS).

These tests pin two things:
1. The posture stamp: Landlock-without-mount-ns runs carry
   sandbox_info["landlock_metadata_ops_unrestricted"] = True so
   downstream readers do not trust file modes/timestamps after such a
   run; mount-ns runs do not carry it.
2. The limitation itself, falsifiably: chmod outside the allowlist
   SUCCEEDS in the Landlock-only posture. If a future kernel or fix
   closes the gap this test fails, telling us to drop the stamp and
   the docs bullet rather than keep documenting a fixed limitation.
"""

import os
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

import pytest

pytestmark = pytest.mark.skipif(
    sys.platform != "linux", reason="Landlock posture stamps are Linux-only",
)


def _landlock_ok():
    from core.sandbox import check_landlock_available
    return check_landlock_available()


class TestTruncateGapStamp(unittest.TestCase):
    """On Landlock ABI 1/2 (pre-6.2 kernels) the
    TRUNCATE right is silently absent from the handled write mask.
    Mirror the metadata-gap treatment: warn once at ruleset build and
    stamp sandbox_info["landlock_truncate_unrestricted"] on
    Landlock-only runs. Hermetic via a monkeypatched ABI probe."""

    def setUp(self):
        if not _landlock_ok():
            self.skipTest("Landlock unavailable on this host")
        from core.sandbox import landlock as ll
        if ll._get_landlock_abi() < 2:
            # Patching the probe UP past the real kernel ABI would
            # put unsupported bits (REFER) in the handled mask.
            self.skipTest("host Landlock ABI < 2")
        self._out = tempfile.TemporaryDirectory(prefix="raptor-truncgap-")
        self.addCleanup(self._out.cleanup)
        self.out = self._out.name

    def _ll_run(self, cmd, abi):
        from core.sandbox import sandbox
        with patch("core.sandbox.landlock._get_landlock_abi",
                   return_value=abi), \
             patch("core.sandbox.context.check_net_available",
                   return_value=False), \
             patch("core.sandbox.context.check_mount_available",
                   return_value=False):
            with sandbox(output=self.out, block_network=False) as run:
                return run(cmd, capture_output=True, text=True, timeout=60)

    def test_abi2_landlock_only_run_stamps_truncate_gap(self):
        r = self._ll_run(["/bin/true"], abi=2)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(
            r.sandbox_info.get("landlock_truncate_unrestricted"),
            "ABI<3 Landlock-only posture must stamp the TRUNCATE gap",
        )

    def test_abi3_landlock_only_run_does_not_stamp(self):
        r = self._ll_run(["/bin/true"], abi=3)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn(
            "landlock_truncate_unrestricted", r.sandbox_info,
            "ABI>=3 handles TRUNCATE — the gap stamp must not appear",
        )


class TestTruncateGapWarning(unittest.TestCase):
    """The build-time degradation notice: one process-wide WARNING
    when a filesystem-governing ruleset is built on a pre-3 ABI, none
    on ABI>=3, none for net-only rulesets."""

    def test_warns_once_on_pre3_abi_fs_ruleset(self):
        from core.sandbox import landlock as ll
        with patch.object(ll, "_truncate_warned", False), \
             patch.object(ll, "_get_landlock_abi", return_value=2):
            with self.assertLogs("core.sandbox.landlock",
                                 level="WARNING") as cm:
                ll._make_landlock_preexec(["/tmp"])
            self.assertTrue(
                any("TRUNCATE" in m for m in cm.output),
                f"expected a TRUNCATE degradation warning: {cm.output}")
            # Second build in the same process: throttled to once.
            with self.assertNoLogs("core.sandbox.landlock",
                                   level="WARNING"):
                ll._make_landlock_preexec(["/tmp"])

    def test_no_warning_on_abi3(self):
        # ABI 3 has TRUNCATE, so no truncate-gap warning; the
        # unrelated scoping notice (needs ABI 6) is latched out so
        # this test keeps pinning only the truncate contract.
        from core.sandbox import landlock as ll
        with patch.object(ll, "_truncate_warned", False), \
             patch.object(ll, "_scoping_warned", True), \
             patch.object(ll, "_get_landlock_abi", return_value=3), \
             self.assertNoLogs("core.sandbox.landlock", level="WARNING"):
            ll._make_landlock_preexec(["/tmp"])


class TestScopingGapWarning(unittest.TestCase):
    def test_warns_once_below_abi6(self):
        from core.sandbox import landlock as ll
        with patch.object(ll, "_scoping_warned", False), \
             patch.object(ll, "_truncate_warned", True), \
             patch.object(ll, "_get_landlock_abi", return_value=3):
            with self.assertLogs(
                    "core.sandbox.landlock", level="WARNING") as logs:
                ll._make_landlock_preexec(["/tmp"])
            self.assertEqual(
                len([m for m in logs.output
                     if "scoping unavailable" in m]), 1)
            # latched: a second build emits nothing further
            with self.assertNoLogs(
                    "core.sandbox.landlock", level="WARNING"):
                ll._make_landlock_preexec(["/tmp"])

    def test_no_scoping_warning_at_abi6(self):
        from core.sandbox import landlock as ll
        with patch.object(ll, "_scoping_warned", False), \
             patch.object(ll, "_truncate_warned", True), \
             patch.object(ll, "_get_landlock_abi", return_value=6), \
             self.assertNoLogs("core.sandbox.landlock", level="WARNING"):
            ll._make_landlock_preexec(["/tmp"])

    def test_no_warning_for_net_only_ruleset(self):
        # A net-only deny governs no filesystem access — the missing
        # TRUNCATE right is irrelevant there.
        from core.sandbox import landlock as ll
        with patch.object(ll, "_truncate_warned", False), \
             patch.object(ll, "_get_landlock_abi", return_value=2), \
             self.assertNoLogs("core.sandbox.landlock", level="WARNING"):
            ll._make_landlock_preexec([], deny_all_tcp_connect=True)


class TestMetadataGapStamp(unittest.TestCase):
    def setUp(self):
        if not _landlock_ok():
            self.skipTest("Landlock unavailable on this host")
        self._out = tempfile.TemporaryDirectory(prefix="raptor-metagap-")
        self.addCleanup(self._out.cleanup)
        self.out = self._out.name
        home = os.path.expanduser("~")
        if not os.access(home, os.W_OK):
            self.skipTest("home directory not writable on this host")
        # Same-UID victim outside every allowlist (home-rooted like the
        # battery; /tmp is inside the unrestricted writable baseline).
        self._victim_dir = tempfile.TemporaryDirectory(
            dir=home, prefix=".raptor-metagap-")
        self.addCleanup(self._victim_dir.cleanup)
        self.victim = os.path.join(self._victim_dir.name, "victim.txt")
        with open(self.victim, "w") as f:
            f.write("victim\n")
        os.chmod(self.victim, 0o600)

    def _ll_run(self, cmd):
        from core.sandbox import sandbox
        with patch("core.sandbox.context.check_net_available",
                   return_value=False), \
             patch("core.sandbox.context.check_mount_available",
                   return_value=False):
            with sandbox(output=self.out, block_network=False) as run:
                return run(cmd, capture_output=True, text=True, timeout=60)

    def test_landlock_only_run_stamps_metadata_gap(self):
        r = self._ll_run(["/bin/true"])
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(
            r.sandbox_info.get("landlock_metadata_ops_unrestricted"),
            "Landlock-only posture must stamp the metadata-op gap",
        )

    def test_metadata_gap_is_real_until_the_kernel_closes_it(self):
        """chmod outside the allowlist succeeds in LL-only posture.

        This pins the documented limitation. When it starts FAILING,
        the kernel (or a new layer) closed the gap: remove the stamp,
        the docs bullet, and this test together.
        """
        r = self._ll_run(["/bin/chmod", "0640", self.victim])
        self.assertEqual(
            r.returncode, 0,
            f"chmod unexpectedly blocked (stderr: {r.stderr!r}) — the "
            f"documented Landlock metadata gap appears closed; update "
            f"the stamp and docs",
        )
        mode = stat.S_IMODE(os.stat(self.victim).st_mode)
        self.assertEqual(mode, 0o640)

    def test_content_write_still_blocked_where_metadata_is_not(self):
        """The gap is metadata-ONLY: content writes to the same victim
        stay blocked by Landlock."""
        r = self._ll_run(["/bin/sh", "-c", f"echo pwned >> {self.victim}"])
        self.assertNotEqual(r.returncode, 0,
                            "content write outside the allowlist must "
                            "stay blocked")
        with open(self.victim) as f:
            self.assertNotIn("pwned", f.read())

    def test_mount_ns_run_does_not_stamp(self):
        import shutil as _shutil

        from core.sandbox import check_mount_available
        if not (check_mount_available()
                and _shutil.which("newuidmap")):
            self.skipTest("mount-ns unavailable on this host")
        from core.sandbox import sandbox
        with sandbox(target=self.out, output=self.out) as run:
            r = run(["/bin/true"], capture_output=True, text=True,
                    timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        if not r.sandbox_info.get("mount_ns_active"):
            self.skipTest("mount-ns did not engage on this run")
        self.assertNotIn("landlock_metadata_ops_unrestricted",
                         r.sandbox_info)


if __name__ == "__main__":
    unittest.main()
