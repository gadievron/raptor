"""Mount-stacking order across target/output/extra_ro binds.

A mount attached at a path covers (shadows) every EARLIER mount
attached at or below that path — path resolution enters the topmost
mount on a dentry. setup_mount_ns used to order binds by CLASS
(target/output in step 8, every readable_paths entry in step 8b), so
a read-only bind naming an ANCESTOR of the output dir — the shape of
a run dir nested under a repo checkout that is itself in
readable_paths — mounted AFTER the rw output bind and shadowed it.
The child's own output dir went read-only: every run-dir write failed
with EROFS while the run carried on against an unwritable output.
Within the readable_paths list the ordering was caller-order luck: a
descendant entry stayed visible only when the caller listed its
ancestor first.

Fix under test: binds mount ancestors-first across target, output,
and readable_paths — a proper ro ancestor of target/output mounts
BEFORE step 8, the rw output (and the evidence/marker shadows stacked
on it) ends up topmost, and the readable_paths list itself is
ancestor-sorted so nesting never depends on caller order.

All tests are end-to-end through run_sandboxed and skip gracefully
where mount-ns prerequisites are missing (same pattern as
test_spawn_mount_ns.py).
"""

from __future__ import annotations

import shutil
import sys
import tempfile
import unittest
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(
    sys.platform != "linux", reason="mount-ns backend is Linux-only",
)

from core.sandbox.tests.capability import (  # noqa: E402
    requires_landlock,
    requires_mount,
    requires_userns,
)


def _mount_ns_usable() -> bool:
    if not shutil.which("newuidmap") or not shutil.which("newgidmap"):
        return False
    sysctl = Path("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
    if sysctl.exists() and sysctl.read_text().strip() == "1":
        return False
    return True


_LIMITS = {"memory_mb": 0, "max_file_mb": 10240, "cpu_seconds": 300}


def _run(cmd, *, target, output, readable_paths, writable_paths):
    from core.sandbox._spawn import run_sandboxed
    return run_sandboxed(
        cmd,
        target=target, output=output,
        block_network=True,
        nproc_limit=1024,
        limits=dict(_LIMITS),
        writable_paths=writable_paths,
        readable_paths=readable_paths,
        allowed_tcp_ports=None,
        seccomp_profile=None, seccomp_block_udp=False,
        env=None, cwd=None, timeout=15,
        capture_output=True, text=True,
    )


@requires_landlock
@requires_userns
# Exercises mount-delivered capability; hosts with userns but no mount
# capability degrade by design -> named SKIP.
@requires_mount
class TestRwOutputUnderRoAncestorBind(unittest.TestCase):
    """The output dir nested under a readable_paths tree — the exact
    four-mount shape that shadowed the run dir: rw output bind + its
    run-marker mask, then the ro ancestor bind + a sibling ro bind."""

    def setUp(self):
        if not _mount_ns_usable():
            self.skipTest(
                "mount-ns unusable here (needs uidmap package + "
                "kernel.apparmor_restrict_unprivileged_userns=0)"
            )
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        # repo/ (readable)  — the covering ancestor
        #   readme.txt
        #   out/run_a/      — the OUTPUT dir (writable, nested)
        #     .raptor-run.json  (mask target: step 8a2)
        #   out/run_b/      — a second readable entry under the ancestor
        #     artifact.txt
        self.repo = Path(self.tmp.name) / "repo"
        self.outdir = self.repo / "out" / "run_a"
        self.sibling = self.repo / "out" / "run_b"
        self.outdir.mkdir(parents=True)
        self.sibling.mkdir(parents=True)
        (self.repo / "readme.txt").write_text("REPO-CONTENT\n")
        (self.sibling / "artifact.txt").write_text("SIBLING-CONTENT\n")
        (self.outdir / ".raptor-run.json").write_text('{"meta": "M"}\n')
        self.target = Path(self.tmp.name) / "target"
        self.target.mkdir()

    def _dispatch(self, cmd):
        return _run(
            cmd,
            target=str(self.target), output=str(self.outdir),
            readable_paths=[str(self.repo), str(self.sibling)],
            writable_paths=[str(self.outdir), "/tmp"],
        )

    def test_output_stays_writable_under_later_ro_ancestor(self):
        """The regression: a write into the output dir must succeed in
        the child and persist on the host — the ro ancestor bind must
        not cover the rw output bind."""
        proof = self.outdir / "proof.txt"
        r = self._dispatch(
            ["sh", "-c", f"echo OK > {proof} && echo WROTE-OUTPUT"])
        self.assertEqual(r.returncode, 0, f"stderr: {r.stderr!r}")
        self.assertIn(
            "WROTE-OUTPUT", r.stdout,
            "output dir went read-only inside the sandbox — the ro "
            "ancestor bind shadowed the rw output bind (EROFS on the "
            "child's own run dir)",
        )
        self.assertTrue(proof.exists(),
                        "child write did not land on the host output dir")

    def test_ancestor_stays_read_only_around_the_output(self):
        """The rw output must not widen the ancestor: writes anywhere
        else in the readable tree keep failing, and its content stays
        readable."""
        atk = self.repo / "atk.txt"
        r = self._dispatch(
            ["sh", "-c",
             f"cat {self.repo / 'readme.txt'};"
             f"echo pwn > {atk} 2>/dev/null || echo ANCESTOR-RO"])
        self.assertEqual(r.returncode, 0, f"stderr: {r.stderr!r}")
        self.assertIn("REPO-CONTENT", r.stdout,
                      "readable ancestor content not visible")
        self.assertIn("ANCESTOR-RO", r.stdout,
                      "write into the read-only ancestor bind succeeded")
        self.assertFalse(atk.exists(),
                         "host file materialised through the read-only "
                         "ancestor bind")

    def test_sibling_readable_entry_stays_visible(self):
        """The second readable entry under the same ancestor (the shape
        that only ever worked by caller-order luck) stays served."""
        r = self._dispatch(["cat", str(self.sibling / "artifact.txt")])
        self.assertEqual(r.returncode, 0, f"stderr: {r.stderr!r}")
        self.assertIn("SIBLING-CONTENT", r.stdout)

    def test_run_marker_mask_stays_on_top(self):
        """The step-8a2 marker mask must apply to the FINAL topmost
        output bind: the child reads the run marker as empty, not the
        real metadata through a shadowed (or shadowing) view."""
        r = self._dispatch(
            ["sh", "-c", f"wc -c < {self.outdir / '.raptor-run.json'}"])
        self.assertEqual(r.returncode, 0, f"stderr: {r.stderr!r}")
        self.assertEqual(
            r.stdout.strip(), "0",
            "run-marker content leaked through the child's output view "
            "— the mask no longer sits on the topmost output bind",
        )

    def test_descendant_listed_before_ancestor_still_stacks(self):
        """Intra-list ordering must not depend on the caller: the
        descendant readable entry listed BEFORE its ancestor still
        ends up stacked ON the ancestor's mount (parent-id relation in
        the child's mountinfo), not shadowed under it."""
        r = _run(
            ["cat", "/proc/self/mountinfo"],
            target=str(self.target), output=str(self.outdir),
            # Descendant first — the order that used to lose.
            readable_paths=[str(self.sibling), str(self.repo)],
            writable_paths=[str(self.outdir), "/tmp"],
        )
        self.assertEqual(r.returncode, 0, f"stderr: {r.stderr!r}")
        mounts = {}  # mountpoint -> (mount_id, parent_id)
        for line in r.stdout.splitlines():
            fields = line.split()
            if len(fields) >= 5:
                mounts[fields[4]] = (fields[0], fields[1])
        self.assertIn(str(self.repo), mounts, "ancestor bind missing")
        self.assertIn(str(self.sibling), mounts, "descendant bind missing")
        self.assertEqual(
            mounts[str(self.sibling)][1], mounts[str(self.repo)][0],
            "descendant readable bind is not a child of its ancestor's "
            "mount — it mounted first and got shadowed (caller-order "
            "dependence regressed)",
        )


@requires_landlock
@requires_userns
# Exercises mount-delivered capability; hosts with userns but no mount
# capability degrade by design -> named SKIP.
@requires_mount
class TestDoubleSlashSpellings(unittest.TestCase):
    """POSIX preserves an exactly-two-slash prefix through abspath, so
    a "//"-spelled path names the same file under a spelling that
    used to evade every exact-string policy check: a //-prefixed
    readable ancestor was not classified as an ancestor (mounted in
    the post pass and re-shadowed the rw output — the same run-dir
    EROFS this module's ordering fix closes), and "//tmp" evaded the
    per-ns shadow refusal (binding HOST /tmp read-only over the fresh
    per-sandbox tmpfs). Canonicalisation must collapse the spelling
    before any policy comparison."""

    def setUp(self):
        if not _mount_ns_usable():
            self.skipTest(
                "mount-ns unusable here (needs uidmap package + "
                "kernel.apparmor_restrict_unprivileged_userns=0)"
            )
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.repo = Path(self.tmp.name) / "repo"
        self.outdir = self.repo / "out" / "run_a"
        self.outdir.mkdir(parents=True)
        self.target = Path(self.tmp.name) / "target"
        self.target.mkdir()

    def test_doubleslash_ancestor_does_not_shadow_output(self):
        """"//"-spelled readable ancestor of the output dir: the
        collapse must classify it as an ancestor, so the rw output
        bind still ends up topmost and writable."""
        proof = self.outdir / "proof.txt"
        r = _run(
            ["sh", "-c", f"echo OK > {proof} && echo WROTE-OUTPUT"],
            target=str(self.target), output=str(self.outdir),
            readable_paths=["/" + str(self.repo)],  # "//tmp/.../repo"
            writable_paths=[str(self.outdir), "/tmp"],
        )
        self.assertEqual(r.returncode, 0, f"stderr: {r.stderr!r}")
        self.assertIn(
            "WROTE-OUTPUT", r.stdout,
            "//-spelled ancestor evaded classification and re-shadowed "
            "the rw output bind (run dir read-only again)",
        )
        self.assertTrue(proof.exists())

    def test_doubleslash_tmp_refused_by_shadow_policy(self):
        """"//tmp" must hit the per-ns shadow refusal exactly like
        "/tmp" — not bind host /tmp over the per-sandbox tmpfs."""
        with tempfile.NamedTemporaryFile(
            dir="/tmp", prefix=".raptor-canary-", mode="w",
        ) as cf:
            cf.write("SHOULD-NOT-BE-VISIBLE\n")
            cf.flush()
            r = _run(
                ["sh", "-c", f"cat {cf.name} 2>/dev/null || echo GONE"],
                target=str(self.target), output=str(self.outdir),
                readable_paths=["//tmp"],
                writable_paths=[str(self.outdir), "/tmp"],
            )
        self.assertEqual(r.returncode, 0, f"stderr: {r.stderr!r}")
        self.assertNotIn("SHOULD-NOT-BE-VISIBLE", r.stdout,
                         "host /tmp content leaked through a //tmp "
                         "readable bind over the per-ns tmpfs")
        self.assertIn("GONE", r.stdout)


@requires_landlock
@requires_userns
# Exercises mount-delivered capability; hosts with userns but no mount
# capability degrade by design -> named SKIP.
@requires_mount
class TestMaskedPathsStayMasked(unittest.TestCase):
    """readable_paths entries at or below the 8a evidence dir and the
    8a2 run marker mount in the post pass — AFTER the masks — and used
    to stack a live host view over them: the child could read the full
    run marker (finder dossier) or the evidence dir through its own
    readable_paths. The plan loop now refuses such entries loudly and
    the masks stay authoritative."""

    def setUp(self):
        if not _mount_ns_usable():
            self.skipTest(
                "mount-ns unusable here (needs uidmap package + "
                "kernel.apparmor_restrict_unprivileged_userns=0)"
            )
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.outdir = Path(self.tmp.name) / "outdir"
        self.outdir.mkdir()
        self.target = Path(self.tmp.name) / "target"
        self.target.mkdir()

    def test_run_marker_in_readable_paths_stays_masked(self):
        marker = self.outdir / ".raptor-run.json"
        marker.write_text('{"meta": "M"}\n')
        r = _run(
            ["sh", "-c", f"wc -c < {marker}"],
            target=str(self.target), output=str(self.outdir),
            readable_paths=[str(marker)],
            writable_paths=[str(self.outdir), "/tmp"],
        )
        self.assertEqual(r.returncode, 0, f"stderr: {r.stderr!r}")
        self.assertEqual(
            r.stdout.strip(), "0",
            "run-marker content unmasked by a readable_paths bind "
            "stacked over the 8a2 mask",
        )
        self.assertIn("masked path", r.stderr or "",
                      "expected the loud masked-path refusal")

    def test_evidence_dir_in_readable_paths_stays_shadowed(self):
        audit = self.outdir / ".audit"
        audit.mkdir()
        (audit / "note.txt").write_text("EVIDENCE-CONTENT\n")
        r = _run(
            ["sh", "-c",
             f"cat {audit / 'note.txt'} 2>/dev/null || echo MASKED"],
            target=str(self.target), output=str(self.outdir),
            readable_paths=[str(audit)],
            writable_paths=[str(self.outdir), "/tmp"],
        )
        self.assertEqual(r.returncode, 0, f"stderr: {r.stderr!r}")
        self.assertNotIn("EVIDENCE-CONTENT", r.stdout,
                         "evidence dir unmasked by a readable_paths "
                         "bind stacked over the 8a shadow")
        self.assertIn("MASKED", r.stdout)


@requires_landlock
@requires_userns
# Exercises mount-delivered capability; hosts with userns but no mount
# capability degrade by design -> named SKIP.
@requires_mount
class TestRoBindUnderRwOutput(unittest.TestCase):
    """Inverse nesting direction, pinned: a read-only bind BELOW the
    rw output mounts after it, stacks on top, and enforces read-only
    for exactly its subtree."""

    def setUp(self):
        if not _mount_ns_usable():
            self.skipTest(
                "mount-ns unusable here (needs uidmap package + "
                "kernel.apparmor_restrict_unprivileged_userns=0)"
            )
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.outdir = Path(self.tmp.name) / "outdir"
        self.tools = self.outdir / "tools"
        self.tools.mkdir(parents=True)
        (self.tools / "helper.txt").write_text("HELPER-CONTENT\n")
        self.target = Path(self.tmp.name) / "target"
        self.target.mkdir()

    def test_ro_subtree_under_rw_output(self):
        atk = self.tools / "atk.txt"
        proof = self.outdir / "proof.txt"
        r = _run(
            ["sh", "-c",
             f"cat {self.tools / 'helper.txt'};"
             f"echo pwn > {atk} 2>/dev/null || echo SUBTREE-RO;"
             f"echo OK > {proof} && echo WROTE-OUTPUT"],
            target=str(self.target), output=str(self.outdir),
            readable_paths=[str(self.tools)],
            writable_paths=[str(self.outdir), "/tmp"],
        )
        self.assertEqual(r.returncode, 0, f"stderr: {r.stderr!r}")
        self.assertIn("HELPER-CONTENT", r.stdout,
                      "ro subtree content not visible through the bind")
        self.assertIn("SUBTREE-RO", r.stdout,
                      "write through the ro bind under the rw output "
                      "succeeded")
        self.assertFalse(atk.exists())
        self.assertIn("WROTE-OUTPUT", r.stdout,
                      "rest of the output dir lost its writability")
        self.assertTrue(proof.exists())


@requires_landlock
@requires_userns
# Exercises mount-delivered capability; hosts with userns but no mount
# capability degrade by design -> named SKIP. (Landlock alone cannot
# carve a read-only hole out of an ancestor write grant, so the ro
# mount stack is the only enforcement for this nesting.)
@requires_mount
class TestTargetUnderOutput(unittest.TestCase):
    """Target nested INSIDE the output dir: the ro target bind must
    mount after (stack on) the rw output bind, keeping the target
    read-only through the child's view."""

    def setUp(self):
        if not _mount_ns_usable():
            self.skipTest(
                "mount-ns unusable here (needs uidmap package + "
                "kernel.apparmor_restrict_unprivileged_userns=0)"
            )
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.outdir = Path(self.tmp.name) / "outdir"
        self.target = self.outdir / "checkout"
        self.target.mkdir(parents=True)
        (self.target / "src.txt").write_text("SRC-CONTENT\n")

    def test_nested_target_stays_read_only(self):
        atk = self.target / "atk.txt"
        proof = self.outdir / "proof.txt"
        r = _run(
            ["sh", "-c",
             f"cat {self.target / 'src.txt'};"
             f"echo pwn > {atk} 2>/dev/null || echo TARGET-RO;"
             f"echo OK > {proof} && echo WROTE-OUTPUT"],
            target=str(self.target), output=str(self.outdir),
            readable_paths=None,
            writable_paths=[str(self.outdir), "/tmp"],
        )
        self.assertEqual(r.returncode, 0, f"stderr: {r.stderr!r}")
        self.assertIn("SRC-CONTENT", r.stdout,
                      "nested target content not visible")
        self.assertIn(
            "TARGET-RO", r.stdout,
            "write into the nested read-only target succeeded — the rw "
            "output bind shadowed the ro target bind",
        )
        self.assertFalse(atk.exists(),
                         "host file materialised through the nested "
                         "read-only target")
        self.assertIn("WROTE-OUTPUT", r.stdout)
        self.assertTrue(proof.exists())


if __name__ == "__main__":
    unittest.main()
