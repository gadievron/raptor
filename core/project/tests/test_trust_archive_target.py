"""Archive equivalence in the one-target gate.

A project whose target is an archive never sees runs whose target
path EQUALS the archive: runs extract to the content-addressed
``_sources/<name>-<sha>/`` cache and record/scan that tree. Pre-fix
the pure resolved-path compare in ``run_target_matches_project``
mismatched every such run — ``pinned_write_target_ok`` then
SUPPRESSED all project-store writes (findings/coverage/journal) with
only a warning, and the trust markers were silently dropped.

Pins the two equivalence witnesses (run-marker acquisition sha; the
project's own extraction cache dir), their fail-closed edges, and the
unchanged directory-target behaviour. Hermetic: temp projects dir via
patched ``PROJECTS_DIR``; real (tiny) zip bytes so the archive
detector sees true magic.
"""

import json
import unittest
import zipfile
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from core.hash import sha256_file
from core.project.project import ProjectManager
from core.project.trust import run_target_matches_project
from core.run.pin import pinned_write_target_ok


def _make_zip(path: Path) -> str:
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("app/main.py", "print('hi')\n")
    return sha256_file(path)


class ArchiveProjectFixture(unittest.TestCase):
    """Temp projects dir; one active project whose target is a zip."""

    def setUp(self):
        self._tmp = TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        self.projects_dir = self.root / "projects"
        self.archive = self.root / "app.zip"
        self.sha = _make_zip(self.archive)
        self.out_root = self.root / "out"
        self.mgr = ProjectManager(projects_dir=self.projects_dir)
        self.project = self.mgr.create(
            "p", str(self.archive), output_dir=str(self.out_root))
        self.mgr.set_active("p")
        patcher = patch("core.project.project.PROJECTS_DIR",
                        self.projects_dir)
        patcher.start()
        self.addCleanup(patcher.stop)

    def _cache_dir(self, sha: str | None = None) -> Path:
        from core.archive import safe_cache_name
        name = safe_cache_name("app.zip", sha or self.sha)
        d = Path(self.project.output_dir) / "_sources" / name
        d.mkdir(parents=True, exist_ok=True)
        return d

    def _run_dir(self, target_path: Path, *,
                 archive_sha: str | None = None) -> Path:
        """A pinned run dir whose marker records *target_path* and,
        optionally, an archive acquisition stamp."""
        run_dir = Path(self.project.output_dir) / "scan-20260925-000000-x"
        run_dir.mkdir(parents=True, exist_ok=True)
        manifest: dict = {}
        if archive_sha is not None:
            manifest["target"] = {
                "source": "archive",
                "archive_sha256": archive_sha,
                "archive_name": "app.zip",
                "format": "zip",
            }
        marker = {
            "project": "p",
            "project_source": "session",
            "target_path": str(target_path),
            "manifest": manifest,
            "status": "running",
        }
        (run_dir / ".raptor-run.json").write_text(
            json.dumps(marker), encoding="utf-8")
        return run_dir


class TestManifestShaWitness(ArchiveProjectFixture):
    def test_matching_acquisition_sha_matches(self):
        extracted = self._cache_dir()
        run_dir = self._run_dir(extracted, archive_sha=self.sha)
        self.assertTrue(
            run_target_matches_project(str(extracted), str(run_dir)))

    def test_mismatched_sha_fails_closed(self):
        # A replaced archive (different bytes) must NOT match: the
        # run's verdicts describe the old bytes.
        extracted = self.root / "elsewhere"
        extracted.mkdir()
        run_dir = self._run_dir(extracted, archive_sha="0" * 64)
        self.assertFalse(
            run_target_matches_project(str(extracted), str(run_dir)))

    def test_no_acquisition_stamp_fails_closed_off_cache(self):
        # No stamp AND a target outside the project's extraction
        # cache: nothing ties the run to the archive.
        foreign = self.root / "foreign"
        foreign.mkdir()
        run_dir = self._run_dir(foreign)
        self.assertFalse(
            run_target_matches_project(str(foreign), str(run_dir)))


class TestStampWitnessContract(ArchiveProjectFixture):
    """The acquisition-stamp witness answers the CALLER's question:
    a matching stamp alone must not vouch for arbitrary paths."""

    def test_foreign_path_not_vouched_by_legit_stamp(self):
        # Review probe P1c: pre-tighten, run_target_matches_project
        # ("/etc", run_dir) returned True once the run carried a
        # matching stamp.
        extracted = self._cache_dir()
        run_dir = self._run_dir(extracted, archive_sha=self.sha)
        self.assertFalse(
            run_target_matches_project("/etc", str(run_dir)))

    def test_recorded_target_and_subpaths_still_vouched(self):
        extracted = self._cache_dir()
        sub = extracted / "app"
        sub.mkdir()
        run_dir = self._run_dir(extracted, archive_sha=self.sha)
        self.assertTrue(
            run_target_matches_project(str(extracted), str(run_dir)))
        self.assertTrue(
            run_target_matches_project(str(sub), str(run_dir)))


class TestSnapshotMemoValidity(ArchiveProjectFixture):
    def test_same_size_swap_with_forged_mtime_fails_closed(self):
        """Review probe P1d: a same-size content swap with a forged
        utime() mtime must not be served a stale sha from the memo —
        ctime (which unprivileged utime cannot set) is in the
        validity key."""
        import os
        import time

        from core.project.trust import _ARCHIVE_SNAP_MEMO
        _ARCHIVE_SNAP_MEMO.clear()
        extracted = self._cache_dir()
        run_dir = self._run_dir(extracted, archive_sha=self.sha)
        # Warm the memo with the genuine archive.
        self.assertTrue(
            run_target_matches_project(str(extracted), str(run_dir)))
        st = self.archive.stat()
        # Same-size different-content replacement (stored, same
        # member-name and payload lengths → identical byte size).
        swap = self.root / "swap.zip"
        with zipfile.ZipFile(swap, "w") as zf:
            zf.writestr("app/main.py", "print('XX')\n")
        old = self.archive.read_bytes()
        new = swap.read_bytes()
        self.assertEqual(len(new), len(old), "probe needs a same-size swap")
        self.assertNotEqual(new, old)
        self.archive.write_bytes(new)
        os.utime(self.archive, ns=(st.st_atime_ns, st.st_mtime_ns))
        st2 = self.archive.stat()
        if st2.st_ctime_ns == st.st_ctime_ns:
            # Coarse-ctime filesystem (second granularity) and the
            # swap landed inside the original second: force a later
            # ctime so the test exercises the key, not fs granularity
            # (the sub-second window on such filesystems is a
            # documented residual).
            time.sleep(1.1)
            self.archive.write_bytes(new)
            os.utime(self.archive, ns=(st.st_atime_ns, st.st_mtime_ns))
            st2 = self.archive.stat()
        self.assertEqual(st2.st_mtime_ns, st.st_mtime_ns)
        self.assertEqual(st2.st_size, st.st_size)
        self.assertNotEqual(st2.st_ctime_ns, st.st_ctime_ns)
        # Old bytes' stamp no longer matches the swapped archive.
        self.assertFalse(
            run_target_matches_project(str(extracted), str(run_dir)))


class TestExtractionCacheWitness(ArchiveProjectFixture):
    def test_project_cache_dir_matches_without_run_marker(self):
        extracted = self._cache_dir()
        self.assertTrue(run_target_matches_project(str(extracted)))

    def test_subdir_of_cache_dir_matches(self):
        sub = self._cache_dir() / "app"
        sub.mkdir()
        self.assertTrue(run_target_matches_project(str(sub)))

    def test_cache_dir_for_other_sha_fails_closed(self):
        stale = self._cache_dir("f" * 64)
        self.assertFalse(run_target_matches_project(str(stale)))

    def test_missing_archive_fails_closed(self):
        self.archive.unlink()
        extracted = self._cache_dir()
        self.assertFalse(run_target_matches_project(str(extracted)))


class TestPinnedWriteGate(ArchiveProjectFixture):
    """The defect's observable: project-store writes for archive-target
    projects were suppressed wholesale."""

    def test_archive_run_writes_no_longer_suppressed(self):
        extracted = self._cache_dir()
        run_dir = self._run_dir(extracted, archive_sha=self.sha)
        self.assertTrue(pinned_write_target_ok(str(run_dir)))

    def test_foreign_target_run_still_suppressed(self):
        # Two-direction: the widening must not open the gate for a run
        # against some OTHER tree.
        foreign = self.root / "foreign"
        foreign.mkdir()
        run_dir = self._run_dir(foreign)
        self.assertFalse(pinned_write_target_ok(str(run_dir)))


class TestNonArchiveTargetsUnchanged(ArchiveProjectFixture):
    def test_plain_file_project_target_never_widens(self):
        # A non-archive file target gets no equivalence arm.
        plain = self.root / "notes.txt"
        plain.write_text("x", encoding="utf-8")
        self.mgr.create("q", str(plain),
                        output_dir=str(self.root / "out-q"))
        self.mgr.set_active("q")
        other = self.root / "other"
        other.mkdir()
        self.assertFalse(run_target_matches_project(str(other)))

    def test_directory_target_still_path_compares(self):
        code = self.root / "code"
        (code / "sub").mkdir(parents=True)
        self.mgr.create("r", str(code),
                        output_dir=str(self.root / "out-r"))
        self.mgr.set_active("r")
        self.assertTrue(run_target_matches_project(str(code / "sub")))
        foreign = self.root / "foreign"
        foreign.mkdir()
        self.assertFalse(run_target_matches_project(str(foreign)))


if __name__ == "__main__":
    unittest.main()
