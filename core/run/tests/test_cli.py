"""Tests for libexec/raptor-run-lifecycle."""

import json
import os
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from core.json import load_json
from core.run.metadata import RUN_METADATA_FILE

REPO_ROOT = Path(__file__).resolve().parents[3]  # core/run/tests -> repo root
LIFECYCLE = str(REPO_ROOT / "libexec" / "raptor-run-lifecycle")


def _run(*args, tmp_home=None):
    """Run libexec/raptor-run-lifecycle with given args."""
    env = os.environ.copy()
    env.pop("RAPTOR_CALLER_DIR", None)
    if tmp_home:
        env["HOME"] = tmp_home
    result = subprocess.run(
        [sys.executable, LIFECYCLE] + list(args),
        capture_output=True, text=True, env=env,
    )
    return result


def _extract_out_dir(result):
    """Parse OUTPUT_DIR=<path> from the last line of stdout."""
    for line in reversed(result.stdout.strip().splitlines()):
        if line.startswith("OUTPUT_DIR="):
            return Path(line.split("=", 1)[1])
    raise ValueError(f"no OUTPUT_DIR= in stdout: {result.stdout!r}")


def _setup_project_symlink(home_dir, project_dir):
    """Create a .active symlink in a temp home pointing to a project."""
    projects_dir = Path(home_dir) / ".raptor" / "projects"
    projects_dir.mkdir(parents=True, exist_ok=True)
    project_json = projects_dir / "_test.json"
    project_json.write_text(json.dumps({
        "name": "_test",
        "target": "/tmp",
        "output_dir": str(project_dir),
    }))
    active = projects_dir / ".active"
    if active.is_symlink() or active.exists():
        active.unlink()
    active.symlink_to("_test.json")


class TestRunLifecycle(unittest.TestCase):

    def test_start_creates_dir_and_metadata(self):
        with TemporaryDirectory() as d, TemporaryDirectory() as home:
            _setup_project_symlink(home, d)
            result = _run("start", "scan", tmp_home=home)
            self.assertEqual(result.returncode, 0, result.stderr)
            out_dir = _extract_out_dir(result)
            self.assertTrue(out_dir.exists())
            self.assertTrue(out_dir.name.startswith("scan-"))
            meta = load_json(out_dir / RUN_METADATA_FILE)
            self.assertEqual(meta["command"], "scan")
            self.assertEqual(meta["status"], "running")

    def test_complete_updates_status(self):
        with TemporaryDirectory() as d, TemporaryDirectory() as home:
            _setup_project_symlink(home, d)
            result = _run("start", "validate", tmp_home=home)
            self.assertEqual(result.returncode, 0, result.stderr)
            out_dir = _extract_out_dir(result)
            result = _run("complete", str(out_dir))
            self.assertEqual(result.returncode, 0)
            meta = load_json(out_dir / RUN_METADATA_FILE)
            self.assertEqual(meta["status"], "completed")

    def test_fail_updates_status_with_error(self):
        with TemporaryDirectory() as d, TemporaryDirectory() as home:
            _setup_project_symlink(home, d)
            result = _run("start", "scan", tmp_home=home)
            self.assertEqual(result.returncode, 0, result.stderr)
            out_dir = _extract_out_dir(result)
            result = _run("fail", str(out_dir), "semgrep crashed")
            self.assertEqual(result.returncode, 0)
            meta = load_json(out_dir / RUN_METADATA_FILE)
            self.assertEqual(meta["status"], "failed")
            self.assertEqual(meta["extra"]["error"], "semgrep crashed")

    def test_cancel_updates_status(self):
        with TemporaryDirectory() as d, TemporaryDirectory() as home:
            _setup_project_symlink(home, d)
            result = _run("start", "scan", tmp_home=home)
            self.assertEqual(result.returncode, 0, result.stderr)
            out_dir = _extract_out_dir(result)
            result = _run("cancel", str(out_dir))
            self.assertEqual(result.returncode, 0)
            meta = load_json(out_dir / RUN_METADATA_FILE)
            self.assertEqual(meta["status"], "cancelled")

    def test_standalone_mode(self):
        """Without a project symlink, creates underscore-style dir in out/."""
        with TemporaryDirectory() as home:
            result = _run("start", "scan", tmp_home=home)
            self.assertEqual(result.returncode, 0, result.stderr)
            out_dir = _extract_out_dir(result)
            self.assertTrue(out_dir.name.startswith("scan_"))

    def test_start_no_command_fails(self):
        result = _run("start")
        self.assertNotEqual(result.returncode, 0)

    def test_unknown_action_fails(self):
        result = _run("bogus")
        self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()


class TestJournalIndexMerge(unittest.TestCase):
    """`complete`/`interrupt` must fold the run's review journal into
    the project-level index. Pre-fix `_merge_journal_index` resolved
    the `.active` symlink and required `is_dir()` — but `.active`
    points at the project's `<name>.json` FILE, so the merge was dead
    code and the project index never updated."""

    @staticmethod
    def _journal_entry(run_dir, file="a.c", function="f"):
        from core.coverage.journal import (
            ReviewJournalEntry,
            append_entry,
            now_iso,
        )
        append_entry(Path(run_dir), ReviewJournalEntry(
            ts=now_iso(),
            run_id=Path(run_dir).name,
            file=file,
            function=function,
            verdict="clean",
            source_hash="deadbeef",
            line_start=1,
        ))

    def test_complete_merges_journal_into_project_index(self):
        from core.coverage.journal import INDEX_FILENAME
        with TemporaryDirectory() as d, TemporaryDirectory() as home:
            _setup_project_symlink(home, d)
            result = _run("start", "audit", tmp_home=home)
            self.assertEqual(result.returncode, 0, result.stderr)
            out_dir = _extract_out_dir(result)
            self._journal_entry(out_dir, file="src/x.c", function="parse")

            result = _run("complete", str(out_dir), tmp_home=home)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("merged into project index", result.stderr)

            index_path = Path(d) / INDEX_FILENAME
            self.assertTrue(index_path.is_file(), result.stderr)
            index = json.loads(index_path.read_text())
            entries = index.get("entries", index)
            joined = json.dumps(entries)
            self.assertIn("src/x.c", joined)
            self.assertIn("parse", joined)

    def test_interrupt_merges_journal_into_project_index(self):
        from core.coverage.journal import INDEX_FILENAME
        with TemporaryDirectory() as d, TemporaryDirectory() as home:
            _setup_project_symlink(home, d)
            result = _run("start", "audit", tmp_home=home)
            self.assertEqual(result.returncode, 0, result.stderr)
            out_dir = _extract_out_dir(result)
            self._journal_entry(out_dir)

            result = _run("interrupt", str(out_dir), "supervisor stop",
                          tmp_home=home)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue((Path(d) / INDEX_FILENAME).is_file(),
                            result.stderr)

    def test_foreign_run_does_not_pollute_active_project(self):
        """A run completed OUTSIDE the active project's dir must not
        merge into that project's index."""
        from core.coverage.journal import INDEX_FILENAME
        with TemporaryDirectory() as d, TemporaryDirectory() as home, \
                TemporaryDirectory() as elsewhere:
            _setup_project_symlink(home, d)
            out_dir = Path(elsewhere) / "audit-foreign"
            result = _run("start", "audit", "--out", str(out_dir),
                          tmp_home=home)
            self.assertEqual(result.returncode, 0, result.stderr)
            self._journal_entry(out_dir)

            result = _run("complete", str(out_dir), tmp_home=home)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse((Path(d) / INDEX_FILENAME).exists())
            self.assertFalse(
                (Path(elsewhere) / INDEX_FILENAME).exists())

    def test_no_active_project_is_silent_noop(self):
        from core.coverage.journal import INDEX_FILENAME
        with TemporaryDirectory() as home:
            # No .active symlink at all; run lands in the default out/
            # location under a scratch cwd-independent --out.
            with TemporaryDirectory() as scratch:
                out_dir = Path(scratch) / "audit-standalone"
                result = _run("start", "audit", "--out", str(out_dir),
                              tmp_home=home)
                self.assertEqual(result.returncode, 0, result.stderr)
                self._journal_entry(out_dir)
                result = _run("complete", str(out_dir), tmp_home=home)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertFalse(
                    (Path(scratch) / INDEX_FILENAME).exists())
