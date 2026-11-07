"""Tests for libexec/raptor-run-lifecycle."""

import json
import os
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from core.testing.standalone_cli import standalone_cli_env
from core.json import load_json
from core.run.metadata import RUN_METADATA_FILE

REPO_ROOT = Path(__file__).resolve().parents[3]  # core/run/tests -> repo root
LIFECYCLE = str(REPO_ROOT / "libexec" / "raptor-run-lifecycle")


def _run(*args, tmp_home=None):
    """Run libexec/raptor-run-lifecycle with given args."""
    env = os.environ.copy()
    env.pop("RAPTOR_CALLER_DIR", None)
    with standalone_cli_env(env=env, data_home=os.environ["XDG_DATA_HOME"]) as child_env:
        home = Path(tmp_home or child_env["HOME"])
        child_env["RAPTOR_OUT_DIR"] = str(home / "out")
        if tmp_home:
            child_env["HOME"] = tmp_home
            # Keep the fixture's registry across start and completion calls.
            child_env["RAPTOR_REGISTRY_HOME"] = str(Path(tmp_home) / ".raptor")
        return subprocess.run(
            [sys.executable, LIFECYCLE] + list(args),
            capture_output=True, text=True, env=child_env, timeout=60,
        )


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
    project_json = projects_dir / "testproj.json"
    project_json.write_text(json.dumps({
        "name": "testproj",
        "target": "/tmp",
        "output_dir": str(project_dir),
    }))
    active = projects_dir / ".active"
    if active.is_symlink() or active.exists():
        active.unlink()
    active.symlink_to("testproj.json")


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
            self.assertTrue(out_dir.is_relative_to(Path(home)))

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

    def test_pinned_out_run_merges_into_pinned_project(self):
        """Under run pinning: a run PINNED to project P merges into
        P's index wherever --out physically put it — the pin, not
        directory topology, decides. (The pre-fix containment rule
        protected against ambient pollution; the pin provides that
        protection now, see the projectless companion below.)"""
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
            self.assertTrue((Path(d) / INDEX_FILENAME).exists(),
                            "pinned run's journal did not follow the pin")
            self.assertFalse(
                (Path(elsewhere) / INDEX_FILENAME).exists())

    def test_projectless_pin_never_pollutes_active_project(self):
        """`--project -` (or no resolution) pins null: the journal
        merges NOWHERE, even though a project is active — the ambient
        pollution the pre-fix containment rule guarded against."""
        from core.coverage.journal import INDEX_FILENAME
        with TemporaryDirectory() as d, TemporaryDirectory() as home, \
                TemporaryDirectory() as elsewhere:
            _setup_project_symlink(home, d)
            out_dir = Path(elsewhere) / "audit-orphan"
            result = _run("start", "audit", "--out", str(out_dir),
                          "--project", "-", tmp_home=home)
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


def test_stale_parent_launch_cannot_block_lifecycle(tmp_path, monkeypatch):
    monkeypatch.setenv("_RAPTOR_SCRATCH_AUTH", "invalid-parent-authorization")
    monkeypatch.setenv("TMPDIR", str(tmp_path / "missing-parent-scratch"))
    home = tmp_path / "home"
    home.mkdir()
    project = tmp_path / "project"
    project.mkdir()
    _setup_project_symlink(home, project)
    result = _run("start", "audit", tmp_home=str(home))
    assert result.returncode == 0, result.stderr
    out = _extract_out_dir(result)
    result = _run("complete", str(out), tmp_home=str(home))
    assert result.returncode == 0, result.stderr
    assert load_json(out / RUN_METADATA_FILE)["status"] == "completed"
