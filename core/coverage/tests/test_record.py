"""Tests for coverage record building and tracking."""

import json
import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from core.coverage.record import (
    build_from_manifest,
    build_from_semgrep,
    write_record,
    load_record,
    cleanup_manifest,
    READS_MANIFEST,
    COVERAGE_RECORD_FILE,
)
from core.coverage.track_read import main as track_read_main


class TestBuildFromManifest(unittest.TestCase):

    def test_builds_from_manifest(self):
        with TemporaryDirectory() as d:
            manifest = Path(d) / READS_MANIFEST
            manifest.write_text("/tmp/src/auth.py\n/tmp/src/db.py\n/tmp/src/auth.py\n")
            record = build_from_manifest(Path(d), "llm:validate")
            self.assertEqual(record["tool"], "llm:validate")
            # Deduplicated and sorted
            self.assertEqual(len(record["files_examined"]), 2)
            self.assertIn("/tmp/src/auth.py", record["files_examined"])
            self.assertIn("/tmp/src/db.py", record["files_examined"])

    def test_returns_none_without_manifest(self):
        with TemporaryDirectory() as d:
            self.assertIsNone(build_from_manifest(Path(d), "test"))

    def test_includes_rules(self):
        with TemporaryDirectory() as d:
            manifest = Path(d) / READS_MANIFEST
            manifest.write_text("/tmp/file.py\n")
            record = build_from_manifest(Path(d), "test", rules_applied=["stage-a"])
            self.assertEqual(record["rules_applied"], ["stage-a"])

    def test_includes_extra_files(self):
        with TemporaryDirectory() as d:
            manifest = Path(d) / READS_MANIFEST
            manifest.write_text("/tmp/a.py\n")
            record = build_from_manifest(Path(d), "test", extra_files=["/tmp/b.py"])
            self.assertIn("/tmp/a.py", record["files_examined"])
            self.assertIn("/tmp/b.py", record["files_examined"])


class TestBuildFromSemgrep(unittest.TestCase):

    def test_builds_from_semgrep_json(self):
        with TemporaryDirectory() as d:
            semgrep_json = Path(d) / "semgrep.json"
            semgrep_json.write_text(json.dumps({
                "version": "1.67.0",
                "paths": {"scanned": ["/tmp/src/auth.py", "/tmp/src/db.py"]},
                "results": [],
                "errors": [],
            }))
            record = build_from_semgrep(Path(d), semgrep_json,
                                        rules_applied=["p/owasp-top-ten"])
            self.assertEqual(record["tool"], "semgrep")
            self.assertEqual(record["version"], "1.67.0")
            self.assertEqual(len(record["files_examined"]), 2)
            self.assertEqual(record["rules_applied"], ["p/owasp-top-ten"])

    def test_captures_errors(self):
        with TemporaryDirectory() as d:
            semgrep_json = Path(d) / "semgrep.json"
            semgrep_json.write_text(json.dumps({
                "paths": {"scanned": ["/tmp/src/ok.py"]},
                "results": [],
                "errors": [{"path": "/tmp/src/bad.js", "message": "parse error"}],
            }))
            record = build_from_semgrep(Path(d), semgrep_json)
            self.assertEqual(len(record["files_failed"]), 1)
            self.assertEqual(record["files_failed"][0]["path"], "/tmp/src/bad.js")

    def test_returns_none_without_scanned(self):
        with TemporaryDirectory() as d:
            semgrep_json = Path(d) / "semgrep.json"
            semgrep_json.write_text(json.dumps({"paths": {}, "results": []}))
            self.assertIsNone(build_from_semgrep(Path(d), semgrep_json))


class TestWriteAndLoad(unittest.TestCase):

    def test_roundtrip(self):
        with TemporaryDirectory() as d:
            record = {"tool": "test", "files_examined": ["a.py"]}
            write_record(Path(d), record)
            loaded = load_record(Path(d))
            self.assertEqual(loaded["tool"], "test")
            self.assertEqual(loaded["files_examined"], ["a.py"])

    def test_load_missing(self):
        with TemporaryDirectory() as d:
            self.assertIsNone(load_record(Path(d)))


class TestCleanupManifest(unittest.TestCase):

    def test_removes_manifest(self):
        with TemporaryDirectory() as d:
            manifest = Path(d) / READS_MANIFEST
            manifest.write_text("file.py\n")
            cleanup_manifest(Path(d))
            self.assertFalse(manifest.exists())

    def test_no_error_if_missing(self):
        with TemporaryDirectory() as d:
            cleanup_manifest(Path(d))  # Should not raise


class TestTrackReadHook(unittest.TestCase):

    def _setup_project(self, project_dir, run_dir, target="/tmp/src"):
        """Set up a temporary project with an active symlink and running run."""
        projects_dir = Path.home() / ".raptor" / "projects"
        projects_dir.mkdir(parents=True, exist_ok=True)

        # Save existing state
        active_link = projects_dir / ".active"
        self._old_link = os.readlink(active_link) if active_link.is_symlink() else None
        self._old_json = None
        if active_link.is_symlink():
            old_json_path = projects_dir / self._old_link
            self._old_json = old_json_path.read_text() if old_json_path.exists() else None

        # Create test project
        import json as _json
        project_json = projects_dir / "_test_hook.json"
        project_json.write_text(_json.dumps({
            "name": "_test_hook",
            "target": target,
            "output_dir": str(project_dir),
        }))
        if active_link.is_symlink() or active_link.exists():
            active_link.unlink()
        active_link.symlink_to("_test_hook.json")

        # Create running run
        run_dir.mkdir(parents=True, exist_ok=True)
        meta = run_dir / ".raptor-run.json"
        meta.write_text(_json.dumps({"status": "running", "command": "test"}))

    def _teardown_project(self):
        """Restore project state."""
        projects_dir = Path.home() / ".raptor" / "projects"
        active_link = projects_dir / ".active"
        test_json = projects_dir / "_test_hook.json"
        if test_json.exists():
            test_json.unlink()
        if active_link.is_symlink() or active_link.exists():
            active_link.unlink()
        if self._old_link:
            active_link.symlink_to(self._old_link)

    def _run_hook(self, file_path, project_dir, run_dir, target="/tmp/src"):
        """Helper to invoke track_read with a simulated hook payload."""
        import io
        self._setup_project(project_dir, run_dir, target)
        payload = json.dumps({"tool_input": {"file_path": file_path}})
        old_stdin = __import__("sys").stdin
        try:
            __import__("sys").stdin = io.StringIO(payload)
            track_read_main()
        finally:
            __import__("sys").stdin = old_stdin
            self._teardown_project()

    def test_appends_to_manifest(self):
        with TemporaryDirectory() as d:
            project_dir = Path(d) / "project"
            run_dir = project_dir / "validate-20260408"
            self._run_hook("/tmp/src/auth.py", project_dir, run_dir)
            manifest = run_dir / READS_MANIFEST
            self.assertTrue(manifest.exists())
            self.assertIn("/tmp/src/auth.py", manifest.read_text())

    def test_skips_non_source(self):
        with TemporaryDirectory() as d:
            project_dir = Path(d) / "project"
            run_dir = project_dir / "validate-20260408"
            self._run_hook("/tmp/src/image.png", project_dir, run_dir)
            manifest = run_dir / READS_MANIFEST
            self.assertFalse(manifest.exists())

    def test_skips_without_active_project(self):
        """No active project → exits immediately."""
        import io
        # Ensure no active symlink
        active_link = Path.home() / ".raptor" / "projects" / ".active"
        old_link = os.readlink(active_link) if active_link.is_symlink() else None
        if active_link.is_symlink():
            active_link.unlink()
        payload = json.dumps({"tool_input": {"file_path": "/tmp/src/auth.py"}})
        old_stdin = __import__("sys").stdin
        try:
            __import__("sys").stdin = io.StringIO(payload)
            track_read_main()  # Should not raise
        finally:
            __import__("sys").stdin = old_stdin
            if old_link:
                active_link.symlink_to(old_link)

    def test_skips_outside_target(self):
        """Files outside target are ignored."""
        with TemporaryDirectory() as d:
            project_dir = Path(d) / "project"
            run_dir = project_dir / "validate-20260408"
            self._run_hook("/home/raptor/raptor/core/config.py", project_dir, run_dir, target="/tmp/vuln")
            manifest = run_dir / READS_MANIFEST
            self.assertFalse(manifest.exists())


if __name__ == "__main__":
    unittest.main()
