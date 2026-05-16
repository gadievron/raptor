"""Tests for coverage record building and tracking."""

import json
import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from core.coverage.record import (
    build_from_manifest,
    build_from_semgrep,
    build_from_codeql,
    build_from_cocci,
    build_from_findings,
    write_record,
    load_record,
    load_records,
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


class TestBuildFromCodeQL(unittest.TestCase):

    def test_builds_from_sarif(self):
        with TemporaryDirectory() as d:
            sarif = Path(d) / "codeql.sarif"
            sarif.write_text(json.dumps({
                "runs": [{
                    "tool": {
                        "driver": {"name": "CodeQL", "version": "2.16.0",
                                   "rules": [{"id": "cpp/overflow"}, {"id": "cpp/injection"}]},
                        "extensions": [{"name": "codeql/cpp-queries", "version": "1.0.0"}],
                    },
                    "artifacts": [
                        {"location": {"uri": "src/main.c"}},
                        {"location": {"uri": "src/util.c"}},
                    ],
                    "invocations": [],
                }]
            }))
            record = build_from_codeql(sarif)
            self.assertEqual(record["tool"], "codeql")
            self.assertEqual(record["version"], "2.16.0")
            self.assertEqual(len(record["files_examined"]), 2)
            self.assertIn("src/main.c", record["files_examined"])
            self.assertEqual(record["packs"], ["codeql/cpp-queries@1.0.0"])
            self.assertEqual(len(record["rules_applied"]), 2)

    def test_captures_failures(self):
        with TemporaryDirectory() as d:
            sarif = Path(d) / "codeql.sarif"
            sarif.write_text(json.dumps({
                "runs": [{
                    "tool": {"driver": {"name": "CodeQL", "rules": []}, "extensions": []},
                    "artifacts": [{"location": {"uri": "src/ok.c"}}],
                    "invocations": [{
                        "toolExecutionNotifications": [{
                            "level": "error",
                            "message": {"text": "extraction failed"},
                            "locations": [{"physicalLocation": {
                                "artifactLocation": {"uri": "src/bad.c"}
                            }}],
                        }]
                    }],
                }]
            }))
            record = build_from_codeql(sarif)
            self.assertEqual(len(record["files_failed"]), 1)
            self.assertEqual(record["files_failed"][0]["path"], "src/bad.c")

    def test_returns_none_without_artifacts(self):
        with TemporaryDirectory() as d:
            sarif = Path(d) / "codeql.sarif"
            sarif.write_text(json.dumps({"runs": [{"tool": {"driver": {}}, "artifacts": []}]}))
            self.assertIsNone(build_from_codeql(sarif))


class _StubSpatchResult:
    """Test double matching the SpatchResult attribute surface
    ``build_from_cocci`` reads. Avoids importing the real dataclass
    so this test module stays decoupled from packages/coccinelle —
    matches the dependency posture of the production
    ``build_from_cocci`` (Any-typed input)."""
    def __init__(self, rule="", files_examined=(), errors=()):
        self.rule = rule
        self.files_examined = list(files_examined)
        self.errors = list(errors)


class TestBuildFromCocci(unittest.TestCase):

    def test_returns_none_for_empty_input(self):
        """No spatch results at all (e.g. cocci skipped because
        target had no C source) → no record. Matches
        ``build_from_semgrep`` shape; callers don't write empty
        records."""
        self.assertIsNone(build_from_cocci([]))

    def test_returns_none_when_results_have_nothing(self):
        """A list of empty SpatchResults (no rules, no files) →
        also no record. Defensive — a future runner change that
        emits placeholder results shouldn't pollute coverage."""
        self.assertIsNone(build_from_cocci([_StubSpatchResult()]))

    def test_builds_from_results_with_files_and_rules(self):
        """Canonical happy path: 2 rules, 3 files examined, no
        errors. Record carries rule_applied as a sorted set,
        files_examined sorted, tool=coccinelle."""
        results = [
            _StubSpatchResult(
                rule="missing_null_check",
                files_examined=["src/parser.c", "src/util.c"],
            ),
            _StubSpatchResult(
                rule="lock_imbalance",
                files_examined=["src/util.c", "src/sched.c"],
            ),
        ]
        record = build_from_cocci(results, spatch_version="1.3")
        self.assertEqual(record["tool"], "coccinelle")
        self.assertEqual(record["version"], "1.3")
        self.assertEqual(record["files_examined"],
                         ["src/parser.c", "src/sched.c", "src/util.c"])
        self.assertEqual(record["rules_applied"],
                         ["lock_imbalance", "missing_null_check"])
        self.assertNotIn("files_failed", record)

    def test_captures_per_rule_errors(self):
        """A rule that errored is tracked in files_failed under
        the rule name (no per-file binding for cocci errors —
        spatch reports errors at rule level, not match level)."""
        results = [
            _StubSpatchResult(
                rule="broken_rule",
                files_examined=["src/x.c"],
                errors=["semantic error: unbound metavariable foo"],
            ),
        ]
        record = build_from_cocci(results)
        self.assertIn("files_failed", record)
        self.assertEqual(len(record["files_failed"]), 1)
        self.assertEqual(record["files_failed"][0]["path"], "broken_rule")
        self.assertIn("unbound metavariable",
                      record["files_failed"][0]["reason"])

    def test_dedupes_files_across_rules(self):
        """Two rules examining the same files → ``files_examined``
        is a sorted union, not a duplicated list."""
        results = [
            _StubSpatchResult(rule="r1", files_examined=["a.c", "b.c"]),
            _StubSpatchResult(rule="r2", files_examined=["b.c", "c.c"]),
        ]
        record = build_from_cocci(results)
        self.assertEqual(record["files_examined"],
                         ["a.c", "b.c", "c.c"])

    def test_dedupes_rules_across_results(self):
        """If the runner emits the same rule name in multiple
        result objects (e.g. multi-target invocation pattern),
        ``rules_applied`` deduplicates."""
        results = [
            _StubSpatchResult(rule="r1", files_examined=["a.c"]),
            _StubSpatchResult(rule="r1", files_examined=["b.c"]),
        ]
        record = build_from_cocci(results)
        self.assertEqual(record["rules_applied"], ["r1"])

    def test_omits_version_when_unknown(self):
        """spatch version is best-effort — when ``packages.coccinelle.runner.version()``
        returns None, the ``version`` field is absent rather than
        carrying a misleading empty string."""
        results = [_StubSpatchResult(rule="r", files_examined=["a.c"])]
        record = build_from_cocci(results)  # no spatch_version
        self.assertNotIn("version", record)

    def test_truncates_long_error_messages(self):
        """spatch errors can be very long (semantic-error backtraces).
        Pin the 500-char cap so coverage records stay disk-friendly."""
        long_err = "x" * 5000
        results = [_StubSpatchResult(
            rule="r", files_examined=["a.c"], errors=[long_err],
        )]
        record = build_from_cocci(results)
        self.assertEqual(len(record["files_failed"][0]["reason"]), 500)


class TestBuildFromFindings(unittest.TestCase):

    def test_builds_from_findings_and_manifest(self):
        with TemporaryDirectory() as d:
            findings = Path(d) / "findings.json"
            findings.write_text(json.dumps({
                "findings": [
                    {"id": "F1", "file": "src/auth.c", "function": "check_pw", "line": 10},
                    {"id": "F2", "file": "src/db.c", "function": "query", "line": 20},
                ]
            }))
            manifest = Path(d) / READS_MANIFEST
            manifest.write_text("src/auth.c\nsrc/db.c\nsrc/util.c\n")
            record = build_from_findings(findings, reads_manifest_path=manifest)
            self.assertEqual(record["tool"], "llm")
            self.assertEqual(len(record["files_examined"]), 3)  # auth, db, util
            self.assertEqual(len(record["functions_analysed"]), 2)
            self.assertIn("src/util.c", record["files_examined"])

    def test_findings_only(self):
        with TemporaryDirectory() as d:
            findings = Path(d) / "findings.json"
            findings.write_text(json.dumps({
                "findings": [
                    {"id": "F1", "file": "src/vuln.c", "function": "main", "line": 5},
                ]
            }))
            record = build_from_findings(findings)
            self.assertEqual(len(record["files_examined"]), 1)
            self.assertEqual(len(record["functions_analysed"]), 1)

    def test_manifest_only(self):
        with TemporaryDirectory() as d:
            findings = Path(d) / "findings.json"
            findings.write_text(json.dumps({"findings": []}))
            manifest = Path(d) / READS_MANIFEST
            manifest.write_text("src/auth.c\n")
            record = build_from_findings(findings, reads_manifest_path=manifest)
            self.assertEqual(len(record["files_examined"]), 1)
            self.assertNotIn("functions_analysed", record)

    def test_returns_none_without_data(self):
        with TemporaryDirectory() as d:
            findings = Path(d) / "findings.json"
            findings.write_text(json.dumps({"findings": []}))
            self.assertIsNone(build_from_findings(findings))


class TestWriteAndLoad(unittest.TestCase):

    def test_roundtrip(self):
        with TemporaryDirectory() as d:
            record = {"tool": "test", "files_examined": ["a.py"]}
            write_record(Path(d), record)
            loaded = load_record(Path(d))
            self.assertEqual(loaded["tool"], "test")
            self.assertEqual(loaded["files_examined"], ["a.py"])

    def test_per_tool_write(self):
        with TemporaryDirectory() as d:
            record = {"tool": "semgrep", "files_examined": ["a.py"]}
            path = write_record(Path(d), record, tool_name="semgrep")
            self.assertEqual(path.name, "coverage-semgrep.json")
            self.assertTrue(path.exists())

    def test_load_records_multiple(self):
        with TemporaryDirectory() as d:
            write_record(Path(d), {"tool": "semgrep"}, tool_name="semgrep")
            write_record(Path(d), {"tool": "codeql"}, tool_name="codeql")
            write_record(Path(d), {"tool": "llm"}, tool_name="llm")
            records = load_records(Path(d))
            tools = {r["tool"] for r in records}
            self.assertEqual(tools, {"semgrep", "codeql", "llm"})

    def test_load_records_falls_back_to_legacy(self):
        with TemporaryDirectory() as d:
            write_record(Path(d), {"tool": "legacy"})
            records = load_records(Path(d))
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0]["tool"], "legacy")

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
