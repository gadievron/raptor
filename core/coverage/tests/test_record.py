"""Tests for coverage record building and tracking."""

import json
import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from core.coverage.record import (
    READS_MANIFEST,
    build_from_cocci,
    build_from_codeql,
    build_from_findings,
    build_from_manifest,
    build_from_semgrep,
    load_record,
    load_records,
    write_record,
)
from core.coverage.track_read import main as track_read_main


class TestBuildFromManifest(unittest.TestCase):

    def test_builds_from_manifest(self):
        with TemporaryDirectory() as d:
            manifest = Path(d) / READS_MANIFEST
            manifest.write_text("src/auth.py\nsrc/db.py\nsrc/auth.py\n")
            record = build_from_manifest(Path(d), "llm:validate")
            self.assertEqual(record["tool"], "llm:validate")
            # Deduplicated and sorted
            self.assertEqual(len(record["files_examined"]), 2)
            self.assertIn("src/auth.py", record["files_examined"])
            self.assertIn("src/db.py", record["files_examined"])

    def test_returns_none_without_manifest(self):
        with TemporaryDirectory() as d:
            self.assertIsNone(build_from_manifest(Path(d), "test"))

    def test_includes_rules(self):
        with TemporaryDirectory() as d:
            manifest = Path(d) / READS_MANIFEST
            manifest.write_text("file.py\n")
            record = build_from_manifest(Path(d), "test", rules_applied=["stage-a"])
            self.assertEqual(record["rules_applied"], ["stage-a"])

    def test_includes_extra_files(self):
        with TemporaryDirectory() as d:
            manifest = Path(d) / READS_MANIFEST
            manifest.write_text("a.py\n")
            record = build_from_manifest(Path(d), "test", extra_files=["b.py"])
            self.assertIn("a.py", record["files_examined"])
            self.assertIn("b.py", record["files_examined"])


class TestManifestSharedLock(unittest.TestCase):
    """``build_from_manifest`` takes LOCK_SH like ``build_from_findings``
    — the two manifest readers coordinate with the writer via the same
    shared flock."""

    def test_build_from_manifest_takes_shared_flock(self):
        import fcntl
        calls = []
        real_flock = fcntl.flock

        def recording_flock(fd, op):
            calls.append(op)
            return real_flock(fd, op)

        with TemporaryDirectory() as d:
            manifest = Path(d) / READS_MANIFEST
            manifest.write_text("src/a.py\n")
            with patch("fcntl.flock", side_effect=recording_flock):
                record = build_from_manifest(Path(d), "test")
            self.assertEqual(record["files_examined"], ["src/a.py"])
            self.assertIn(fcntl.LOCK_SH, calls)

    def test_build_from_findings_takes_shared_flock(self):
        import fcntl
        calls = []
        real_flock = fcntl.flock

        def recording_flock(fd, op):
            calls.append(op)
            return real_flock(fd, op)

        with TemporaryDirectory() as d:
            manifest = Path(d) / READS_MANIFEST
            manifest.write_text("src/a.py\n")
            findings = Path(d) / "findings.json"
            findings.write_text(json.dumps({"findings": []}))
            with patch("fcntl.flock", side_effect=recording_flock):
                record = build_from_findings(findings, manifest)
            self.assertEqual(record["files_examined"], ["src/a.py"])
            self.assertIn(fcntl.LOCK_SH, calls)

    def test_flock_failure_falls_back_to_unlocked_read(self):
        with TemporaryDirectory() as d:
            manifest = Path(d) / READS_MANIFEST
            manifest.write_text("src/a.py\n")
            with patch("fcntl.flock", side_effect=OSError("no locks")):
                record = build_from_manifest(Path(d), "test")
            self.assertEqual(record["files_examined"], ["src/a.py"])


class TestManifestCapAndDecoding(unittest.TestCase):
    """``build_from_manifest`` gets the same size cap + tolerant decode
    as ``build_from_findings``."""

    def test_build_from_manifest_honours_cap(self):
        with TemporaryDirectory() as d:
            manifest = Path(d) / READS_MANIFEST
            manifest.write_text("a.py\nb.py\nc.py\n")
            with patch("core.coverage.record._MANIFEST_CAP", 8):
                record = build_from_manifest(Path(d), "test")
            # a.py\n (5 bytes) fits; b.py\n pushes past the 8-byte cap.
            self.assertEqual(record["files_examined"], ["a.py"])

    def test_build_from_findings_honours_cap(self):
        with TemporaryDirectory() as d:
            manifest = Path(d) / READS_MANIFEST
            manifest.write_text("a.py\nb.py\nc.py\n")
            findings = Path(d) / "findings.json"
            findings.write_text(json.dumps({"findings": []}))
            with patch("core.coverage.record._MANIFEST_CAP", 8):
                record = build_from_findings(findings, manifest)
            self.assertEqual(record["files_examined"], ["a.py"])

    def test_invalid_utf8_does_not_raise(self):
        # Pre-fix build_from_manifest used strict utf-8 decoding;
        # a UnicodeDecodeError escaped the OSError handler and
        # crashed the caller. Now decoded with errors="replace".
        with TemporaryDirectory() as d:
            manifest = Path(d) / READS_MANIFEST
            manifest.write_bytes(b"good.py\n\xff\xfe-bad\ngood2.py\n")
            record = build_from_manifest(Path(d), "test")
            self.assertIn("good.py", record["files_examined"])
            self.assertIn("good2.py", record["files_examined"])

    def test_trailing_space_filename_preserved(self):
        # rstrip("\r\n") only — POSIX filenames may end with a space.
        with TemporaryDirectory() as d:
            manifest = Path(d) / READS_MANIFEST
            manifest.write_text("src/odd name .py\r\n")
            record = build_from_manifest(Path(d), "test")
            self.assertEqual(record["files_examined"], ["src/odd name .py"])


class TestBuildFromSemgrep(unittest.TestCase):

    def test_builds_from_semgrep_json(self):
        with TemporaryDirectory() as d:
            semgrep_json = Path(d) / "semgrep.json"
            semgrep_json.write_text(json.dumps({
                "version": "1.67.0",
                "paths": {"scanned": ["src/auth.py", "src/db.py"]},
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
                "paths": {"scanned": ["src/ok.py"]},
                "results": [],
                "errors": [{"path": "src/bad.js", "message": "parse error"}],
            }))
            record = build_from_semgrep(Path(d), semgrep_json)
            self.assertEqual(len(record["files_failed"]), 1)
            self.assertEqual(record["files_failed"][0]["path"], "src/bad.js")

    def test_all_pathless_errors_omit_files_failed(self):
        """When every error lacks a path, no phantom empty
        files_failed list is emitted."""
        with TemporaryDirectory() as d:
            semgrep_json = Path(d) / "semgrep.json"
            semgrep_json.write_text(json.dumps({
                "paths": {"scanned": ["src/a.py"]},
                "errors": [{"message": "timeout"}, {"path": "", "message": "x"}],
            }))
            record = build_from_semgrep(Path(d), semgrep_json)
            self.assertNotIn("files_failed", record)

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

    def test_all_pathless_failures_omit_files_failed(self):
        """Notifications with no file location (e.g. a global
        extraction error) don't produce an empty files_failed list."""
        with TemporaryDirectory() as d:
            sarif = Path(d) / "results.sarif"
            sarif.write_text(json.dumps({
                "runs": [{
                    "artifacts": [{"location": {"uri": "src/a.c"}}],
                    "tool": {"driver": {"name": "codeql"}},
                    "invocations": [{
                        "toolExecutionNotifications": [
                            {"level": "error",
                             "message": {"text": "global extraction error"}},
                        ],
                    }],
                }],
            }))
            record = build_from_codeql(sarif)
            self.assertNotIn("files_failed", record)

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

    def test_error_without_rule_name_not_in_files_failed(self):
        """An error on a result with no rule name is dropped —
        ``build_from_cocci`` filters empty-path failures like its
        semgrep/codeql siblings."""
        results = [_StubSpatchResult(rule="", files_examined=["a.c"],
                                     errors=["spatch exploded"])]
        record = build_from_cocci(results)
        self.assertNotIn("files_failed", record)
        self.assertEqual(record["files_examined"], ["a.c"])

    def test_named_rule_failure_kept_alongside_unnamed(self):
        """Filtering unnamed-rule errors must not drop failures that
        DO carry a rule name."""
        results = [
            _StubSpatchResult(rule="", files_examined=["a.c"],
                              errors=["anonymous failure"]),
            _StubSpatchResult(rule="good_rule", files_examined=["b.c"],
                              errors=["parse error"]),
        ]
        record = build_from_cocci(results)
        self.assertEqual(len(record["files_failed"]), 1)
        self.assertEqual(record["files_failed"][0]["path"], "good_rule")

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

    def test_load_records_finds_tool_subdirs(self):
        # Agentic writes scanner records into scan/ and codeql into codeql/.
        # load_records must find records in immediate tool subdirs, not only
        # at the top level.
        with TemporaryDirectory() as d:
            run = Path(d)
            (run / "scan").mkdir()
            write_record(run / "scan", {"tool": "semgrep"}, tool_name="semgrep")
            write_record(run / "scan", {"tool": "coccinelle"}, tool_name="coccinelle")
            write_record(run, {"tool": "codeql"}, tool_name="codeql")  # top level
            tools = {r["tool"] for r in load_records(run)}
            self.assertEqual(tools, {"semgrep", "coccinelle", "codeql"})

    def test_load_records_dedups_tool_across_top_and_subdir(self):
        with TemporaryDirectory() as d:
            run = Path(d)
            (run / "codeql").mkdir()
            write_record(run, {"tool": "codeql", "files_examined": ["top.c"]},
                         tool_name="codeql")
            write_record(run / "codeql", {"tool": "codeql", "files_examined": ["sub.c"]},
                         tool_name="codeql")
            records = load_records(run)
            codeql = [r for r in records if r["tool"] == "codeql"]
            self.assertEqual(len(codeql), 1)                     # de-duped
            self.assertEqual(codeql[0]["files_examined"], ["top.c"])  # top wins

    def test_load_records_falls_back_to_legacy(self):
        with TemporaryDirectory() as d:
            write_record(Path(d), {"tool": "legacy"})
            records = load_records(Path(d))
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0]["tool"], "legacy")

    def test_load_missing(self):
        with TemporaryDirectory() as d:
            self.assertIsNone(load_record(Path(d)))


class TestTrackReadHook(unittest.TestCase):
    """Hook tests run against a per-test fake HOME.

    The hook resolves the active project via
    ``Path.home()/.raptor/projects/.active`` — a GLOBAL symlink. Under
    pytest-xdist, tests in this class land on different workers, and
    one worker's teardown (or test_skips_without_active_project's
    unlink) raced another worker's mid-test resolution, flaking
    test_appends_to_manifest. Pointing HOME at a private tmpdir makes
    every test see its own projects dir; the save/restore logic in
    _setup_project then only ever touches the fake home."""

    def setUp(self):
        self._home_tmp = TemporaryDirectory()
        self._old_home = os.environ.get("HOME")
        os.environ["HOME"] = self._home_tmp.name

    def tearDown(self):
        if self._old_home is None:
            os.environ.pop("HOME", None)
        else:
            os.environ["HOME"] = self._old_home
        self._home_tmp.cleanup()

    def _setup_project(self, project_dir, run_dir, target=None):
        """Plant a synthetic project + active symlink under
        ``~/.raptor/projects/`` so track_read_main resolves to the
        test's run_dir. ``target`` should be passed explicitly so
        it stays in sync with the file_path the test sends — when
        omitted, defaults to a sentinel under project_dir's parent
        (a tmpdir) so callers can construct matching file_paths
        without hardcoding /tmp."""
        if target is None:
            target = str(project_dir.parent / "src")
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

    def _run_hook(self, file_path, project_dir, run_dir, target=None):
        """Helper to invoke track_read with a simulated hook payload.

        ``target`` defaults to the sentinel chosen by _setup_project
        (under project_dir's parent tmpdir)."""
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
            # file_path must be UNDER target for the hook to record it.
            # Build both from the same scratch root so the path-containment
            # check passes without hardcoding /tmp.
            target = str(Path(d) / "src")
            file_path = target + "/auth.py"
            self._run_hook(file_path, project_dir, run_dir, target=target)
            manifest = run_dir / READS_MANIFEST
            self.assertTrue(manifest.exists())
            self.assertIn("auth.py", manifest.read_text())

    def test_skips_non_source(self):
        with TemporaryDirectory() as d:
            project_dir = Path(d) / "project"
            run_dir = project_dir / "validate-20260408"
            # file_path under target but with non-source extension —
            # the hook should skip on extension, not target match.
            target = str(Path(d) / "src")
            file_path = target + "/image.png"
            self._run_hook(file_path, project_dir, run_dir, target=target)
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
        payload = json.dumps({"tool_input": {"file_path": "src/auth.py"}})
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
            # file_path under <d>/elsewhere; target under <d>/vuln —
            # disjoint, so the hook must drop the read.
            target = str(Path(d) / "vuln")
            outside = str(Path(d) / "elsewhere" / "core" / "config.py")
            self._run_hook(outside, project_dir, run_dir, target=target)
            manifest = run_dir / READS_MANIFEST
            self.assertFalse(manifest.exists())


if __name__ == "__main__":
    unittest.main()


class TestCleanupManifest:
    """``cleanup_manifest`` — consume-then-delete for the reads
    manifest (the validation helper's post-record cleanup)."""

    def test_removes_existing_manifest(self, tmp_path):
        from core.coverage.record import READS_MANIFEST, cleanup_manifest

        manifest = tmp_path / READS_MANIFEST
        manifest.write_text("src/a.c\n", encoding="utf-8")
        assert cleanup_manifest(tmp_path) is True
        assert not manifest.exists()

    def test_missing_manifest_is_noop(self, tmp_path):
        from core.coverage.record import cleanup_manifest

        assert cleanup_manifest(tmp_path) is False

    def test_importable_from_package(self):
        from core.coverage import cleanup_manifest  # noqa: F401


class TestSemgrepCrossPackErrorMerge:
    """errors are per-pack; the record must merge every pack's, deduped."""

    def _json(self, tmp_path, name, scanned, errors):
        import json as _json
        p = tmp_path / name
        p.write_text(_json.dumps(
            {"paths": {"scanned": scanned}, "errors": errors,
             "version": "1.172.0"}))
        return p

    def test_extra_pack_errors_merged_and_deduped(self, tmp_path):
        from core.coverage.record import build_from_semgrep
        j1 = self._json(tmp_path, "a.json", ["a.c", "b.c"], [
            {"path": "b.c", "message": "Timeout on b.c"},
        ])
        j2 = self._json(tmp_path, "b.json", ["a.c", "b.c"], [
            {"path": "b.c", "message": "Timeout on b.c"},  # dup
            {"path": "a.c", "message": "OOM on a.c"},
        ])
        rec = build_from_semgrep(tmp_path, j1,
                                 extra_error_json_paths=[j1, j2])
        failed = {(f["path"], f["reason"]) for f in rec["files_failed"]}
        assert failed == {("b.c", "Timeout on b.c"), ("a.c", "OOM on a.c")}

    def test_no_extras_keeps_old_shape(self, tmp_path):
        from core.coverage.record import build_from_semgrep
        j1 = self._json(tmp_path, "a.json", ["a.c"], [])
        rec = build_from_semgrep(tmp_path, j1)
        assert rec["files_examined"] == ["a.c"]
        assert "files_failed" not in rec


class TestBuildFromJournal(unittest.TestCase):
    """coverage-journal.json: function-level review marks, never whole-file."""

    def _run_dir_with_entries(self, tmp):
        from core.coverage.journal import ReviewJournalEntry, append_entry
        run_dir = Path(tmp)
        for func, verdict in (("parse", "clean"), ("emit", "suspicious")):
            append_entry(run_dir, ReviewJournalEntry(
                ts="2026-01-01T00:00:00+00:00", run_id="r1",
                file="src/a.c", function=func, verdict=verdict,
                source_hash="abcd1234",
            ))
        return run_dir

    def test_emits_function_marks_only(self):
        # The record's tool label is review-grade (llm/analysed), and the
        # importer marks files_examined WHOLE-FILE under the record's tool.
        # A journal entry reviews one function, not its file — a files list
        # here would inflate every containing file to reviewed.
        from core.coverage.record import build_from_journal
        with TemporaryDirectory() as tmp:
            rec = build_from_journal(self._run_dir_with_entries(tmp))
        assert rec["tool"] == "journal"
        assert "files_examined" not in rec
        analysed = {(f["file"], f["function"]) for f in rec["functions_analysed"]}
        assert analysed == {("src/a.c", "parse"), ("src/a.c", "emit")}
        assert rec["journal_statuses"] == {"clean": 1, "suspicious": 1}

    def test_returns_none_without_entries(self):
        from core.coverage.record import build_from_journal
        with TemporaryDirectory() as tmp:
            assert build_from_journal(Path(tmp)) is None
