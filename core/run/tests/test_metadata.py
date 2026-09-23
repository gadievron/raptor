"""Tests for run metadata lifecycle."""

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from core.json import load_json
from core.project.sessions import (
    _walk_session_pid as _REAL_WALK_SESSION_PID,
)
from core.run import (
    RUN_METADATA_FILE,
    cancel_run,
    complete_run,
    fail_run,
    generate_run_metadata,
    infer_command_type,
    is_run_directory,
    load_run_metadata,
    start_run,
    tracked_run,
)


def _age_run_tree(d, seconds=7200.0):
    """Back-date a run dir and everything inside it.

    The same-session abandon sweep treats recent write activity in the
    run dir as a live-run heartbeat; tests exercising the abandon path
    must make the fixture run look write-quiet past the grace window.
    """
    import contextlib
    import os
    import time
    old = time.time() - seconds
    for root, dirs, files in os.walk(d, followlinks=False):
        for name in dirs + files:
            with contextlib.suppress(OSError):
                os.utime(os.path.join(root, name), (old, old),
                         follow_symlinks=False)
    with contextlib.suppress(OSError):
        os.utime(d, (old, old))


class TestRunLifecycle(unittest.TestCase):

    def test_start_creates_metadata(self):
        with TemporaryDirectory() as d:
            out = Path(d) / "scan-20260406"
            start_run(out, "scan")
            meta = load_json(out / RUN_METADATA_FILE)
            self.assertEqual(meta["command"], "scan")
            self.assertEqual(meta["status"], "running")
            self.assertEqual(meta["version"], 2)
            self.assertIn("timestamp", meta)
            # Provenance manifest is sealed at start.
            self.assertIn("manifest", meta)
            self.assertIn("source_control", meta["manifest"])
            self.assertIn("environment", meta["manifest"])

    def test_start_with_extra(self):
        with TemporaryDirectory() as d:
            out = Path(d) / "run"
            start_run(out, "scan", extra={"packs": ["injection"]})
            meta = load_json(out / RUN_METADATA_FILE)
            self.assertEqual(meta["extra"]["packs"], ["injection"])

    def test_complete_updates_status(self):
        with TemporaryDirectory() as d:
            out = Path(d) / "run"
            start_run(out, "scan")
            complete_run(out, extra={"findings_count": 12})
            meta = load_json(out / RUN_METADATA_FILE)
            self.assertEqual(meta["status"], "completed")
            self.assertEqual(meta["extra"]["findings_count"], 12)

    def test_complete_merges_manifest_preserving_start_seal(self):
        with TemporaryDirectory() as d:
            out = Path(d) / "run"
            start_run(out, "agentic")
            complete_run(out, manifest={
                "models": [{
                    "provider": "gemini", "alias": "gemini-2.5-pro",
                    "resolved": "gemini-2.5-pro-002", "role": "primary",
                    "calls": 3,
                }],
                "deterministically_reproducible": False,
            })
            m = load_json(out / RUN_METADATA_FILE)["manifest"]
            # Start-sealed snapshots survive the end-of-run merge.
            self.assertIn("source_control", m)
            self.assertIn("environment", m)
            # End-of-run provenance is merged in.
            self.assertEqual(m["deterministically_reproducible"], False)
            self.assertEqual(m["models"][0]["resolved"], "gemini-2.5-pro-002")

    def test_fail_updates_status(self):
        with TemporaryDirectory() as d:
            out = Path(d) / "run"
            start_run(out, "scan")
            fail_run(out, error="timeout")
            meta = load_json(out / RUN_METADATA_FILE)
            self.assertEqual(meta["status"], "failed")
            self.assertEqual(meta["extra"]["error"], "timeout")

    def test_cancel_updates_status(self):
        with TemporaryDirectory() as d:
            out = Path(d) / "run"
            start_run(out, "agentic")
            cancel_run(out)
            meta = load_json(out / RUN_METADATA_FILE)
            self.assertEqual(meta["status"], "cancelled")

    def test_start_creates_directory(self):
        with TemporaryDirectory() as d:
            out = Path(d) / "new" / "nested" / "run"
            start_run(out, "scan")
            self.assertTrue(out.exists())

    def test_load_missing(self):
        with TemporaryDirectory() as d:
            self.assertIsNone(load_run_metadata(Path(d)))

    def test_complete_without_start_raises(self):
        with TemporaryDirectory() as d:
            out = Path(d) / "orphan"
            out.mkdir()
            with self.assertRaises(FileNotFoundError):
                complete_run(out)

    def test_fail_without_start_raises(self):
        with TemporaryDirectory() as d:
            out = Path(d) / "orphan"
            out.mkdir()
            with self.assertRaises(FileNotFoundError):
                fail_run(out, error="test")

    def test_start_records_session_pid(self):
        """start_run records session_pid when CLAUDECODE is set."""
        import os
        with TemporaryDirectory() as d:
            out = Path(d) / "project" / "scan-20260406"
            # CLAUDECODE is set in our test env (running inside CC)
            if os.environ.get("CLAUDECODE"):
                start_run(out, "scan")
                meta = load_json(out / RUN_METADATA_FILE)
                self.assertIn("session_pid", meta)
                self.assertIsInstance(meta["session_pid"], int)

    def test_start_cleanup_abandoned(self):
        """start_run marks same-session same-type abandoned runs as
        failed — provided they're past the freshness gate AND their
        recorded worker (tool_pid) is dead. Fresh siblings (within
        `_ABANDON_FRESHNESS_S`) are LEFT ALONE because they're
        indistinguishable from a legitimate concurrent run of the
        same command; live-worker siblings are left alone because
        they ARE one."""
        import os
        if not os.environ.get("CLAUDECODE"):
            self.skipTest("Requires CLAUDECODE environment")
        if not Path("/proc").is_dir():
            self.skipTest("_find_claude_ancestor walks /proc — Linux only")
        from core.json import save_json
        with TemporaryDirectory() as d:
            project = Path(d) / "project"
            project.mkdir()
            # First run
            run1 = project / "validate-20260401"
            start_run(run1, "validate")
            meta1 = load_json(run1 / RUN_METADATA_FILE)
            self.assertEqual(meta1["status"], "running")
            # Age run1's timestamp past the freshness threshold so
            # the cleanup recognises it as a real abandon, not a
            # concurrent in-flight run, and mark its worker dead
            # (the Esc-cancel kills the tool process).
            from datetime import datetime, timedelta, timezone
            meta1["timestamp"] = (
                datetime.now(timezone.utc) - timedelta(minutes=5)
            ).isoformat()
            meta1["tool_pid"] = _dead_pid()
            save_json(run1 / RUN_METADATA_FILE, meta1)
            # Quiet the run dir past the activity grace — recent
            # writes read as a live-run heartbeat.
            _age_run_tree(run1)
            # Second run of same type — should mark first as failed
            run2 = project / "validate-20260402"
            start_run(run2, "validate")
            meta1 = load_json(run1 / RUN_METADATA_FILE)
            self.assertEqual(meta1["status"], "failed")
            meta2 = load_json(run2 / RUN_METADATA_FILE)
            self.assertEqual(meta2["status"], "running")

    def test_start_no_cleanup_recent_sibling(self):
        """start_run leaves a fresh same-session same-type sibling
        alone (concurrent in-flight, not Esc-then-retry)."""
        import os
        if not os.environ.get("CLAUDECODE"):
            self.skipTest("Requires CLAUDECODE environment")
        if not Path("/proc").is_dir():
            self.skipTest("_find_claude_ancestor walks /proc — Linux only")
        with TemporaryDirectory() as d:
            project = Path(d) / "project"
            project.mkdir()
            run1 = project / "validate-20260401"
            start_run(run1, "validate")
            # Immediately start a second run; freshness gate keeps
            # run1 in 'running' state.
            run2 = project / "validate-20260402"
            start_run(run2, "validate")
            meta1 = load_json(run1 / RUN_METADATA_FILE)
            self.assertEqual(meta1["status"], "running")
            meta2 = load_json(run2 / RUN_METADATA_FILE)
            self.assertEqual(meta2["status"], "running")

    def test_start_no_cleanup_different_type(self):
        """start_run does not mark runs of a different command type."""
        import os
        if not os.environ.get("CLAUDECODE"):
            self.skipTest("Requires CLAUDECODE environment")
        if not Path("/proc").is_dir():
            self.skipTest("_find_claude_ancestor walks /proc — Linux only")
        with TemporaryDirectory() as d:
            project = Path(d) / "project"
            project.mkdir()
            run1 = project / "validate-20260401"
            start_run(run1, "validate")
            run2 = project / "scan-20260402"
            start_run(run2, "scan")
            meta1 = load_json(run1 / RUN_METADATA_FILE)
            self.assertEqual(meta1["status"], "running")  # untouched


def _dead_pid() -> int:
    """A PID that is certainly not alive: spawn a trivial child and
    reap it. Reuse in the microseconds before the check is possible in
    principle but not observed in practice."""
    import subprocess
    proc = subprocess.Popen(["/bin/true"])
    proc.wait()
    return proc.pid


class TestFindClaudeAncestor(unittest.TestCase):
    """Hermetic: the ancestry walk runs against a FAKE process tree.

    The previous versions asserted on the live process tree (a real
    ``claude`` ancestor), which broke whenever the test battery ran
    detached from the launching session while ``CLAUDECODE`` was still
    in the environment (nohup'd full-battery runs). Mocking the
    primitives (``os.getppid``, ``_read_ppid``, ``/proc/<pid>/comm``)
    keeps the behaviour under test — the walk itself — deterministic
    everywhere.
    """

    def _patch_tree(self, parents, comms):
        """Patch ancestry primitives: ``parents`` maps pid -> ppid,
        ``comms`` maps pid -> process name. Returns an ExitStack."""
        import contextlib
        import sys
        from unittest import mock

        import core.run.metadata as md

        self_pid = 100

        class _FakeProcPath:
            def __init__(self, pid):
                self._pid = pid

            def read_text(self, encoding="utf-8"):
                try:
                    return comms[self._pid] + "\n"
                except KeyError:
                    raise OSError(f"no comm for pid {self._pid}") from None

        real_path = md.Path

        def _path_factory(arg, *rest):
            s = str(arg)
            if s.startswith("/proc/") and s.endswith("/comm") and not rest:
                return _FakeProcPath(int(s.split("/")[2]))
            return real_path(arg, *rest)

        def _fake_read_ppid(pid):
            try:
                return parents[pid]
            except KeyError:
                raise OSError(f"no such pid {pid}") from None

        from core.project import sessions

        stack = contextlib.ExitStack()
        # The battery-wide conftest neutralises the walk (hermetic
        # default); these tests exercise it — restore the real one.
        stack.enter_context(mock.patch.object(
            sessions, "_walk_session_pid", _REAL_WALK_SESSION_PID))
        stack.enter_context(mock.patch.object(sys, "platform", "linux"))
        stack.enter_context(mock.patch.object(md.os, "getpid",
                                              lambda: self_pid))
        stack.enter_context(mock.patch.object(md.os, "getppid",
                                              lambda: parents[self_pid]))
        stack.enter_context(mock.patch.object(md, "_read_ppid",
                                              _fake_read_ppid))
        stack.enter_context(mock.patch.object(md, "Path", _path_factory))
        # The shared resolver lives in core.project.sessions and walks
        # the same tree — give it the same fake comms and an isolated,
        # empty registry (no entry-bearing ancestors unless a test
        # writes one).
        stack.enter_context(mock.patch.object(
            sessions, "_comm", lambda pid: comms.get(pid)))
        self._sessions_tmp = stack.enter_context(TemporaryDirectory())
        stack.enter_context(mock.patch.object(
            sessions, "SESSIONS_DIR",
            Path(self._sessions_tmp) / "sessions.d"))
        return stack

    # pid 100 (test) -> 50 (bash) -> 40 (claude) -> 1 (init)
    _TREE = {100: 50, 50: 40, 40: 1}
    _COMMS = {50: "bash", 40: "claude"}
    # pid 100 (test) -> 50 (claude subagent) -> 45 (bash)
    #   -> 40 (claude SESSION) -> 1 (init)
    _NESTED_TREE = {100: 50, 50: 45, 45: 40, 40: 1}
    _NESTED_COMMS = {50: "claude", 45: "bash", 40: "claude"}

    def test_finds_claude_ancestor(self):
        """The walk returns the nearest ancestor whose comm is claude."""
        from core.run.metadata import _find_claude_ancestor
        with self._patch_tree(self._TREE, self._COMMS):
            self.assertEqual(_find_claude_ancestor(), 40)

    def test_stable_across_calls(self):
        from core.run.metadata import _find_claude_ancestor
        with self._patch_tree(self._TREE, self._COMMS):
            self.assertEqual(_find_claude_ancestor(),
                             _find_claude_ancestor())

    def test_none_when_no_claude_in_ancestry(self):
        """Detached process (reparented to init): no claude ancestor
        even when CLAUDECODE is still in the environment."""
        import os
        from unittest import mock

        from core.run.metadata import _find_claude_ancestor
        with self._patch_tree({100: 50, 50: 1}, {50: "bash"}), \
                mock.patch.dict(os.environ, {"CLAUDECODE": "1"}):
            self.assertIsNone(_find_claude_ancestor())

    def test_matches_session_pid_in_metadata(self):
        """session_pid stored by start_run equals the walked ancestor."""
        import os
        from unittest import mock

        from core.run.metadata import _find_claude_ancestor
        with self._patch_tree(self._TREE, self._COMMS), \
                mock.patch.dict(os.environ, {"CLAUDECODE": "1"}):
            with TemporaryDirectory() as d:
                out = Path(d) / "test-run"
                start_run(out, "scan")
                meta = load_json(out / RUN_METADATA_FILE)
                self.assertEqual(meta["session_pid"], 40)
                self.assertEqual(meta["session_pid"],
                                 _find_claude_ancestor())

    def test_nested_claude_resolves_outermost(self):
        """Beneath a nested ``claude -p`` subagent, the shared resolver
        picks the OUTERMOST claude ancestor (the session), not the
        nearest (the subagent) — one logical session, one identity
       . ``_find_claude_ancestor`` itself stays
        nearest-first for its remaining boolean consumers."""
        from core.project.sessions import resolve_session_pid
        from core.run.metadata import (
            _find_claude_ancestor,
            _get_session_pid,
        )
        with self._patch_tree(self._NESTED_TREE, self._NESTED_COMMS):
            self.assertEqual(_find_claude_ancestor(), 50)
            self.assertEqual(resolve_session_pid(), 40)
            self.assertEqual(_get_session_pid(), 40)

    def test_nested_claude_prefers_verified_entry_bearing(self):
        """When an intermediate claude ancestor owns a VERIFIED registry
        entry, it wins over the outermost — but a mere unverifiable
        entry (recycled pid shape) must not."""
        from unittest import mock

        from core.project import sessions
        with self._patch_tree(self._NESTED_TREE, self._NESTED_COMMS):
            sessions.SESSIONS_DIR.mkdir(parents=True, exist_ok=True)
            (sessions.SESSIONS_DIR / "50").write_text(
                "v=2\nproject=myapp\nsince=x\nstarttime=7\n"
                "boot_id=b\npidns=1\n", encoding="utf-8")
            # Unverifiable stamp → outermost still wins.
            self.assertEqual(sessions.resolve_session_pid(), 40)
            with mock.patch.object(sessions, "_identity_matches",
                                   lambda pid, fields: pid == 50), \
                    mock.patch.object(sessions, "_pid_running",
                                      lambda pid: True):
                self.assertEqual(sessions.resolve_session_pid(), 50)


class TestIsRunDirectory(unittest.TestCase):

    def test_with_metadata(self):
        with TemporaryDirectory() as d:
            out = Path(d) / "run"
            start_run(out, "scan")
            self.assertTrue(is_run_directory(out))

    def test_with_known_prefix_strict_rejects(self):
        # Default strict mode: prefix alone is not enough — needs
        # the canonical .raptor-run.json marker. Prevents over-match
        # on user dirs that happen to start with `scan_`.
        with TemporaryDirectory() as d:
            out = Path(d) / "scan_vulns_20260406"
            out.mkdir()
            self.assertFalse(is_run_directory(out))
            self.assertTrue(is_run_directory(out, strict=False))

    def test_with_typical_files_strict_rejects(self):
        # Default strict mode: stray findings.json in an unrelated
        # dir doesn't make it a run dir. Lenient mode (the legacy
        # heuristic, now opt-in) still accepts.
        with TemporaryDirectory() as d:
            out = Path(d) / "mystery_dir"
            out.mkdir()
            (out / "findings.json").write_text("{}")
            self.assertFalse(is_run_directory(out))
            self.assertTrue(is_run_directory(out, strict=False))

    def test_empty_dir(self):
        with TemporaryDirectory() as d:
            out = Path(d) / "empty"
            out.mkdir()
            self.assertFalse(is_run_directory(out))

    def test_not_a_dir(self):
        with TemporaryDirectory() as d:
            f = Path(d) / "file.txt"
            f.write_text("hello")
            self.assertFalse(is_run_directory(f))


class TestInferCommandType(unittest.TestCase):

    def test_from_metadata(self):
        with TemporaryDirectory() as d:
            out = Path(d) / "run"
            start_run(out, "validate")
            self.assertEqual(infer_command_type(out), "validate")

    def test_from_scan_prefix(self):
        with TemporaryDirectory() as d:
            out = Path(d) / "scan_vulns_20260406"
            out.mkdir()
            self.assertEqual(infer_command_type(out), "scan")

    def test_from_raptor_prefix(self):
        with TemporaryDirectory() as d:
            out = Path(d) / "raptor_vulns_20260406"
            out.mkdir()
            self.assertEqual(infer_command_type(out), "agentic")

    def test_from_validate_prefix(self):
        with TemporaryDirectory() as d:
            out = Path(d) / "exploitability-validation-20260406"
            out.mkdir()
            self.assertEqual(infer_command_type(out), "validate")

    def test_from_openant_prefix(self):
        with TemporaryDirectory() as d:
            out = Path(d) / "openant_20260504_abc"
            out.mkdir()
            self.assertEqual(infer_command_type(out), "openant")

    def test_unknown(self):
        with TemporaryDirectory() as d:
            out = Path(d) / "mystery"
            out.mkdir()
            self.assertEqual(infer_command_type(out), "unknown")


class TestGenerateRunMetadata(unittest.TestCase):

    def test_generates_for_missing(self):
        with TemporaryDirectory() as d:
            out = Path(d) / "scan_vulns_20260406_100000"
            out.mkdir()
            generate_run_metadata(out)
            meta = load_json(out / RUN_METADATA_FILE)
            self.assertEqual(meta["command"], "scan")
            self.assertEqual(meta["status"], "completed")
            self.assertTrue(meta["extra"].get("adopted"))

    def test_skips_existing(self):
        with TemporaryDirectory() as d:
            out = Path(d) / "run"
            start_run(out, "custom")
            generate_run_metadata(out)  # Should not overwrite
            meta = load_json(out / RUN_METADATA_FILE)
            self.assertEqual(meta["command"], "custom")

    def test_parses_timestamp_from_name(self):
        with TemporaryDirectory() as d:
            out = Path(d) / "scan-20260406-100000"
            out.mkdir()
            generate_run_metadata(out)
            meta = load_json(out / RUN_METADATA_FILE)
            self.assertIn("2026-04-06", meta["timestamp"])


class TestTrackedRun(unittest.TestCase):

    def test_completes_on_success(self):
        with TemporaryDirectory() as d:
            out = Path(d) / "run"
            with tracked_run(out, "scan"):
                (out / "findings.json").write_text("[]")
            meta = load_json(out / RUN_METADATA_FILE)
            self.assertEqual(meta["status"], "completed")

    def test_fails_on_exception(self):
        with TemporaryDirectory() as d:
            out = Path(d) / "run"
            with self.assertRaises(RuntimeError), tracked_run(out, "scan"):
                raise RuntimeError("something broke")
            meta = load_json(out / RUN_METADATA_FILE)
            self.assertEqual(meta["status"], "failed")
            self.assertIn("something broke", meta["extra"]["error"])

    def test_cancels_on_keyboard_interrupt(self):
        with TemporaryDirectory() as d:
            out = Path(d) / "run"
            with self.assertRaises(KeyboardInterrupt), \
                    tracked_run(out, "scan"):
                raise KeyboardInterrupt()
            meta = load_json(out / RUN_METADATA_FILE)
            self.assertEqual(meta["status"], "cancelled")

    def test_creates_directory(self):
        with TemporaryDirectory() as d:
            out = Path(d) / "new" / "nested" / "run"
            with tracked_run(out, "scan"):
                pass
            self.assertTrue(out.exists())

    def test_extra_metadata_preserved(self):
        with TemporaryDirectory() as d:
            out = Path(d) / "run"
            with tracked_run(out, "scan", extra={"packs": ["injection"]}):
                pass
            meta = load_json(out / RUN_METADATA_FILE)
            self.assertEqual(meta["extra"]["packs"], ["injection"])


if __name__ == "__main__":
    unittest.main()




class _ProjectRunCase(unittest.TestCase):
    """Mixin: an isolated project REGISTRY for the whole test, plus
    ``_as_project(dir)`` giving a fabricated project-shaped dir a real
    project so runs started under it PIN to it — under run pinning a
    pin-null run correctly refuses shape-inferred project stores, so
    tests that mean 'a project run' must say so. The registry patch
    spans the whole test (completion-time pin reads need it too)."""

    def setUp(self):
        super().setUp()
        from tempfile import TemporaryDirectory
        from unittest import mock
        self._registry_tmp = TemporaryDirectory()
        self.addCleanup(self._registry_tmp.cleanup)
        self._registry = Path(self._registry_tmp.name) / "projects"
        patcher = mock.patch("core.project.project.PROJECTS_DIR",
                             self._registry)
        patcher.start()
        self.addCleanup(patcher.stop)
        from core.run.pin import set_process_project
        self.addCleanup(set_process_project, None)

    def _as_project(self, project_dir):
        import contextlib

        from core.project.project import ProjectManager
        from core.run.pin import set_process_project

        mgr = ProjectManager(projects_dir=self._registry)
        if mgr.load("snapproj") is None:
            mgr.create("snapproj", str(project_dir),
                       output_dir=str(project_dir))
        set_process_project("snapproj")

        @contextlib.contextmanager
        def _ctx():
            try:
                yield
            finally:
                set_process_project(None)
        return _ctx()


class TestRunCoverageSnapshot(_ProjectRunCase):
    """complete_run folds a project run's coverage into the durable store
    (so it survives out-of-band deletion), and is a no-op for standalone runs."""

    def _checklist(self):
        import json
        return json.dumps({"files": [
            {"path": "a.c", "lines": 50, "items": [
                {"name": "f1", "line_start": 1, "line_end": 20}]}]})

    def test_completion_snapshots_project_run_coverage(self):
        import json

        from core.coverage.store import CoverageStore
        with TemporaryDirectory() as d:
            proj = Path(d)
            (proj / "checklist.json").write_text(self._checklist())
            run = proj / "scan-20260526_120000"
            with self._as_project(proj):
                start_run(run, "scan")
            (run / "coverage-semgrep.json").write_text(json.dumps(
                {"tool": "semgrep", "files_examined": ["a.c"], "timestamp": "t"}))
            (run / "findings.json").write_text(json.dumps(
                [{"id": "F1", "file": "a.c", "line": 10, "rule_id": "x"}]))
            complete_run(run)

            store = CoverageStore(proj / "coverage.json")    # persisted at completion
            self.assertEqual(store.who_checked("a.c", 10), ["semgrep"])
            self.assertEqual(store.function_verdict("a.c", 1, 20), "open")  # F1 in f1

    def test_completion_merges_review_journal_into_store(self):
        # /audit appends per-run review-journal.jsonl entries; completion
        # must merge them into the project-level index (the source
        # import_journal reads) and fold them into the durable store.
        # Regression: the merge used to live only in the libexec shim and
        # resolved the project via the .active symlink (a registry JSON
        # file, never a directory), so completed audit runs reported 0%
        # LLM coverage.
        import json

        from core.coverage.journal import INDEX_FILENAME
        from core.coverage.store import CoverageStore
        with TemporaryDirectory() as d:
            proj = Path(d)
            (proj / "checklist.json").write_text(self._checklist())
            run = proj / "audit-20260821_120000"
            with self._as_project(proj):
                start_run(run, "audit")
            entry = {"ts": "2026-08-21T00:00:00Z", "run_id": run.name,
                     "file": "a.c", "function": "f1", "verdict": "clean",
                     "source_hash": "abc123def456"}
            (run / "review-journal.jsonl").write_text(json.dumps(entry) + "\n")
            complete_run(run)

            self.assertTrue((proj / INDEX_FILENAME).exists())
            store = CoverageStore(proj / "coverage.json")
            self.assertEqual(store.who_checked_function("a.c", 1, 20),
                             {"audit": "full"})

    def test_interrupt_merges_review_journal_into_index(self):
        # An interrupted run's verdicts are real reviews — they must
        # reach the project index for sibling runs and the resume, even
        # though interrupt_run takes no coverage-store snapshot.
        import json

        from core.coverage.journal import INDEX_FILENAME
        from core.run.metadata import interrupt_run
        with TemporaryDirectory() as d:
            proj = Path(d)
            (proj / "checklist.json").write_text(self._checklist())
            run = proj / "audit-20260821_130000"
            with self._as_project(proj):
                start_run(run, "audit")
            entry = {"ts": "2026-08-21T00:00:00Z", "run_id": run.name,
                     "file": "a.c", "function": "f1", "verdict": "clean",
                     "source_hash": "abc123def456"}
            (run / "review-journal.jsonl").write_text(json.dumps(entry) + "\n")
            interrupt_run(run, "SIGTERM drain")

            self.assertTrue((proj / INDEX_FILENAME).exists())

    def test_completion_converts_reads_manifest_to_read_coverage(self):
        # The coverage plugin captures LLM file-reads into .reads-manifest;
        # complete_run materialises that into a coverage-read.json record.
        # Labelled `read` (shallow), NOT a function-level review — so the
        # function still surfaces in the LLM-review gap (read != reviewed).
        import json

        from core.coverage.store import CoverageStore
        from core.coverage.store_summary import store_view
        with TemporaryDirectory() as d:
            proj = Path(d)
            (proj / "checklist.json").write_text(self._checklist())  # a.c, lines 50
            run = proj / "agentic-20260526_120000"
            with self._as_project(proj):
                with self._as_project(proj):
                    start_run(run, "agentic")
            (run / ".reads-manifest").write_text("a.c\n")  # the LLM read a.c
            complete_run(run)

            self.assertTrue((run / "coverage-read.json").exists())
            store = CoverageStore(proj / "coverage.json")
            self.assertEqual(store.who_checked("a.c", 5), ["read"])
            # read != reviewed: f1 is still in the LLM-review gap.
            view = store_view(store, json.loads(self._checklist()))
            self.assertEqual(view["functions_reviewed"], 0)
            self.assertTrue(any(g["file"] == "a.c"
                                for g in view["llm_gap_functions"]))

    def test_non_completion_endings_still_convert_reads(self):
        # The LLM's reads happened regardless of how the run ended.
        # Pre-fix only complete_run converted the manifest, so a
        # failed/cancelled/interrupted run's reads never became coverage
        # (nothing imports raw manifests).
        from core.run.metadata import interrupt_run
        for ending in (
            lambda run: fail_run(run, error="boom"),
            cancel_run,
            interrupt_run,
        ):
            with TemporaryDirectory() as d:
                proj = Path(d)
                (proj / "checklist.json").write_text(self._checklist())
                run = proj / "agentic-20260526_120000"
                with self._as_project(proj):
                    start_run(run, "agentic")
                (run / ".reads-manifest").write_text("a.c\n")
                ending(run)
                self.assertTrue(
                    (run / "coverage-read.json").exists(), ending,
                )
                # Manifest stays: a resume→complete re-converts it with
                # any new reads (write_record overwrites; idempotent).
                self.assertTrue((run / ".reads-manifest").exists())

    def test_standalone_run_writes_no_store(self):
        import json
        with TemporaryDirectory() as d:
            out = Path(d) / "out"
            out.mkdir()
            run = out / "scan-20260526_120000"
            # Deliberately NO project: the run pins null and must not
            # write any shape-inferred store.
            start_run(run, "scan")
            (run / "coverage-semgrep.json").write_text(json.dumps(
                {"tool": "semgrep", "files_examined": ["a.c"], "timestamp": "t"}))
            complete_run(run)
            # No project pin -> no durable store written.
            self.assertFalse((out / "coverage.json").exists())

    def test_two_completions_accumulate_under_lock(self):
        import json

        from core.coverage.store import CoverageStore
        with TemporaryDirectory() as d:
            proj = Path(d)
            (proj / "checklist.json").write_text(json.dumps({"files": [
                {"path": "a.c", "lines": 50, "items": [
                    {"name": "f1", "line_start": 1, "line_end": 20}]},
                {"path": "b.c", "lines": 30, "items": [
                    {"name": "g1", "line_start": 1, "line_end": 10}]}]}))
            for nm, f in [("scan-20260526_01", "a.c"), ("codeql-20260526_02", "b.c")]:
                run = proj / nm
                with self._as_project(proj):
                    start_run(run, nm.split("-")[0])
                (run / "coverage-semgrep.json").write_text(json.dumps(
                    {"tool": "semgrep", "files_examined": [f], "timestamp": "t"}))
                complete_run(run)
            # Second snapshot's read-modify-write preserved the first's coverage.
            store = CoverageStore(proj / "coverage.json")
            self.assertEqual(store.who_checked("a.c", 5), ["semgrep"])
            self.assertEqual(store.who_checked("b.c", 5), ["semgrep"])


class TestCleanupAbandonedDeadSession(unittest.TestCase):
    """Dead-owner branch of _cleanup_abandoned: a status=running run
    whose recorded session_pid no longer maps to a live claude process
    has no lifecycle hook left to finalize it — start_run heals it
    regardless of command type. Live foreign sessions and the current
    session's other-command runs stay untouched."""

    CURRENT_SESSION = 50_000

    def _make_run(self, parent, name, command, session_pid, *, aged=True):
        from datetime import datetime, timedelta, timezone

        from core.json import save_json
        d = parent / name
        d.mkdir()
        ts = datetime.now(timezone.utc)
        if aged:
            ts -= timedelta(minutes=5)
        save_json(d / RUN_METADATA_FILE, {
            "version": 2,
            "command": command,
            "timestamp": ts.isoformat(),
            "status": "running",
            "session_pid": session_pid,
            "extra": {},
        })
        return d

    def _cleanup(self, project, alive_pids):
        from unittest.mock import patch

        from core.run.metadata import _cleanup_abandoned
        with patch("core.run.metadata._pid_alive",
                   side_effect=lambda pid: pid in alive_pids):
            _cleanup_abandoned(project, "scan", self.CURRENT_SESSION)

    def _status(self, d):
        return load_json(d / RUN_METADATA_FILE)["status"]

    def test_dead_session_run_failed_any_command(self):
        with TemporaryDirectory() as tmp:
            project = Path(tmp)
            dead = self._make_run(project, "codeql-001", "codeql", 40_001)
            self._cleanup(project, alive_pids=set())
            self.assertEqual(self._status(dead), "failed")
            meta = load_json(dead / RUN_METADATA_FILE)
            self.assertIn("owning session terminated",
                          meta["extra"]["error"])

    def test_live_foreign_session_untouched(self):
        with TemporaryDirectory() as tmp:
            project = Path(tmp)
            other = self._make_run(project, "codeql-001", "codeql", 40_002)
            self._cleanup(project, alive_pids={40_002})
            self.assertEqual(self._status(other), "running")

    def test_current_session_other_command_untouched(self):
        with TemporaryDirectory() as tmp:
            project = Path(tmp)
            mine = self._make_run(project, "validate-001", "validate",
                                  self.CURRENT_SESSION)
            self._cleanup(project, alive_pids=set())
            self.assertEqual(self._status(mine), "running")

    def test_fresh_dead_session_run_untouched(self):
        # Freshness gate absorbs the just-spawned window.
        with TemporaryDirectory() as tmp:
            project = Path(tmp)
            fresh = self._make_run(project, "codeql-001", "codeql",
                                   40_003, aged=False)
            self._cleanup(project, alive_pids=set())
            self.assertEqual(self._status(fresh), "running")

    def test_run_without_session_pid_untouched(self):
        with TemporaryDirectory() as tmp:
            project = Path(tmp)
            unowned = self._make_run(project, "codeql-001", "codeql", None)
            self._cleanup(project, alive_pids=set())
            self.assertEqual(self._status(unowned), "running")


class TestCleanupAbandonedLiveWorker(unittest.TestCase):
    """Worker-liveness gate on the same-session-retry branch of
    _cleanup_abandoned: a run of the same command in the same session
    that is past the freshness gate but whose recorded tool_pid is
    still alive is a LIVE parallel run, not an Esc-then-retry abandon.
    Pre-fix it was failed here, and the terminal-status guard in
    _update_status then refused its real completion — misfiling the
    live run's results."""

    CURRENT_SESSION = 50_000

    def _make_run(self, parent, name, command, *, tool_pid, aged=True):
        from datetime import datetime, timedelta, timezone

        from core.json import save_json
        d = parent / name
        d.mkdir()
        ts = datetime.now(timezone.utc)
        if aged:
            ts -= timedelta(minutes=5)
        meta = {
            "version": 2,
            "command": command,
            "timestamp": ts.isoformat(),
            "status": "running",
            "session_pid": self.CURRENT_SESSION,
            "extra": {},
        }
        if tool_pid is not None:
            meta["tool_pid"] = tool_pid
        save_json(d / RUN_METADATA_FILE, meta)
        if aged:
            # Aged fixtures must also be write-quiet: recent run-dir
            # activity reads as a live-run heartbeat.
            _age_run_tree(d)
        return d

    def _cleanup(self, project):
        from core.run.metadata import _cleanup_abandoned
        _cleanup_abandoned(project, "scan", self.CURRENT_SESSION)

    def _status(self, d):
        return load_json(d / RUN_METADATA_FILE)["status"]

    def test_live_worker_not_false_failed(self):
        # A >30s-old parallel run whose worker is this very process:
        # certainly alive, must stay running.
        import os
        with TemporaryDirectory() as tmp:
            project = Path(tmp)
            live = self._make_run(project, "scan-001", "scan",
                                  tool_pid=os.getpid())
            self._cleanup(project)
            self.assertEqual(self._status(live), "running")

    def test_live_worker_completion_still_lands(self):
        # The full misfiling shape: after a cleanup pass, the live
        # run's real completion must not be refused by the terminal-
        # status guard.
        import os
        with TemporaryDirectory() as tmp:
            project = Path(tmp)
            live = self._make_run(project, "scan-001", "scan",
                                  tool_pid=os.getpid())
            self._cleanup(project)
            complete_run(live)
            self.assertEqual(self._status(live), "completed")

    def test_dead_worker_failed(self):
        with TemporaryDirectory() as tmp:
            project = Path(tmp)
            stale = self._make_run(project, "scan-001", "scan",
                                   tool_pid=_dead_pid())
            self._cleanup(project)
            self.assertEqual(self._status(stale), "failed")
            meta = load_json(stale / RUN_METADATA_FILE)
            self.assertIn("replaced by new run", meta["extra"]["error"])

    def test_legacy_run_without_tool_pid_failed(self):
        # Metadata written before tool_pid was recorded keeps the old
        # (freshness-only) behaviour.
        with TemporaryDirectory() as tmp:
            project = Path(tmp)
            legacy = self._make_run(project, "scan-001", "scan",
                                    tool_pid=None)
            self._cleanup(project)
            self.assertEqual(self._status(legacy), "failed")

    def test_fresh_live_worker_untouched(self):
        import os
        with TemporaryDirectory() as tmp:
            project = Path(tmp)
            fresh = self._make_run(project, "scan-001", "scan",
                                   tool_pid=os.getpid(), aged=False)
            self._cleanup(project)
            self.assertEqual(self._status(fresh), "running")

    def test_recent_activity_not_false_failed(self):
        # Stub-driven run: the recorded tool_pid is the lifecycle
        # stub's transient shell (dead seconds after start), but the
        # run dir shows recent writes — the heartbeat that survives
        # the shell. Must NOT be failed by a same-command sweep.
        with TemporaryDirectory() as tmp:
            project = Path(tmp)
            live = self._make_run(project, "scan-001", "scan",
                                  tool_pid=_dead_pid())
            (live / "journal.jsonl").write_text("{}\n")  # fresh write
            self._cleanup(project)
            self.assertEqual(self._status(live), "running")


class TestAbandonSweepRecovery(unittest.TestCase):
    """A sweep-stamped abandon is heuristic: a live run it misjudged
    must still be able to record its real terminal state, while
    genuinely-failed runs keep the terminal-status guard."""

    def test_wrong_abandon_overridden_by_real_completion(self):
        with TemporaryDirectory() as d:
            out = Path(d) / "scan-001"
            start_run(out, "scan")
            fail_run(out, "abandoned — replaced by new run in same session",
                     extra={"abandon_sweep": True}, record_timing=False)
            self.assertEqual(
                load_json(out / RUN_METADATA_FILE)["status"], "failed")
            complete_run(out)
            meta = load_json(out / RUN_METADATA_FILE)
            self.assertEqual(meta["status"], "completed")
            # The sweep's markers are cleared on override.
            self.assertNotIn("abandon_sweep", meta["extra"])
            self.assertNotIn("error", meta["extra"])

    def test_real_failure_after_sweep_consumes_marker(self):
        # A GENUINE fail_run landing after a sweep-stamped abandon
        # consumes the marker: without that, the extras merge kept
        # abandon_sweep alongside the real error and a later
        # complete_run laundered the genuinely failed run green,
        # deleting the real error.
        with TemporaryDirectory() as d:
            out = Path(d) / "scan-001"
            start_run(out, "scan")
            fail_run(out, "abandoned — replaced by new run in same session",
                     extra={"abandon_sweep": True}, record_timing=False)
            fail_run(out, "tool crashed with OOM")  # REAL failure
            meta = load_json(out / RUN_METADATA_FILE)
            self.assertNotIn("abandon_sweep", meta["extra"])
            complete_run(out)
            meta = load_json(out / RUN_METADATA_FILE)
            self.assertEqual(meta["status"], "failed")
            self.assertEqual(meta["extra"]["error"], "tool crashed with OOM")

    def test_resweep_keeps_marker_overridable(self):
        # Two-direction guard: a second SWEEP write (extra carries the
        # marker) must not consume it — the run stays recoverable by
        # its real finaliser.
        with TemporaryDirectory() as d:
            out = Path(d) / "scan-001"
            start_run(out, "scan")
            for _ in range(2):
                fail_run(out, "abandoned — owning session terminated",
                         extra={"abandon_sweep": True},
                         record_timing=False)
            complete_run(out)
            meta = load_json(out / RUN_METADATA_FILE)
            self.assertEqual(meta["status"], "completed")

    def test_sweep_after_real_failure_is_noop(self):
        # Race ordering: the run's REAL failure lands first; a sweep
        # that read status=running moments earlier then delivers its
        # marker-carrying failed write. The failed→failed merge used
        # to overwrite the real error with the sweep's message and
        # plant the marker — a later stray complete_run then took the
        # recovery branch and laundered the genuine failure green.
        # The sweep lost the race: its write must be a no-op.
        with TemporaryDirectory() as d:
            out = Path(d) / "scan-001"
            start_run(out, "scan")
            fail_run(out, "tool crashed with OOM")  # REAL failure first
            fail_run(out, "session ended without explicit completion",
                     extra={"abandon_sweep": True}, record_timing=False)
            meta = load_json(out / RUN_METADATA_FILE)
            self.assertEqual(meta["status"], "failed")
            self.assertNotIn("abandon_sweep", meta["extra"])
            self.assertEqual(meta["extra"]["error"], "tool crashed with OOM")
            complete_run(out)  # stray finaliser must find no marker
            meta = load_json(out / RUN_METADATA_FILE)
            self.assertEqual(meta["status"], "failed")
            self.assertEqual(meta["extra"]["error"], "tool crashed with OOM")

    def test_sweep_onto_completed_is_noop(self):
        # Same guard, other terminal state: a marker-carrying failed
        # write onto completed changes nothing (exercised via
        # _update_status directly — fail_run's own pre-check already
        # refuses non-failed terminal states before any side effect).
        from core.run.metadata import _update_status
        with TemporaryDirectory() as d:
            out = Path(d) / "scan-001"
            start_run(out, "scan")
            complete_run(out)
            _update_status(out, "failed",
                           extra={"abandon_sweep": True,
                                  "error": "session ended"},
                           record_timing=False)
            meta = load_json(out / RUN_METADATA_FILE)
            self.assertEqual(meta["status"], "completed")
            self.assertNotIn("abandon_sweep", meta.get("extra") or {})

    def test_genuine_refail_without_marker_still_restamps(self):
        # Idempotent re-stamp: a second REAL failed write (no marker)
        # keeps merging — only sweep-stamped writes are dropped.
        with TemporaryDirectory() as d:
            out = Path(d) / "scan-001"
            start_run(out, "scan")
            fail_run(out, "tool crashed")
            fail_run(out, "tool crashed (retry also failed)")
            meta = load_json(out / RUN_METADATA_FILE)
            self.assertEqual(meta["status"], "failed")
            self.assertEqual(meta["extra"]["error"],
                             "tool crashed (retry also failed)")

    def test_real_failure_still_refuses_completion(self):
        # Two-direction guard: only sweep-stamped abandons may be
        # overridden — a real failure stays terminal.
        with TemporaryDirectory() as d:
            out = Path(d) / "scan-001"
            start_run(out, "scan")
            fail_run(out, "tool crashed")
            complete_run(out)
            meta = load_json(out / RUN_METADATA_FILE)
            self.assertEqual(meta["status"], "failed")
            self.assertEqual(meta["extra"]["error"], "tool crashed")

    def test_fail_after_complete_refused_without_side_effects(self):
        # fail_run re-validates BEFORE its finalisers: a sweep racing a
        # completed run must not downgrade it or stamp an error.
        with TemporaryDirectory() as d:
            out = Path(d) / "scan-001"
            start_run(out, "scan")
            complete_run(out)
            fail_run(out, "late sweep failure")
            meta = load_json(out / RUN_METADATA_FILE)
            self.assertEqual(meta["status"], "completed")
            self.assertNotIn("error", meta.get("extra") or {})


class TestUpdateStatusConcurrency(unittest.TestCase):
    """_update_status read-modify-writes the run JSON under a file
    lock; concurrent writers must all land instead of last-writer-wins
    dropping each other's `extra` updates."""

    def test_concurrent_extra_updates_all_land(self):
        import threading

        from core.json import save_json
        from core.run.metadata import STATUS_RUNNING, _update_status
        with TemporaryDirectory() as tmp:
            run_dir = Path(tmp) / "scan-001"
            run_dir.mkdir()
            save_json(run_dir / RUN_METADATA_FILE, {
                "version": 2,
                "command": "scan",
                "timestamp": "2026-01-01T00:00:00+00:00",
                "status": STATUS_RUNNING,
                "extra": {},
            })

            n_writers = 8
            barrier = threading.Barrier(n_writers)
            errors = []

            def writer(i):
                try:
                    barrier.wait(timeout=10)
                    _update_status(run_dir, STATUS_RUNNING,
                                   extra={f"k{i}": i})
                except Exception as e:  # noqa: BLE001 — surfaced via assert below
                    errors.append(e)

            threads = [threading.Thread(target=writer, args=(i,))
                       for i in range(n_writers)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=30)

            self.assertEqual(errors, [])
            meta = load_json(run_dir / RUN_METADATA_FILE)
            for i in range(n_writers):
                self.assertEqual(meta["extra"].get(f"k{i}"), i,
                                 f"writer {i}'s update was dropped")

    def test_racing_terminal_writers_keep_first_verdict(self):
        # Two terminal writers race; whichever lands first wins and
        # the other is refused — the file must end in ONE coherent
        # terminal state, never a torn or resurrected one.
        import threading

        from core.json import save_json
        from core.run.metadata import (
            STATUS_COMPLETED,
            STATUS_FAILED,
            STATUS_RUNNING,
            _update_status,
        )
        with TemporaryDirectory() as tmp:
            run_dir = Path(tmp) / "scan-001"
            run_dir.mkdir()
            save_json(run_dir / RUN_METADATA_FILE, {
                "version": 2,
                "command": "scan",
                "timestamp": "2026-01-01T00:00:00+00:00",
                "status": STATUS_RUNNING,
                "extra": {},
            })
            barrier = threading.Barrier(2)

            def hit(status):
                barrier.wait(timeout=10)
                _update_status(run_dir, status)

            t1 = threading.Thread(target=hit, args=(STATUS_COMPLETED,))
            t2 = threading.Thread(target=hit, args=(STATUS_FAILED,))
            t1.start()
            t2.start()
            t1.join(timeout=30)
            t2.join(timeout=30)

            meta = load_json(run_dir / RUN_METADATA_FILE)
            self.assertIn(meta["status"], (STATUS_COMPLETED, STATUS_FAILED))


class TestCorroborateTargetPath(unittest.TestCase):
    """Recovered target paths must be checked against the sealed
    ``target_path`` from start_run before use."""

    def test_matching_target_ok(self):
        from core.run.metadata import corroborate_target_path
        with TemporaryDirectory() as d:
            target = Path(d) / "repo"
            target.mkdir()
            run_dir = Path(d) / "run"
            start_run(run_dir, "audit", target=target)
            self.assertIsNone(corroborate_target_path(run_dir, target))
            self.assertIsNone(
                corroborate_target_path(run_dir, str(target)))

    def test_mismatch_refused(self):
        from core.run.metadata import corroborate_target_path
        with TemporaryDirectory() as d:
            target = Path(d) / "repo"
            target.mkdir()
            other = Path(d) / "other"
            other.mkdir()
            run_dir = Path(d) / "run"
            start_run(run_dir, "audit", target=target)
            msg = corroborate_target_path(run_dir, other)
            self.assertIsNotNone(msg)
            self.assertIn(RUN_METADATA_FILE, msg)
            self.assertIn(str(target), msg)

    def test_mismatch_text_escapes_hostile_candidate(self):
        """The mismatch description is printed verbatim by every
        consumer shim, and the candidate is the LLM-writable checklist
        value — it fires exactly in the tamper-detected case, so the
        text must be terminal-safe at this chokepoint."""
        from core.run.metadata import corroborate_target_path
        with TemporaryDirectory() as d:
            target = Path(d) / "repo"
            target.mkdir()
            run_dir = Path(d) / "run"
            start_run(run_dir, "audit", target=target)
            msg = corroborate_target_path(
                run_dir, f"{d}/evil\x1b[2J\x9bpath")
            self.assertIsNotNone(msg)
            self.assertNotIn("\x1b", msg)
            self.assertNotIn("\x9b", msg)
            self.assertIn("evil", msg)

    def test_symlinked_equivalent_ok(self):
        from core.run.metadata import corroborate_target_path
        with TemporaryDirectory() as d:
            target = Path(d) / "repo"
            target.mkdir()
            alias = Path(d) / "alias"
            alias.symlink_to(target)
            run_dir = Path(d) / "run"
            start_run(run_dir, "audit", target=target)
            self.assertIsNone(corroborate_target_path(run_dir, alias))

    def test_no_metadata_is_unverifiable_not_refused(self):
        from core.run.metadata import corroborate_target_path
        with TemporaryDirectory() as d:
            run_dir = Path(d) / "run"
            run_dir.mkdir()
            self.assertIsNone(
                corroborate_target_path(run_dir, Path(d)))

    def test_no_sealed_target_is_unverifiable_not_refused(self):
        from core.run.metadata import corroborate_target_path
        with TemporaryDirectory() as d:
            run_dir = Path(d) / "run"
            start_run(run_dir, "audit")   # no target sealed
            self.assertIsNone(
                corroborate_target_path(run_dir, Path(d)))

    def test_empty_candidate_ok(self):
        from core.run.metadata import corroborate_target_path
        with TemporaryDirectory() as d:
            run_dir = Path(d) / "run"
            start_run(run_dir, "audit", target=Path(d))
            self.assertIsNone(corroborate_target_path(run_dir, None))
            self.assertIsNone(corroborate_target_path(run_dir, ""))


class TestCoverageProgress(_ProjectRunCase):
    _checklist = TestRunCoverageSnapshot._checklist

    def test_completion_appends_progress_row(self):
        import json
        with TemporaryDirectory() as d:
            proj = Path(d)
            (proj / "checklist.json").write_text(self._checklist())
            for name in ("audit-1", "audit-2"):
                run = proj / name
                with self._as_project(proj):
                    start_run(run, "audit")
                complete_run(run)
            progress = proj / "coverage-progress.jsonl"
            rows = [json.loads(x) for x in
                    progress.read_text().splitlines() if x.strip()]
            self.assertEqual([r["run"] for r in rows],
                             ["audit-1", "audit-2"])
            for r in rows:
                self.assertIn("llm_reviewed", r)
                self.assertIn("llm_reviewable", r)

    def test_standalone_run_appends_nothing(self):
        with TemporaryDirectory() as d:
            out = Path(d) / "out"
            out.mkdir()
            run = out / "scan-1"
            start_run(run, "scan")
            complete_run(run)
            self.assertFalse((out / "coverage-progress.jsonl").exists())


class TestSessionIdentityStamp(unittest.TestCase):
    """Run-metadata identity stamps: a
    recycled claude PID must not keep a dead session's runs alive, a
    resumed run must carry the RESUMING session's stamp, and unstamped
    legacy metadata keeps the fail-open comm check."""

    def _stamped_meta(self, pid: int, start: str = "7", boot: str = "b",
                      pidns: str = "1") -> dict:
        return {
            "session_pid": pid,
            "session_start": start,
            "session_boot_id": boot,
            "session_pidns": pidns,
        }

    def test_start_run_records_stamp(self):
        import os
        from unittest import mock

        from core.project import sessions
        from core.run.metadata import RUN_METADATA_FILE, start_run
        with TemporaryDirectory() as d, \
                mock.patch(
                    "core.run.metadata._get_session_pid",
                    return_value=os.getpid()), \
                mock.patch.object(sessions, "proc_starttime",
                                  lambda pid: "1234"), \
                mock.patch.object(sessions, "boot_id", lambda: "boot-x"), \
                mock.patch.object(sessions, "pidns_id", lambda: "42"):
            out = Path(d) / "run"
            start_run(out, "scan")
            meta = load_json(out / RUN_METADATA_FILE)
            self.assertEqual(meta["session_start"], "1234")
            self.assertEqual(meta["session_boot_id"], "boot-x")
            self.assertEqual(meta["session_pidns"], "42")

    def test_stamp_mismatch_reads_dead(self):
        """Live claude process at the pid, WRONG starttime — a recycled
        pid; the owner is dead (closes forever-contention)."""
        import os
        from unittest import mock

        from core.project import sessions
        from core.run.metadata import _session_alive_for_meta
        meta = self._stamped_meta(os.getpid(), start="999999")
        with mock.patch.object(sessions, "boot_id", lambda: "b"), \
                mock.patch.object(sessions, "pidns_id", lambda: "1"), \
                mock.patch.object(sessions, "_comm",
                                  lambda pid: "claude"), \
                mock.patch.object(sessions, "proc_starttime",
                                  lambda pid: "7"):
            self.assertTrue(
                _session_alive_for_meta(self._stamped_meta(os.getpid())))
            self.assertFalse(_session_alive_for_meta(meta))

    def test_foreign_stamp_reads_alive(self):
        """Other boot / pid namespace — unverifiable here: fail OPEN
        (sweeps skip, contention preserved)."""
        from unittest import mock

        from core.project import sessions
        from core.run.metadata import _session_alive_for_meta
        meta = self._stamped_meta(1, boot="other-boot")
        with mock.patch.object(sessions, "boot_id", lambda: "b"):
            self.assertTrue(_session_alive_for_meta(meta))

    def test_prior_boot_of_same_machine_reads_dead(self):
        """A stamp carrying THIS machine's identity but another boot_id
        was written during a prior boot — provably dead: sweeps may
        reap it and it releases run contention (no permanent
        status=running zombies after a reboot)."""
        from unittest import mock

        from core.project import sessions
        from core.run.metadata import _session_alive_for_meta
        meta = self._stamped_meta(1, boot="prior-boot")
        meta["session_machine_id"] = "same-machine-hash"
        with mock.patch.object(sessions, "boot_id", lambda: "b"), \
                mock.patch.object(sessions, "machine_id",
                                  lambda: "same-machine-hash"):
            self.assertFalse(_session_alive_for_meta(meta))

    def test_other_machine_stamp_reads_alive(self):
        """A doctored/foreign machine identity with a foreign boot is
        NOT provably dead — could be a live run on another machine
        sharing the filesystem: fail open."""
        from unittest import mock

        from core.project import sessions
        from core.run.metadata import _session_alive_for_meta
        meta = self._stamped_meta(1, boot="prior-boot")
        meta["session_machine_id"] = "some-other-machine-hash"
        with mock.patch.object(sessions, "boot_id", lambda: "b"), \
                mock.patch.object(sessions, "machine_id",
                                  lambda: "same-machine-hash"):
            self.assertTrue(_session_alive_for_meta(meta))

    def test_absent_machine_id_keeps_fail_open(self):
        """Legacy stamp (no machine identity) with a foreign boot keeps
        today's fail-open alive verdict."""
        from unittest import mock

        from core.project import sessions
        from core.run.metadata import _session_alive_for_meta
        meta = self._stamped_meta(1, boot="prior-boot")
        with mock.patch.object(sessions, "boot_id", lambda: "b"), \
                mock.patch.object(sessions, "machine_id",
                                  lambda: "same-machine-hash"):
            self.assertTrue(_session_alive_for_meta(meta))

    def test_local_machine_id_unreadable_keeps_fail_open(self):
        """No local machine identity to compare against — the stamp is
        unverifiable: fail open."""
        from unittest import mock

        from core.project import sessions
        from core.run.metadata import _session_alive_for_meta
        meta = self._stamped_meta(1, boot="prior-boot")
        meta["session_machine_id"] = "same-machine-hash"
        with mock.patch.object(sessions, "boot_id", lambda: "b"), \
                mock.patch.object(sessions, "machine_id", lambda: None):
            self.assertTrue(_session_alive_for_meta(meta))

    def test_start_run_records_machine_id(self):
        import os
        from unittest import mock

        from core.project import sessions
        from core.run.metadata import RUN_METADATA_FILE, start_run
        with TemporaryDirectory() as d, \
                mock.patch(
                    "core.run.metadata._get_session_pid",
                    return_value=os.getpid()), \
                mock.patch.object(sessions, "proc_starttime",
                                  lambda pid: "1234"), \
                mock.patch.object(sessions, "boot_id", lambda: "boot-x"), \
                mock.patch.object(sessions, "pidns_id", lambda: "42"), \
                mock.patch.object(sessions, "machine_id",
                                  lambda: "machine-hash-x"):
            out = Path(d) / "run"
            start_run(out, "scan")
            meta = load_json(out / RUN_METADATA_FILE)
            self.assertEqual(meta["session_machine_id"], "machine-hash-x")

    def test_start_run_records_harness_session_id(self):
        import os
        from unittest import mock

        from core.run.metadata import RUN_METADATA_FILE, start_run
        sid = "aaaaaaaa-1111-2222-3333-444444444444"
        with TemporaryDirectory() as d, \
                mock.patch("core.run.metadata._get_session_pid",
                           return_value=os.getpid()), \
                mock.patch.dict(os.environ,
                                {"CLAUDE_CODE_SESSION_ID": sid}):
            out = Path(d) / "run"
            start_run(out, "scan")
            meta = load_json(out / RUN_METADATA_FILE)
            self.assertEqual(meta["session_id"], sid)

    def test_start_run_ignores_malformed_session_id(self):
        import os
        from unittest import mock

        from core.run.metadata import RUN_METADATA_FILE, start_run
        with TemporaryDirectory() as d, \
                mock.patch("core.run.metadata._get_session_pid",
                           return_value=os.getpid()), \
                mock.patch.dict(os.environ,
                                {"CLAUDE_CODE_SESSION_ID": "no spaces;$(",
                                 "CLAUDE_SESSION_ID": ""}):
            out = Path(d) / "run"
            start_run(out, "scan")
            meta = load_json(out / RUN_METADATA_FILE)
            self.assertNotIn("session_id", meta)

    def test_resume_refreshes_session_id(self):
        import os
        from unittest import mock

        from core.run.metadata import (
            RUN_METADATA_FILE,
            fail_run,
            resume_run,
            start_run,
        )
        first = "aaaaaaaa-1111-2222-3333-444444444444"
        second = "bbbbbbbb-5555-6666-7777-888888888888"
        with TemporaryDirectory() as d:
            out = Path(d) / "run"
            with mock.patch("core.run.metadata._get_session_pid",
                            return_value=11111), \
                    mock.patch.dict(os.environ,
                                    {"CLAUDE_CODE_SESSION_ID": first}):
                start_run(out, "scan")
            fail_run(out, "interrupted for test", record_timing=False)
            with mock.patch("core.run.metadata._get_session_pid",
                            return_value=22222), \
                    mock.patch.dict(os.environ,
                                    {"CLAUDE_CODE_SESSION_ID": second}):
                resume_run(out)
            meta = load_json(out / RUN_METADATA_FILE)
            self.assertEqual(meta["session_id"], second)

    def test_cleanup_abandoned_sweeps_prior_boot_zombie(self):
        """End-to-end: the dead-session sweep branch reaps a run whose
        stamp is from a prior boot of this machine — the exact
        post-reboot zombie shape."""
        from unittest import mock

        from core.project import sessions
        from core.run import metadata as md
        from core.run.metadata import RUN_METADATA_FILE, start_run
        with TemporaryDirectory() as d:
            out = Path(d) / "old-run"
            with mock.patch("core.run.metadata._get_session_pid",
                            return_value=33333), \
                    mock.patch.object(sessions, "proc_starttime",
                                      lambda pid: "7"), \
                    mock.patch.object(sessions, "boot_id",
                                      lambda: "prior-boot"), \
                    mock.patch.object(sessions, "pidns_id", lambda: "1"), \
                    mock.patch.object(sessions, "machine_id",
                                      lambda: "same-machine-hash"):
                start_run(out, "scan")
            # Age it past the freshness gate.
            meta = load_json(out / RUN_METADATA_FILE)
            meta["timestamp"] = "2020-01-01T00:00:00+00:00"
            from core.json import save_json
            save_json(out / RUN_METADATA_FILE, meta)
            # Rebooted: same machine, new boot id.
            with mock.patch.object(sessions, "boot_id", lambda: "b"), \
                    mock.patch.object(sessions, "pidns_id", lambda: "1"), \
                    mock.patch.object(sessions, "machine_id",
                                      lambda: "same-machine-hash"):
                md._cleanup_abandoned(Path(d), "scan", 44444)
            meta = load_json(out / RUN_METADATA_FILE)
            self.assertEqual(meta["status"], "failed")

    def test_unstamped_uses_legacy_comm_check(self):
        import os
        from unittest import mock

        from core.run import metadata as md
        meta = {"session_pid": os.getpid()}
        with mock.patch.object(md, "_pid_alive",
                               lambda pid: pid == os.getpid()):
            self.assertTrue(md._session_alive_for_meta(meta))
        with mock.patch.object(md, "_pid_alive", lambda pid: False):
            self.assertFalse(md._session_alive_for_meta(meta))

    def test_resume_refreshes_full_stamp(self):
        """A run resumed by a different session must not carry the old
        session's stamp — the verifiers would judge the LIVE resumed
        run abandoned."""
        from unittest import mock

        from core.project import sessions
        from core.run.metadata import (
            RUN_METADATA_FILE,
            fail_run,
            resume_run,
            start_run,
        )
        with TemporaryDirectory() as d:
            out = Path(d) / "run"
            with mock.patch("core.run.metadata._get_session_pid",
                            return_value=11111), \
                    mock.patch.object(sessions, "proc_starttime",
                                      lambda pid: "old-start"), \
                    mock.patch.object(sessions, "boot_id", lambda: "b"), \
                    mock.patch.object(sessions, "pidns_id", lambda: "1"):
                start_run(out, "scan")
            fail_run(out, "interrupted for test", record_timing=False)
            with mock.patch("core.run.metadata._get_session_pid",
                            return_value=22222), \
                    mock.patch.object(sessions, "proc_starttime",
                                      lambda pid: "new-start"), \
                    mock.patch.object(sessions, "boot_id", lambda: "b"), \
                    mock.patch.object(sessions, "pidns_id", lambda: "1"):
                resume_run(out)
            meta = load_json(out / RUN_METADATA_FILE)
            self.assertEqual(meta["session_pid"], 22222)
            self.assertEqual(meta["session_start"], "new-start")

    def test_cleanup_abandoned_sweeps_recycled_claude_pid(self):
        """The dead-session branch fires on a stamped mismatch even when
        a claude-comm process is live at the recorded pid."""
        from unittest import mock

        from core.project import sessions
        from core.run import metadata as md
        from core.run.metadata import RUN_METADATA_FILE, start_run
        with TemporaryDirectory() as d:
            out = Path(d) / "old-run"
            with mock.patch("core.run.metadata._get_session_pid",
                            return_value=33333), \
                    mock.patch.object(sessions, "proc_starttime",
                                      lambda pid: "gone"), \
                    mock.patch.object(sessions, "boot_id", lambda: "b"), \
                    mock.patch.object(sessions, "pidns_id", lambda: "1"):
                start_run(out, "scan")
            # Age it past the freshness gate.
            meta = load_json(out / RUN_METADATA_FILE)
            meta["timestamp"] = "2020-01-01T00:00:00+00:00"
            from core.json import save_json
            save_json(out / RUN_METADATA_FILE, meta)
            # Recycled: live claude at 33333 with a DIFFERENT starttime.
            with mock.patch.object(sessions, "boot_id", lambda: "b"), \
                    mock.patch.object(sessions, "pidns_id", lambda: "1"), \
                    mock.patch.object(sessions, "_pid_running",
                                      lambda pid: True), \
                    mock.patch.object(sessions, "_comm",
                                      lambda pid: "claude"), \
                    mock.patch.object(sessions, "proc_starttime",
                                      lambda pid: "recycled"):
                md._cleanup_abandoned(Path(d), "scan", 44444)
            meta = load_json(out / RUN_METADATA_FILE)
            self.assertEqual(meta["status"], "failed")


class TestMetadataReadBudget(unittest.TestCase):
    """Every reader of the sandbox-writable ``.raptor-run.json`` pays
    the shared byte budget: an oversize plant costs no disk (sparse)
    and OOM-killed the uncapped readers — including the contention
    gate every future start in the project runs, the victim run's own
    finalisers, and resume."""

    def _sparse_meta(self, run_dir: Path) -> None:
        from core.run.metadata import RUN_METADATA_MAX_BYTES
        with (run_dir / RUN_METADATA_FILE).open("wb") as f:
            f.truncate(RUN_METADATA_MAX_BYTES + 1)

    def test_load_meta_refuses_oversize(self):
        from core.run.metadata import _load_meta
        with TemporaryDirectory() as d:
            run = Path(d)
            self._sparse_meta(run)
            self.assertIsNone(_load_meta(run / RUN_METADATA_FILE))

    def test_oversize_sibling_never_blocks_contention_gate(self):
        # The gate loads EVERY sibling's metadata inside start_run —
        # one planted sparse file must degrade to "no conflict", not
        # buffer the payload or block the start.
        from core.run.metadata import _live_conflicting_run
        with TemporaryDirectory() as d:
            project = Path(d)
            me = project / "run_me"
            me.mkdir()
            sibling = project / "run_other"
            sibling.mkdir()
            self._sparse_meta(sibling)
            self.assertIsNone(
                _live_conflicting_run(project, me, None))

    def test_oversize_meta_fails_resume_closed(self):
        from core.run.metadata import resume_run
        with TemporaryDirectory() as d:
            run = Path(d)
            self._sparse_meta(run)
            # Over-budget follows the malformed/missing contract:
            # refuse the resume, never materialise the payload.
            with self.assertRaises((FileNotFoundError, ValueError)):
                resume_run(run)

    def test_every_metadata_read_routes_through_the_budget(self):
        # Closure oracle (the intake-bounds commit's own pattern):
        # no bare load_json may target the metadata file — readers
        # go through _load_meta / load_run_metadata, so the budget
        # is single-homed in fact, not just in the comment.
        import ast
        import inspect

        from core.run import metadata as md
        src = inspect.getsource(md)
        tree = ast.parse(src)
        offenders: list[int] = []
        funcs = [
            n for n in ast.walk(tree)
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
        ]

        def _enclosing(lineno: int) -> str:
            best, span = "<module>", None
            for f in funcs:
                if f.lineno <= lineno <= (f.end_lineno or f.lineno):
                    s = (f.end_lineno or f.lineno) - f.lineno
                    if span is None or s < span:
                        best, span = f.name, s
            return best

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = ""
            if isinstance(node.func, ast.Name):
                name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                name = node.func.attr
            if name != "load_json":
                continue
            if _enclosing(node.lineno) in ("_load_meta",):
                continue  # the budgeted loader's own body
            arg_src = (ast.get_source_segment(src, node.args[0])
                       if node.args else "") or ""
            has_cap = any(k.arg == "max_bytes" for k in node.keywords)
            if has_cap:
                continue
            if "checklist" in arg_src:
                # checklist.json readers carry the run-artifact
                # budget class; the coverage/run closure test owns
                # their cap spelling.
                continue
            offenders.append(f"{node.lineno}: load_json({arg_src})")
        self.assertEqual(
            offenders, [],
            "bare load_json in metadata.py — metadata readers route "
            "through _load_meta/load_run_metadata; other artifacts "
            f"pass max_bytes: {offenders}")


class MetadataLockTamperTest(unittest.TestCase):
    """The `.lock` sibling lives inside the sandbox child's write
    grant (the metadata FILE is namespace-masked; the sibling is not)
    — the lock open must not follow a planted symlink, must not block
    on a planted FIFO, and must degrade LOUDLY, never silently."""

    def setUp(self):
        self._tmp = TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.run_dir = Path(self._tmp.name)
        self.meta_path = self.run_dir / ".raptor-run.json"
        self.lock_path = self.run_dir / ".raptor-run.json.lock"

    def test_planted_symlink_not_followed(self):
        import os

        from core.run.metadata import _metadata_lock
        victim = self.run_dir / "attacker-chosen-path"
        os.symlink(victim, self.lock_path)
        with self.assertLogs("core.run.metadata", level="WARNING") as logs:
            with _metadata_lock(self.meta_path):
                pass
        self.assertFalse(victim.exists(),
                         "symlink was followed — file created at the "
                         "attacker-chosen path")
        self.assertTrue(any("UNSERIALISED" in m for m in logs.output))

    def test_planted_fifo_does_not_wedge(self):
        import os
        import time

        from core.run.metadata import _metadata_lock
        if not hasattr(os, "mkfifo"):
            self.skipTest("no mkfifo on this platform")
        os.mkfifo(self.lock_path)
        start = time.monotonic()
        with self.assertLogs("core.run.metadata", level="WARNING"):
            with _metadata_lock(self.meta_path):
                pass
        self.assertLess(time.monotonic() - start, 2.0,
                        "FIFO open blocked the lifecycle finaliser")

    def test_planted_fifo_with_reader_refused(self):
        import os
        import time

        from core.run.metadata import _metadata_lock
        if not hasattr(os, "mkfifo"):
            self.skipTest("no mkfifo on this platform")
        os.mkfifo(self.lock_path)
        rfd = os.open(self.lock_path, os.O_RDONLY | os.O_NONBLOCK)
        self.addCleanup(os.close, rfd)
        start = time.monotonic()
        with self.assertLogs("core.run.metadata", level="WARNING") as logs:
            with _metadata_lock(self.meta_path):
                pass
        self.assertLess(time.monotonic() - start, 2.0)
        self.assertTrue(any("not a regular file" in m for m in logs.output))

    def test_regular_lock_flow_stays_silent_and_locks(self):
        import fcntl
        import os

        from core.run.metadata import _metadata_lock
        with _metadata_lock(self.meta_path):
            self.assertTrue(self.lock_path.is_file())
            # A second would-be locker cannot take the flock while the
            # window is held.
            fd = os.open(self.lock_path, os.O_WRONLY)
            try:
                with self.assertRaises(BlockingIOError):
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            finally:
                os.close(fd)


class MetadataReaderTreeClosureTest(unittest.TestCase):
    """Tree-wide widening of the module-scoped budget oracle above.

    The module-scoped oracle (`inspect.getsource(core.run.metadata)`)
    structurally cannot see readers of the SAME sandbox-writable file
    in sibling packages — and they re-grew: sweep, CLI, sessions, and
    rename readers all loaded `.raptor-run.json` bare. Derive the
    reader set mechanically instead: every function in core/project +
    core/run + core/coverage whose source names the metadata file
    (RUN_METADATA_FILE or the literal) must pass ``max_bytes=`` on
    each load_json call inside it, or route through
    _load_meta/load_run_metadata. Heuristic residual (documented): a
    reader that builds the path in one function and loads it in
    another, or reads via read_text, is outside this derivation —
    the per-member behaviour tests carry those.
    """

    def test_metadata_file_readers_carry_a_budget(self):
        import ast

        repo = Path(__file__).resolve().parents[3]
        markers = ("RUN_METADATA_FILE", ".raptor-run.json")
        offenders: list[str] = []
        for pkg in ("core/project", "core/run", "core/coverage"):
            for py in sorted((repo / pkg).rglob("*.py")):
                if "tests" in py.parts or py.name.startswith("test_"):
                    continue
                src = py.read_text(encoding="utf-8")
                if not any(m in src for m in markers):
                    continue
                tree = ast.parse(src)
                for fn in ast.walk(tree):
                    if not isinstance(fn, (ast.FunctionDef,
                                           ast.AsyncFunctionDef)):
                        continue
                    if fn.name in ("_load_meta", "load_run_metadata"):
                        continue  # the budgeted loaders themselves
                    fsrc = ast.get_source_segment(src, fn) or ""
                    if not any(m in fsrc for m in markers):
                        continue
                    for node in ast.walk(fn):
                        if not isinstance(node, ast.Call):
                            continue
                        name = ""
                        if isinstance(node.func, ast.Name):
                            name = node.func.id
                        elif isinstance(node.func, ast.Attribute):
                            name = node.func.attr
                        if name not in ("load_json", "_lj"):
                            continue
                        if any(k.arg == "max_bytes"
                               for k in node.keywords):
                            continue
                        arg = (ast.get_source_segment(src, node.args[0])
                               if node.args else "") or ""
                        offenders.append(
                            f"{py.relative_to(repo)}:{node.lineno} "
                            f"{fn.name}() load_json({arg[:60]})")
        self.assertEqual(
            offenders, [],
            "bare load_json inside a metadata-file-reading function — "
            "route through _load_meta/load_run_metadata or pass "
            f"max_bytes: {offenders}")

    def test_oracle_is_not_vacuous(self):
        # Two-direction guard: the derivation must actually see the
        # known reader set (sweep + gate homes at minimum).
        import ast

        repo = Path(__file__).resolve().parents[3]
        seen = set()
        markers = ("RUN_METADATA_FILE", ".raptor-run.json")
        for pkg in ("core/project", "core/run", "core/coverage"):
            for py in sorted((repo / pkg).rglob("*.py")):
                if "tests" in py.parts or py.name.startswith("test_"):
                    continue
                src = py.read_text(encoding="utf-8")
                if not any(m in src for m in markers):
                    continue
                tree = ast.parse(src)
                for fn in ast.walk(tree):
                    if isinstance(fn, (ast.FunctionDef,
                                       ast.AsyncFunctionDef)):
                        fsrc = ast.get_source_segment(src, fn) or ""
                        if any(m in fsrc for m in markers):
                            seen.add((py.name, fn.name))
        self.assertIn(("project.py", "_sweep_stale"), seen)
        self.assertIn(("metadata.py", "_live_conflicting_run"), seen)
        self.assertGreater(len(seen), 10)


class UpdateStatusUnreadableMarkerTest(unittest.TestCase):
    """A marker that EXISTS but fails the budgeted read must refuse
    with the malformed-on-disk contract (ValueError), not claim the
    file is missing — the FileNotFoundError misled callers that had
    just enumerated it."""

    def test_oversize_marker_raises_value_error(self):
        import json as _json

        from core.run.metadata import _update_status
        with TemporaryDirectory() as d:
            run = Path(d)
            (run / RUN_METADATA_FILE).write_text(_json.dumps({
                "status": "running",
                "pad": "A" * (2 * 1024 * 1024),
            }), encoding="utf-8")
            with self.assertRaises(ValueError):
                _update_status(run, "failed")

    def test_missing_marker_still_file_not_found(self):
        from core.run.metadata import _update_status
        with TemporaryDirectory() as d:
            with self.assertRaises(FileNotFoundError):
                _update_status(Path(d), "failed")
