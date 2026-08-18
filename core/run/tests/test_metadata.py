"""Tests for run metadata lifecycle."""

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from core.json import load_json
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

        stack = contextlib.ExitStack()
        stack.enter_context(mock.patch.object(sys, "platform", "linux"))
        stack.enter_context(mock.patch.object(md.os, "getpid",
                                              lambda: self_pid))
        stack.enter_context(mock.patch.object(md.os, "getppid",
                                              lambda: parents[self_pid]))
        stack.enter_context(mock.patch.object(md, "_read_ppid",
                                              _fake_read_ppid))
        stack.enter_context(mock.patch.object(md, "Path", _path_factory))
        return stack

    # pid 100 (test) -> 50 (bash) -> 40 (claude) -> 1 (init)
    _TREE = {100: 50, 50: 40, 40: 1}
    _COMMS = {50: "bash", 40: "claude"}

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


class TestRunCoverageSnapshot(unittest.TestCase):
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
            start_run(run, "scan")
            (run / "coverage-semgrep.json").write_text(json.dumps(
                {"tool": "semgrep", "files_examined": ["a.c"], "timestamp": "t"}))
            (run / "findings.json").write_text(json.dumps(
                [{"id": "F1", "file": "a.c", "line": 10, "rule_id": "x"}]))
            complete_run(run)

            store = CoverageStore(proj / "coverage.json")    # persisted at completion
            self.assertEqual(store.who_checked("a.c", 10), ["semgrep"])
            self.assertEqual(store.function_verdict("a.c", 1, 20), "open")  # F1 in f1

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

    def test_standalone_run_writes_no_store(self):
        import json
        with TemporaryDirectory() as d:
            out = Path(d) / "out"
            out.mkdir()
            run = out / "scan-20260526_120000"
            start_run(run, "scan")
            (run / "coverage-semgrep.json").write_text(json.dumps(
                {"tool": "semgrep", "files_examined": ["a.c"], "timestamp": "t"}))
            complete_run(run)
            # No project-level checklist in the parent -> no durable store written.
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
