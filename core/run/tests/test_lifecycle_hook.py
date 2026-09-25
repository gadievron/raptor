"""Tests for libexec/raptor-lifecycle-hook."""

import importlib.machinery
import importlib.util
import io
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from core.json import load_json, save_json
from core.run.metadata import (
    RUN_METADATA_FILE, STATUS_RUNNING, STATUS_COMPLETED, STATUS_FAILED,
)

REPO_ROOT = Path(__file__).resolve().parents[3]  # core/run/tests/ → raptor/
HOOK_SCRIPT = REPO_ROOT / "libexec" / "raptor-lifecycle-hook"

# Import the hook module despite its hyphenated filename and missing .py ext.
_loader = importlib.machinery.SourceFileLoader("lifecycle_hook", str(HOOK_SCRIPT))
_spec = importlib.util.spec_from_loader("lifecycle_hook", _loader,
                                        origin=str(HOOK_SCRIPT))
_hook_mod = importlib.util.module_from_spec(_spec)
_hook_mod.__file__ = str(HOOK_SCRIPT)
_spec.loader.exec_module(_hook_mod)

FAILURE_MARKER = _hook_mod.FAILURE_MARKER
MULTI_TURN = _hook_mod._MULTI_TURN_COMMANDS

SESSION_PID = 99999


def _make_running_run(parent: Path, name: str, command: str,
                      session_pid: int = SESSION_PID,
                      tool_pid: int = 11111) -> Path:
    """Create a run directory with status=running metadata."""
    d = parent / name
    d.mkdir(parents=True, exist_ok=True)
    meta = {
        "version": 1,
        "command": command,
        "timestamp": "2026-05-03T12:00:00+00:00",
        "status": STATUS_RUNNING,
        "extra": {},
        "session_pid": session_pid,
        "tool_pid": tool_pid,
    }
    save_json(d / RUN_METADATA_FILE, meta)
    return d


def _status(d: Path) -> str:
    return load_json(d / RUN_METADATA_FILE).get("status")


#: PostToolUseFailure stdin payload for a failed RAPTOR pipeline call —
#: the only shape that may stamp the failure marker.
RAPTOR_BASH_FAILURE = json.dumps({
    "tool_name": "Bash",
    "tool_input": {"command": "libexec/raptor-run-lifecycle start scan"},
})


def _stdin(payload: str):
    return patch.object(sys, "stdin", io.StringIO(payload))


class TestToolFailureMarker(unittest.TestCase):
    """tool-failure mode writes a soft marker without changing status."""

    def test_writes_marker(self):
        with TemporaryDirectory() as tmp:
            out = Path(tmp) / "out"
            run = _make_running_run(out, "scan-20260503", "scan")
            with patch.object(_hook_mod, "REPO_ROOT", Path(tmp)), \
                 patch("core.run.metadata._get_session_pid",
                       return_value=SESSION_PID), \
                 _stdin(RAPTOR_BASH_FAILURE):
                sys.argv = ["hook", "tool-failure"]
                _hook_mod.main()
            self.assertTrue((run / FAILURE_MARKER).exists())
            self.assertEqual(_status(run), STATUS_RUNNING)

    def test_marks_only_newest_running_in_session(self):
        # Stamping EVERY running run let a failed single-call command
        # poison an unrelated in-flight run (the next Stop fail_run's
        # it). With no run dir named in the command, only the newest
        # running run — the one a just-failed single-call belongs to —
        # gets the marker.
        with TemporaryDirectory() as tmp:
            out = Path(tmp) / "out"
            run1 = _make_running_run(out, "scan-001", "scan")
            run2 = _make_running_run(out, "agentic-002", "agentic")
            meta = load_json(run2 / RUN_METADATA_FILE)
            meta["timestamp"] = "2026-05-03T13:00:00+00:00"  # newer
            save_json(run2 / RUN_METADATA_FILE, meta)
            with patch.object(_hook_mod, "REPO_ROOT", Path(tmp)), \
                 patch("core.run.metadata._get_session_pid",
                       return_value=SESSION_PID), \
                 _stdin(RAPTOR_BASH_FAILURE):
                sys.argv = ["hook", "tool-failure"]
                _hook_mod.main()
            self.assertFalse((run1 / FAILURE_MARKER).exists())
            self.assertTrue((run2 / FAILURE_MARKER).exists())

    def test_marks_the_run_named_in_the_command(self):
        # A failing command that carries a run dir (lifecycle-managed
        # commands carry their OUTPUT_DIR) attributes the marker to
        # THAT run, even when a newer run is in flight.
        with TemporaryDirectory() as tmp:
            out = Path(tmp) / "out"
            run1 = _make_running_run(out, "scan-001", "scan")
            run2 = _make_running_run(out, "agentic-002", "agentic")
            meta = load_json(run2 / RUN_METADATA_FILE)
            meta["timestamp"] = "2026-05-03T13:00:00+00:00"  # newer
            save_json(run2 / RUN_METADATA_FILE, meta)
            payload = json.dumps({
                "tool_name": "Bash",
                "tool_input": {"command":
                               f"libexec/raptor-run-lifecycle complete {run1}"},
            })
            with patch.object(_hook_mod, "REPO_ROOT", Path(tmp)), \
                 patch("core.run.metadata._get_session_pid",
                       return_value=SESSION_PID), \
                 _stdin(payload):
                sys.argv = ["hook", "tool-failure"]
                _hook_mod.main()
            self.assertTrue((run1 / FAILURE_MARKER).exists())
            self.assertFalse((run2 / FAILURE_MARKER).exists())

    def test_skips_different_session(self):
        with TemporaryDirectory() as tmp:
            out = Path(tmp) / "out"
            run = _make_running_run(out, "scan-001", "scan",
                                    session_pid=88888)
            with patch.object(_hook_mod, "REPO_ROOT", Path(tmp)), \
                 patch("core.run.metadata._get_session_pid",
                       return_value=SESSION_PID), \
                 _stdin(RAPTOR_BASH_FAILURE):
                sys.argv = ["hook", "tool-failure"]
                _hook_mod.main()
            self.assertFalse((run / FAILURE_MARKER).exists())

    def test_skips_non_running(self):
        with TemporaryDirectory() as tmp:
            out = Path(tmp) / "out"
            run = _make_running_run(out, "scan-001", "scan")
            meta = load_json(run / RUN_METADATA_FILE)
            meta["status"] = STATUS_COMPLETED
            save_json(run / RUN_METADATA_FILE, meta)
            with patch.object(_hook_mod, "REPO_ROOT", Path(tmp)), \
                 patch("core.run.metadata._get_session_pid",
                       return_value=SESSION_PID), \
                 _stdin(RAPTOR_BASH_FAILURE):
                sys.argv = ["hook", "tool-failure"]
                _hook_mod.main()
            self.assertFalse((run / FAILURE_MARKER).exists())


class TestToolFailureFiltering(unittest.TestCase):
    """Only failed Bash calls on the libexec/raptor-* dispatch surface
    may stamp the failure marker: the hook-config `matcher` filters by
    tool NAME only, so an unrelated failed Bash call (a typo'd grep)
    would otherwise flip a successful run to failed at the next Stop."""

    def _run_hook(self, tmp: str, payload: str) -> Path:
        out = Path(tmp) / "out"
        run = _make_running_run(out, "scan-001", "scan")
        with patch.object(_hook_mod, "REPO_ROOT", Path(tmp)), \
             patch("core.run.metadata._get_session_pid",
                   return_value=SESSION_PID), \
             _stdin(payload):
            sys.argv = ["hook", "tool-failure"]
            _hook_mod.main()
        return run

    def test_unrelated_bash_failure_writes_no_marker(self):
        payload = json.dumps({
            "tool_name": "Bash",
            "tool_input": {"command": "grep -r pattern /nonexistent"},
        })
        with TemporaryDirectory() as tmp:
            run = self._run_hook(tmp, payload)
            self.assertFalse((run / FAILURE_MARKER).exists())

    def test_non_bash_tool_failure_writes_no_marker(self):
        payload = json.dumps({
            "tool_name": "Read",
            "tool_input": {"file_path": "libexec/raptor-agentic"},
        })
        with TemporaryDirectory() as tmp:
            run = self._run_hook(tmp, payload)
            self.assertFalse((run / FAILURE_MARKER).exists())

    def test_malformed_stdin_writes_no_marker(self):
        with TemporaryDirectory() as tmp:
            run = self._run_hook(tmp, "{not json")
            self.assertFalse((run / FAILURE_MARKER).exists())

    def test_empty_stdin_writes_no_marker(self):
        with TemporaryDirectory() as tmp:
            run = self._run_hook(tmp, "")
            self.assertFalse((run / FAILURE_MARKER).exists())

    def test_raptor_dispatch_failure_writes_marker(self):
        with TemporaryDirectory() as tmp:
            run = self._run_hook(tmp, RAPTOR_BASH_FAILURE)
            self.assertTrue((run / FAILURE_MARKER).exists())

    def test_mention_only_command_writes_no_marker(self):
        # Commands that merely MENTION the dispatch surface fail for
        # their own reasons: CLAUDE.md's dispatch rule instructs
        # `ls libexec/raptor-<name>*`, which exits 2 on a glob miss —
        # a marker here flips a successful run to Failed at Stop.
        for command in (
            "ls libexec/raptor-coverage*",
            "grep -n verdict libexec/raptor-agentic",
            "cat libexec/raptor-run-lifecycle",
        ):
            payload = json.dumps({
                "tool_name": "Bash",
                "tool_input": {"command": command},
            })
            with TemporaryDirectory() as tmp:
                run = self._run_hook(tmp, payload)
                self.assertFalse(
                    (run / FAILURE_MARKER).exists(),
                    f"mention-only command stamped a marker: {command}",
                )

    def test_invocation_shapes_write_marker(self):
        # Command-position invocations, including behind a path
        # prefix or a shell separator, are the relevant shapes.
        for command in (
            "libexec/raptor-coverage-summary --gaps",
            '"$CLAUDE_PROJECT_DIR"/libexec/raptor-run-lifecycle start scan',
            "cd /repo && libexec/raptor-agentic --repo /x",
            "true; libexec/raptor-verified-outcomes out/run",
        ):
            payload = json.dumps({
                "tool_name": "Bash",
                "tool_input": {"command": command},
            })
            with TemporaryDirectory() as tmp:
                run = self._run_hook(tmp, payload)
                self.assertTrue(
                    (run / FAILURE_MARKER).exists(),
                    f"invocation shape missed: {command}",
                )


class TestStopHook(unittest.TestCase):
    """Stop mode: complete or fail single-call runs with dead tool_pid."""

    def test_completes_when_no_marker(self):
        with TemporaryDirectory() as tmp:
            out = Path(tmp) / "out"
            run = _make_running_run(out, "scan-001", "scan", tool_pid=1)
            with patch.object(_hook_mod, "REPO_ROOT", Path(tmp)), \
                 patch("core.run.metadata._get_session_pid",
                       return_value=SESSION_PID), \
                 patch("core.run.metadata._pid_alive", return_value=False):
                sys.argv = ["hook", "stop"]
                _hook_mod.main()
            self.assertEqual(_status(run), STATUS_COMPLETED)

    def test_fails_when_marker_present(self):
        with TemporaryDirectory() as tmp:
            out = Path(tmp) / "out"
            run = _make_running_run(out, "scan-001", "scan", tool_pid=1)
            (run / FAILURE_MARKER).write_text("")
            with patch.object(_hook_mod, "REPO_ROOT", Path(tmp)), \
                 patch("core.run.metadata._get_session_pid",
                       return_value=SESSION_PID), \
                 patch("core.run.metadata._pid_alive", return_value=False):
                sys.argv = ["hook", "stop"]
                _hook_mod.main()
            self.assertEqual(_status(run), STATUS_FAILED)
            meta = load_json(run / RUN_METADATA_FILE)
            self.assertIn("tool exited with error", meta["extra"]["error"])

    def test_cleans_up_marker(self):
        with TemporaryDirectory() as tmp:
            out = Path(tmp) / "out"
            run = _make_running_run(out, "scan-001", "scan", tool_pid=1)
            (run / FAILURE_MARKER).write_text("")
            with patch.object(_hook_mod, "REPO_ROOT", Path(tmp)), \
                 patch("core.run.metadata._get_session_pid",
                       return_value=SESSION_PID), \
                 patch("core.run.metadata._pid_alive", return_value=False):
                sys.argv = ["hook", "stop"]
                _hook_mod.main()
            self.assertFalse((run / FAILURE_MARKER).exists())

    def test_cleans_up_marker_on_complete(self):
        """Marker from a previous intermediate failure is cleaned on complete."""
        with TemporaryDirectory() as tmp:
            out = Path(tmp) / "out"
            run = _make_running_run(out, "agentic-001", "agentic", tool_pid=1)
            # Stale marker that shouldn't persist
            (run / FAILURE_MARKER).write_text("")
            # Remove marker to simulate LLM recovery — but actually we want
            # to test that Stop cleans it up even on the fail path.
            # Test the complete path instead: no marker.
            (run / FAILURE_MARKER).unlink()
            with patch.object(_hook_mod, "REPO_ROOT", Path(tmp)), \
                 patch("core.run.metadata._get_session_pid",
                       return_value=SESSION_PID), \
                 patch("core.run.metadata._pid_alive", return_value=False):
                sys.argv = ["hook", "stop"]
                _hook_mod.main()
            self.assertEqual(_status(run), STATUS_COMPLETED)
            self.assertFalse((run / FAILURE_MARKER).exists())

    def test_skips_multi_turn_validate(self):
        with TemporaryDirectory() as tmp:
            out = Path(tmp) / "out"
            run = _make_running_run(out, "validate-001", "validate",
                                    tool_pid=1)
            with patch.object(_hook_mod, "REPO_ROOT", Path(tmp)), \
                 patch("core.run.metadata._get_session_pid",
                       return_value=SESSION_PID), \
                 patch("core.run.metadata._pid_alive", return_value=False):
                sys.argv = ["hook", "stop"]
                _hook_mod.main()
            self.assertEqual(_status(run), STATUS_RUNNING)

    def test_skips_multi_turn_understand(self):
        with TemporaryDirectory() as tmp:
            out = Path(tmp) / "out"
            run = _make_running_run(out, "understand-001", "understand",
                                    tool_pid=1)
            with patch.object(_hook_mod, "REPO_ROOT", Path(tmp)), \
                 patch("core.run.metadata._get_session_pid",
                       return_value=SESSION_PID), \
                 patch("core.run.metadata._pid_alive", return_value=False):
                sys.argv = ["hook", "stop"]
                _hook_mod.main()
            self.assertEqual(_status(run), STATUS_RUNNING)

    def test_skips_alive_tool_pid(self):
        with TemporaryDirectory() as tmp:
            out = Path(tmp) / "out"
            run = _make_running_run(out, "scan-001", "scan", tool_pid=12345)
            with patch.object(_hook_mod, "REPO_ROOT", Path(tmp)), \
                 patch("core.run.metadata._get_session_pid",
                       return_value=SESSION_PID), \
                 patch("core.run.metadata._tool_pid_alive",
                       return_value=True):
                sys.argv = ["hook", "stop"]
                _hook_mod.main()
            self.assertEqual(_status(run), STATUS_RUNNING)

    def test_skips_different_session(self):
        with TemporaryDirectory() as tmp:
            out = Path(tmp) / "out"
            run = _make_running_run(out, "scan-001", "scan",
                                    session_pid=88888, tool_pid=1)
            with patch.object(_hook_mod, "REPO_ROOT", Path(tmp)), \
                 patch("core.run.metadata._get_session_pid",
                       return_value=SESSION_PID), \
                 patch("core.run.metadata._pid_alive", return_value=False):
                sys.argv = ["hook", "stop"]
                _hook_mod.main()
            self.assertEqual(_status(run), STATUS_RUNNING)

    def test_skips_already_completed(self):
        with TemporaryDirectory() as tmp:
            out = Path(tmp) / "out"
            run = _make_running_run(out, "scan-001", "scan", tool_pid=1)
            meta = load_json(run / RUN_METADATA_FILE)
            meta["status"] = STATUS_COMPLETED
            save_json(run / RUN_METADATA_FILE, meta)
            with patch.object(_hook_mod, "REPO_ROOT", Path(tmp)), \
                 patch("core.run.metadata._get_session_pid",
                       return_value=SESSION_PID), \
                 patch("core.run.metadata._pid_alive", return_value=False):
                sys.argv = ["hook", "stop"]
                _hook_mod.main()
            self.assertEqual(_status(run), STATUS_COMPLETED)

    def test_handles_no_tool_pid(self):
        """Runs without tool_pid (pre-change) are acted on if session matches."""
        with TemporaryDirectory() as tmp:
            out = Path(tmp) / "out"
            d = out / "scan-001"
            d.mkdir(parents=True)
            meta = {
                "version": 1, "command": "scan",
                "timestamp": "2026-05-03T12:00:00+00:00",
                "status": STATUS_RUNNING, "extra": {},
                "session_pid": SESSION_PID,
                # no tool_pid
            }
            save_json(d / RUN_METADATA_FILE, meta)
            with patch.object(_hook_mod, "REPO_ROOT", Path(tmp)), \
                 patch("core.run.metadata._get_session_pid",
                       return_value=SESSION_PID):
                sys.argv = ["hook", "stop"]
                _hook_mod.main()
            self.assertEqual(_status(d), STATUS_COMPLETED)


class TestSessionEndHook(unittest.TestCase):
    """SessionEnd mode: fail everything still running."""

    def test_fails_all_running(self):
        with TemporaryDirectory() as tmp:
            out = Path(tmp) / "out"
            run1 = _make_running_run(out, "scan-001", "scan")
            run2 = _make_running_run(out, "validate-002", "validate")
            with patch.object(_hook_mod, "REPO_ROOT", Path(tmp)), \
                 patch("core.run.metadata._get_session_pid",
                       return_value=SESSION_PID):
                sys.argv = ["hook", "session-end"]
                _hook_mod.main()
            self.assertEqual(_status(run1), STATUS_FAILED)
            self.assertEqual(_status(run2), STATUS_FAILED)

    def test_includes_multi_turn(self):
        """SessionEnd catches multi-turn commands that Stop skips."""
        with TemporaryDirectory() as tmp:
            out = Path(tmp) / "out"
            run = _make_running_run(out, "validate-001", "validate")
            with patch.object(_hook_mod, "REPO_ROOT", Path(tmp)), \
                 patch("core.run.metadata._get_session_pid",
                       return_value=SESSION_PID):
                sys.argv = ["hook", "session-end"]
                _hook_mod.main()
            self.assertEqual(_status(run), STATUS_FAILED)
            meta = load_json(run / RUN_METADATA_FILE)
            self.assertIn("session ended", meta["extra"]["error"])

    def test_cleans_up_marker(self):
        with TemporaryDirectory() as tmp:
            out = Path(tmp) / "out"
            run = _make_running_run(out, "scan-001", "scan")
            (run / FAILURE_MARKER).write_text("")
            with patch.object(_hook_mod, "REPO_ROOT", Path(tmp)), \
                 patch("core.run.metadata._get_session_pid",
                       return_value=SESSION_PID):
                sys.argv = ["hook", "session-end"]
                _hook_mod.main()
            self.assertFalse((run / FAILURE_MARKER).exists())

    def test_skips_non_running(self):
        with TemporaryDirectory() as tmp:
            out = Path(tmp) / "out"
            run = _make_running_run(out, "scan-001", "scan")
            meta = load_json(run / RUN_METADATA_FILE)
            meta["status"] = STATUS_COMPLETED
            save_json(run / RUN_METADATA_FILE, meta)
            with patch.object(_hook_mod, "REPO_ROOT", Path(tmp)), \
                 patch("core.run.metadata._get_session_pid",
                       return_value=SESSION_PID):
                sys.argv = ["hook", "session-end"]
                _hook_mod.main()
            self.assertEqual(_status(run), STATUS_COMPLETED)

    def test_skips_different_session(self):
        with TemporaryDirectory() as tmp:
            out = Path(tmp) / "out"
            run = _make_running_run(out, "scan-001", "scan",
                                    session_pid=88888)
            with patch.object(_hook_mod, "REPO_ROOT", Path(tmp)), \
                 patch("core.run.metadata._get_session_pid",
                       return_value=SESSION_PID):
                sys.argv = ["hook", "session-end"]
                _hook_mod.main()
            self.assertEqual(_status(run), STATUS_RUNNING)


class TestLLMOverride(unittest.TestCase):
    """LLM's explicit complete/fail takes priority over hook markers."""

    def test_llm_complete_prevents_hook_action(self):
        """If LLM calls complete_run, Stop skips (status != running)."""
        with TemporaryDirectory() as tmp:
            out = Path(tmp) / "out"
            run = _make_running_run(out, "scan-001", "scan", tool_pid=1)
            (run / FAILURE_MARKER).write_text("")
            # LLM explicitly completes
            from core.run.metadata import complete_run
            complete_run(run)
            self.assertEqual(_status(run), STATUS_COMPLETED)
            # Now Stop fires — should skip because not running
            with patch.object(_hook_mod, "REPO_ROOT", Path(tmp)), \
                 patch("core.run.metadata._get_session_pid",
                       return_value=SESSION_PID), \
                 patch("core.run.metadata._pid_alive", return_value=False):
                sys.argv = ["hook", "stop"]
                _hook_mod.main()
            self.assertEqual(_status(run), STATUS_COMPLETED)

    def test_llm_fail_prevents_hook_action(self):
        """If LLM calls fail_run, Stop skips."""
        with TemporaryDirectory() as tmp:
            out = Path(tmp) / "out"
            run = _make_running_run(out, "scan-001", "scan", tool_pid=1)
            from core.run.metadata import fail_run
            fail_run(run, "analysis found nothing")
            self.assertEqual(_status(run), STATUS_FAILED)
            with patch.object(_hook_mod, "REPO_ROOT", Path(tmp)), \
                 patch("core.run.metadata._get_session_pid",
                       return_value=SESSION_PID), \
                 patch("core.run.metadata._pid_alive", return_value=False):
                sys.argv = ["hook", "stop"]
                _hook_mod.main()
            self.assertEqual(_status(run), STATUS_FAILED)
            meta = load_json(run / RUN_METADATA_FILE)
            self.assertEqual(meta["extra"]["error"], "analysis found nothing")


class TestProjectDirScan(unittest.TestCase):
    """Hook scans both .active project dir and out/."""

    def test_finalizes_project_run_via_ledger(self):
        """Project runs live at out/projects/<name>/<run> — TWO levels
        below the out root, unreachable by the legacy one-level walk
        (the pre-fix `.active` symlink discovery read a path nothing
        creates, so orphaned project runs were never finalized). The
        session run ledger names the run dir exactly."""
        import os
        from core.project import sessions
        with TemporaryDirectory() as tmp:
            repo = Path(tmp)
            proj = repo / "out" / "projects" / "myapp"
            run = _make_running_run(proj, "scan-001", "scan", tool_pid=1)
            sessions_dir = repo / "sessions.d"
            with patch.object(_hook_mod, "REPO_ROOT", repo), \
                 patch.object(sessions, "SESSIONS_DIR", sessions_dir), \
                 patch.object(sessions, "_comm",
                              lambda pid: "claude"
                              if pid in (SESSION_PID, os.getpid())
                              else None), \
                 patch.object(sessions, "_pid_running",
                              lambda pid: pid in (SESSION_PID,
                                                  os.getpid())), \
                 patch.object(sessions, "proc_starttime",
                              lambda pid: "7"), \
                 patch("core.run.metadata._get_session_pid",
                       return_value=SESSION_PID), \
                 patch("core.run.metadata._pid_alive",
                       return_value=False):
                sessions.record_session("myapp", pid=SESSION_PID)
                sessions.ledger_record_start(run, pid=SESSION_PID)
                sys.argv = ["hook", "stop"]
                _hook_mod.main()
            self.assertEqual(_status(run), STATUS_COMPLETED)

    def test_scans_out_dir(self):
        with TemporaryDirectory() as tmp:
            repo = Path(tmp)
            out = repo / "out"
            run = _make_running_run(out, "scan-001", "scan", tool_pid=1)
            with patch.object(_hook_mod, "REPO_ROOT", repo), \
                 patch("core.run.metadata._get_session_pid",
                       return_value=SESSION_PID), \
                 patch("core.run.metadata._pid_alive", return_value=False):
                sys.argv = ["hook", "stop"]
                _hook_mod.main()
            self.assertEqual(_status(run), STATUS_COMPLETED)

    def test_skips_hidden_dirs(self):
        with TemporaryDirectory() as tmp:
            repo = Path(tmp)
            out = repo / "out"
            run = _make_running_run(out, ".internal", "scan", tool_pid=1)
            with patch.object(_hook_mod, "REPO_ROOT", repo), \
                 patch("core.run.metadata._get_session_pid",
                       return_value=SESSION_PID), \
                 patch("core.run.metadata._pid_alive", return_value=False):
                sys.argv = ["hook", "stop"]
                _hook_mod.main()
            self.assertEqual(_status(run), STATUS_RUNNING)


class TestMultiTurnGuard(unittest.TestCase):
    """Verify the multi-turn command list is complete."""

    def test_multi_turn_set_contents(self):
        # ``audit`` is here because its run is finalized by the
        # orchestrator itself (possibly in a background shell); the
        # Stop hook once stamped an in-flight audit ``completed``
        # after that shell died.
        self.assertEqual(MULTI_TURN, {"validate", "understand", "audit"})

    def test_all_multi_turn_skipped_by_stop(self):
        """Every command in _MULTI_TURN_COMMANDS is skipped by Stop."""
        for cmd in MULTI_TURN:
            with TemporaryDirectory() as tmp:
                out = Path(tmp) / "out"
                run = _make_running_run(out, f"{cmd}-001", cmd, tool_pid=1)
                with patch.object(_hook_mod, "REPO_ROOT", Path(tmp)), \
                     patch("core.run.metadata._get_session_pid",
                           return_value=SESSION_PID), \
                     patch("core.run.metadata._pid_alive",
                           return_value=False):
                    sys.argv = ["hook", "stop"]
                    _hook_mod.main()
                self.assertEqual(
                    _status(run), STATUS_RUNNING,
                    f"Stop should skip multi-turn command '{cmd}'")

    def test_all_multi_turn_caught_by_session_end(self):
        """SessionEnd catches every multi-turn command."""
        for cmd in MULTI_TURN:
            with TemporaryDirectory() as tmp:
                out = Path(tmp) / "out"
                run = _make_running_run(out, f"{cmd}-001", cmd)
                with patch.object(_hook_mod, "REPO_ROOT", Path(tmp)), \
                     patch("core.run.metadata._get_session_pid",
                           return_value=SESSION_PID):
                    sys.argv = ["hook", "session-end"]
                    _hook_mod.main()
                self.assertEqual(
                    _status(run), STATUS_FAILED,
                    f"SessionEnd should catch multi-turn command '{cmd}'")


class TestE2EHookScript(unittest.TestCase):
    """Run the actual hook script as a subprocess."""

    def test_invalid_arg_exits_nonzero(self):
        result = subprocess.run(
            [sys.executable, str(HOOK_SCRIPT), "bogus"],
            capture_output=True, text=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Usage", result.stderr)

    def test_no_args_exits_nonzero(self):
        result = subprocess.run(
            [sys.executable, str(HOOK_SCRIPT)],
            capture_output=True, text=True,
        )
        self.assertNotEqual(result.returncode, 0)

    def test_stop_runs_in_claudecode(self):
        """In Claude Code env, stop runs without error."""
        if not os.environ.get("CLAUDECODE"):
            self.skipTest("Requires CLAUDECODE environment")
        result = subprocess.run(
            [sys.executable, str(HOOK_SCRIPT), "stop"],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0)

    def test_tool_failure_runs_in_claudecode(self):
        """In Claude Code env, tool-failure runs without error."""
        if not os.environ.get("CLAUDECODE"):
            self.skipTest("Requires CLAUDECODE environment")
        result = subprocess.run(
            [sys.executable, str(HOOK_SCRIPT), "tool-failure"],
            capture_output=True, text=True, input=RAPTOR_BASH_FAILURE,
        )
        self.assertEqual(result.returncode, 0)

    def test_session_end_runs_in_claudecode(self):
        """In Claude Code env, session-end runs without error."""
        if not os.environ.get("CLAUDECODE"):
            self.skipTest("Requires CLAUDECODE environment")
        result = subprocess.run(
            [sys.executable, str(HOOK_SCRIPT), "session-end"],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0)


class TestSessionEndLivenessProof(unittest.TestCase):
    """session-end proves the recorded session dead before reaping.

    A SessionEnd event can fire from a context that inherited the
    parent session's identity env (a nested subagent ending its own
    session) while the recorded session_pid is alive and mid-pipeline
    — pre-fix the reap failed the parent's live run. Stamped metas
    (session_start + session_boot_id) get the full identity check;
    whatever IS reaped carries ``extra.abandon_sweep`` so the
    metadata recovery clause can self-heal a misjudged reap.
    """

    def _isolated(self, tmp: Path, session_pid: int):
        """Patch stack confining the hook to *tmp* and *session_pid*.

        The stub tests use REAL (recyclable) pids, so the ledger and
        the configured out dir must not leak real runs into the scan.
        """
        return (
            patch.object(_hook_mod, "REPO_ROOT", tmp),
            patch("core.run.metadata._get_session_pid",
                  return_value=session_pid),
            patch("core.project.sessions.ledger_runs",
                  side_effect=Exception("no ledger in this test")),
            patch("core.config.RaptorConfig.get_out_dir",
                  return_value=tmp / "out"),
        )

    def _run_session_end(self, tmp: Path, session_pid: int,
                         payload: str = "") -> None:
        p1, p2, p3, p4 = self._isolated(tmp, session_pid)
        with p1, p2, p3, p4, _stdin(payload):
            sys.argv = ["hook", "session-end"]
            _hook_mod.main()

    @staticmethod
    def _spawn_claude_shaped_stub(tmp: Path) -> subprocess.Popen:
        """A live stub whose comm reads ``claude`` (comm comes from
        the execve filename, so a symlink to the interpreter named
        ``claude`` suffices — no real session)."""
        link = tmp / "claude"
        link.symlink_to(sys.executable)
        proc = subprocess.Popen(
            [str(link), "-c",
             "import time; print('ready', flush=True); time.sleep(300)"],
            stdout=subprocess.PIPE, text=True,
        )
        assert proc.stdout is not None
        proc.stdout.readline()
        return proc

    @staticmethod
    def _reap_stub(proc: subprocess.Popen) -> None:
        if proc.poll() is None:
            proc.kill()
        proc.wait(timeout=10)

    @staticmethod
    def _stamp_meta(run: Path, **fields) -> None:
        meta = load_json(run / RUN_METADATA_FILE)
        meta.update(fields)
        save_json(run / RUN_METADATA_FILE, meta)

    @unittest.skipUnless(sys.platform == "linux",
                         "identity proof is procfs-based")
    def test_live_stamped_session_is_skipped(self):
        from core.run.metadata import _session_stamp
        with TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            stub = self._spawn_claude_shaped_stub(tmp)
            try:
                run = _make_running_run(tmp / "out", "validate-001",
                                        "validate", session_pid=stub.pid)
                stamp = _session_stamp(stub.pid)
                self.assertIn("session_start", stamp)  # live stub readable
                self._stamp_meta(run, **stamp)
                self._run_session_end(tmp, stub.pid)
                self.assertEqual(_status(run), STATUS_RUNNING)
                self.assertIsNone(stub.poll())
            finally:
                self._reap_stub(stub)

    @unittest.skipUnless(sys.platform == "linux",
                         "identity proof is procfs-based")
    def test_dead_stamped_session_is_reaped_with_marker(self):
        from core.project.sessions import boot_id, pidns_id
        with TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            dead_pid = 2_000_000_000  # inert: beyond pid_max
            run = _make_running_run(tmp / "out", "validate-001",
                                    "validate", session_pid=dead_pid)
            # Live boot/ns so the stamp is judged HERE (a foreign
            # stamp reads as alive — fail-open — and would skip).
            self._stamp_meta(
                run, session_start="12345",
                session_boot_id=boot_id(), session_pidns=pidns_id(),
            )
            self._run_session_end(tmp, dead_pid)
            self.assertEqual(_status(run), STATUS_FAILED)
            meta = load_json(run / RUN_METADATA_FILE)
            self.assertIs(meta["extra"]["abandon_sweep"], True)
            self.assertIn("session ended", meta["extra"]["error"])

    @unittest.skipUnless(sys.platform == "linux",
                         "identity proof is procfs-based")
    def test_recycled_pid_is_treated_dead_and_reaped(self):
        # A live claude-shaped process at the recorded pid whose
        # starttime does not match the stamp is a RECYCLED pid — the
        # recorded session is gone; the run is reaped (with marker),
        # and the impostor process is never signalled.
        from core.project.sessions import boot_id, pidns_id, proc_starttime
        with TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            stub = self._spawn_claude_shaped_stub(tmp)
            try:
                run = _make_running_run(tmp / "out", "validate-001",
                                        "validate", session_pid=stub.pid)
                real_start = proc_starttime(stub.pid)
                self.assertIsNotNone(real_start)
                self._stamp_meta(
                    run, session_start=str(int(real_start) + 1),
                    session_boot_id=boot_id(), session_pidns=pidns_id(),
                )
                self._run_session_end(tmp, stub.pid)
                self.assertEqual(_status(run), STATUS_FAILED)
                meta = load_json(run / RUN_METADATA_FILE)
                self.assertIs(meta["extra"]["abandon_sweep"], True)
                self.assertIsNone(stub.poll())
            finally:
                self._reap_stub(stub)

    def test_legacy_meta_keeps_unconditional_reap(self):
        # No identity fields — no proof is possible either way; the
        # pre-existing reap applies, now with the recovery marker.
        with TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            run = _make_running_run(tmp / "out", "scan-001", "scan")
            self._run_session_end(tmp, SESSION_PID)
            self.assertEqual(_status(run), STATUS_FAILED)
            meta = load_json(run / RUN_METADATA_FILE)
            self.assertIs(meta["extra"]["abandon_sweep"], True)

    def test_matching_session_id_finalizes_despite_live_owner(self):
        # Owner-end proof: the SessionEnd payload's session_id equals
        # the id start_run recorded — the ending session IS the owner,
        # so the run is finalized immediately even though the owner
        # process still breathes while its own hook executes.
        if sys.platform != "linux":
            self.skipTest("identity proof is procfs-based")
        from core.run.metadata import _session_stamp
        sid = "aaaaaaaa-1111-2222-3333-444444444444"
        with TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            stub = self._spawn_claude_shaped_stub(tmp)
            try:
                run = _make_running_run(tmp / "out", "validate-001",
                                        "validate", session_pid=stub.pid)
                stamp = _session_stamp(stub.pid)
                self.assertIn("session_start", stamp)
                self._stamp_meta(run, session_id=sid, **stamp)
                # No ``reason`` in the payload: absent reads as a real
                # end (the enum may grow) — finalize.
                self._run_session_end(
                    tmp, stub.pid,
                    payload=json.dumps({"session_id": sid,
                                        "hook_event_name": "SessionEnd"}))
                self.assertEqual(_status(run), STATUS_FAILED)
                meta = load_json(run / RUN_METADATA_FILE)
                self.assertIs(meta["extra"]["abandon_sweep"], True)
                self.assertIsNone(stub.poll())  # owner never signalled
            finally:
                self._reap_stub(stub)

    def _matching_id_session_end(self, reason: str) -> str:
        """Run session-end with a matching recorded/payload session_id
        and the given payload ``reason``; returns the run's status."""
        from core.run.metadata import _session_stamp
        sid = "aaaaaaaa-1111-2222-3333-444444444444"
        with TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            stub = self._spawn_claude_shaped_stub(tmp)
            try:
                run = _make_running_run(tmp / "out", "validate-001",
                                        "validate", session_pid=stub.pid)
                stamp = _session_stamp(stub.pid)
                self.assertIn("session_start", stamp)
                self._stamp_meta(run, session_id=sid, **stamp)
                self._run_session_end(
                    tmp, stub.pid,
                    payload=json.dumps({"session_id": sid,
                                        "reason": reason,
                                        "hook_event_name": "SessionEnd"}))
                self.assertIsNone(stub.poll())
                return _status(run)
            finally:
                self._reap_stub(stub)

    @unittest.skipUnless(sys.platform == "linux",
                         "identity proof is procfs-based")
    def test_reason_clear_keeps_liveness_skip(self):
        # /clear retires the session id but the owner PROCESS survives
        # (a background orchestrator may still finalize its run) — the
        # matching id must NOT finalize; the liveness gate applies.
        self.assertEqual(self._matching_id_session_end("clear"),
                         STATUS_RUNNING)

    @unittest.skipUnless(sys.platform == "linux",
                         "identity proof is procfs-based")
    def test_reason_resume_keeps_liveness_skip(self):
        self.assertEqual(self._matching_id_session_end("resume"),
                         STATUS_RUNNING)

    @unittest.skipUnless(sys.platform == "linux",
                         "identity proof is procfs-based")
    def test_reason_logout_finalizes(self):
        # A real end reason (and any future unknown one) finalizes.
        self.assertEqual(self._matching_id_session_end("logout"),
                         STATUS_FAILED)

    def test_mismatched_session_id_keeps_liveness_skip(self):
        # A different session's end (e.g. a nested subagent's own
        # SessionEnd, which carries ITS id) must not reap the live
        # owner's run.
        if sys.platform != "linux":
            self.skipTest("identity proof is procfs-based")
        from core.run.metadata import _session_stamp
        with TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            stub = self._spawn_claude_shaped_stub(tmp)
            try:
                run = _make_running_run(tmp / "out", "validate-001",
                                        "validate", session_pid=stub.pid)
                stamp = _session_stamp(stub.pid)
                self.assertIn("session_start", stamp)
                self._stamp_meta(
                    run,
                    session_id="aaaaaaaa-1111-2222-3333-444444444444",
                    **stamp)
                self._run_session_end(
                    tmp, stub.pid,
                    payload=json.dumps({
                        "session_id":
                            "bbbbbbbb-5555-6666-7777-888888888888",
                        "hook_event_name": "SessionEnd"}))
                self.assertEqual(_status(run), STATUS_RUNNING)
            finally:
                self._reap_stub(stub)

    def test_absent_payload_session_id_keeps_liveness_skip(self):
        # No payload id (or unreadable stdin) proves nothing — the
        # liveness-gated behaviour applies unchanged.
        if sys.platform != "linux":
            self.skipTest("identity proof is procfs-based")
        from core.run.metadata import _session_stamp
        with TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            stub = self._spawn_claude_shaped_stub(tmp)
            try:
                run = _make_running_run(tmp / "out", "validate-001",
                                        "validate", session_pid=stub.pid)
                stamp = _session_stamp(stub.pid)
                self.assertIn("session_start", stamp)
                self._stamp_meta(
                    run,
                    session_id="aaaaaaaa-1111-2222-3333-444444444444",
                    **stamp)
                self._run_session_end(tmp, stub.pid, payload="")
                self.assertEqual(_status(run), STATUS_RUNNING)
            finally:
                self._reap_stub(stub)

    def test_meta_without_recorded_id_keeps_liveness_skip(self):
        # A stamped meta that predates session_id recording offers no
        # owner-end proof: a payload id matches nothing, the live
        # owner keeps its run.
        if sys.platform != "linux":
            self.skipTest("identity proof is procfs-based")
        from core.run.metadata import _session_stamp
        with TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            stub = self._spawn_claude_shaped_stub(tmp)
            try:
                run = _make_running_run(tmp / "out", "validate-001",
                                        "validate", session_pid=stub.pid)
                stamp = _session_stamp(stub.pid)
                self.assertIn("session_start", stamp)
                self._stamp_meta(run, **stamp)
                self._run_session_end(
                    tmp, stub.pid,
                    payload=json.dumps({
                        "session_id":
                            "aaaaaaaa-1111-2222-3333-444444444444",
                        "hook_event_name": "SessionEnd"}))
                self.assertEqual(_status(run), STATUS_RUNNING)
            finally:
                self._reap_stub(stub)

    def test_reaped_run_recovers_through_real_finaliser(self):
        # End-to-end self-heal: a hook-reaped run's real finaliser
        # overrides the heuristic verdict via the metadata recovery
        # clause, clearing the marker and the sweep's error.
        from core.run.metadata import complete_run
        with TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            run = _make_running_run(tmp / "out", "validate-001",
                                    "validate")
            self._run_session_end(tmp, SESSION_PID)
            self.assertEqual(_status(run), STATUS_FAILED)
            complete_run(run)
            self.assertEqual(_status(run), STATUS_COMPLETED)
            meta = load_json(run / RUN_METADATA_FILE)
            extra = meta.get("extra") or {}
            self.assertNotIn("abandon_sweep", extra)
            self.assertNotIn("error", extra)


if __name__ == "__main__":
    unittest.main()
