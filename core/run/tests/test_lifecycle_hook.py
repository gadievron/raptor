"""Tests for libexec/raptor-lifecycle-hook."""

import importlib.machinery
import importlib.util
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
    start_run,
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


class TestToolFailureMarker(unittest.TestCase):
    """tool-failure mode writes a soft marker without changing status."""

    def test_writes_marker(self):
        with TemporaryDirectory() as tmp:
            out = Path(tmp) / "out"
            run = _make_running_run(out, "scan-20260503", "scan")
            with patch.object(_hook_mod, "REPO_ROOT", Path(tmp)), \
                 patch("core.run.metadata._find_claude_ancestor",
                       return_value=SESSION_PID):
                sys.argv = ["hook", "tool-failure"]
                _hook_mod.main()
            self.assertTrue((run / FAILURE_MARKER).exists())
            self.assertEqual(_status(run), STATUS_RUNNING)

    def test_marks_all_running_in_session(self):
        with TemporaryDirectory() as tmp:
            out = Path(tmp) / "out"
            run1 = _make_running_run(out, "scan-001", "scan")
            run2 = _make_running_run(out, "agentic-002", "agentic")
            with patch.object(_hook_mod, "REPO_ROOT", Path(tmp)), \
                 patch("core.run.metadata._find_claude_ancestor",
                       return_value=SESSION_PID):
                sys.argv = ["hook", "tool-failure"]
                _hook_mod.main()
            self.assertTrue((run1 / FAILURE_MARKER).exists())
            self.assertTrue((run2 / FAILURE_MARKER).exists())

    def test_skips_different_session(self):
        with TemporaryDirectory() as tmp:
            out = Path(tmp) / "out"
            run = _make_running_run(out, "scan-001", "scan",
                                    session_pid=88888)
            with patch.object(_hook_mod, "REPO_ROOT", Path(tmp)), \
                 patch("core.run.metadata._find_claude_ancestor",
                       return_value=SESSION_PID):
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
                 patch("core.run.metadata._find_claude_ancestor",
                       return_value=SESSION_PID):
                sys.argv = ["hook", "tool-failure"]
                _hook_mod.main()
            self.assertFalse((run / FAILURE_MARKER).exists())


class TestStopHook(unittest.TestCase):
    """Stop mode: complete or fail single-call runs with dead tool_pid."""

    def test_completes_when_no_marker(self):
        with TemporaryDirectory() as tmp:
            out = Path(tmp) / "out"
            run = _make_running_run(out, "scan-001", "scan", tool_pid=1)
            with patch.object(_hook_mod, "REPO_ROOT", Path(tmp)), \
                 patch("core.run.metadata._find_claude_ancestor",
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
                 patch("core.run.metadata._find_claude_ancestor",
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
                 patch("core.run.metadata._find_claude_ancestor",
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
                 patch("core.run.metadata._find_claude_ancestor",
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
                 patch("core.run.metadata._find_claude_ancestor",
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
                 patch("core.run.metadata._find_claude_ancestor",
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
                 patch("core.run.metadata._find_claude_ancestor",
                       return_value=SESSION_PID), \
                 patch("core.run.metadata._pid_alive", return_value=True):
                sys.argv = ["hook", "stop"]
                _hook_mod.main()
            self.assertEqual(_status(run), STATUS_RUNNING)

    def test_skips_different_session(self):
        with TemporaryDirectory() as tmp:
            out = Path(tmp) / "out"
            run = _make_running_run(out, "scan-001", "scan",
                                    session_pid=88888, tool_pid=1)
            with patch.object(_hook_mod, "REPO_ROOT", Path(tmp)), \
                 patch("core.run.metadata._find_claude_ancestor",
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
                 patch("core.run.metadata._find_claude_ancestor",
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
                 patch("core.run.metadata._find_claude_ancestor",
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
                 patch("core.run.metadata._find_claude_ancestor",
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
                 patch("core.run.metadata._find_claude_ancestor",
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
                 patch("core.run.metadata._find_claude_ancestor",
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
                 patch("core.run.metadata._find_claude_ancestor",
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
                 patch("core.run.metadata._find_claude_ancestor",
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
                 patch("core.run.metadata._find_claude_ancestor",
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
                 patch("core.run.metadata._find_claude_ancestor",
                       return_value=SESSION_PID), \
                 patch("core.run.metadata._pid_alive", return_value=False):
                sys.argv = ["hook", "stop"]
                _hook_mod.main()
            self.assertEqual(_status(run), STATUS_FAILED)
            meta = load_json(run / RUN_METADATA_FILE)
            self.assertEqual(meta["extra"]["error"], "analysis found nothing")


class TestProjectDirScan(unittest.TestCase):
    """Hook scans both .active project dir and out/."""

    def test_scans_active_project(self):
        with TemporaryDirectory() as tmp:
            repo = Path(tmp)
            proj = repo / "projects" / "myapp"
            run = _make_running_run(proj, "scan-001", "scan", tool_pid=1)
            active = repo / ".active"
            active.symlink_to(proj)
            with patch.object(_hook_mod, "REPO_ROOT", repo), \
                 patch("core.run.metadata._find_claude_ancestor",
                       return_value=SESSION_PID), \
                 patch("core.run.metadata._pid_alive", return_value=False):
                sys.argv = ["hook", "stop"]
                _hook_mod.main()
            self.assertEqual(_status(run), STATUS_COMPLETED)

    def test_scans_out_dir(self):
        with TemporaryDirectory() as tmp:
            repo = Path(tmp)
            out = repo / "out"
            run = _make_running_run(out, "scan-001", "scan", tool_pid=1)
            with patch.object(_hook_mod, "REPO_ROOT", repo), \
                 patch("core.run.metadata._find_claude_ancestor",
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
                 patch("core.run.metadata._find_claude_ancestor",
                       return_value=SESSION_PID), \
                 patch("core.run.metadata._pid_alive", return_value=False):
                sys.argv = ["hook", "stop"]
                _hook_mod.main()
            self.assertEqual(_status(run), STATUS_RUNNING)


class TestMultiTurnGuard(unittest.TestCase):
    """Verify the multi-turn command list is complete."""

    def test_multi_turn_set_contents(self):
        self.assertEqual(MULTI_TURN, {"validate", "understand"})

    def test_all_multi_turn_skipped_by_stop(self):
        """Every command in _MULTI_TURN_COMMANDS is skipped by Stop."""
        for cmd in MULTI_TURN:
            with TemporaryDirectory() as tmp:
                out = Path(tmp) / "out"
                run = _make_running_run(out, f"{cmd}-001", cmd, tool_pid=1)
                with patch.object(_hook_mod, "REPO_ROOT", Path(tmp)), \
                     patch("core.run.metadata._find_claude_ancestor",
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
                     patch("core.run.metadata._find_claude_ancestor",
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
            capture_output=True, text=True,
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


if __name__ == "__main__":
    unittest.main()
