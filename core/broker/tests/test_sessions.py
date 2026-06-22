"""Tests for remote session management."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from core.broker.sessions import (
    RemoteTaskState,
    SessionBackend,
    cleanup_workspace,
    detect_session_backend,
    poll,
    start_detached,
)
from core.broker.transport import CommandResult


def _mock_transport(run_results: dict[str, CommandResult] | None = None):
    """Build a mock transport with configurable run() responses."""
    t = MagicMock()

    if run_results:
        def run_side_effect(cmd, **kwargs):
            for pattern, result in run_results.items():
                if pattern in cmd:
                    return result
            return CommandResult(exit_code=1, stdout="", stderr="not found")
        t.run.side_effect = run_side_effect
    else:
        t.run.return_value = CommandResult(exit_code=0, stdout="", stderr="")

    return t


class TestDetectSessionBackend:
    def test_prefers_tmux(self):
        t = _mock_transport({"which tmux": CommandResult(0, "/usr/bin/tmux", "")})
        assert detect_session_backend(t) == SessionBackend.TMUX

    def test_falls_back_to_screen(self):
        t = _mock_transport({
            "which tmux": CommandResult(1, "", ""),
            "which screen": CommandResult(0, "/usr/bin/screen", ""),
        })
        assert detect_session_backend(t) == SessionBackend.SCREEN

    def test_falls_back_to_nohup(self):
        t = _mock_transport({
            "which tmux": CommandResult(1, "", ""),
            "which screen": CommandResult(1, "", ""),
        })
        assert detect_session_backend(t) == SessionBackend.NOHUP


class TestStartDetached:
    def test_tmux_session_created(self):
        t = _mock_transport()
        start_detached(t, "abc123", "raptor fuzz /src", "/tmp/raptor-task-abc123", SessionBackend.TMUX)

        calls = [str(c) for c in t.run.call_args_list]
        assert any("tmux new-session" in c for c in calls)
        assert any("raptor-abc123" in c for c in calls)

    def test_screen_session_created(self):
        t = _mock_transport()
        start_detached(t, "abc123", "raptor fuzz /src", "/tmp/raptor-task-abc123", SessionBackend.SCREEN)

        calls = [str(c) for c in t.run.call_args_list]
        assert any("screen -dmS" in c for c in calls)

    def test_nohup_fallback(self):
        t = _mock_transport()
        start_detached(t, "abc123", "raptor fuzz /src", "/tmp/raptor-task-abc123", SessionBackend.NOHUP)

        calls = [str(c) for c in t.run.call_args_list]
        assert any("nohup" in c for c in calls)

    def test_raises_on_failure(self):
        t = MagicMock()
        t.run.return_value = CommandResult(1, "", "session error")
        with pytest.raises(Exception, match="failed to start"):
            start_detached(t, "abc", "cmd", "/tmp/x", SessionBackend.TMUX)


class TestPoll:
    def test_completed_task(self):
        t = _mock_transport({
            "cat /tmp/ws/.raptor-exit-code": CommandResult(0, "0\n", ""),
            "cat /tmp/ws/.raptor-pid": CommandResult(0, "12345\n", ""),
            "tail": CommandResult(0, "output line\n", ""),
        })
        state = poll(t, "abc123", "/tmp/ws")
        assert state.running is False
        assert state.exit_code == 0

    def test_running_task(self):
        t = _mock_transport({
            "cat /tmp/ws/.raptor-exit-code": CommandResult(1, "", "No such file"),
            "cat /tmp/ws/.raptor-pid": CommandResult(0, "12345\n", ""),
            "tail": CommandResult(0, "progress...\n", ""),
        })
        state = poll(t, "abc123", "/tmp/ws")
        assert state.running is True
        assert state.pid == 12345

    def test_failed_task(self):
        t = _mock_transport({
            "cat /tmp/ws/.raptor-exit-code": CommandResult(0, "1\n", ""),
            "tail": CommandResult(0, "", "error output\n"),
        })
        state = poll(t, "abc123", "/tmp/ws")
        assert state.running is False
        assert state.exit_code == 1


class TestCleanupWorkspace:
    def test_unix_cleanup(self):
        t = MagicMock()
        t.run.return_value = CommandResult(0, "", "")
        cleanup_workspace(t, "/tmp/raptor-task-abc")
        t.run.assert_called_once()
        assert "rm -rf" in t.run.call_args[0][0]

    def test_windows_cleanup(self):
        t = MagicMock()
        t.run.return_value = CommandResult(0, "", "")
        cleanup_workspace(t, "C:\\temp\\raptor-task-abc", is_windows=True)
        t.run.assert_called_once()
        assert "Remove-Item" in t.run.call_args[0][0]
