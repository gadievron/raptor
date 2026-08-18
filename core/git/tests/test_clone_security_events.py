"""Security-event emission on the clone/fetch URL-rejection paths.

The pre-restructure ``core/git.py`` (commit c1af3314) emitted
``log_security_event("invalid_repo_url", ...)`` when ``validate_repo_url``
rejected a URL; the April restructures dropped the emitter. These tests
pin the restored behaviour:

  * rejection emits exactly one ``invalid_repo_url`` event;
  * the happy path emits nothing;
  * URL userinfo credentials are redacted before the event is built;
  * a broken logging sink never masks or replaces the ValueError.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from core.git.clone import clone_repository, fetch_commit
from core.logging import RaptorLogger

_VALID_SHA = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"


def _completed(rc: int) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(
        args=[], returncode=rc, stdout="", stderr="",
    )


def test_clone_rejection_emits_security_event(tmp_path: Path) -> None:
    with patch("core.git.clone._log_security_event") as mock_emit, \
            pytest.raises(ValueError):
        clone_repository("https://evil.example.com/repo",
                         tmp_path / "out")
    assert mock_emit.call_count == 1
    args, kwargs = mock_emit.call_args
    assert args[0] == "invalid_repo_url"
    assert "evil.example.com" in args[1]
    assert kwargs.get("operation") == "clone_repository"


def test_fetch_rejection_emits_security_event(tmp_path: Path) -> None:
    with patch("core.git.clone._log_security_event") as mock_emit, \
            pytest.raises(ValueError):
        fetch_commit(tmp_path / "repo",
                     "https://evil.example.com/repo", _VALID_SHA)
    assert mock_emit.call_count == 1
    assert mock_emit.call_args.args[0] == "invalid_repo_url"
    assert mock_emit.call_args.kwargs.get("operation") == "fetch_commit"


def test_rejected_url_userinfo_is_redacted(tmp_path: Path) -> None:
    """Rejected URLs are exactly the ones that may carry credentials
    (validate_repo_url refuses userinfo) — the event must not leak them."""
    with patch("core.git.clone._log_security_event") as mock_emit, \
            pytest.raises(ValueError):
        clone_repository(
            "https://oauth2:hunter2token@github.com/foo/bar",
            tmp_path / "out",
        )
    message = mock_emit.call_args.args[1]
    assert "hunter2token" not in message
    assert "github.com" in message


def test_happy_path_emits_no_security_event(tmp_path: Path) -> None:
    with patch("core.git.clone._log_security_event") as mock_emit, \
            patch("core.sandbox.run_untrusted_networked") as mock_run:
        mock_run.return_value = _completed(0)
        assert clone_repository("https://github.com/foo/bar",
                                tmp_path / "out") is True
    mock_emit.assert_not_called()


def test_clone_failure_emits_no_security_event(tmp_path: Path) -> None:
    """A valid-URL clone that fails at git level is an operational
    error, not a security event."""
    with patch("core.git.clone._log_security_event") as mock_emit, \
            patch("core.sandbox.run_untrusted_networked") as mock_run:
        mock_run.return_value = _completed(128)
        with pytest.raises(RuntimeError):
            clone_repository("https://github.com/foo/bar",
                             tmp_path / "out")
    mock_emit.assert_not_called()


def test_sink_failure_does_not_mask_the_rejection(tmp_path: Path) -> None:
    """End-to-end no-raise: with the REAL emitter wired and the logging
    sink broken, the caller still sees the ValueError (never the sink
    error, never a silent pass-through to the subprocess)."""
    with patch.object(
        RaptorLogger, "warning", side_effect=OSError("sink down"),
    ), patch("core.sandbox.run_untrusted_networked") as mock_run:
        with pytest.raises(ValueError):
            clone_repository("https://evil.example.com/repo",
                             tmp_path / "out")
        mock_run.assert_not_called()
