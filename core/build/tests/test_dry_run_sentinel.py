"""_dry_run must not report signal death as 'all files compiled'.

Regression: only a nonzero exit WITH a Python traceback returned the
None ("didn't run") sentinel. An OOM-killed script (returncode -9,
empty stderr) fell through to the stderr error-parse, returned [], and
the caller logged "Dry-run: all files compiled successfully".
"""

from types import SimpleNamespace
from unittest import mock

from core.build.build_detector import BuildDetector


def _dry_run_with(tmp_path, returncode: int, stderr: str):
    result = SimpleNamespace(returncode=returncode, stderr=stderr, stdout="")
    with mock.patch("core.build.build_detector._sandbox_run", return_value=result):
        return BuildDetector(tmp_path)._dry_run(tmp_path / "script.py")


def test_signal_death_returns_didnt_run_sentinel(tmp_path):
    assert _dry_run_with(tmp_path, returncode=-9, stderr="") is None


def test_nonzero_exit_without_diagnostics_returns_sentinel(tmp_path):
    assert _dry_run_with(tmp_path, returncode=2, stderr="Killed\n") is None


def test_traceback_crash_returns_sentinel(tmp_path):
    stderr = "Traceback (most recent call last):\n  ...\nValueError: boom\n"
    assert _dry_run_with(tmp_path, returncode=1, stderr=stderr) is None


def test_clean_run_returns_empty_failures(tmp_path):
    assert _dry_run_with(tmp_path, returncode=0, stderr="") == []


def test_nonzero_exit_with_diagnostics_still_parses_failures(tmp_path):
    stderr = "a.c: error: expected ';'\n"
    failures = _dry_run_with(tmp_path, returncode=1, stderr=stderr)
    assert failures == [{"file": "a.c", "error": "error: expected ';'"}]
