"""Semgrep ``run_single_semgrep`` tests for scanner.py.

Adapted from Josh's PR #60 ``core/tests/test_semgrep.py``. Phase 2.1 of
the centralisation refactor kept the semgrep orchestration in scanner.py
rather than ``core/``, so these tests target the scanner module instead.

Dropped in adaptation:
  - ``TestRunSemgrep`` — Josh added a single-config wrapper named
    ``run_semgrep``; scanner.py exposes only ``run_single_semgrep``
    so there is no target to test.
  - ``TestSemgrepIntegration`` — those real-semgrep tests called the
    missing ``run_semgrep`` wrapper. The mocked unit tests below cover
    the same control flow without requiring semgrep installed.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from unittest.mock import patch


# packages/static-analysis has a hyphen — load via importlib.
_SCANNER_PATH = Path(__file__).parent.parent / "scanner.py"
_spec = importlib.util.spec_from_file_location(
    "static_analysis_scanner_semgrep", _SCANNER_PATH,
)
_scanner_mod = importlib.util.module_from_spec(_spec)
sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
_spec.loader.exec_module(_scanner_mod)

run_single_semgrep = _scanner_mod.run_single_semgrep


class TestRunSingleSemgrep:
    """Tests for run_single_semgrep function."""

    @patch('shutil.which')
    @patch.object(_scanner_mod, "run")
    @patch.object(_scanner_mod, "validate_sarif")
    def test_creates_output_files(self, mock_validate, mock_run, mock_which, tmp_path):
        """Test that all expected output files are created."""
        mock_which.return_value = "/usr/bin/semgrep"
        mock_run.return_value = (0, '{"runs": []}', "some stderr")
        mock_validate.return_value = True

        sarif_path, success = run_single_semgrep(
            name="test_scan",
            config="p/default",
            repo_path=tmp_path,
            out_dir=tmp_path,
            timeout=300
        )

        assert success is True
        assert Path(sarif_path).exists()
        assert (tmp_path / "semgrep_test_scan.stderr.log").exists()
        assert (tmp_path / "semgrep_test_scan.exit").exists()

    @patch('shutil.which')
    @patch.object(_scanner_mod, "run")
    @patch.object(_scanner_mod, "validate_sarif")
    def test_sanitizes_name_with_slashes(self, mock_validate, mock_run, mock_which, tmp_path):
        """Test that names with special chars are sanitized."""
        mock_which.return_value = "/usr/bin/semgrep"
        mock_run.return_value = (0, '{"runs": []}', "")
        mock_validate.return_value = True

        sarif_path, success = run_single_semgrep(
            name="p/security-audit",
            config="p/security-audit",
            repo_path=tmp_path,
            out_dir=tmp_path,
            timeout=300
        )

        # Name should be sanitized (slashes replaced)
        assert "p_security-audit" in sarif_path

    @patch('shutil.which')
    @patch.object(_scanner_mod, "run")
    @patch.object(_scanner_mod, "validate_sarif")
    def test_progress_callback_called(self, mock_validate, mock_run, mock_which, tmp_path):
        """Test that progress callback is invoked."""
        mock_which.return_value = "/usr/bin/semgrep"
        mock_run.return_value = (0, '{"runs": []}', "")
        mock_validate.return_value = True

        callback_calls = []

        def progress_callback(msg):
            callback_calls.append(msg)

        run_single_semgrep(
            name="test",
            config="p/default",
            repo_path=tmp_path,
            out_dir=tmp_path,
            timeout=300,
            progress_callback=progress_callback
        )

        assert len(callback_calls) > 0
        assert any("test" in call for call in callback_calls)
