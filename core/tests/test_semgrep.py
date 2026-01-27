"""Tests for core.semgrep module."""

import os
import pytest
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core.semgrep import (
    get_semgrep_version,
    run_semgrep,
    run_single_semgrep,
)


class TestGetSemgrepVersion:
    """Tests for get_semgrep_version function."""

    @patch('shutil.which')
    @patch('core.exec.run')
    def test_returns_version_when_available(self, mock_run, mock_which):
        """Test version is returned when semgrep is installed."""
        mock_which.return_value = "/usr/bin/semgrep"
        mock_run.return_value = (0, "1.50.0", "")

        version = get_semgrep_version()
        assert version == "1.50.0"

    @patch('shutil.which')
    @patch('core.exec.run')
    def test_returns_none_when_unavailable(self, mock_run, mock_which):
        """Test None is returned when semgrep is not installed."""
        mock_which.return_value = None
        mock_run.side_effect = FileNotFoundError()

        version = get_semgrep_version()
        assert version is None


class TestRunSemgrep:
    """Tests for run_semgrep function."""

    @patch('shutil.which')
    @patch('core.exec.run')
    @patch('core.semgrep.validate_sarif')
    def test_successful_scan(self, mock_validate, mock_run, mock_which, tmp_path):
        """Test successful semgrep scan."""
        mock_which.return_value = "/usr/bin/semgrep"
        mock_run.return_value = (0, '{"runs": []}', "")
        mock_validate.return_value = True

        output_file = tmp_path / "output.sarif"
        success, sarif_path = run_semgrep(
            config="p/default",
            target=tmp_path,
            output=output_file,
            timeout=300
        )

        assert success is True
        assert sarif_path == output_file

    @patch('shutil.which')
    @patch('core.exec.run')
    @patch('core.semgrep.validate_sarif')
    def test_scan_with_findings(self, mock_validate, mock_run, mock_which, tmp_path):
        """Test scan with exit code 1 (findings found) is still successful."""
        mock_which.return_value = "/usr/bin/semgrep"
        mock_run.return_value = (1, '{"runs": [{"results": []}]}', "")
        mock_validate.return_value = True

        output_file = tmp_path / "output.sarif"
        success, sarif_path = run_semgrep(
            config="p/default",
            target=tmp_path,
            output=output_file
        )

        assert success is True

    @patch('shutil.which')
    @patch('core.exec.run')
    def test_scan_failure(self, mock_run, mock_which, tmp_path):
        """Test failed semgrep scan."""
        mock_which.return_value = "/usr/bin/semgrep"
        mock_run.side_effect = Exception("semgrep crashed")

        output_file = tmp_path / "output.sarif"
        success, sarif_path = run_semgrep(
            config="p/default",
            target=tmp_path,
            output=output_file
        )

        assert success is False
        # Should write empty SARIF on error
        assert output_file.read_text() == '{"runs": []}'


class TestRunSingleSemgrep:
    """Tests for run_single_semgrep function."""

    @patch('shutil.which')
    @patch('core.exec.run')
    @patch('core.semgrep.validate_sarif')
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
    @patch('core.exec.run')
    @patch('core.semgrep.validate_sarif')
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
    @patch('core.exec.run')
    @patch('core.semgrep.validate_sarif')
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
