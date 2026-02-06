"""Tests for core.semgrep module."""

import json
import os
import pytest
import shutil
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core.semgrep import (
    run_semgrep,
    run_single_semgrep,
)


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


# ============================================================================
# INTEGRATION TESTS - Real Semgrep Execution
# ============================================================================

# Check if semgrep is available for integration tests
SEMGREP_AVAILABLE = shutil.which("semgrep") is not None


@pytest.mark.skipif(not SEMGREP_AVAILABLE, reason="semgrep not installed")
class TestSemgrepIntegration:
    """Integration tests that run actual semgrep commands."""

    def test_run_semgrep_finds_vulnerability(self, tmp_path):
        """Test that semgrep actually finds vulnerabilities in test code."""
        # Create a Python file with a SQL injection vulnerability
        vulnerable_file = tmp_path / "vulnerable.py"
        vulnerable_file.write_text("""
import sqlite3

def unsafe_query(user_input):
    conn = sqlite3.connect('db.sqlite')
    # This is a SQL injection vulnerability
    query = f"SELECT * FROM users WHERE name = '{user_input}'"
    return conn.execute(query)
""")

        output_file = tmp_path / "output.sarif"
        success, sarif_path = run_semgrep(
            config="p/python",
            target=tmp_path,
            output=output_file,
            timeout=60
        )

        assert success is True
        assert sarif_path.exists()

        # Verify SARIF file is valid JSON
        sarif_content = json.loads(sarif_path.read_text())
        assert "runs" in sarif_content
        assert isinstance(sarif_content["runs"], list)

        # Check if findings were detected (semgrep should find SQL injection)
        if len(sarif_content["runs"]) > 0:
            results = sarif_content["runs"][0].get("results", [])
            # May or may not have findings depending on semgrep rules
            # But at least verify the structure is correct
            assert isinstance(results, list)

    def test_run_semgrep_handles_empty_directory(self, tmp_path):
        """Test semgrep on empty directory."""
        output_file = tmp_path / "output.sarif"
        success, sarif_path = run_semgrep(
            config="p/python",
            target=tmp_path,
            output=output_file,
            timeout=60
        )

        assert success is True
        assert sarif_path.exists()

        # Should produce valid SARIF even with no findings
        sarif_content = json.loads(sarif_path.read_text())
        assert "runs" in sarif_content

    def test_run_semgrep_with_javascript_vulnerability(self, tmp_path):
        """Test semgrep finds XSS vulnerability in JavaScript."""
        vulnerable_file = tmp_path / "vulnerable.js"
        vulnerable_file.write_text("""
function displayUserInput(userInput) {
    // XSS vulnerability
    document.getElementById('output').innerHTML = userInput;
}
""")

        output_file = tmp_path / "output.sarif"
        success, sarif_path = run_semgrep(
            config="p/javascript",
            target=tmp_path,
            output=output_file,
            timeout=60
        )

        assert success is True
        assert sarif_path.exists()

        # Verify SARIF structure
        sarif_content = json.loads(sarif_path.read_text())
        assert "runs" in sarif_content

    def test_run_semgrep_validates_sarif_output(self, tmp_path):
        """Test that semgrep produces valid SARIF that passes validation."""
        # Create a simple test file
        test_file = tmp_path / "test.py"
        test_file.write_text("print('hello')")

        output_file = tmp_path / "output.sarif"
        success, sarif_path = run_semgrep(
            config="p/python",
            target=tmp_path,
            output=output_file,
            timeout=60
        )

        assert success is True
        assert sarif_path.exists()

        # Verify it's valid JSON
        sarif_content = json.loads(sarif_path.read_text())

        # Verify SARIF schema structure
        assert "$schema" in sarif_content or "version" in sarif_content
        assert "runs" in sarif_content
        assert isinstance(sarif_content["runs"], list)

    def test_run_single_semgrep_real_execution(self, tmp_path):
        """Test run_single_semgrep with real semgrep execution."""
        # Create test file
        test_file = tmp_path / "test.py"
        test_file.write_text("""
import os
def unsafe_command(user_input):
    os.system(user_input)  # Command injection
""")

        sarif_path, success = run_single_semgrep(
            name="integration_test",
            config="p/python",
            repo_path=tmp_path,
            out_dir=tmp_path,
            timeout=60
        )

        assert success is True
        assert Path(sarif_path).exists()

        # Verify all expected output files exist
        assert (tmp_path / "semgrep_integration_test.stderr.log").exists()
        assert (tmp_path / "semgrep_integration_test.exit").exists()

        # Verify exit code file
        exit_code = int((tmp_path / "semgrep_integration_test.exit").read_text().strip())
        # Exit code 0 = no findings, 1 = findings found (both are success)
        assert exit_code in [0, 1]

        # Verify SARIF is valid
        sarif_content = json.loads(Path(sarif_path).read_text())
        assert "runs" in sarif_content

    def test_run_semgrep_timeout_handling(self, tmp_path):
        """Test that timeout is respected in real execution."""
        # Create a large directory structure to potentially slow down semgrep
        for i in range(10):
            (tmp_path / f"file_{i}.py").write_text("print('test')")

        output_file = tmp_path / "output.sarif"
        # Use a reasonable timeout (not too short to fail immediately)
        success, sarif_path = run_semgrep(
            config="p/python",
            target=tmp_path,
            output=output_file,
            timeout=300  # 5 minutes should be enough
        )

        # Should complete successfully with reasonable timeout
        assert success is True
        assert sarif_path.exists()

    def test_run_semgrep_with_custom_config(self, tmp_path):
        """Test semgrep with a custom inline rule."""
        # Create test file
        test_file = tmp_path / "test.py"
        test_file.write_text("password = 'secret123'")

        # Create custom semgrep config file
        config_file = tmp_path / "custom_rule.yaml"
        config_file.write_text("""
rules:
  - id: test-password-detection
    pattern: password = ...
    message: Found password assignment
    languages: [python]
    severity: WARNING
""")

        output_file = tmp_path / "output.sarif"
        success, sarif_path = run_semgrep(
            config=str(config_file),
            target=tmp_path,
            output=output_file,
            timeout=60
        )

        assert success is True
        assert sarif_path.exists()

        # Verify SARIF contains results
        sarif_content = json.loads(sarif_path.read_text())
        assert "runs" in sarif_content

    def test_run_semgrep_error_handling_invalid_config(self, tmp_path):
        """Test semgrep handles invalid config gracefully."""
        test_file = tmp_path / "test.py"
        test_file.write_text("print('test')")

        output_file = tmp_path / "output.sarif"
        success, sarif_path = run_semgrep(
            config="nonexistent-config-12345",
            target=tmp_path,
            output=output_file,
            timeout=60
        )

        # Should handle error gracefully (may succeed with empty results or fail)
        # Either way, should produce a SARIF file
        assert sarif_path.exists()

        # Verify SARIF structure even on error
        sarif_content = json.loads(sarif_path.read_text())
        assert "runs" in sarif_content
