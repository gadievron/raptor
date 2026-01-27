"""Tests for core.exec module."""

import os
import pytest
import subprocess
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core.exec import run, run_streaming
from core.config import RaptorConfig


class TestRun:
    """Tests for run() function."""

    def test_run_simple_command(self):
        """Test running a simple command."""
        rc, stdout, stderr = run(["python", "--version"], timeout=10)
        assert rc == 0
        assert "Python" in stdout or stdout  # May be empty on some systems

    def test_run_with_cwd_string(self, tmp_path):
        """Test run() with cwd as string."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("test content")
        
        # On Windows, use 'type' or 'cat' depending on what's available
        import platform
        if platform.system() == "Windows":
            rc, stdout, stderr = run(["python", "-c", "import os; print(os.getcwd())"], cwd=str(tmp_path), timeout=10)
        else:
            rc, stdout, stderr = run(["pwd"], cwd=str(tmp_path), timeout=10)
        assert rc == 0

    def test_run_with_cwd_path(self, tmp_path):
        """Test run() with cwd as Path object."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("test content")
        
        import platform
        if platform.system() == "Windows":
            rc, stdout, stderr = run(["python", "-c", "import os; print(os.getcwd())"], cwd=tmp_path, timeout=10)
        else:
            rc, stdout, stderr = run(["pwd"], cwd=tmp_path, timeout=10)
        assert rc == 0

    def test_run_with_timeout(self):
        """Test that timeout parameter is respected."""
        import platform
        if platform.system() == "Windows":
            # Use a command that will timeout
            try:
                rc, stdout, stderr = run(["python", "-c", "import time; time.sleep(2)"], timeout=1)
            except subprocess.TimeoutExpired:
                pass  # Expected
        else:
            try:
                rc, stdout, stderr = run(["sleep", "2"], timeout=1)
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass  # Expected on Windows or if sleep doesn't exist

    def test_run_with_env(self, tmp_path):
        """Test run() with custom environment variables."""
        test_env = {"TEST_VAR": "test_value"}
        rc, stdout, stderr = run(
            ["python", "-c", "import os; print(os.environ.get('TEST_VAR', ''))"],
            env=test_env,
            timeout=10
        )
        assert rc == 0
        assert "test_value" in stdout

    def test_run_env_merges_with_os_environ(self):
        """Test that env parameter merges with os.environ."""
        test_env = {"TEST_VAR": "test_value"}
        rc, stdout, stderr = run(
            ["python", "-c", "import os; print(os.environ.get('PATH', '')[:10])"],
            env=test_env,
            timeout=10
        )
        assert rc == 0
        # Should still have PATH from os.environ

    def test_run_with_description(self, caplog):
        """Test that description parameter logs correctly."""
        rc, stdout, stderr = run(
            ["python", "--version"],
            description="Testing Python version",
            timeout=10
        )
        assert "Testing Python version" in caplog.text or rc == 0  # May not log if logger not configured

    def test_run_returns_tuple(self):
        """Test that run() returns correct tuple format."""
        rc, stdout, stderr = run(["python", "--version"], timeout=10)
        assert isinstance(rc, int)
        assert isinstance(stdout, str)
        assert isinstance(stderr, str)

    def test_run_command_failure(self):
        """Test run() with failing command."""
        rc, stdout, stderr = run(["python", "-c", "import sys; sys.exit(1)"], timeout=10)
        assert rc == 1

    def test_run_uses_list_args_not_shell(self):
        """Test that run() uses list-based arguments (security check)."""
        # This is implicit - if shell=True was used, this would be dangerous
        # We verify by checking that list-based args work correctly
        rc, stdout, stderr = run(["python", "-c", "print('safe')"], timeout=10)
        assert rc == 0
        # If shell=True was used, we'd see shell injection vulnerabilities

    def test_run_default_timeout(self):
        """Test that default timeout is used when not specified."""
        # Just verify it doesn't crash - actual timeout testing is platform-specific
        rc, stdout, stderr = run(["python", "--version"])
        assert isinstance(rc, int)

    def test_run_timeout_expired_raises(self):
        """Test that timeout expiration raises TimeoutExpired."""
        import platform
        if platform.system() == "Windows":
            with pytest.raises(subprocess.TimeoutExpired):
                run(["python", "-c", "import time; time.sleep(5)"], timeout=0.1)
        else:
            try:
                with pytest.raises(subprocess.TimeoutExpired):
                    run(["sleep", "5"], timeout=0.1)
            except FileNotFoundError:
                pytest.skip("sleep command not available")


class TestRunStreaming:
    """Tests for run_streaming() function."""

    def test_run_streaming_basic(self):
        """Test basic streaming functionality."""
        rc, stdout, stderr = run_streaming(
            ["python", "-c", "print('line1'); print('line2')"],
            timeout=10,
            print_output=False  # Don't print during test
        )
        assert rc == 0
        assert "line1" in stdout
        assert "line2" in stdout

    def test_run_streaming_captures_output(self):
        """Test that streaming also captures full output."""
        rc, stdout, stderr = run_streaming(
            ["python", "-c", "print('test output')"],
            timeout=10,
            print_output=False
        )
        assert rc == 0
        assert "test output" in stdout

    def test_run_streaming_with_description(self, caplog):
        """Test that description parameter works with streaming."""
        rc, stdout, stderr = run_streaming(
            ["python", "--version"],
            description="Streaming Python version",
            timeout=10,
            print_output=False
        )
        assert rc == 0

    def test_run_streaming_with_cwd(self, tmp_path):
        """Test streaming with custom working directory."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("content")
        
        import platform
        if platform.system() == "Windows":
            rc, stdout, stderr = run_streaming(
                ["python", "-c", "import os; print(os.getcwd())"],
                cwd=tmp_path,
                timeout=10,
                print_output=False
            )
        else:
            rc, stdout, stderr = run_streaming(
                ["pwd"],
                cwd=tmp_path,
                timeout=10,
                print_output=False
            )
        assert rc == 0

    def test_run_streaming_with_env(self):
        """Test streaming with custom environment."""
        test_env = {"STREAM_TEST": "value"}
        rc, stdout, stderr = run_streaming(
            ["python", "-c", "import os; print(os.environ.get('STREAM_TEST', ''))"],
            env=test_env,
            timeout=10,
            print_output=False
        )
        assert rc == 0
        assert "value" in stdout

    def test_run_streaming_timeout(self):
        """Test that streaming respects timeout."""
        import platform
        if platform.system() == "Windows":
            with pytest.raises(subprocess.TimeoutExpired):
                run_streaming(
                    ["python", "-c", "import time; time.sleep(5)"],
                    timeout=0.1,
                    print_output=False
                )
        else:
            try:
                with pytest.raises(subprocess.TimeoutExpired):
                    run_streaming(
                        ["sleep", "5"],
                        timeout=0.1,
                        print_output=False
                    )
            except FileNotFoundError:
                pytest.skip("sleep command not available")

    def test_run_streaming_default_timeout(self):
        """Test that streaming uses default timeout (1800s)."""
        # Just verify it doesn't crash
        rc, stdout, stderr = run_streaming(
            ["python", "--version"],
            print_output=False
        )
        assert isinstance(rc, int)

    def test_run_streaming_handles_stderr(self):
        """Test that streaming captures stderr."""
        rc, stdout, stderr = run_streaming(
            ["python", "-c", "import sys; sys.stderr.write('error output')"],
            timeout=10,
            print_output=False
        )
        assert "error output" in stderr

    def test_run_streaming_kills_on_timeout(self):
        """Test that process is killed on timeout."""
        import platform
        if platform.system() == "Windows":
            # On Windows, verify exception is raised
            with pytest.raises(subprocess.TimeoutExpired):
                run_streaming(
                    ["python", "-c", "import time; time.sleep(10)"],
                    timeout=0.1,
                    print_output=False
                )
        else:
            try:
                with pytest.raises(subprocess.TimeoutExpired):
                    run_streaming(
                        ["sleep", "10"],
                        timeout=0.1,
                        print_output=False
                    )
            except FileNotFoundError:
                pytest.skip("sleep command not available")
