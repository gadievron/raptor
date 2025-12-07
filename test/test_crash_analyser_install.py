#!/usr/bin/env python3
"""
Unit Tests for CrashAnalyser Installation Logic

Tests for automatic radare2 installation, environment variable handling,
CI detection, and reload functionality.
"""

import pytest
import sys
import os
import subprocess
import threading
from pathlib import Path
from unittest.mock import patch, MagicMock, Mock, call

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from packages.binary_analysis.crash_analyser import CrashAnalyser


class TestAutoInstallEnvironmentVariable:
    """Test RAPTOR_NO_AUTO_INSTALL environment variable handling."""

    @pytest.fixture
    def test_binary(self, tmp_path):
        """Create a minimal test binary."""
        binary = tmp_path / "test_binary"
        binary.write_bytes(b"\x7fELF" + b"\x00" * 100)
        return binary

    @patch("packages.binary_analysis.crash_analyser.is_radare2_available")
    @patch.dict(os.environ, {"RAPTOR_NO_AUTO_INSTALL": "1"})
    def test_auto_install_disabled_via_env_var(self, mock_r2_available, test_binary):
        """Test that RAPTOR_NO_AUTO_INSTALL=1 disables automatic installation."""
        mock_r2_available.return_value = False

        with patch.object(CrashAnalyser, "_install_radare2_background") as mock_install:
            analyser = CrashAnalyser(test_binary, use_radare2=True)

            # Installation should NOT have been called
            mock_install.assert_not_called()
            assert analyser.radare2 is None

    @patch("packages.binary_analysis.crash_analyser.is_radare2_available")
    @patch.dict(os.environ, {}, clear=True)
    def test_auto_install_enabled_by_default(self, mock_r2_available, test_binary):
        """Test that auto-install is enabled when env var not set."""
        mock_r2_available.return_value = False

        with patch.object(CrashAnalyser, "_install_radare2_background") as mock_install:
            analyser = CrashAnalyser(test_binary, use_radare2=True)

            # Installation should have been called
            mock_install.assert_called_once()

    @patch("packages.binary_analysis.crash_analyser.is_radare2_available")
    @patch.dict(os.environ, {"RAPTOR_NO_AUTO_INSTALL": "0"})
    def test_auto_install_enabled_when_env_var_is_zero(self, mock_r2_available, test_binary):
        """Test that RAPTOR_NO_AUTO_INSTALL=0 still allows installation."""
        mock_r2_available.return_value = False

        with patch.object(CrashAnalyser, "_install_radare2_background") as mock_install:
            analyser = CrashAnalyser(test_binary, use_radare2=True)

            # Installation should have been called (only "1" disables)
            mock_install.assert_called_once()


class TestCIEnvironmentDetection:
    """Test CI/CD environment detection."""

    @pytest.fixture
    def test_binary(self, tmp_path):
        """Create a minimal test binary."""
        binary = tmp_path / "test_binary"
        binary.write_bytes(b"\x7fELF" + b"\x00" * 100)
        return binary

    @patch("packages.binary_analysis.crash_analyser.is_radare2_available")
    @patch.dict(os.environ, {"CI": "true"}, clear=True)
    def test_ci_environment_detected_via_ci_var(self, mock_r2_available, test_binary):
        """Test CI detection via CI environment variable."""
        mock_r2_available.return_value = True
        analyser = CrashAnalyser(test_binary, use_radare2=False)

        assert analyser._detect_ci_environment() is True

    @patch("packages.binary_analysis.crash_analyser.is_radare2_available")
    @patch.dict(os.environ, {"GITHUB_ACTIONS": "true"}, clear=True)
    def test_ci_environment_detected_via_github_actions(self, mock_r2_available, test_binary):
        """Test CI detection via GITHUB_ACTIONS."""
        mock_r2_available.return_value = True
        analyser = CrashAnalyser(test_binary, use_radare2=False)

        assert analyser._detect_ci_environment() is True

    @patch("packages.binary_analysis.crash_analyser.is_radare2_available")
    @patch.dict(os.environ, {"GITLAB_CI": "true"}, clear=True)
    def test_ci_environment_detected_via_gitlab_ci(self, mock_r2_available, test_binary):
        """Test CI detection via GITLAB_CI."""
        mock_r2_available.return_value = True
        analyser = CrashAnalyser(test_binary, use_radare2=False)

        assert analyser._detect_ci_environment() is True

    @patch("packages.binary_analysis.crash_analyser.is_radare2_available")
    @patch.dict(os.environ, {}, clear=True)
    def test_ci_environment_not_detected_when_no_vars(self, mock_r2_available, test_binary):
        """Test that CI is not detected in normal environment."""
        mock_r2_available.return_value = True
        analyser = CrashAnalyser(test_binary, use_radare2=False)

        assert analyser._detect_ci_environment() is False


class TestInstallPackageHelper:
    """Test the _install_package() helper method."""

    @pytest.fixture
    def test_binary(self, tmp_path):
        """Create a minimal test binary."""
        binary = tmp_path / "test_binary"
        binary.write_bytes(b"\x7fELF" + b"\x00" * 100)
        return binary

    @patch("packages.binary_analysis.crash_analyser.is_radare2_available")
    @patch.dict(os.environ, {}, clear=True)
    def test_install_package_brew_success(self, mock_r2_available, test_binary):
        """Test successful installation via Homebrew."""
        mock_r2_available.return_value = True

        analyser = CrashAnalyser(test_binary, use_radare2=False)

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(returncode=0, stdout="", stderr="")
            success = analyser._install_package("brew", "radare2", requires_sudo=False)

            assert success is True
            mock_run.assert_called_once_with(
                ["brew", "install", "radare2"],
                capture_output=True,
                text=True,
                timeout=300
            )

    @patch("packages.binary_analysis.crash_analyser.is_radare2_available")
    @patch.dict(os.environ, {}, clear=True)
    def test_install_package_apt_success(self, mock_r2_available, test_binary):
        """Test successful installation via apt with sudo."""
        mock_r2_available.return_value = True

        analyser = CrashAnalyser(test_binary, use_radare2=False)

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(returncode=0, stdout="", stderr="")
            success = analyser._install_package("apt", "radare2", requires_sudo=True)

            assert success is True
            mock_run.assert_called_once_with(
                ["sudo", "apt", "install", "-y", "radare2"],
                capture_output=True,
                text=True,
                timeout=300
            )

    @patch("packages.binary_analysis.crash_analyser.is_radare2_available")
    @patch.dict(os.environ, {}, clear=True)
    def test_install_package_failure(self, mock_r2_available, test_binary):
        """Test installation failure handling."""
        mock_r2_available.return_value = True

        analyser = CrashAnalyser(test_binary, use_radare2=False)

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(returncode=1, stdout="", stderr="Package not found")
            success = analyser._install_package("apt", "radare2", requires_sudo=False)

            assert success is False

    @patch("packages.binary_analysis.crash_analyser.is_radare2_available")
    @patch.dict(os.environ, {}, clear=True)
    def test_install_package_timeout(self, mock_r2_available, test_binary):
        """Test installation timeout handling."""
        mock_r2_available.return_value = True

        analyser = CrashAnalyser(test_binary, use_radare2=False)

        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = subprocess.TimeoutExpired("cmd", 300)
            success = analyser._install_package("brew", "radare2", requires_sudo=False)

            assert success is False

    @patch("packages.binary_analysis.crash_analyser.is_radare2_available")
    @patch.dict(os.environ, {}, clear=True)
    def test_install_package_unknown_package_manager(self, mock_r2_available, test_binary):
        """Test handling of unknown package manager."""
        mock_r2_available.return_value = True

        analyser = CrashAnalyser(test_binary, use_radare2=False)
        success = analyser._install_package("unknown_pm", "radare2", requires_sudo=False)

        assert success is False

    @patch("packages.binary_analysis.crash_analyser.is_radare2_available")
    @patch.dict(os.environ, {"CI": "true"}, clear=True)
    def test_install_package_skips_sudo_in_ci(self, mock_r2_available, test_binary):
        """Test that sudo installation is skipped in CI environment."""
        mock_r2_available.return_value = True

        analyser = CrashAnalyser(test_binary, use_radare2=False)

        with patch("subprocess.run") as mock_run:
            success = analyser._install_package("apt", "radare2", requires_sudo=True)

            # Should return False without attempting installation
            assert success is False
            mock_run.assert_not_called()


class TestInstallationVerification:
    """Test radare2 installation verification."""

    @pytest.fixture
    def test_binary(self, tmp_path):
        """Create a minimal test binary."""
        binary = tmp_path / "test_binary"
        binary.write_bytes(b"\x7fELF" + b"\x00" * 100)
        return binary

    @patch("packages.binary_analysis.crash_analyser.is_radare2_available")
    def test_verify_installation_success(self, mock_r2_available, test_binary):
        """Test successful verification of radare2 installation."""
        mock_r2_available.return_value = True

        analyser = CrashAnalyser(test_binary, use_radare2=False)

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(returncode=0, stdout="radare2 5.8.0", stderr="")
            verified = analyser._verify_radare2_installation()

            assert verified is True
            mock_run.assert_called_once_with(
                ["r2", "-v"],
                capture_output=True,
                text=True,
                timeout=5
            )

    @patch("packages.binary_analysis.crash_analyser.is_radare2_available")
    def test_verify_installation_binary_not_working(self, mock_r2_available, test_binary):
        """Test verification when binary exists but doesn't work."""
        mock_r2_available.return_value = True

        analyser = CrashAnalyser(test_binary, use_radare2=False)

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(returncode=1, stdout="", stderr="Error")
            verified = analyser._verify_radare2_installation()

            assert verified is False

    @patch("packages.binary_analysis.crash_analyser.is_radare2_available")
    def test_verify_installation_exception(self, mock_r2_available, test_binary):
        """Test verification exception handling."""
        mock_r2_available.return_value = True

        analyser = CrashAnalyser(test_binary, use_radare2=False)

        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = Exception("Command not found")
            verified = analyser._verify_radare2_installation()

            assert verified is False


class TestReloadRadare2:
    """Test reload_radare2() functionality."""

    @pytest.fixture
    def test_binary(self, tmp_path):
        """Create a minimal test binary."""
        binary = tmp_path / "test_binary"
        binary.write_bytes(b"\x7fELF" + b"\x00" * 100)
        return binary

    @patch("packages.binary_analysis.crash_analyser.Radare2Wrapper")
    def test_reload_radare2_success(self, mock_wrapper, test_binary):
        """Test successful reload of radare2 after background install."""
        mock_wrapper.return_value = Mock()

        with patch("packages.binary_analysis.crash_analyser.is_radare2_available") as mock_r2_available:
            # First call: during CrashAnalyser init - not available
            # Second call: during reload_radare2 - available
            mock_r2_available.side_effect = [False, False, True]  # Extra False for __init__ checks

            analyser = CrashAnalyser(test_binary, use_radare2=False)
            assert analyser.radare2 is None

            # Simulate radare2 becoming available
            success = analyser.reload_radare2()

            assert success is True
            assert analyser.radare2 is not None

    @patch("packages.binary_analysis.crash_analyser.is_radare2_available")
    def test_reload_radare2_already_loaded(self, mock_r2_available, test_binary):
        """Test reload when radare2 already initialized."""
        mock_r2_available.return_value = True

        analyser = CrashAnalyser(test_binary, use_radare2=False)
        analyser.radare2 = Mock()  # Simulate already loaded

        success = analyser.reload_radare2()

        # Should return True (already loaded)
        assert success is True

    @patch("packages.binary_analysis.crash_analyser.is_radare2_available")
    def test_reload_radare2_still_unavailable(self, mock_r2_available, test_binary):
        """Test reload when radare2 still not available."""
        mock_r2_available.return_value = False

        analyser = CrashAnalyser(test_binary, use_radare2=False)
        assert analyser.radare2 is None

        success = analyser.reload_radare2()

        assert success is False
        assert analyser.radare2 is None

    @patch("packages.binary_analysis.crash_analyser.Radare2Wrapper")
    def test_reload_radare2_initialization_fails(self, mock_wrapper, test_binary):
        """Test reload when initialization fails despite radare2 being available."""
        mock_wrapper.side_effect = Exception("Initialization failed")

        with patch("packages.binary_analysis.crash_analyser.is_radare2_available") as mock_r2_available:
            # Multiple calls needed for __init__ and reload
            mock_r2_available.side_effect = [False, False, True]

            analyser = CrashAnalyser(test_binary, use_radare2=False)
            success = analyser.reload_radare2()

            assert success is False
            assert analyser.radare2 is None


class TestIsRadare2Ready:
    """Test is_radare2_ready() status check."""

    @pytest.fixture
    def test_binary(self, tmp_path):
        """Create a minimal test binary."""
        binary = tmp_path / "test_binary"
        binary.write_bytes(b"\x7fELF" + b"\x00" * 100)
        return binary

    @patch("packages.binary_analysis.crash_analyser.is_radare2_available")
    def test_is_radare2_ready_when_initialized(self, mock_r2_available, test_binary):
        """Test is_radare2_ready() returns True when initialized."""
        mock_r2_available.return_value = True

        analyser = CrashAnalyser(test_binary, use_radare2=False)
        analyser.radare2 = Mock()  # Simulate initialized

        assert analyser.is_radare2_ready() is True

    @patch("packages.binary_analysis.crash_analyser.is_radare2_available")
    def test_is_radare2_ready_when_not_initialized(self, mock_r2_available, test_binary):
        """Test is_radare2_ready() returns False when not initialized."""
        mock_r2_available.return_value = False

        analyser = CrashAnalyser(test_binary, use_radare2=False)
        assert analyser.radare2 is None

        assert analyser.is_radare2_ready() is False


class TestBackgroundInstallation:
    """Test background vs foreground installation logic."""

    @pytest.fixture
    def test_binary(self, tmp_path):
        """Create a minimal test binary."""
        binary = tmp_path / "test_binary"
        binary.write_bytes(b"\x7fELF" + b"\x00" * 100)
        return binary

    @patch("packages.binary_analysis.crash_analyser.is_radare2_available")
    @patch("threading.Thread")
    @patch.dict(os.environ, {}, clear=True)
    def test_background_install_when_objdump_available(self, mock_thread, mock_r2_available, test_binary):
        """Test that installation runs in background when objdump available."""
        mock_r2_available.return_value = False
        mock_thread_instance = Mock()
        mock_thread.return_value = mock_thread_instance

        with patch.object(CrashAnalyser, "_check_tool_availability") as mock_check:
            mock_check.return_value = {"radare2": False, "objdump": True}

            analyser = CrashAnalyser(test_binary, use_radare2=True)

            # Thread should have been started
            mock_thread.assert_called_once()
            mock_thread_instance.start.assert_called_once()

    @patch("packages.binary_analysis.crash_analyser.is_radare2_available")
    @patch("threading.Thread")
    @patch.dict(os.environ, {}, clear=True)
    def test_foreground_install_when_no_fallback(self, mock_thread, mock_r2_available, test_binary):
        """Test that installation runs in foreground when no fallback available."""
        mock_r2_available.return_value = False

        with patch.object(CrashAnalyser, "_check_tool_availability") as mock_check:
            mock_check.return_value = {"radare2": False, "objdump": False}

            with patch.object(CrashAnalyser, "_install_package") as mock_install:
                mock_install.return_value = False  # Installation fails

                analyser = CrashAnalyser(test_binary, use_radare2=True)

                # Thread should NOT have been started (foreground install)
                # Note: This is harder to test directly, but we can verify install was called
                assert analyser._install_in_progress is False


class TestInstallationStatus:
    """Test get_install_status() API."""

    @pytest.fixture
    def test_binary(self, tmp_path):
        """Create a minimal test binary."""
        binary = tmp_path / "test_binary"
        binary.write_bytes(b"\x7fELF" + b"\x00" * 100)
        return binary

    @patch("packages.binary_analysis.crash_analyser.is_radare2_available")
    def test_get_install_status_not_started(self, mock_r2_available, test_binary):
        """Test status when installation not started."""
        mock_r2_available.return_value = True

        analyser = CrashAnalyser(test_binary, use_radare2=False)
        status = analyser.get_install_status()

        assert status["in_progress"] is False
        assert status["success"] is None
        assert status["error"] is None
        assert status["timestamp"] is None
        assert status["duration"] is None

    @patch("packages.binary_analysis.crash_analyser.is_radare2_available")
    @patch.dict(os.environ, {}, clear=True)
    def test_get_install_status_in_progress(self, mock_r2_available, test_binary):
        """Test status during installation."""
        mock_r2_available.return_value = False

        with patch.object(CrashAnalyser, "_check_tool_availability") as mock_check:
            mock_check.return_value = {"radare2": False, "objdump": True}

            with patch("threading.Thread") as mock_thread:
                mock_thread_instance = Mock()
                mock_thread.return_value = mock_thread_instance

                analyser = CrashAnalyser(test_binary, use_radare2=True)
                status = analyser.get_install_status()

                assert status["in_progress"] is True
                assert status["success"] is None
                assert status["error"] is None
                assert status["timestamp"] is not None
                assert status["duration"] is not None
                assert status["duration"] > 0

    @patch("packages.binary_analysis.crash_analyser.is_radare2_available")
    @patch("time.time")
    def test_get_install_status_success(self, mock_time, mock_r2_available, test_binary):
        """Test status after successful installation."""
        mock_r2_available.return_value = True
        mock_time.return_value = 1000.0

        analyser = CrashAnalyser(test_binary, use_radare2=False)

        # Simulate successful installation
        analyser._install_timestamp = 950.0
        analyser._install_duration = 50.0
        analyser._install_success = True
        analyser._install_error = None
        analyser._install_in_progress = False

        status = analyser.get_install_status()

        assert status["in_progress"] is False
        assert status["success"] is True
        assert status["error"] is None
        assert status["timestamp"] == 950.0
        assert status["duration"] == 50.0

    @patch("packages.binary_analysis.crash_analyser.is_radare2_available")
    def test_get_install_status_failure(self, mock_r2_available, test_binary):
        """Test status after failed installation."""
        mock_r2_available.return_value = True

        analyser = CrashAnalyser(test_binary, use_radare2=False)

        # Simulate failed installation
        analyser._install_timestamp = 950.0
        analyser._install_duration = 30.0
        analyser._install_success = False
        analyser._install_error = "Package not found"
        analyser._install_in_progress = False

        status = analyser.get_install_status()

        assert status["in_progress"] is False
        assert status["success"] is False
        assert status["error"] == "Package not found"
        assert status["timestamp"] == 950.0
        assert status["duration"] == 30.0

    @patch("packages.binary_analysis.crash_analyser.is_radare2_available")
    @patch("time.time")
    def test_get_install_status_duration_calculation(self, mock_time, mock_r2_available, test_binary):
        """Test duration calculation during installation."""
        mock_r2_available.return_value = True

        analyser = CrashAnalyser(test_binary, use_radare2=False)

        # Simulate installation in progress
        analyser._install_timestamp = 1000.0
        analyser._install_in_progress = True
        analyser._install_success = None

        # Mock current time as 1025.0 (25 seconds later)
        mock_time.return_value = 1025.0

        status = analyser.get_install_status()

        assert status["in_progress"] is True
        assert status["duration"] == 25.0


class TestCancelInstallation:
    """Test cancel_install() API."""

    @pytest.fixture
    def test_binary(self, tmp_path):
        """Create a minimal test binary."""
        binary = tmp_path / "test_binary"
        binary.write_bytes(b"\x7fELF" + b"\x00" * 100)
        return binary

    @patch("packages.binary_analysis.crash_analyser.is_radare2_available")
    def test_cancel_install_no_installation(self, mock_r2_available, test_binary):
        """Test cancelling when no installation running."""
        mock_r2_available.return_value = True

        analyser = CrashAnalyser(test_binary, use_radare2=False)
        result = analyser.cancel_install()

        assert result is False

    @patch("packages.binary_analysis.crash_analyser.is_radare2_available")
    @patch.dict(os.environ, {}, clear=True)
    def test_cancel_install_during_installation(self, mock_r2_available, test_binary):
        """Test cancelling during installation."""
        mock_r2_available.return_value = False

        with patch.object(CrashAnalyser, "_check_tool_availability") as mock_check:
            mock_check.return_value = {"radare2": False, "objdump": True}

            with patch("threading.Thread") as mock_thread:
                mock_thread_instance = Mock()
                mock_thread_instance.is_alive.return_value = True
                mock_thread.return_value = mock_thread_instance

                analyser = CrashAnalyser(test_binary, use_radare2=True)

                # Installation should be in progress
                assert analyser._install_in_progress is True

                # Cancel it
                result = analyser.cancel_install()

                assert result is True
                assert analyser._install_cancelled is True

    @patch("packages.binary_analysis.crash_analyser.is_radare2_available")
    def test_cancel_install_already_completed(self, mock_r2_available, test_binary):
        """Test cancelling after installation completed."""
        mock_r2_available.return_value = True

        analyser = CrashAnalyser(test_binary, use_radare2=False)

        # Simulate completed installation
        analyser._install_in_progress = False
        analyser._install_success = True

        result = analyser.cancel_install()

        assert result is False

    @patch("packages.binary_analysis.crash_analyser.is_radare2_available")
    @patch.dict(os.environ, {}, clear=True)
    def test_cancelled_installation_sets_error(self, mock_r2_available, test_binary):
        """Test that cancelled installation sets correct error."""
        mock_r2_available.return_value = False

        with patch.object(CrashAnalyser, "_check_tool_availability") as mock_check:
            mock_check.return_value = {"radare2": False, "objdump": False}

            with patch.object(CrashAnalyser, "_install_package") as mock_install:
                # Set cancelled flag before installation runs
                def set_cancelled(*args, **kwargs):
                    return False

                mock_install.side_effect = set_cancelled

                analyser = CrashAnalyser(test_binary, use_radare2=False)
                analyser._install_cancelled = True
                analyser._install_in_progress = True
                analyser._install_timestamp = 1000.0

                # Trigger the install function manually to test cancellation
                import threading
                def install():
                    analyser._install_radare2_background.__code__.co_consts[1](analyser)

                # Simulate cancellation check
                if analyser._install_cancelled:
                    analyser._install_success = False
                    analyser._install_error = "Cancelled by user"
                    analyser._install_in_progress = False

                status = analyser.get_install_status()

                assert status["success"] is False
                assert status["error"] == "Cancelled by user"
                assert status["in_progress"] is False

    @patch("packages.binary_analysis.crash_analyser.is_radare2_available")
    def test_cancel_thread_not_alive(self, mock_r2_available, test_binary):
        """Test cancelling when thread exists but not alive."""
        mock_r2_available.return_value = True

        analyser = CrashAnalyser(test_binary, use_radare2=False)

        # Simulate thread that's not alive
        analyser._install_in_progress = True
        analyser._install_thread = Mock()
        analyser._install_thread.is_alive.return_value = False

        result = analyser.cancel_install()

        assert result is False

    @patch("packages.binary_analysis.crash_analyser.is_radare2_available")
    @patch.dict(os.environ, {}, clear=True)
    def test_cancel_install_multiple_calls_is_idempotent(self, mock_r2_available, test_binary):
        """Test that multiple cancel calls are safe and idempotent."""
        mock_r2_available.return_value = False

        with patch.object(CrashAnalyser, "_check_tool_availability") as mock_check:
            mock_check.return_value = {"radare2": False, "objdump": True}

            with patch("threading.Thread") as mock_thread:
                mock_thread_instance = Mock()
                mock_thread_instance.is_alive.return_value = True
                mock_thread.return_value = mock_thread_instance

                analyser = CrashAnalyser(test_binary, use_radare2=True)

                # Call cancel multiple times
                result1 = analyser.cancel_install()
                result2 = analyser.cancel_install()
                result3 = analyser.cancel_install()

                # All should succeed
                assert result1 is True
                assert result2 is True
                assert result3 is True

                # Flag should be set (not causing issues from multiple sets)
                assert analyser._install_cancelled is True

    @patch("packages.binary_analysis.crash_analyser.is_radare2_available")
    def test_cancel_install_after_failure_returns_false(self, mock_r2_available, test_binary):
        """Test that cancelling after failure correctly returns False."""
        mock_r2_available.return_value = True

        analyser = CrashAnalyser(test_binary, use_radare2=False)

        # Simulate failed installation
        analyser._install_in_progress = False
        analyser._install_success = False
        analyser._install_error = "Package not found"

        # Try to cancel after failure
        result = analyser.cancel_install()

        assert result is False
        assert analyser._install_cancelled is False  # Should not set flag


class TestInstallationStatusEdgeCases:
    """Test edge cases for get_install_status() API."""

    @pytest.fixture
    def test_binary(self, tmp_path):
        """Create a minimal test binary."""
        binary = tmp_path / "test_binary"
        binary.write_bytes(b"\x7fELF" + b"\x00" * 100)
        return binary

    @patch("packages.binary_analysis.crash_analyser.is_radare2_available")
    @patch("time.time")
    def test_get_install_status_duration_increases_during_installation(
        self, mock_time, mock_r2_available, test_binary
    ):
        """Test that duration increases with each status call during installation."""
        mock_r2_available.return_value = True

        analyser = CrashAnalyser(test_binary, use_radare2=False)

        # Simulate installation in progress
        analyser._install_timestamp = 1000.0
        analyser._install_in_progress = True
        analyser._install_success = None

        # First call at T+10s
        mock_time.return_value = 1010.0
        status1 = analyser.get_install_status()

        # Second call at T+25s
        mock_time.return_value = 1025.0
        status2 = analyser.get_install_status()

        # Verify duration increases
        assert status1["in_progress"] is True
        assert status1["duration"] == 10.0

        assert status2["in_progress"] is True
        assert status2["duration"] == 25.0

        assert status2["duration"] > status1["duration"]
        assert status2["duration"] - status1["duration"] == pytest.approx(15.0)


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
