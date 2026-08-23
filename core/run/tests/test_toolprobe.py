"""Tests for core.run.toolprobe — shared which + version probing.

Pins the drift fixes the consolidation makes: probes exec the
RESOLVED path (not the bare name — the check-then-exec PATH race),
and run under the sanitised env from ``RaptorConfig.get_safe_env()``
(several hand-rolled probes inherited the caller's full environment).
"""

from __future__ import annotations

import subprocess
from unittest.mock import MagicMock, patch

import pytest

from core.run.toolprobe import ToolInfo, probe, reset_probe_cache


@pytest.fixture(autouse=True)
def _clean_cache():
    reset_probe_cache()
    yield
    reset_probe_cache()


class TestProbe:
    def test_missing_tool_returns_none(self):
        with patch("shutil.which", return_value=None):
            assert probe("no-such-tool-xyz") is None

    def test_probe_runs_resolved_path_not_bare_name(self):
        # Drift fix pin: the semgrep copy which()-checked then exec'd
        # the BARE name, re-resolving PATH at exec time (TOCTOU). The
        # shared probe must exec the resolved absolute path.
        with patch("shutil.which", return_value="/opt/bin/sometool"), \
                patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                stdout="1.2.3\n", stderr="", returncode=0)
            info = probe("sometool")
            argv = mock_run.call_args[0][0]
            assert argv == ["/opt/bin/sometool", "--version"]
        assert info is not None
        assert info.path == "/opt/bin/sometool"

    def test_probe_uses_safe_env(self):
        # Drift fix pin: hand-rolled probes inherited the full caller
        # env; the shared probe passes RaptorConfig.get_safe_env().
        from core.config import RaptorConfig
        with patch("shutil.which", return_value="/opt/bin/sometool"), \
                patch("subprocess.run") as mock_run, \
                patch.object(
                    RaptorConfig, "get_safe_env",
                    return_value={"PATH": "/sanitised"},
                ) as mock_env:
            mock_run.return_value = MagicMock(
                stdout="", stderr="", returncode=0)
            probe("sometool")
            assert mock_env.called
            assert mock_run.call_args.kwargs["env"] == {"PATH": "/sanitised"}

    def test_probe_failure_yields_toolinfo_not_raise(self):
        with patch("shutil.which", return_value="/opt/bin/sometool"), \
                patch(
                    "subprocess.run",
                    side_effect=subprocess.TimeoutExpired("sometool", 10),
                ):
            info = probe("sometool")
        assert info is not None
        assert info.returncode is None
        assert info.first_line is None
        assert "TimeoutExpired" in info.error

    def test_custom_args_and_timeout(self):
        with patch("shutil.which", return_value="/opt/bin/java"), \
                patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                stdout="", stderr='openjdk version "21.0.1"\n',
                returncode=0)
            info = probe("java", args=("-version",), timeout=5)
            assert mock_run.call_args[0][0] == ["/opt/bin/java", "-version"]
            assert mock_run.call_args.kwargs["timeout"] == 5
        assert info is not None
        # stderr fallback: java prints its version there.
        assert info.first_line == 'openjdk version "21.0.1"'


class TestToolInfoParsing:
    def test_first_line_prefers_stdout(self):
        info = ToolInfo(name="t", path="/t", stdout="1.2.3\nrest",
                        stderr="err", returncode=0)
        assert info.first_line == "1.2.3"

    def test_version_tuple(self):
        info = ToolInfo(name="t", path="/t",
                        stdout="tool version 2.10.4 (build x)\n",
                        returncode=0)
        assert info.version_tuple() == (2, 10, 4)

    def test_version_tuple_two_component(self):
        info = ToolInfo(name="t", path="/t", stdout="spatch version 1.3\n",
                        returncode=0)
        assert info.version_tuple() == (1, 3)

    def test_version_tuple_none_when_unparseable(self):
        info = ToolInfo(name="t", path="/t", stdout="no digits here\n",
                        returncode=0)
        assert info.version_tuple() is None


class TestCache:
    def test_cache_memoises_positive_and_negative(self):
        with patch("shutil.which", return_value="/opt/bin/sometool"), \
                patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                stdout="1.0\n", stderr="", returncode=0)
            probe("sometool", use_cache=True)
            probe("sometool", use_cache=True)
            assert mock_run.call_count == 1
        with patch("shutil.which", return_value=None) as mock_which:
            assert probe("gone-tool", use_cache=True) is None
            assert probe("gone-tool", use_cache=True) is None
            assert mock_which.call_count == 1

    def test_uncached_by_default(self):
        with patch("shutil.which", return_value="/opt/bin/sometool"), \
                patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                stdout="1.0\n", stderr="", returncode=0)
            probe("sometool")
            probe("sometool")
            assert mock_run.call_count == 2

    def test_reset_probe_cache(self):
        with patch("shutil.which", return_value="/opt/bin/sometool"), \
                patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                stdout="1.0\n", stderr="", returncode=0)
            probe("sometool", use_cache=True)
            reset_probe_cache()
            probe("sometool", use_cache=True)
            assert mock_run.call_count == 2

    def test_cache_key_includes_args(self):
        with patch("shutil.which", return_value="/opt/bin/sometool"), \
                patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                stdout="1.0\n", stderr="", returncode=0)
            probe("sometool", use_cache=True)
            probe("sometool", args=("-V",), use_cache=True)
            assert mock_run.call_count == 2
