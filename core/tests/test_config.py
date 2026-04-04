"""Tests for core.config.RaptorConfig."""

import os
import pytest
from pathlib import Path
from unittest.mock import patch

import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core.config import RaptorConfig


class TestGetSafeEnv:
    """Tests for RaptorConfig.get_safe_env()."""

    def test_strips_dangerous_env_vars(self):
        """TERMINAL, BROWSER, PAGER, VISUAL, EDITOR must be removed."""
        injected = {var: f"malicious_{var}" for var in RaptorConfig.DANGEROUS_ENV_VARS}
        with patch.dict(os.environ, injected):
            env = RaptorConfig.get_safe_env()
            for var in RaptorConfig.DANGEROUS_ENV_VARS:
                assert var not in env, f"{var} should be stripped from safe env"

    def test_strips_proxy_env_vars(self):
        """HTTP_PROXY and friends must be removed."""
        injected = {var: "http://proxy.evil.com" for var in RaptorConfig.PROXY_ENV_VARS}
        with patch.dict(os.environ, injected):
            env = RaptorConfig.get_safe_env()
            for var in RaptorConfig.PROXY_ENV_VARS:
                assert var not in env, f"{var} should be stripped from safe env"

    def test_sets_pythonunbuffered(self):
        env = RaptorConfig.get_safe_env()
        assert env.get("PYTHONUNBUFFERED") == "1"

    def test_does_not_strip_term(self):
        """TERM is read as a string (terminfo lookup), not shell-evaluated — must not be stripped."""
        with patch.dict(os.environ, {"TERM": "xterm-256color"}):
            env = RaptorConfig.get_safe_env()
            assert "TERM" in env

    def test_missing_dangerous_vars_handled_gracefully(self):
        """Should not raise if dangerous vars are absent."""
        cleaned = {var: None for var in RaptorConfig.DANGEROUS_ENV_VARS}
        env_without = {k: v for k, v in os.environ.items() if k not in cleaned}
        with patch.dict(os.environ, env_without, clear=True):
            env = RaptorConfig.get_safe_env()  # must not raise
            assert isinstance(env, dict)

    def test_returns_copy_not_original(self):
        """Mutations to the returned dict must not affect os.environ."""
        env = RaptorConfig.get_safe_env()
        env["RAPTOR_TEST_SENTINEL"] = "should_not_leak"
        assert "RAPTOR_TEST_SENTINEL" not in os.environ


class TestGetGitEnv:
    """Tests for RaptorConfig.get_git_env()."""

    def test_disables_terminal_prompt(self):
        env = RaptorConfig.get_git_env()
        assert env.get("GIT_TERMINAL_PROMPT") == "0"

    def test_sets_askpass(self):
        env = RaptorConfig.get_git_env()
        assert env.get("GIT_ASKPASS") == "true"

    def test_also_strips_dangerous_vars(self):
        injected = {var: "bad" for var in RaptorConfig.DANGEROUS_ENV_VARS}
        with patch.dict(os.environ, injected):
            env = RaptorConfig.get_git_env()
            for var in RaptorConfig.DANGEROUS_ENV_VARS:
                assert var not in env

    def test_also_strips_proxy_vars(self):
        injected = {var: "http://proxy.evil.com" for var in RaptorConfig.PROXY_ENV_VARS}
        with patch.dict(os.environ, injected):
            env = RaptorConfig.get_git_env()
            for var in RaptorConfig.PROXY_ENV_VARS:
                assert var not in env


class TestGetOutDir:
    """Tests for RaptorConfig.get_out_dir()."""

    def test_uses_raptor_out_dir_env(self, tmp_path):
        with patch.dict(os.environ, {"RAPTOR_OUT_DIR": str(tmp_path)}):
            result = RaptorConfig.get_out_dir()
            assert result == tmp_path.resolve()

    def test_falls_back_to_base_out_dir(self):
        env_without = {k: v for k, v in os.environ.items() if k != "RAPTOR_OUT_DIR"}
        with patch.dict(os.environ, env_without, clear=True):
            result = RaptorConfig.get_out_dir()
            assert result == RaptorConfig.BASE_OUT_DIR

class TestEnsureDirectories:
    """Tests for RaptorConfig.ensure_directories()."""

    def test_creates_required_directories(self, tmp_path):
        """Patch REPO_ROOT so dirs are created under tmp_path."""
        with patch.object(RaptorConfig, "BASE_OUT_DIR", tmp_path / "out"), \
             patch.object(RaptorConfig, "MCP_JOB_DIR", tmp_path / "out" / "jobs"), \
             patch.object(RaptorConfig, "LOG_DIR", tmp_path / "out" / "logs"), \
             patch.object(RaptorConfig, "SCHEMAS_DIR", tmp_path / "schemas"), \
             patch.object(RaptorConfig, "CODEQL_DB_DIR", tmp_path / "codeql_dbs"), \
             patch.object(RaptorConfig, "CODEQL_SUITES_DIR", tmp_path / "codeql" / "suites"):
            RaptorConfig.ensure_directories()
            assert (tmp_path / "out").exists()
            assert (tmp_path / "out" / "jobs").exists()
            assert (tmp_path / "out" / "logs").exists()

    def test_idempotent(self, tmp_path):
        """Calling twice must not raise."""
        with patch.object(RaptorConfig, "BASE_OUT_DIR", tmp_path / "out"), \
             patch.object(RaptorConfig, "MCP_JOB_DIR", tmp_path / "out" / "jobs"), \
             patch.object(RaptorConfig, "LOG_DIR", tmp_path / "out" / "logs"), \
             patch.object(RaptorConfig, "SCHEMAS_DIR", tmp_path / "schemas"), \
             patch.object(RaptorConfig, "CODEQL_DB_DIR", tmp_path / "codeql_dbs"), \
             patch.object(RaptorConfig, "CODEQL_SUITES_DIR", tmp_path / "codeql" / "suites"):
            RaptorConfig.ensure_directories()
            RaptorConfig.ensure_directories()  # must not raise


