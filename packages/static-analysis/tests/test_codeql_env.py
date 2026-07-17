"""Tests for ``packages.static_analysis.codeql.env``."""

from __future__ import annotations

import os
from pathlib import Path


class TestEnvFallbackStrip:
    """When core.config is not importable, the version probe must still
    strip dangerous env vars rather than inheriting them wholesale."""

    def test_fallback_strips_dangerous_vars(self, monkeypatch):
        monkeypatch.setenv("JAVA_TOOL_OPTIONS", "-javaagent:evil.jar")
        monkeypatch.setenv("LD_PRELOAD", "/tmp/evil.so")
        monkeypatch.setenv("BASH_ENV", "/tmp/evil.sh")
        monkeypatch.setenv("PYTHONPATH", "/tmp/evil")
        monkeypatch.setenv("NODE_OPTIONS", "--require=evil.js")
        monkeypatch.setenv("PATH", "/usr/bin")

        _DANGEROUS = {
            "LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT",
            "DYLD_INSERT_LIBRARIES",
            "JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS",
            "PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP", "PYTHONUSERBASE",
            "NODE_OPTIONS",
            "OPENSSL_CONF",
            "GIT_CONFIG_GLOBAL", "GIT_SSH_COMMAND",
            "BASH_ENV", "ENV", "CDPATH",
        }
        env = {k: v for k, v in os.environ.items() if k not in _DANGEROUS}

        assert "JAVA_TOOL_OPTIONS" not in env
        assert "LD_PRELOAD" not in env
        assert "BASH_ENV" not in env
        assert "PYTHONPATH" not in env
        assert "NODE_OPTIONS" not in env
        assert env.get("PATH") == "/usr/bin"

    def test_fallback_code_matches_source(self):
        source = Path(__file__).resolve().parents[1] / "codeql" / "env.py"
        content = source.read_text()
        assert "env = None" not in content, (
            "env.py still has `env = None` fallback"
        )
        assert "_DANGEROUS" in content
        assert "PYTHONPATH" in content
