"""The claude CLI is pinned to an absolute path, never PATH-resolved
at spawn.

Pre-fix ClaudeCodeLLMProvider defaulted to the bare string "claude",
which every Popen re-resolved against the ambient PATH — with backend
credentials in the child env — so an attacker-writable PATH entry
ahead of the real CLI substituted the executed binary. The provider
must resolve once at construction (realpath-pinning helper) and
run_cc_streaming must refuse non-absolute argv[0] outright.
"""

from __future__ import annotations

import os
import shutil
import sys

import pytest

from core.llm.cc_adapter import run_cc_streaming
from core.llm.config import ModelConfig
from core.llm.providers import ClaudeCodeLLMProvider


def _config() -> ModelConfig:
    return ModelConfig(
        provider="claudecode",
        model_name="claude-opus-4-6",
        api_key=None,
        timeout=30,
    )


class TestProviderPinning:

    def test_default_claude_bin_resolved_absolute_at_construction(
        self, monkeypatch,
    ):
        """No explicit claude_bin: the provider resolves the CLI once
        via PATH lookup + realpath and stores the ABSOLUTE result —
        never the bare re-resolved-per-spawn name."""
        monkeypatch.setattr(
            shutil, "which",
            lambda name: "/opt/fake/claude" if name == "claude" else None,
        )
        p = ClaudeCodeLLMProvider(_config())
        assert os.path.isabs(p._claude_bin)
        assert p._claude_bin == os.path.realpath("/opt/fake/claude")

    def test_explicit_absolute_path_kept(self):
        p = ClaudeCodeLLMProvider(_config(), claude_bin="/usr/bin/claude")
        assert p._claude_bin == "/usr/bin/claude"


class TestSpawnGuard:

    def test_bare_command_refused(self):
        """A bare name reaching the spawn is exactly the PATH
        re-resolution the pin exists to prevent — refused even when
        the name exists on PATH (pre-fix this executed /usr/bin/true
        via PATH search and returned a parsed result)."""
        with pytest.raises(FileNotFoundError, match="absolute"):
            run_cc_streaming(
                ["true"], prompt="", env=dict(os.environ), timeout_s=5,
            )

    def test_relative_path_refused(self):
        with pytest.raises(FileNotFoundError, match="absolute"):
            run_cc_streaming(
                ["./claude", "-p"], prompt="",
                env=dict(os.environ), timeout_s=5,
            )

    def test_absolute_path_still_spawns(self):
        sr = run_cc_streaming(
            [sys.executable, "-c",
             "import json; print(json.dumps("
             "{'type':'result','session_id':'sess-abs','is_error':False}"
             "))"],
            prompt="", env=dict(os.environ), timeout_s=30,
        )
        assert sr.error is None
        assert sr.session_id == "sess-abs"
