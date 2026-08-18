"""RAPTOR_LLM_WORKER_KEYLESS — enforce the keyless worker posture.

The dispatcher's designed posture is keyless workers (keys injected
per-request from the in-memory store); the env-direct key fallback in
``raptor.py:_run_script`` exists for dispatcher-down resilience and
non-dispatcher-routed providers. The knob makes the keyless posture
enforceable per-install without removing the fallback default.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_RAPTOR_ROOT = Path(__file__).resolve().parents[4]


def _import_raptor():
    if "raptor" not in sys.modules:
        sys.path.insert(0, str(_RAPTOR_ROOT))
    import raptor
    return raptor


class TestWorkerKeylessKnob:

    @pytest.mark.parametrize("raw,expected", [
        (None, False),
        ("", False),
        ("0", False),
        ("false", False),
        ("garbage", False),
        ("1", True),
        ("true", True),
        ("TRUE", True),
        ("yes", True),
        ("on", True),
    ])
    def test_resolution(self, monkeypatch, raw, expected):
        raptor = _import_raptor()
        if raw is None:
            monkeypatch.delenv("RAPTOR_LLM_WORKER_KEYLESS", raising=False)
        else:
            monkeypatch.setenv("RAPTOR_LLM_WORKER_KEYLESS", raw)
        assert raptor._worker_keyless_enabled() is expected

    def test_keyless_env_carries_no_provider_keys(self, monkeypatch):
        """The env built on the keyless branch: safe baseline +
        routing names, no ANTHROPIC/OPENAI/AWS secret material."""
        _import_raptor()  # ensures RAPTOR_ROOT on sys.path
        from core.config import RaptorConfig
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-SECRET")
        monkeypatch.setenv("OPENAI_API_KEY", "sk-oai-SECRET")
        monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "AWSSECRET")
        monkeypatch.setenv("CLAUDE_CODE_USE_BEDROCK", "1")
        env = RaptorConfig.get_safe_env(
            preserve_proxy=True, include_python_user_base=True,
        )
        env.update(RaptorConfig.llm_routing_env())
        assert "ANTHROPIC_API_KEY" not in env
        assert "OPENAI_API_KEY" not in env
        assert "AWS_SECRET_ACCESS_KEY" not in env
        # Routing NAMES still present so workers resolve their
        # models.json entries.
        assert env.get("CLAUDE_CODE_USE_BEDROCK") == "1"

    def test_default_env_keeps_keys(self, monkeypatch):
        """Default (knob off) posture unchanged: get_llm_env carries
        the provider keys as the env-direct fallback."""
        _import_raptor()
        from core.config import RaptorConfig
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-SECRET")
        env = RaptorConfig.get_llm_env(include_python_user_base=True)
        assert env.get("ANTHROPIC_API_KEY") == "sk-ant-SECRET"
