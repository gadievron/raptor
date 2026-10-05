"""Tests for reasoning-tier eligibility of open-weight models.

Verifies that ``_get_best_thinking_model`` recognises open-weight
reasoning models (deepseek-r1, qwen3, qwq, ...) via stem matching and
the ``role: "thinking"`` config tag, not just the hard-coded cloud
pattern table.
"""
from __future__ import annotations

from unittest.mock import patch

import pytest

from core.llm.config import _get_best_thinking_model


@pytest.fixture(autouse=True)
def _reset_cache():
    import core.llm.config as cfg
    saved_checked = getattr(cfg, "_thinking_model_checked", False)
    saved_cached = getattr(cfg, "_cached_thinking_model", None)
    cfg._thinking_model_checked = False
    cfg._cached_thinking_model = None
    yield
    cfg._thinking_model_checked = saved_checked
    cfg._cached_thinking_model = saved_cached


def _mock_models(entries):
    """Patch ``_get_configured_models`` to return *entries*."""
    return patch("core.llm.config._get_configured_models", return_value=entries)


def _mock_ollama():
    """Prevent Ollama URL resolution from hitting real config."""
    return patch(
        "core.llm.config._validate_ollama_url",
        return_value="http://localhost:11434",
    )


class TestOpenWeightReasoningStemMatch:
    def test_deepseek_r1_eligible(self):
        with _mock_models([{"provider": "ollama", "model": "deepseek-r1:70b"}]), _mock_ollama():
            result = _get_best_thinking_model()
        assert result is not None
        assert result.model_name == "deepseek-r1:70b"

    def test_qwq_eligible(self):
        with _mock_models([{"provider": "ollama", "model": "qwq:32b"}]), _mock_ollama():
            result = _get_best_thinking_model()
        assert result is not None
        assert result.model_name == "qwq:32b"

    def test_qwen3_eligible(self):
        with _mock_models([{"provider": "ollama", "model": "qwen3:8b"}]), _mock_ollama():
            result = _get_best_thinking_model()
        assert result is not None
        assert result.model_name == "qwen3:8b"

    def test_marco_o1_eligible(self):
        with _mock_models([{"provider": "ollama", "model": "marco-o1:7b"}]), _mock_ollama():
            result = _get_best_thinking_model()
        assert result is not None
        assert result.model_name == "marco-o1:7b"

    def test_stem_match_case_insensitive(self):
        with _mock_models([{"provider": "ollama", "model": "DeepSeek-R1:70b"}]), _mock_ollama():
            result = _get_best_thinking_model()
        assert result is not None
        assert result.model_name == "DeepSeek-R1:70b"


class TestRoleThinkingStandalone:
    def test_unknown_model_with_thinking_role_eligible(self):
        entry = {"provider": "ollama", "model": "my-custom-reasoner:latest",
                 "role": "thinking"}
        with _mock_models([entry]), _mock_ollama():
            result = _get_best_thinking_model()
        assert result is not None
        assert result.model_name == "my-custom-reasoner:latest"
        assert result.role == "thinking"

    def test_reasoning_role_also_eligible(self):
        entry = {"provider": "ollama", "model": "custom:latest",
                 "role": "reasoning"}
        with _mock_models([entry]), _mock_ollama():
            result = _get_best_thinking_model()
        assert result is not None
        assert result.model_name == "custom:latest"

    def test_unknown_model_without_role_not_eligible(self):
        with _mock_models([{"provider": "ollama", "model": "my-custom-model:latest"}]):
            result = _get_best_thinking_model()
        assert result is None


class TestScoringPriority:
    def test_cloud_model_beats_local_stem(self):
        entries = [
            {"provider": "ollama", "model": "deepseek-r1:70b"},
            {"provider": "anthropic", "model": "claude-sonnet-4-6",
             "api_key": "sk-ant-test"},
        ]
        with _mock_models(entries), _mock_ollama():
            result = _get_best_thinking_model()
        assert result is not None
        assert result.model_name == "claude-sonnet-4-6"

    def test_role_boost_on_stem_match(self):
        entries = [
            {"provider": "ollama", "model": "deepseek-r1:70b",
             "role": "thinking"},
            {"provider": "ollama", "model": "qwq:32b"},
        ]
        with _mock_models(entries), _mock_ollama():
            result = _get_best_thinking_model()
        assert result is not None
        # deepseek-r1 stem=52 + role boost=10 = 62; qwq stem=50
        assert result.model_name == "deepseek-r1:70b"

    def test_role_only_lower_than_stem(self):
        entries = [
            {"provider": "ollama", "model": "custom-reasoner:latest",
             "role": "thinking"},
            {"provider": "ollama", "model": "qwq:32b"},
        ]
        with _mock_models(entries), _mock_ollama():
            result = _get_best_thinking_model()
        assert result is not None
        # custom role-only=40+10=50; qwq stem=50 -> tie, first-seen wins
        assert result.model_name == "custom-reasoner:latest"

    def test_empty_config_returns_none(self):
        with _mock_models([]):
            result = _get_best_thinking_model()
        assert result is None
