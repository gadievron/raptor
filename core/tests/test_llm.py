"""Tests for core.llm module after refactoring."""

import pytest
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core.llm import LLMClient, LLMConfig, LLMProvider
from core.llm.config import ModelConfig
from core.llm.providers import LLMResponse, create_provider


class TestLLMImports:
    """Test that LLM components are importable from core.llm."""

    def test_import_llm_client(self):
        """Test LLMClient can be imported from core.llm."""
        from core.llm import LLMClient
        assert LLMClient is not None

    def test_import_llm_config(self):
        """Test LLMConfig can be imported from core.llm."""
        from core.llm import LLMConfig
        assert LLMConfig is not None

    def test_import_llm_provider(self):
        """Test LLMProvider can be imported from core.llm."""
        from core.llm import LLMProvider
        assert LLMProvider is not None

    def test_import_from_submodules(self):
        """Test imports from submodules work."""
        from core.llm.client import LLMClient
        from core.llm.config import LLMConfig, ModelConfig
        from core.llm.providers import LLMProvider, LLMResponse, create_provider

        assert LLMClient is not None
        assert LLMConfig is not None
        assert ModelConfig is not None
        assert LLMProvider is not None
        assert LLMResponse is not None
        assert create_provider is not None


class TestModelConfig:
    """Tests for ModelConfig dataclass."""

    def test_model_config_defaults(self):
        """Test ModelConfig has correct defaults."""
        config = ModelConfig(
            provider="openai",
            model_name="gpt-4"
        )

        assert config.provider == "openai"
        assert config.model_name == "gpt-4"
        assert config.api_key is None
        assert config.max_tokens == 4096
        assert config.temperature == 0.7
        assert config.enabled is True

    def test_model_config_custom_values(self):
        """Test ModelConfig with custom values."""
        config = ModelConfig(
            provider="anthropic",
            model_name="claude-3-opus",
            api_key="test-key",
            max_tokens=8192,
            temperature=0.5,
            cost_per_1k_tokens=0.015
        )

        assert config.api_key == "test-key"
        assert config.max_tokens == 8192
        assert config.temperature == 0.5
        assert config.cost_per_1k_tokens == 0.015


class TestLLMConfig:
    """Tests for LLMConfig class."""

    def test_llm_config_defaults(self):
        """Test LLMConfig has sensible defaults."""
        config = LLMConfig()

        assert config.enable_fallback is True
        assert config.max_retries == 3
        assert config.enable_caching is True
        assert config.max_cost_per_scan == 10.0

    def test_get_model_for_task_returns_primary(self):
        """Test get_model_for_task returns primary when no specialized."""
        config = LLMConfig()
        model = config.get_model_for_task("unknown_task")

        assert model == config.primary_model

    def test_get_retry_delay_local(self):
        """Test retry delay for local servers."""
        config = LLMConfig()
        delay = config.get_retry_delay("http://localhost:11434")

        assert delay == config.retry_delay

    def test_get_retry_delay_remote(self):
        """Test retry delay for remote servers."""
        config = LLMConfig()
        delay = config.get_retry_delay("https://api.openai.com")

        assert delay == config.retry_delay_remote


class TestLLMResponse:
    """Tests for LLMResponse dataclass."""

    def test_llm_response_creation(self):
        """Test LLMResponse can be created."""
        response = LLMResponse(
            content="Hello, world!",
            model="gpt-4",
            provider="openai",
            tokens_used=10,
            cost=0.001,
            finish_reason="stop"
        )

        assert response.content == "Hello, world!"
        assert response.model == "gpt-4"
        assert response.provider == "openai"
        assert response.tokens_used == 10
        assert response.cost == 0.001
        assert response.finish_reason == "stop"
        assert response.raw_response is None


class TestCreateProvider:
    """Tests for create_provider factory function."""

    @patch('core.llm.providers.LiteLLMProvider')
    def test_create_provider_returns_litellm_provider(self, mock_provider_class):
        """Test that create_provider returns a LiteLLMProvider."""
        config = ModelConfig(provider="openai", model_name="gpt-4")

        # Mock the provider constructor
        mock_provider = MagicMock()
        mock_provider_class.return_value = mock_provider

        result = create_provider(config)

        mock_provider_class.assert_called_once_with(config)
        assert result == mock_provider
