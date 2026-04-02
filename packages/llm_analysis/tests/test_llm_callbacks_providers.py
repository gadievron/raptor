"""Tests for provider creation and cost calculation.

Replaces the old multi-provider LiteLLM callback tests. Now tests
create_provider factory, SDK availability gating, and split-pricing
cost calculation without any LiteLLM dependency.
"""

import pytest
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

# Add parent directories to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from packages.llm_analysis.llm.config import ModelConfig
from packages.llm_analysis.llm.model_data import MODEL_COSTS
import packages.llm_analysis.llm.providers as _providers_module


def _ensure_mock_sdk(module, attr_name):
    """Ensure a mock is set on the module for a conditionally imported SDK.

    Returns (mock, cleanup_fn). Call cleanup_fn after the test to restore state.
    """
    original = getattr(module, attr_name, None)
    mock = MagicMock()
    setattr(module, attr_name, mock)

    def cleanup():
        if original is not None:
            setattr(module, attr_name, original)
        elif hasattr(module, attr_name):
            delattr(module, attr_name)

    return mock, cleanup


class TestCreateProviderAnthropicRoute:
    """Verify create_provider returns AnthropicProvider for 'anthropic'."""

    @patch("packages.llm_analysis.llm.providers.ANTHROPIC_SDK_AVAILABLE", True)
    @patch("packages.llm_analysis.llm.providers.INSTRUCTOR_AVAILABLE", False)
    def test_returns_anthropic_provider(self):
        """create_provider('anthropic') returns AnthropicProvider."""
        mock_anthropic, cleanup = _ensure_mock_sdk(_providers_module, 'anthropic')
        try:
            from packages.llm_analysis.llm.providers import create_provider, AnthropicProvider
            config = ModelConfig(
                provider="anthropic",
                model_name="claude-sonnet-4-6",
                api_key="sk-ant-test-key",
            )
            provider = create_provider(config)
            assert isinstance(provider, AnthropicProvider)
        finally:
            cleanup()


class TestCreateProviderOpenAIRoute:
    """Verify create_provider returns OpenAICompatibleProvider for OpenAI-compatible providers."""

    def _make_provider(self, provider_name, model_name, api_key=None, api_base=None):
        """Helper to create a provider with mocked OpenAI SDK."""
        mock_openai, cleanup = _ensure_mock_sdk(_providers_module, 'OpenAI')
        try:
            with patch("packages.llm_analysis.llm.providers.OPENAI_SDK_AVAILABLE", True), \
                 patch("packages.llm_analysis.llm.providers.INSTRUCTOR_AVAILABLE", False):
                from packages.llm_analysis.llm.providers import create_provider, OpenAICompatibleProvider
                config = ModelConfig(
                    provider=provider_name,
                    model_name=model_name,
                    api_key=api_key,
                    api_base=api_base,
                )
                provider = create_provider(config)
                assert isinstance(provider, OpenAICompatibleProvider)
        finally:
            cleanup()

    def test_returns_openai_provider_for_openai(self):
        """create_provider('openai') returns OpenAICompatibleProvider."""
        self._make_provider("openai", "gpt-5.2", "sk-test", "https://api.openai.com/v1")

    def test_returns_openai_provider_for_gemini(self):
        """create_provider('gemini') returns OpenAICompatibleProvider."""
        self._make_provider("gemini", "gemini-2.5-pro", "AIza-test",
                           "https://generativelanguage.googleapis.com/v1beta/openai")

    def test_returns_openai_provider_for_mistral(self):
        """create_provider('mistral') returns OpenAICompatibleProvider."""
        self._make_provider("mistral", "mistral-large-latest", "test-key",
                           "https://api.mistral.ai/v1")

    def test_returns_openai_provider_for_ollama(self):
        """create_provider('ollama') returns OpenAICompatibleProvider."""
        self._make_provider("ollama", "mistral", api_base="http://localhost:11434/v1")


class TestCreateProviderSDKUnavailable:
    """Verify create_provider raises RuntimeError when SDK is not available."""

    @patch("packages.llm_analysis.llm.providers.OPENAI_SDK_AVAILABLE", False)
    @patch("packages.llm_analysis.llm.providers.ANTHROPIC_SDK_AVAILABLE", False)
    def test_raises_for_anthropic_without_sdk(self):
        """RuntimeError when neither Anthropic nor OpenAI SDK available for anthropic provider."""
        from packages.llm_analysis.llm.providers import create_provider

        config = ModelConfig(
            provider="anthropic",
            model_name="claude-sonnet-4-6",
            api_key="sk-ant-test",
        )

        with pytest.raises(RuntimeError, match="Anthropic provider requires"):
            create_provider(config)

    @patch("packages.llm_analysis.llm.providers.OPENAI_SDK_AVAILABLE", False)
    def test_raises_for_openai_without_sdk(self):
        """RuntimeError when OpenAI SDK not available for openai provider."""
        from packages.llm_analysis.llm.providers import create_provider

        config = ModelConfig(
            provider="openai",
            model_name="gpt-5.2",
            api_key="sk-test",
        )

        with pytest.raises(RuntimeError, match="requires.*pip install openai"):
            create_provider(config)

    @patch("packages.llm_analysis.llm.providers.OPENAI_SDK_AVAILABLE", False)
    def test_raises_for_ollama_without_sdk(self):
        """RuntimeError when OpenAI SDK not available for ollama provider."""
        from packages.llm_analysis.llm.providers import create_provider

        config = ModelConfig(
            provider="ollama",
            model_name="mistral",
            api_base="http://localhost:11434/v1",
        )

        with pytest.raises(RuntimeError, match="requires.*pip install openai"):
            create_provider(config)


class TestCalculateCostSplit:
    """Verify _calculate_cost_split uses MODEL_COSTS for known models."""

    def _make_provider_instance(self, model_name, cost_per_1k=0.0):
        """Create a minimal provider instance for cost testing."""
        from packages.llm_analysis.llm.providers import LLMProvider

        config = ModelConfig(
            provider="openai",
            model_name=model_name,
            api_key="sk-test",
            api_base="https://api.openai.com/v1",
            cost_per_1k_tokens=cost_per_1k,
        )

        # Create instance bypassing abstract methods
        with patch.multiple(LLMProvider, __abstractmethods__=set()):
            provider = LLMProvider.__new__(LLMProvider)
            provider.config = config
            provider.total_tokens = 0
            provider.total_cost = 0.0

        return provider

    def test_known_model_uses_split_pricing(self):
        """Known models use per-token input/output rates from MODEL_COSTS."""
        model_name = next(iter(MODEL_COSTS))
        rates = MODEL_COSTS[model_name]

        provider = self._make_provider_instance(model_name)

        input_tokens = 1000
        output_tokens = 500

        expected_cost = (
            (input_tokens / 1000) * rates["input"]
            + (output_tokens / 1000) * rates["output"]
        )

        actual_cost = provider._calculate_cost_split(input_tokens, output_tokens)
        assert abs(actual_cost - expected_cost) < 1e-10

    def test_unknown_model_uses_cost_per_1k(self):
        """Unknown models fall back to cost_per_1k_tokens flat rate."""
        provider = self._make_provider_instance(
            model_name="unknown-model-xyz",
            cost_per_1k=0.005,
        )

        input_tokens = 1000
        output_tokens = 500

        expected_cost = ((input_tokens + output_tokens) / 1000) * 0.005

        actual_cost = provider._calculate_cost_split(input_tokens, output_tokens)
        assert abs(actual_cost - expected_cost) < 1e-10

    def test_unknown_model_zero_cost(self):
        """Unknown model with no cost_per_1k_tokens returns 0."""
        provider = self._make_provider_instance(
            model_name="local-model",
            cost_per_1k=0.0,
        )

        actual_cost = provider._calculate_cost_split(2000, 1000)
        assert actual_cost == 0.0

    def test_zero_tokens_returns_zero(self):
        """Zero input and output tokens returns zero cost."""
        model_name = next(iter(MODEL_COSTS))
        provider = self._make_provider_instance(model_name)

        actual_cost = provider._calculate_cost_split(0, 0)
        assert actual_cost == 0.0

class TestThinkingModelFallback:
    """Verify reasoning_content fallback for Ollama thinking models."""

    def _make_ollama_provider(self):
        """Create an OpenAICompatibleProvider configured for Ollama."""
        mock_openai, cleanup = _ensure_mock_sdk(_providers_module, 'OpenAI')
        with patch("packages.llm_analysis.llm.providers.OPENAI_SDK_AVAILABLE", True), \
             patch("packages.llm_analysis.llm.providers.INSTRUCTOR_AVAILABLE", False):
            from packages.llm_analysis.llm.providers import OpenAICompatibleProvider
            config = ModelConfig(
                provider="ollama", model_name="qwen3:8b",
                api_base="http://localhost:11434/v1",
            )
            provider = OpenAICompatibleProvider(config)
        return provider, mock_openai, cleanup

    def test_reasoning_content_used_when_content_empty(self):
        """Thinking models with empty content fall back to reasoning_content."""
        provider, mock_openai, cleanup = self._make_ollama_provider()
        try:
            response = MagicMock()
            response.choices = [MagicMock()]
            response.choices[0].message.content = ""
            response.choices[0].message.reasoning_content = "The answer is 42"
            response.choices[0].message.refusal = None
            response.choices[0].finish_reason = "stop"
            response.usage = MagicMock()
            response.usage.prompt_tokens = 50
            response.usage.completion_tokens = 10
            response.usage.completion_tokens_details = None
            mock_openai.return_value.chat.completions.create.return_value = response

            result = provider.generate("What is the answer?")
            assert result.content == "The answer is 42"
        finally:
            cleanup()

    def test_content_preferred_over_reasoning_content(self):
        """When content is present, reasoning_content is not used."""
        provider, mock_openai, cleanup = self._make_ollama_provider()
        try:
            response = MagicMock()
            response.choices = [MagicMock()]
            response.choices[0].message.content = "Normal response"
            response.choices[0].message.reasoning_content = "Thinking process..."
            response.choices[0].message.refusal = None
            response.choices[0].finish_reason = "stop"
            response.usage = MagicMock()
            response.usage.prompt_tokens = 50
            response.usage.completion_tokens = 10
            response.usage.completion_tokens_details = None
            mock_openai.return_value.chat.completions.create.return_value = response

            result = provider.generate("test")
            assert result.content == "Normal response"
        finally:
            cleanup()

    def test_both_empty_returns_empty(self):
        """When both content and reasoning_content are empty, returns empty."""
        provider, mock_openai, cleanup = self._make_ollama_provider()
        try:
            response = MagicMock()
            response.choices = [MagicMock()]
            response.choices[0].message.content = ""
            response.choices[0].message.reasoning_content = ""
            response.choices[0].message.refusal = None
            response.choices[0].finish_reason = "stop"
            response.usage = MagicMock()
            response.usage.prompt_tokens = 50
            response.usage.completion_tokens = 0
            response.usage.completion_tokens_details = None
            mock_openai.return_value.chat.completions.create.return_value = response

            result = provider.generate("test")
            assert result.content == ""
        finally:
            cleanup()

    def test_no_reasoning_content_attr(self):
        """Models without reasoning_content attribute work normally."""
        provider, mock_openai, cleanup = self._make_ollama_provider()
        try:
            response = MagicMock()
            response.choices = [MagicMock()]
            response.choices[0].message.content = "Normal response"
            # No reasoning_content attribute
            del response.choices[0].message.reasoning_content
            response.choices[0].message.refusal = None
            response.choices[0].finish_reason = "stop"
            response.usage = MagicMock()
            response.usage.prompt_tokens = 50
            response.usage.completion_tokens = 10
            response.usage.completion_tokens_details = None
            mock_openai.return_value.chat.completions.create.return_value = response

            result = provider.generate("test")
            assert result.content == "Normal response"
        finally:
            cleanup()


class TestCalculateCostSplit:
    """Verify _calculate_cost_split uses MODEL_COSTS for known models."""

    def test_all_model_costs_have_input_output(self):
        """Every entry in MODEL_COSTS has both 'input' and 'output' keys."""
        for model_name, rates in MODEL_COSTS.items():
            assert "input" in rates, f"{model_name} missing 'input' rate"
            assert "output" in rates, f"{model_name} missing 'output' rate"
            assert rates["input"] >= 0, f"{model_name} has negative input rate"
            assert rates["output"] >= 0, f"{model_name} has negative output rate"
