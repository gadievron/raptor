"""Tests for provider creation and cost calculation.

Replaces the old multi-provider LiteLLM callback tests. Now tests
create_provider factory, SDK availability gating, split-pricing
cost calculation without any LiteLLM dependency, and endpoint/secret
redaction on provider error paths.
"""

import pytest
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

# Add parent directories to path for imports
# packages/llm_analysis/tests/test_llm_callbacks_providers.py -> repo root
sys.path.insert(0, str(Path(__file__).parents[3]))

from core.llm.config import ModelConfig
from core.llm.model_data import MODEL_COSTS
from core.llm.providers import _endpoint_display, _redact_endpoint
from core.llm.tool_use.types import Message, StopReason, TextBlock
import core.llm.providers as _providers_module


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

    @patch("core.llm.providers.ANTHROPIC_SDK_AVAILABLE", True)
    @patch("core.llm.providers.INSTRUCTOR_AVAILABLE", False)
    def test_returns_anthropic_provider(self):
        """create_provider('anthropic') returns AnthropicProvider."""
        mock_anthropic, cleanup = _ensure_mock_sdk(_providers_module, 'anthropic')
        try:
            from core.llm.providers import create_provider, AnthropicProvider
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
            with patch("core.llm.providers.OPENAI_SDK_AVAILABLE", True), \
                 patch("core.llm.providers.INSTRUCTOR_AVAILABLE", False):
                from core.llm.providers import create_provider, OpenAICompatibleProvider
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

    def test_returns_native_provider_for_gemini(self):
        """create_provider('gemini') returns GeminiProvider when google-genai is installed."""
        from core.llm.providers import GENAI_SDK_AVAILABLE
        if GENAI_SDK_AVAILABLE:
            from core.llm.providers import GeminiProvider, create_provider as _create
            config = ModelConfig(
                provider="gemini", model_name="gemini-2.5-pro",
                api_key="test-gemini-key",
                api_base="https://generativelanguage.googleapis.com/v1beta/openai",
            )
            provider = _create(config)
            assert isinstance(provider, GeminiProvider)
        else:
            self._make_provider("gemini", "gemini-2.5-pro", "test-gemini-key",
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

    @patch("core.llm.providers.OPENAI_SDK_AVAILABLE", False)
    @patch("core.llm.providers.ANTHROPIC_SDK_AVAILABLE", False)
    def test_raises_for_anthropic_without_sdk(self):
        """RuntimeError when neither Anthropic nor OpenAI SDK available for anthropic provider."""
        from core.llm.providers import create_provider

        config = ModelConfig(
            provider="anthropic",
            model_name="claude-sonnet-4-6",
            api_key="sk-ant-test",
        )

        with pytest.raises(RuntimeError, match="Anthropic provider requires"):
            create_provider(config)

    @patch("core.llm.providers.OPENAI_SDK_AVAILABLE", False)
    def test_raises_for_openai_without_sdk(self):
        """RuntimeError when OpenAI SDK not available for openai provider."""
        from core.llm.providers import create_provider

        config = ModelConfig(
            provider="openai",
            model_name="gpt-5.2",
            api_key="sk-test",
        )

        with pytest.raises(RuntimeError, match="requires.*pip install openai"):
            create_provider(config)

    @patch("core.llm.providers.OPENAI_SDK_AVAILABLE", False)
    def test_raises_for_ollama_without_sdk(self):
        """RuntimeError when OpenAI SDK not available for ollama provider."""
        from core.llm.providers import create_provider

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
        from core.llm.providers import LLMProvider

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

    def test_bedrock_form_id_resolves_rates(self):
        """Vendor/region-prefixed Bedrock ids resolve the bare model's
        MODEL_COSTS entry — same normalisation chain as
        context_window_for. Pre-fix they fell into the $0
        unknown-model path and budget caps were unenforced."""
        from core.llm.model_data import _bedrock_cost_multiplier
        bare = next(iter(MODEL_COSTS))
        rates = MODEL_COSTS[bare]
        for prefixed in (f"anthropic.{bare}", f"us.anthropic.{bare}"):
            provider = self._make_provider_instance(prefixed)
            mult = _bedrock_cost_multiplier(prefixed)
            expected = (
                (1000 / 1000) * rates["input"]
                + (500 / 1000) * rates["output"]
            ) * mult
            actual = provider._calculate_cost_split(1000, 500)
            assert abs(actual - expected) < 1e-10, prefixed
            assert actual > 0.0, prefixed

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

# NOTE: A duplicate ``TestThinkingModelFallback`` class previously
# lived here. Python silently discarded it when the same-named class
# at line ~334 was parsed at module scope (F811 hazard). The two defs
# were near-identical (one comment line of difference); the
# downstream copy is the one that actually ran and was being
# maintained. Removed the upstream duplicate as part of W14-E1
# DEEP-1b to make the F811 gate enforceable.


class TestModelCostsShape:
    """Verify the MODEL_COSTS table itself has the right shape.

    Was previously named ``TestCalculateCostSplit`` and silently
    shadowed the earlier class of the same name at line 159 — Python
    discards the first def when a second def at module scope shares the
    name, so the 4 tests in the first class never ran. Renamed to its
    actual purpose so both classes' tests now execute. See W14-E1
    DEEP-1b narrative."""

    def test_all_model_costs_have_input_output(self):
        """Every entry in MODEL_COSTS has both 'input' and 'output' keys."""
        for model_name, rates in MODEL_COSTS.items():
            assert "input" in rates, f"{model_name} missing 'input' rate"
            assert "output" in rates, f"{model_name} missing 'output' rate"
            assert rates["input"] >= 0, f"{model_name} has negative input rate"
            assert rates["output"] >= 0, f"{model_name} has negative output rate"


class TestThinkingModelFallback:
    """Verify reasoning_content fallback for Ollama thinking models."""

    def _make_ollama_provider(self):
        """Create an OpenAICompatibleProvider configured for Ollama."""
        mock_openai, cleanup = _ensure_mock_sdk(_providers_module, 'OpenAI')
        with patch("core.llm.providers.OPENAI_SDK_AVAILABLE", True), \
             patch("core.llm.providers.INSTRUCTOR_AVAILABLE", False):
            from core.llm.providers import OpenAICompatibleProvider
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


class TestContentFilterDetection:
    """Verify that content filter blocks and model refusals raise clear errors."""

    def _make_openai_provider(self):
        """Create an OpenAICompatibleProvider with mocked SDK."""
        mock_openai, cleanup = _ensure_mock_sdk(_providers_module, 'OpenAI')
        with patch("core.llm.providers.OPENAI_SDK_AVAILABLE", True), \
             patch("core.llm.providers.INSTRUCTOR_AVAILABLE", False):
            from core.llm.providers import OpenAICompatibleProvider
            config = ModelConfig(
                provider="openai", model_name="gpt-5.4",
                api_key="test-key", api_base="https://api.openai.com/v1",
            )
            provider = OpenAICompatibleProvider(config)
        return provider, mock_openai, cleanup

    def test_content_filter_raises(self):
        """finish_reason=content_filter with empty content raises RuntimeError."""
        provider, mock_openai, cleanup = self._make_openai_provider()
        try:
            response = MagicMock()
            response.choices = [MagicMock()]
            response.choices[0].message.content = ""
            response.choices[0].message.refusal = None
            response.choices[0].message.reasoning_content = None
            response.choices[0].finish_reason = "content_filter"
            response.usage = MagicMock()
            response.usage.prompt_tokens = 100
            response.usage.completion_tokens = 0
            response.usage.completion_tokens_details = None
            mock_openai.return_value.chat.completions.create.return_value = response

            with pytest.raises(RuntimeError, match="content filter"):
                provider.generate("generate exploit for buffer overflow")
        finally:
            cleanup()

    def test_refusal_raises(self):
        """Model refusal (o-series) raises RuntimeError."""
        provider, mock_openai, cleanup = self._make_openai_provider()
        try:
            response = MagicMock()
            response.choices = [MagicMock()]
            response.choices[0].message.content = ""
            response.choices[0].message.refusal = "I cannot help with exploit development"
            response.choices[0].message.reasoning_content = None
            response.choices[0].finish_reason = "stop"
            response.usage = MagicMock()
            response.usage.prompt_tokens = 100
            response.usage.completion_tokens = 0
            response.usage.completion_tokens_details = None
            mock_openai.return_value.chat.completions.create.return_value = response

            with pytest.raises(RuntimeError, match="refused request"):
                provider.generate("generate exploit")
        finally:
            cleanup()

    def test_normal_response_no_error(self):
        """Normal response with content passes through."""
        provider, mock_openai, cleanup = self._make_openai_provider()
        try:
            response = MagicMock()
            response.choices = [MagicMock()]
            response.choices[0].message.content = "This is exploitable."
            response.choices[0].message.refusal = None
            response.choices[0].message.reasoning_content = None
            response.choices[0].finish_reason = "stop"
            response.usage = MagicMock()
            response.usage.prompt_tokens = 100
            response.usage.completion_tokens = 50
            response.usage.completion_tokens_details = None
            mock_openai.return_value.chat.completions.create.return_value = response

            result = provider.generate("analyze this vulnerability")
            assert result.content == "This is exploitable."
        finally:
            cleanup()

    def test_content_filter_with_partial_content_passes(self):
        """content_filter with non-empty content passes through (partial response)."""
        provider, mock_openai, cleanup = self._make_openai_provider()
        try:
            response = MagicMock()
            response.choices = [MagicMock()]
            response.choices[0].message.content = "The vulnerability is..."
            response.choices[0].message.refusal = None
            response.choices[0].message.reasoning_content = None
            response.choices[0].finish_reason = "content_filter"
            response.usage = MagicMock()
            response.usage.prompt_tokens = 100
            response.usage.completion_tokens = 10
            response.usage.completion_tokens_details = None
            mock_openai.return_value.chat.completions.create.return_value = response

            result = provider.generate("analyze this")
            assert result.content == "The vulnerability is..."
            assert result.finish_reason == "content_filter"
        finally:
            cleanup()


# ---------------------------------------------------------------------------
# Endpoint / secret redaction on provider error paths.
#
# Remote ``api_base`` locations (e.g. a remote OLLAMA_HOST) must never
# reach logs — neither via the provider-init debug line nor via
# interpolated SDK exception text — and ``redact_secrets`` must be
# applied to SDK exception bodies before they are logged or placed in
# ``TurnResponse.error_message``.
# ---------------------------------------------------------------------------

# Documentation-only test host (TEST-NET-3, RFC 5737).
_REMOTE_HOST = "203.0.113.7"
_REMOTE_BASE = f"http://{_REMOTE_HOST}:11434/v1"
_FAKE_OPENAI_KEY = "sk-" + "a" * 48
_FAKE_ANTHROPIC_KEY = "sk-ant-" + "b" * 95


class _RecordingLogger:
    """Minimal logger stand-in capturing fully-formatted messages."""

    def __init__(self):
        self.messages: list[str] = []

    def _record(self, msg, *args):
        self.messages.append(msg % args if args else str(msg))

    debug = info = warning = error = _record


class TestEndpointHelpers:
    """Verify the _endpoint_display / _redact_endpoint scrub helpers."""

    def test_display_none_is_default(self):
        assert _endpoint_display(None) == "default"

    def test_display_loopback_verbatim(self):
        assert _endpoint_display("http://127.0.0.1:11434/v1") == (
            "http://127.0.0.1:11434/v1"
        )
        assert _endpoint_display("http://localhost:11434/v1") == (
            "http://localhost:11434/v1"
        )

    def test_display_remote_placeholder(self):
        out = _endpoint_display(_REMOTE_BASE)
        assert _REMOTE_HOST not in out
        assert out == "[REMOTE-ENDPOINT]"

    def test_redact_endpoint_netloc_and_bare_host(self):
        text = (
            f"Connection error for {_REMOTE_HOST}:11434 — "
            f"HTTPConnectionPool(host='{_REMOTE_HOST}', port=11434)"
        )
        out = _redact_endpoint(text, _REMOTE_BASE)
        assert _REMOTE_HOST not in out
        assert "[REMOTE-ENDPOINT]" in out

    def test_redact_endpoint_loopback_untouched(self):
        text = "refused by 127.0.0.1:11434"
        assert _redact_endpoint(text, "http://127.0.0.1:11434/v1") == text

    def test_redact_endpoint_no_base_untouched(self):
        assert _redact_endpoint("anything", None) == "anything"


def _openai_provider(monkeypatch, recorder):
    pytest.importorskip("openai")
    monkeypatch.setattr(_providers_module, "logger", recorder)
    return _providers_module.OpenAICompatibleProvider(ModelConfig(
        provider="ollama", model_name="test-model",
        api_key="unused", api_base=_REMOTE_BASE, timeout=1,
    ))


def _openai_status_error(message: str):
    import httpx
    import openai
    req = httpx.Request("POST", f"{_REMOTE_BASE}/chat/completions")
    resp = httpx.Response(400, request=req)
    return openai.APIStatusError(message, response=resp, body=None)


class _RaisingCompletions:
    def __init__(self, exc):
        self._exc = exc

    def create(self, **kwargs):
        raise self._exc


class _RaisingClient:
    def __init__(self, exc):
        self.chat = type("chat", (), {})()
        self.chat.completions = _RaisingCompletions(exc)


class TestOpenAIProviderRedaction:
    """Verify OpenAICompatibleProvider redacts endpoints and secrets."""

    def test_init_debug_log_has_no_remote_base(self, monkeypatch):
        recorder = _RecordingLogger()
        _openai_provider(monkeypatch, recorder)
        joined = "\n".join(recorder.messages)
        assert _REMOTE_HOST not in joined
        assert any("base_url=[REMOTE-ENDPOINT]" in m for m in recorder.messages)

    def test_turn_error_message_redacted(self, monkeypatch):
        recorder = _RecordingLogger()
        p = _openai_provider(monkeypatch, recorder)
        exc = _openai_status_error(
            f"400 from {_REMOTE_BASE}: Authorization: Bearer {_FAKE_OPENAI_KEY}"
        )
        p.client = _RaisingClient(exc)
        resp = p.turn(
            [Message(role="user", content=[TextBlock(text="hi")])],
            [], max_retries=0,
        )
        assert resp.stop_reason == StopReason.ERROR
        assert _FAKE_OPENAI_KEY not in resp.error_message
        assert _REMOTE_HOST not in resp.error_message
        joined = "\n".join(recorder.messages)
        assert _FAKE_OPENAI_KEY not in joined
        assert _REMOTE_HOST not in joined

    def test_turn_stream_warning_redacted(self, monkeypatch):
        recorder = _RecordingLogger()
        p = _openai_provider(monkeypatch, recorder)
        exc = _openai_status_error(
            f"stream fail at {_REMOTE_BASE} key {_FAKE_OPENAI_KEY}"
        )
        p.client = _RaisingClient(exc)
        chunks = list(p.turn_stream(
            [Message(role="user", content=[TextBlock(text="hi")])],
            [], max_retries=0,
        ))
        assert chunks[-1].stop_reason == StopReason.ERROR
        joined = "\n".join(recorder.messages)
        assert _FAKE_OPENAI_KEY not in joined
        assert _REMOTE_HOST not in joined

    def test_note_instructor_failure_redacted(self, monkeypatch):
        recorder = _RecordingLogger()
        p = _openai_provider(monkeypatch, recorder)
        recorder.messages.clear()
        p._note_instructor_failure(RuntimeError(
            f"x-api-key: {_FAKE_OPENAI_KEY} via {_REMOTE_HOST}:11434"
        ))
        joined = "\n".join(recorder.messages)
        assert "Instructor structured generation failed" in joined
        assert _FAKE_OPENAI_KEY not in joined
        assert _REMOTE_HOST not in joined
        assert "[REDACTED]" in joined


class _RaisingMessages:
    def __init__(self, exc):
        self._exc = exc

    def create(self, **kwargs):
        raise self._exc


class TestAnthropicProviderRedaction:
    """Verify AnthropicProvider redacts secrets on the turn error path."""

    def test_turn_error_message_redacted(self, monkeypatch):
        pytest.importorskip("anthropic")
        import anthropic
        import httpx

        recorder = _RecordingLogger()
        monkeypatch.setattr(_providers_module, "logger", recorder)
        p = _providers_module.AnthropicProvider(ModelConfig(
            provider="anthropic", model_name="claude-opus-4-6",
            api_key="test-key", timeout=1,
        ))
        req = httpx.Request("POST", "https://api.anthropic.com/v1/messages")
        resp = httpx.Response(400, request=req)
        exc = anthropic.APIStatusError(
            f"invalid request; x-api-key: {_FAKE_ANTHROPIC_KEY}",
            response=resp, body=None,
        )
        p.client = type(
            "client", (), {"messages": _RaisingMessages(exc)},
        )()
        turn = p.turn(
            [Message(role="user", content=[TextBlock(text="hi")])],
            [], max_retries=0,
        )
        assert turn.stop_reason == StopReason.ERROR
        assert _FAKE_ANTHROPIC_KEY not in turn.error_message
        assert "[REDACTED]" in turn.error_message
        joined = "\n".join(recorder.messages)
        assert _FAKE_ANTHROPIC_KEY not in joined
