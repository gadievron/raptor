#!/usr/bin/env python3
"""
Unit tests for quota/rate limit error detection and guidance.

Related: Gemini quota exhaustion issue (Dec 2025)

Fixtures are transport-shaped: the message arms of ``_is_quota_error``
require transport corroboration (a typed SDK error, ``status_code``, or
a transport module root — see
``core.llm.providers.is_api_transport_exception``), so the vocabulary
and anchoring pins here ride a transport-rooted exception type. The
gate itself (content-level matches are inert) is pinned in
``test_transport_gated_classifiers.py``.
"""

import pytest
from core.llm.client import _is_quota_error, _get_quota_guidance


class _TransportError(Exception):
    """Stand-in for an SDK/HTTP transport exception."""
    __module__ = "httpx"


class TestQuotaErrorDetection:
    """Tests for _is_quota_error() function."""

    def test_detects_http_429_error(self):
        """Should detect HTTP 429 (Rate Limit) status code."""
        error = _TransportError("HTTP error 429: Too Many Requests")
        assert _is_quota_error(error) is True

    def test_detects_quota_exceeded_message(self):
        """Should detect 'quota exceeded' in error message."""
        error = _TransportError("API quota exceeded for this month")
        assert _is_quota_error(error) is True

    def test_detects_rate_limit_message(self):
        """Should detect 'rate limit' in error message."""
        error = _TransportError("Rate limit reached, please try again later")
        assert _is_quota_error(error) is True

    def test_detects_gemini_free_tier_quota(self):
        """Should detect Gemini-specific free tier quota error."""
        error = _TransportError(
            "You exceeded your current quota, please check your plan and billing details. "
            "Quota exceeded for: generate_content_free_tier_input_token_count"
        )
        assert _is_quota_error(error) is True

    def test_case_insensitive_detection(self):
        """Should detect quota errors regardless of case."""
        error1 = _TransportError("QUOTA EXCEEDED")
        error2 = _TransportError("quota exceeded")
        error3 = _TransportError("Quota Exceeded")

        assert _is_quota_error(error1) is True
        assert _is_quota_error(error2) is True
        assert _is_quota_error(error3) is True

    def test_detects_quota_and_exceeded_separately(self):
        """Should detect when 'quota' and 'exceeded' appear separately."""
        error = _TransportError("Your quota has been exceeded")
        assert _is_quota_error(error) is True

    def test_non_quota_error_returns_false(self):
        """Should return False for non-quota errors."""
        errors = [
            _TransportError("Connection timeout"),
            _TransportError("Invalid API key"),
            _TransportError("Model not found"),
            _TransportError("Internal server error"),
            _TransportError("Network unreachable"),
        ]

        for error in errors:
            assert _is_quota_error(error) is False, f"Incorrectly detected quota error: {error}"

    def test_bare_429_digits_do_not_false_positive(self):
        """"429" needs status context — a stack-trace line number,
        byte offset, or id containing the digits must not classify as
        quota (retryable), or a fatal error burns the full retry
        budget and corrupts the telemetry disposition."""
        errors = [
            _TransportError('File "worker.py", line 429, in dispatch'),
            _TransportError("HTTP 4290 is not a real status"),
            _TransportError("invalid byte at offset 429 in response"),
            _TransportError("request id req-429-abc failed schema validation"),
        ]
        for error in errors:
            assert _is_quota_error(error) is False, (
                f"Incorrectly detected quota error: {error}"
            )

    def test_context_anchored_429_still_detected(self):
        """Genuine 429 shapes keep classifying after the anchoring."""
        errors = [
            _TransportError("Error code: 429 - rate limited"),
            _TransportError("429 Too Many Requests"),
            _TransportError("HTTP error 429: Too Many Requests"),
            _TransportError("status 429 returned by upstream"),
            _TransportError("rate_limit_error: slow down"),
            # Provider phrasings the first anchored cut missed.
            _TransportError("API Error: 429"),
            _TransportError("rate limiting in effect, retry later"),
            _TransportError("you have exceeded your rate limits"),
            _TransportError("upstream rate-limited the request"),
        ]
        for error in errors:
            assert _is_quota_error(error) is True, (
                f"Missed quota error: {error}"
            )


class TestQuotaGuidance:
    """Tests for _get_quota_guidance() function."""

    def test_gemini_guidance_by_provider(self):
        """Should return Gemini-specific detection message when provider is 'gemini'."""
        guidance = _get_quota_guidance("gemini-2.5-pro", "gemini")

        assert "Google Gemini quota/rate limit exceeded" in guidance

    def test_gemini_guidance_by_model_name(self):
        """Should return Gemini-specific detection message when provider is 'google'."""
        guidance = _get_quota_guidance("gemini-3-pro", "google")

        assert "Google Gemini quota/rate limit exceeded" in guidance

    def test_openai_guidance_by_provider(self):
        """Should return OpenAI-specific detection message when provider is 'openai'."""
        guidance = _get_quota_guidance("gpt-4o-mini", "openai")

        assert "OpenAI rate limit exceeded" in guidance

    def test_openai_guidance_for_gpt_models(self):
        """Should return OpenAI detection message for models with 'gpt' in name."""
        guidance = _get_quota_guidance("gpt-5.2", "openai")

        assert "OpenAI rate limit exceeded" in guidance

    def test_openai_guidance_for_o1_models(self):
        """Should return OpenAI detection message for o1 reasoning models."""
        guidance = _get_quota_guidance("o1-preview", "openai")

        assert "OpenAI rate limit exceeded" in guidance

    def test_anthropic_guidance_by_provider(self):
        """Should return Anthropic-specific detection message when provider is 'anthropic'."""
        guidance = _get_quota_guidance("claude-sonnet-4.5", "anthropic")

        assert "Anthropic rate limit exceeded" in guidance

    def test_anthropic_guidance_for_claude_models(self):
        """Should return Anthropic detection message for models with 'claude' in name."""
        guidance = _get_quota_guidance("claude-opus-4.5", "anthropic")

        assert "Anthropic rate limit exceeded" in guidance

    def test_generic_guidance_for_unknown_provider(self):
        """Should return Ollama-specific detection message for Ollama provider."""
        guidance = _get_quota_guidance("llama3:70b", "ollama")

        assert "Ollama server limit exceeded" in guidance

    def test_truly_unknown_provider_guidance(self):
        """Should return generic detection message for truly unknown providers."""
        guidance = _get_quota_guidance("some-model", "azure")

        assert "Azure rate limit exceeded" in guidance

    def test_all_guidance_is_simple_and_clear(self):
        """All guidance should be simple detection messages."""
        providers_and_models = [
            ("gemini", "gemini-3-pro"),
            ("openai", "gpt-5.2"),
            ("anthropic", "claude-sonnet-4.5"),
        ]

        for provider, model in providers_and_models:
            guidance = _get_quota_guidance(model, provider)
            # Check for simple detection message
            assert "exceeded" in guidance.lower(), \
                f"Guidance for {provider}/{model} missing detection message"

    def test_guidance_format_starts_with_arrow(self):
        """Guidance should start with newline and arrow for visibility."""
        guidance = _get_quota_guidance("gemini-3-pro", "gemini")

        # Should start with newline and arrow
        assert guidance.startswith("\n→")


class TestQuotaDetectionIntegration:
    """Integration tests for quota detection in error handling."""

    def test_quota_detection_with_real_gemini_error_message(self):
        """Should detect real Gemini quota error from production."""
        # Real error message from Gemini API
        real_error = _TransportError(
            '{"code": 429, "message": "You exceeded your current quota, '
            'please check your plan and billing details", "details": '
            '"Quota exceeded for: generate_content_free_tier_input_token_count, '
            'limit: 0"}'
        )

        assert _is_quota_error(real_error) is True

        guidance = _get_quota_guidance("gemini-2.5-pro", "gemini")
        assert "Google Gemini quota/rate limit exceeded" in guidance

    def test_quota_detection_with_real_openai_error_message(self):
        """Should detect real OpenAI rate limit error from production."""
        # Real error message from OpenAI API
        real_error = _TransportError(
            "Error code: 429 - {'error': {'message': 'Rate limit reached for "
            "gpt-5.2 in organization org-xxx on tokens per min (TPM)', 'type': "
            "'tokens', 'param': null, 'code': 'rate_limit_exceeded'}}"
        )

        assert _is_quota_error(real_error) is True

        guidance = _get_quota_guidance("gpt-5.2", "openai")
        assert "OpenAI rate limit exceeded" in guidance

    def test_non_quota_errors_not_falsely_detected(self):
        """Should not falsely detect quota errors in unrelated error messages."""
        # Real error messages that mention "limit" but aren't quota errors
        non_quota_errors = [
            _TransportError("Connection timeout limit exceeded"),
            _TransportError("Maximum retries limit reached"),
            _TransportError("Token limit in prompt exceeded (reduce prompt size)"),
        ]

        for error in non_quota_errors:
            # These shouldn't be detected as quota errors (no "quota" or "429")
            assert _is_quota_error(error) is False, \
                f"Falsely detected quota error: {error}"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
