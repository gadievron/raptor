"""Tests for LLMClient initialization, error detection, and log sanitization.

Replaces the old LiteLLM callback tests. Now tests the provider-based
architecture (OpenAI SDK + Anthropic SDK) without any LiteLLM dependency.
"""

import pytest
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

# Add parent directories to path for imports
# packages/llm_analysis/tests/test_llm_callbacks.py -> repo root
sys.path.insert(0, str(Path(__file__).parents[3]))

from core.llm.client import (
    LLMClient,
    _is_auth_error,
    _is_quota_error,
    _sanitize_log_message,
)
from core.llm.config import LLMConfig, ModelConfig


class TestLLMClientInit:
    """Verify LLMClient initializes correctly without litellm."""

    @patch("core.llm.config.detect_llm_availability")
    def test_init_works_without_litellm(self, mock_detect):
        """LLMClient should initialize without importing litellm."""
        mock_detect.return_value = MagicMock(
            external_llm=True, claude_code=False, llm_available=True
        )
        config = LLMConfig(
            primary_model=ModelConfig(
                provider="openai",
                model_name="gpt-5.2",
                api_key="sk-test",
            ),
            fallback_models=[],
        )

        # Ensure litellm is NOT required
        with patch.dict(sys.modules, {"litellm": None}):
            client = LLMClient(config)

        assert client is not None
        assert client.total_cost == 0.0
        assert client.request_count == 0

    @patch("core.llm.config.detect_llm_availability")
    def test_init_warns_when_no_llm_available(self, mock_detect):
        """LLMClient warns when no external LLM is available."""
        mock_detect.return_value = MagicMock(
            external_llm=False, claude_code=False, llm_available=False
        )
        config = LLMConfig(
            primary_model=None,
            fallback_models=[],
        )

        # Capture warning calls from the logger
        warning_messages = []
        with patch("core.llm.client.logger") as mock_logger:
            mock_logger.warning = lambda msg, *a, **kw: warning_messages.append(msg)
            mock_logger.info = MagicMock()
            mock_logger.debug = MagicMock()
            LLMClient(config)

        assert any("No external LLM available" in msg or "no primary model" in msg.lower()
                    for msg in warning_messages), (
            f"Expected warning about no LLM. Got: {warning_messages}"
        )


class TestIsAuthError:
    """Verify _is_auth_error detects auth errors from both SDKs."""

    def test_detects_openai_authentication_error(self):
        """Detect openai.AuthenticationError by type."""
        try:
            import openai
            # Create a mock AuthenticationError
            mock_response = MagicMock()
            mock_response.status_code = 401
            mock_response.headers = {}
            error = openai.AuthenticationError(
                message="Invalid API key",
                response=mock_response,
                body=None,
            )
            assert _is_auth_error(error) is True
        except ImportError:
            pytest.skip("openai SDK not installed")

    def test_detects_anthropic_authentication_error(self):
        """Detect anthropic.AuthenticationError by type."""
        try:
            import anthropic
            mock_response = MagicMock()
            mock_response.status_code = 401
            mock_response.headers = {}
            error = anthropic.AuthenticationError(
                message="Invalid API key",
                response=mock_response,
                body=None,
            )
            assert _is_auth_error(error) is True
        except (ImportError, TypeError):
            pytest.skip("anthropic SDK not installed or constructor incompatible")

    def test_detects_string_based_401(self):
        """Detect auth errors from string indicators."""
        assert _is_auth_error(Exception("HTTP 401 Unauthorized")) is True

    def test_detects_string_based_invalid_api_key(self):
        """Detect 'invalid api key' in error message."""
        assert _is_auth_error(Exception("Error: invalid api key provided")) is True

    def test_detects_string_based_permission_denied(self):
        """Detect 'permission denied' in error message."""
        assert _is_auth_error(Exception("permission denied for resource")) is True

    def test_non_auth_error_returns_false(self):
        """Non-auth errors should return False."""
        assert _is_auth_error(Exception("Connection timeout")) is False
        assert _is_auth_error(ValueError("bad value")) is False


class TestIsQuotaError:
    """Verify _is_quota_error detects rate limit errors from both SDKs."""

    def test_detects_openai_rate_limit_error(self):
        """Detect openai.RateLimitError by type."""
        try:
            import openai
            mock_response = MagicMock()
            mock_response.status_code = 429
            mock_response.headers = {}
            error = openai.RateLimitError(
                message="Rate limit exceeded",
                response=mock_response,
                body=None,
            )
            assert _is_quota_error(error) is True
        except ImportError:
            pytest.skip("openai SDK not installed")

    def test_detects_anthropic_rate_limit_error(self):
        """Detect anthropic.RateLimitError by type."""
        try:
            import anthropic
            mock_response = MagicMock()
            mock_response.status_code = 429
            mock_response.headers = {}
            error = anthropic.RateLimitError(
                message="Rate limit exceeded",
                response=mock_response,
                body=None,
            )
            assert _is_quota_error(error) is True
        except (ImportError, TypeError):
            pytest.skip("anthropic SDK not installed or constructor incompatible")

    def test_detects_string_based_429(self):
        """Detect 429 status code in error message."""
        assert _is_quota_error(Exception("Error 429: Too Many Requests")) is True

    def test_detects_string_based_quota_exceeded(self):
        """Detect 'quota exceeded' in error message."""
        assert _is_quota_error(Exception("quota exceeded for this billing period")) is True

    def test_detects_string_based_rate_limit(self):
        """Detect 'rate limit' in error message."""
        assert _is_quota_error(Exception("rate limit reached, try again later")) is True

    def test_detects_gemini_free_tier(self):
        """Detect Gemini-specific free tier quota error."""
        assert _is_quota_error(Exception("generate_content_free_tier limit hit")) is True

    def test_non_quota_error_returns_false(self):
        """Non-quota errors should return False."""
        assert _is_quota_error(Exception("Connection timeout")) is False
        assert _is_quota_error(ValueError("bad value")) is False


class TestSanitizeLogMessage:
    """Verify _sanitize_log_message redacts secrets from logs."""

    def test_redacts_openai_api_key(self):
        """OpenAI-style sk-* keys are redacted."""
        key = "sk-proj-" + "a" * 48
        result = _sanitize_log_message(f"Error with key {key}")
        assert key not in result
        assert "[REDACTED-API-KEY]" in result

    def test_redacts_anthropic_api_key(self):
        """Anthropic-style sk-ant-* keys are redacted."""
        key = "sk-" + "ant-api03-" + "b" * 48
        result = _sanitize_log_message(f"Auth failed: {key}")
        assert key not in result
        assert "[REDACTED-API-KEY]" in result

    def test_redacts_google_api_key(self):
        """Google-style AIza* keys are redacted."""
        key = "AIza" + "c" * 36
        result = _sanitize_log_message(f"Invalid key: {key}")
        assert key not in result
        assert "[REDACTED-API-KEY]" in result

    def test_redacts_bearer_token(self):
        """Bearer tokens in auth headers or SDK errors are redacted."""
        bearer = "Bearer " + "d" * 48
        result = _sanitize_log_message(f"Authorization failed for {bearer}")
        assert bearer not in result
        assert "Bearer [REDACTED]" in result

    def test_redacts_dotted_bearer_jwt(self):
        """JWT-shaped bearer values are fully redacted, not only the first segment."""
        bearer = "Bearer " + ".".join(["a" * 24, "b" * 24, "c" * 24])
        result = _sanitize_log_message(f"Authorization failed for {bearer}")
        assert bearer not in result
        assert "a" * 24 not in result
        assert "b" * 24 not in result
        assert "c" * 24 not in result
        assert "Bearer [REDACTED]" in result

    def test_redacts_lowercase_bearer_jwt(self):
        """HTTP auth scheme casing should not prevent bearer redaction."""
        bearer = "bearer " + ".".join(["a" * 24, "b" * 24, "c" * 24])
        result = _sanitize_log_message(f"Authorization failed for {bearer}")
        assert bearer not in result
        assert "b" * 24 not in result
        assert "Bearer [REDACTED]" in result

    def test_redacts_github_tokens(self):
        """GitHub tokens can appear in tool errors and should not be logged."""
        tokens = [
            "ghp_" + "e" * 36,
            "ghr_" + "e" * 36,
            "github_pat_" + "f" * 82,
        ]
        result = _sanitize_log_message("Tokens: " + " ".join(tokens))
        for token in tokens:
            assert token not in result
        assert result.count("[REDACTED-API-KEY]") == len(tokens)

    def test_redacts_aws_access_key_id(self):
        """AWS access key IDs are redacted from command/tool output."""
        key = "AKIA" + "IOSFODNN7EXAMPLE"
        result = _sanitize_log_message(f"AWS key leaked in trace: {key}")
        assert key not in result
        assert "[REDACTED-API-KEY]" in result

    def test_redacts_temporary_aws_access_key_id(self):
        """Temporary AWS ASIA access key IDs are redacted too."""
        key = "ASIA" + "IOSFODNN7EXAMPLE"
        result = _sanitize_log_message(f"temporary AWS key leaked in trace: {key}")
        assert key not in result
        assert "[REDACTED-API-KEY]" in result

    def test_preserves_boundary_length_non_tokens(self):
        """Values below secret length thresholds should not be redacted."""
        bearer = "Bearer " + "d" * 19
        github_token = "ghp_" + "e" * 35
        message = f"Authorization failed for {bearer}; token={github_token}"
        assert _sanitize_log_message(message) == message

    def test_preserves_non_key_content(self):
        """Non-key content should be preserved."""
        msg = "Connection timeout after 30s to api.openai.com"
        result = _sanitize_log_message(msg)
        assert result == msg

    def test_redacts_multiple_secret_types(self):
        """Multiple secret types in one message are all redacted."""
        openai_key = "sk-" + "a" * 48
        google_key = "AIza" + "b" * 36
        github_key = "gho_" + "c" * 36
        result = _sanitize_log_message(
            f"Tried {openai_key} then {google_key} then {github_key}"
        )
        assert openai_key not in result
        assert google_key not in result
        assert github_key not in result
        assert result.count("[REDACTED-API-KEY]") == 3

    def test_redacts_named_secret_assignments(self):
        """Key/value log lines for secret-looking fields redact the value."""
        values = [
            ("OPENAI_API_KEY", "oa-" + "g" * 38),
            ("AWS_SECRET_ACCESS_KEY", "h" * 40),
            ("SERVICE_TOKEN", "tok_" + "i" * 36),
            ("DATABASE_PASSWORD", "pw-" + "j" * 32),
        ]
        message = " ".join(f"{name}={value}" for name, value in values)
        result = _sanitize_log_message(message)
        for name, value in values:
            assert value not in result
            assert f"{name}=[REDACTED-API-KEY]" in result

    def test_redacts_quoted_json_secret_fields(self):
        """JSON-ish secret fields from SDK errors redact quoted values."""
        api_value = "api-" + "k" * 36
        session_value = "sess_" + "l" * 36
        result = _sanitize_log_message(
            f'{{"api_key": "{api_value}", "session_token": "{session_value}"}}'
        )
        assert api_value not in result
        assert session_value not in result
        assert '"api_key": "[REDACTED-API-KEY]"' in result
        assert '"session_token": "[REDACTED-API-KEY]"' in result

    def test_redacts_basic_authorization_header(self):
        """Basic auth credentials in headers are redacted like bearer tokens."""
        credentials = "Basic " + "b" * 44 + "=="
        result = _sanitize_log_message(f"Authorization failed for {credentials}")
        assert credentials not in result
        assert "Basic [REDACTED]" in result

    def test_redacts_short_basic_authorization_with_flexible_whitespace(self):
        """Basic auth is sensitive by scheme, even when short or tab-separated."""
        short_basic = "Basic " + "dXNlcjpwYXNz"
        tab_basic = "Basic\t" + "b" * 24
        result = _sanitize_log_message(f"Headers: {short_basic} and {tab_basic}")
        assert short_basic not in result
        assert tab_basic not in result
        assert result.count("Basic [REDACTED]") == 2

    def test_preserves_basic_non_authorization_words(self):
        """Plain-English uses of basic should not be treated as credentials."""
        message = "basic error during basic setup"
        assert _sanitize_log_message(message) == message

    def test_redacts_short_and_punctuated_named_secret_values(self):
        """Explicit secret fields are redacted even when values are short or punctuated."""
        short_password = "short"
        punctuated_secret = "abc, def ghi"
        result = _sanitize_log_message(
            f'DATABASE_PASSWORD="{short_password}" CLIENT_SECRET="{punctuated_secret}"'
        )
        assert short_password not in result
        assert punctuated_secret not in result
        assert 'DATABASE_PASSWORD="[REDACTED-API-KEY]"' in result
        assert 'CLIENT_SECRET="[REDACTED-API-KEY]"' in result

    def test_preserves_llm_token_usage_metrics(self):
        """Usage counters named *_tokens are telemetry, not credentials."""
        message = "prompt_tokens=123456789012 completion_tokens=987654321098"
        assert _sanitize_log_message(message) == message

    def test_preserves_secret_metadata_and_pagination_fields(self):
        """Secret-related metadata and pagination cursors are not credential values."""
        message = (
            "SECRET_ROTATION_DAYS=90 PASSWORD_POLICY=strong IS_SECRET=false "
            "MAX_API_KEY_LENGTH=128 page_token=abc123 next_token=def456"
        )
        assert _sanitize_log_message(message) == message

    def test_redacts_private_key_blocks(self):
        """PEM private keys in multiline errors should never reach logs."""
        private_key = (
            "-----BEGIN "
            + "PRIVATE KEY-----\n"
            + "m" * 64
            + "\n-----END "
            + "PRIVATE KEY-----"
        )
        result = _sanitize_log_message(f"tool stderr:\n{private_key}\nfailed")
        assert private_key not in result
        assert "m" * 64 not in result
        assert "[REDACTED-PRIVATE-KEY]" in result

    def test_redacts_truncated_private_key_block(self):
        """Truncated PEM private key logs are redacted through message end."""
        private_key = "-----BEGIN " + "PRIVATE KEY-----\n" + "n" * 64
        result = _sanitize_log_message(f"tool stderr:\n{private_key}")
        assert private_key not in result
        assert "n" * 64 not in result
        assert "[REDACTED-PRIVATE-KEY]" in result



class TestBudgetChecking:
    """Verify budget checking works in LLMClient."""

    @patch("core.llm.config.detect_llm_availability")
    def test_check_budget_passes_under_limit(self, mock_detect):
        """Budget check passes when under limit."""
        mock_detect.return_value = MagicMock(
            external_llm=True, claude_code=False, llm_available=True
        )
        config = LLMConfig(
            primary_model=ModelConfig(
                provider="openai", model_name="gpt-5.2", api_key="sk-test"
            ),
            fallback_models=[],
            max_cost_per_scan=10.0,
            enable_cost_tracking=True,
        )
        client = LLMClient(config)
        client.total_cost = 5.0
        assert client._check_budget(estimated_cost=1.0) is True

    @patch("core.llm.config.detect_llm_availability")
    def test_check_budget_fails_over_limit(self, mock_detect):
        """Budget check fails when over limit."""
        mock_detect.return_value = MagicMock(
            external_llm=True, claude_code=False, llm_available=True
        )
        config = LLMConfig(
            primary_model=ModelConfig(
                provider="openai", model_name="gpt-5.2", api_key="sk-test"
            ),
            fallback_models=[],
            max_cost_per_scan=10.0,
            enable_cost_tracking=True,
        )
        client = LLMClient(config)
        client.total_cost = 9.5
        assert client._check_budget(estimated_cost=1.0) is False

    @patch("core.llm.config.detect_llm_availability")
    def test_check_budget_passes_when_tracking_disabled(self, mock_detect):
        """Budget check always passes when cost tracking is disabled."""
        mock_detect.return_value = MagicMock(
            external_llm=True, claude_code=False, llm_available=True
        )
        config = LLMConfig(
            primary_model=ModelConfig(
                provider="openai", model_name="gpt-5.2", api_key="sk-test"
            ),
            fallback_models=[],
            max_cost_per_scan=1.0,
            enable_cost_tracking=False,
        )
        client = LLMClient(config)
        client.total_cost = 999.0
        assert client._check_budget(estimated_cost=100.0) is True
