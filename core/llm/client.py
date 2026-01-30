#!/usr/bin/env python3
"""
LLM Client with Automatic Fallback and Cost Tracking

Manages multiple LLM providers with:
- Automatic fallback on failure
- Retry logic with exponential backoff
- Cost tracking and budget limits
- Response caching
- Task-specific model selection
"""

import hashlib
import json
import re
import sys
import time
from pathlib import Path
from typing import Dict, Optional, Any, Tuple

# Add parent directories to path for core imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from core.logging import get_logger
from .config import LLMConfig, ModelConfig
from .providers import LLMProvider, LLMResponse, create_provider

# Import for type-based quota detection
try:
    import litellm
    LITELLM_AVAILABLE = True
except ImportError:
    LITELLM_AVAILABLE = False

logger = get_logger()


def _sanitize_log_message(msg: str) -> str:
    """
    SECURITY: API Key Sanitization for Application Logs

    Defense-in-depth protection against API key leakage in error messages.

    Why needed:
    - LiteLLM sanitizes ITS internal logs (via redact_message_input_output_from_logging)
    - WE sanitize OUR application logs (when we log exceptions with our logger)
    - Exception messages from LiteLLM MAY contain API keys in edge cases

    Searchable tags: #SECURITY #API_KEY_PROTECTION #LOG_SANITIZATION
    Related: Cursor Bot Bug #2, PR #32, defense-in-depth best practice
    """
    # Redact OpenAI-style API keys (sk-*, pk-*)
    msg = re.sub(r'sk-[a-zA-Z0-9-_]{20,}', '[REDACTED-API-KEY]', msg)
    msg = re.sub(r'pk-[a-zA-Z0-9-_]{20,}', '[REDACTED-API-KEY]', msg)
    # TODO: Add patterns for other providers if needed (Anthropic, Google, etc.)
    return msg


def _is_quota_error(error: Exception) -> bool:
    """
    Detect quota/rate limit errors using type-based + string-based detection.

    Strategy:
    1. Check exception type first (robust, version-safe)
    2. Fall back to string matching (handles edge cases like LiteLLM bug #16189)

    Args:
        error: Exception from LiteLLM/provider

    Returns:
        True if error appears to be quota/rate limit related

    Related: Gemini quota exhaustion issue (Dec 2025)
    """
    # Type-based detection (preferred - robust against message format changes)
    if LITELLM_AVAILABLE:
        try:
            if isinstance(error, litellm.RateLimitError):
                return True
        except AttributeError:
            # RateLimitError doesn't exist in this LiteLLM version
            pass

    # String-based detection (fallback - handles bugs like #16189 where status code is wrong)
    error_str = str(error).lower()
    return any([
        "429" in error_str,  # HTTP 429 (Rate Limit)
        "quota exceeded" in error_str,
        "quota" in error_str and "exceeded" in error_str,
        "rate limit" in error_str,
        "generate_content_free_tier" in error_str,  # Gemini-specific
    ])


def _get_quota_guidance(model_name: str, provider: str) -> str:
    """
    Get simple, clear detection message for quota/rate limit errors.

    Shows LiteLLM's actual error message (which contains provider-specific details)
    rather than maintaining our own provider-specific guidance.

    Args:
        model_name: Model that hit quota limit (for display only)
        provider: Provider name (anthropic, openai, gemini, google, ollama, etc.)

    Returns:
        Simple detection message indicating quota/rate limit error

    Related: Gemini quota exhaustion issue (Dec 2025)
    """
    provider_lower = provider.lower()

    # Simple provider-specific detection messages
    if provider_lower in ("gemini", "google"):
        return "\n→ Google Gemini quota/rate limit exceeded"
    elif provider_lower == "openai":
        return "\n→ OpenAI rate limit exceeded"
    elif provider_lower == "anthropic":
        return "\n→ Anthropic rate limit exceeded"
    elif provider_lower == "ollama":
        return "\n→ Ollama server limit exceeded"
    else:
        return f"\n→ {provider.title()} rate limit exceeded"


class RaptorLLMLogger:
    """
    LiteLLM callback logger for RAPTOR visibility.

    Provides atomic logging of:
    - Model used (provider/name)
    - Tokens consumed (from LiteLLM's perspective)
    - Duration (from LiteLLM's timing)
    - Errors (sanitized for API key protection)

    Complements manual logging (which provides retry/fallback context).
    """

    def __init__(self):
        """Initialize callback logger."""
        self.call_count = 0

    def log_success_event(self, kwargs, response_obj, start_time, end_time):
        """
        Log successful LLM call.

        Args:
            kwargs: Call arguments (contains model, messages, etc.)
            response_obj: LiteLLM response object
            start_time: Call start timestamp
            end_time: Call end timestamp
        """
        try:
            self.call_count += 1

            # Extract model info
            model = kwargs.get("model", "unknown")

            # Extract token usage
            tokens_used = 0
            if hasattr(response_obj, "usage"):
                usage = response_obj.usage
                if hasattr(usage, "total_tokens"):
                    tokens_used = usage.total_tokens

            # Calculate duration (handle both float and datetime types)
            duration = end_time - start_time
            if hasattr(duration, 'total_seconds'):
                duration = duration.total_seconds()

            logger.debug(
                f"[LiteLLM] Success: model={model}, tokens={tokens_used}, duration={duration:.2f}s"
            )

        except Exception as e:
            # Never break LLM calls with callback errors
            logger.debug(f"[LiteLLM] Callback error (non-fatal): {_sanitize_log_message(str(e))}")

    def log_failure_event(self, kwargs, response_obj, start_time, end_time):
        """
        Log failed LLM call.

        Args:
            kwargs: Call arguments
            response_obj: Exception or error response
            start_time: Call start timestamp
            end_time: Call end timestamp
        """
        try:
            # Extract model info
            model = kwargs.get("model", "unknown")

            # Extract error message (sanitize for API keys)
            error_msg = _sanitize_log_message(str(response_obj))

            # Calculate duration (handle both float and datetime types)
            duration = end_time - start_time
            if hasattr(duration, 'total_seconds'):
                duration = duration.total_seconds()

            logger.debug(
                f"[LiteLLM] Failure: model={model}, error={error_msg}, duration={duration:.2f}s"
            )

        except Exception as e:
            # Never break LLM calls with callback errors
            logger.debug(f"[LiteLLM] Callback error (non-fatal): {_sanitize_log_message(str(e))}")


# Singleton instance of callback logger
_raptor_llm_logger_instance = None


def _get_raptor_llm_logger():
    """Get or create singleton RaptorLLMLogger instance."""
    global _raptor_llm_logger_instance
    if _raptor_llm_logger_instance is None:
        _raptor_llm_logger_instance = RaptorLLMLogger()
    return _raptor_llm_logger_instance


class LLMClient:
    """Unified LLM client with multi-provider support and fallback."""

    def __init__(self, config: Optional[LLMConfig] = None):
        self.config = config or LLMConfig()
        self.providers: Dict[str, LLMProvider] = {}
        self.total_cost = 0.0
        self.request_count = 0

        # HEALTH CHECK: Verify LiteLLM library is available
        try:
            import litellm
        except ImportError:
            raise RuntimeError(
                "LiteLLM library not installed. "
                "Install with: pip install litellm"
            )

        # HEALTH CHECK: Warn if no API keys configured
        import os
        has_cloud_keys = any([
            os.getenv("ANTHROPIC_API_KEY"),
            os.getenv("OPENAI_API_KEY"),
            os.getenv("GEMINI_API_KEY"),
        ])
        if not has_cloud_keys and self.config.primary_model.provider != "ollama":
            logger.warning(
                "No cloud LLM API keys found (ANTHROPIC_API_KEY, OPENAI_API_KEY, GEMINI_API_KEY). "
                "RAPTOR will use Ollama if available, or fail. "
                "For production use, configure at least one cloud provider API key."
            )

        # SECURITY: Enable API key sanitization
        litellm.redact_message_input_output_from_logging = True

        # Register LiteLLM callback for visibility (singleton pattern)
        # DUAL LOGGING DESIGN:
        # - Manual logs (logger.info/warning in generate/generate_structured):
        #   Provide RAPTOR-level context (retry #, fallback #, cache hits)
        # - Callback logs (logger.debug in RaptorLLMLogger):
        #   Provide LiteLLM-level metrics (model, tokens, duration from LiteLLM's perspective)
        # Both are necessary and non-redundant:
        #   - Manual: User/operator visibility into RAPTOR's decision-making
        #   - Callback: Developer/debugger access to atomic LiteLLM metrics
        callback = _get_raptor_llm_logger()
        if callback not in litellm.callbacks:
            litellm.callbacks.append(callback)

        # Initialize cache
        if self.config.enable_caching:
            self.config.cache_dir.mkdir(parents=True, exist_ok=True)

        logger.info("LLM Client initialized")
        logger.info(f"Primary model: {self.config.primary_model.provider}/{self.config.primary_model.model_name}")
        if self.config.enable_fallback:
            logger.info(f"Fallback models: {len(self.config.fallback_models)}")

        # Warn if using Ollama for exploit generation
        if self.config.primary_model.provider.lower() == "ollama":
            logger.warning(
                "Using local Ollama model for security analysis. "
                "Local models may generate unreliable exploit PoCs. "
                "For production security research, consider using cloud models "
                "(Anthropic Claude, OpenAI GPT, Google Gemini) which have better "
                "code generation and security analysis capabilities."
            )

    def _get_provider(self, model_config: ModelConfig) -> LLMProvider:
        """Get or create provider for model config."""
        key = f"{model_config.provider}:{model_config.model_name}"

        if key not in self.providers:
            logger.debug(f"Creating provider: {key}")
            self.providers[key] = create_provider(model_config)

        return self.providers[key]

    def _get_cache_key(self, prompt: str, system_prompt: Optional[str], model: str) -> str:
        """Generate cache key for prompt."""
        content = f"{model}:{system_prompt or ''}:{prompt}"
        return hashlib.sha256(content.encode()).hexdigest()

    def _get_cached_response(self, cache_key: str) -> Optional[str]:
        """Retrieve cached response if available."""
        if not self.config.enable_caching:
            return None

        cache_file = self.config.cache_dir / f"{cache_key}.json"
        if cache_file.exists():
            try:
                with open(cache_file) as f:
                    data = json.load(f)
                logger.debug(f"Cache hit: {cache_key}")
                return data.get("content")
            except Exception as e:
                logger.warning(f"Cache read error: {e}")

        return None

    def _save_to_cache(self, cache_key: str, response: LLMResponse) -> None:
        """Save response to cache."""
        if not self.config.enable_caching:
            return

        cache_file = self.config.cache_dir / f"{cache_key}.json"
        try:
            with open(cache_file, 'w') as f:
                json.dump({
                    "content": response.content,
                    "model": response.model,
                    "provider": response.provider,
                    "tokens_used": response.tokens_used,
                    "timestamp": time.time(),
                }, f, indent=2)
        except Exception as e:
            logger.warning(f"Cache write error: {e}")

    def _check_budget(self, estimated_cost: float = 0.1) -> bool:
        """Check if we're within budget."""
        if not self.config.enable_cost_tracking:
            return True

        if self.total_cost + estimated_cost > self.config.max_cost_per_scan:
            logger.error(f"Budget exceeded: ${self.total_cost:.2f} + ${estimated_cost:.2f} > ${self.config.max_cost_per_scan:.2f}")
            return False

        return True

    def generate(self, prompt: str, system_prompt: Optional[str] = None,
                 task_type: Optional[str] = None, **kwargs) -> LLMResponse:
        """
        Generate completion with automatic fallback.

        Args:
            prompt: User prompt
            system_prompt: System prompt
            task_type: Task type for model selection ("code_analysis", "exploit_generation", etc.)
            **kwargs: Additional generation parameters
                model_config: Optional ModelConfig to override default model selection

        Returns:
            LLMResponse with generated content

        Warning: Not thread-safe. Use locks if enabling concurrent access.
        """
        # Check budget
        if not self._check_budget():
            raise RuntimeError(
                f"LLM budget exceeded: ${self.total_cost:.4f} spent > ${self.config.max_cost_per_scan:.4f} limit. "
                f"Increase budget with: LLMConfig(max_cost_per_scan={self.config.max_cost_per_scan * 2:.1f})"
            )

        # Get appropriate model for task (priority: explicit model_config > task_type > primary)
        model_config = kwargs.pop('model_config', None)
        if not model_config:
            if task_type:
                model_config = self.config.get_model_for_task(task_type)
            else:
                model_config = self.config.primary_model

        # Check cache
        cache_key = self._get_cache_key(prompt, system_prompt, model_config.model_name)
        cached_content = self._get_cached_response(cache_key)
        if cached_content:
            print(f"► Using cached response for {model_config.provider}/{model_config.model_name}")
            self.request_count += 1
            return LLMResponse(
                content=cached_content,
                model=model_config.model_name,
                provider=model_config.provider,
                tokens_used=0,
                cost=0.0,
                finish_reason="cached",
            )

        # Try models in order with fallback (same tier only: local→local, cloud→cloud)
        models_to_try = [model_config]
        if self.config.enable_fallback:
            # Filter fallbacks to same tier as primary
            is_local_primary = model_config.provider.lower() == "ollama"
            for fallback in self.config.fallback_models:
                if not fallback.enabled:
                    continue
                # Skip if different tier (don't mix local and cloud)
                is_local_fallback = fallback.provider.lower() == "ollama"
                if is_local_primary == is_local_fallback:
                    # Skip if same as primary (already trying it)
                    if fallback.model_name != model_config.model_name:
                        models_to_try.append(fallback)

        last_error = None
        attempts_count = 0  # Track actual attempts, not just models in list
        for model_idx, model in enumerate(models_to_try):
            if not model.enabled:
                continue

            attempts_count += 1  # Count this as an actual attempt

            # Show which model we're using (visible to user)
            if model_idx == 0:
                print(f"► Using model: {model.provider}/{model.model_name}")
                if model.provider.lower() == "ollama":
                    print(f"  ⚠️  Local model - exploit PoCs may be unreliable")
            else:
                print(f"► Falling back to: {model.provider}/{model.model_name}")
                if model.provider.lower() == "ollama":
                    print(f"  ⚠️  Local model - exploit PoCs may be unreliable")

            logger.debug(f"Trying model: {model.provider}/{model.model_name}")

            for attempt in range(self.config.max_retries):
                try:
                    if attempt > 0:
                        print(f"  ↻ Retrying... (attempt {attempt + 1}/{self.config.max_retries})")

                    provider = self._get_provider(model)
                    response = provider.generate(prompt, system_prompt, **kwargs)

                    # Track cost
                    self.total_cost += response.cost
                    self.request_count += 1

                    # Cache response
                    self._save_to_cache(cache_key, response)

                    logger.info(f"Generation successful: {model.provider}/{model.model_name} "
                               f"(tokens: {response.tokens_used}, cost: ${response.cost:.4f})")

                    return response

                except Exception as e:
                    last_error = e

                    # Check if quota/rate limit error and log specific guidance
                    if _is_quota_error(e):
                        quota_guidance = _get_quota_guidance(model.model_name, model.provider)
                        logger.warning(f"Quota error for {model.provider}/{model.model_name}:{quota_guidance}")

                    logger.warning(f"Attempt {attempt + 1}/{self.config.max_retries} failed for "
                                 f"{model.provider}/{model.model_name}: {_sanitize_log_message(str(e))}")

                    if attempt < self.config.max_retries - 1:
                        delay = self.config.retry_delay * (2 ** attempt)  # Exponential backoff
                        logger.debug(f"Retrying in {delay}s...")
                        time.sleep(delay)

            logger.warning(f"All attempts failed for {model.provider}/{model.model_name}, trying next model...")

        # All models in tier failed
        tier = "local (Ollama)" if model_config.provider.lower() == "ollama" else "cloud"
        error_msg = f"All {tier} models failed (tried {attempts_count} model(s))."

        # Check if last error was quota-related
        if last_error and _is_quota_error(last_error):
            # Show detection message + actual provider error (with light sanitization)
            error_msg += _get_quota_guidance(model_config.model_name, model_config.provider)
            error_msg += f"\nProvider message: {_sanitize_log_message(str(last_error))}"
        elif last_error:
            # Generic error with sanitized last error
            error_msg += f"\nLast error: {_sanitize_log_message(str(last_error))}"
            # Add troubleshooting tips (consistent with generate_structured)
            if tier == "local (Ollama)":
                error_msg += "\n→ Check Ollama server: http://localhost:11434/api/tags"
            else:
                error_msg += "\n→ Check API keys and network connectivity"
        else:
            # No attempts were made (e.g., primary model disabled and no same-tier fallbacks)
            error_msg += "\nNo enabled models available in this tier."
            if tier == "local (Ollama)":
                error_msg += "\n→ Check Ollama server: http://localhost:11434/api/tags"
            else:
                error_msg += "\n→ Check API keys and network connectivity"

        logger.error(error_msg)
        raise RuntimeError(error_msg)

    def generate_structured(self, prompt: str, schema: Dict[str, Any],
                           system_prompt: Optional[str] = None,
                           task_type: Optional[str] = None, **kwargs) -> Tuple[Dict[str, Any], str]:
        """
        Generate structured JSON output with automatic fallback.

        Args:
            prompt: User prompt
            schema: JSON schema for expected output
            system_prompt: System prompt
            task_type: Task type for model selection
            **kwargs: Additional generation parameters
                model_config: Optional ModelConfig to override default model selection

        Returns:
            Tuple of (parsed JSON object matching schema, full response content)

        Warning: Not thread-safe. Use locks if enabling concurrent access.
        """
        # Check budget
        if not self._check_budget():
            raise RuntimeError(
                f"LLM budget exceeded: ${self.total_cost:.4f} spent > ${self.config.max_cost_per_scan:.4f} limit. "
                f"Increase budget with: LLMConfig(max_cost_per_scan={self.config.max_cost_per_scan * 2:.1f})"
            )

        # Get appropriate model (priority: explicit model_config > task_type > primary)
        model_config = kwargs.pop('model_config', None)
        if not model_config:
            if task_type:
                model_config = self.config.get_model_for_task(task_type)
            else:
                model_config = self.config.primary_model

        # Try models in order (same tier only: local→local, cloud→cloud)
        models_to_try = [model_config]
        if self.config.enable_fallback:
            # Filter fallbacks to same tier as primary
            is_local_primary = model_config.provider.lower() == "ollama"
            for fallback in self.config.fallback_models:
                if not fallback.enabled:
                    continue
                # Skip if different tier (don't mix local and cloud)
                is_local_fallback = fallback.provider.lower() == "ollama"
                if is_local_primary == is_local_fallback:
                    # Skip if same as primary (already trying it)
                    if fallback.model_name != model_config.model_name:
                        models_to_try.append(fallback)

        last_error = None
        attempts_count = 0  # Track actual attempts, not just models in list
        for model_idx, model in enumerate(models_to_try):
            if not model.enabled:
                continue

            attempts_count += 1  # Count this as an actual attempt

            # Show which model we're using (visible to user)
            if model_idx == 0:
                print(f"► Using model: {model.provider}/{model.model_name} (structured)")
                if model.provider.lower() == "ollama":
                    print(f"  ⚠️  Local model - exploit PoCs may be unreliable")
            else:
                print(f"► Falling back to: {model.provider}/{model.model_name} (structured)")
                if model.provider.lower() == "ollama":
                    print(f"  ⚠️  Local model - exploit PoCs may be unreliable")

            for attempt in range(self.config.max_retries):
                try:
                    if attempt > 0:
                        print(f"  ↻ Retrying... (attempt {attempt + 1}/{self.config.max_retries})")

                    provider = self._get_provider(model)

                    # Capture cost before call
                    cost_before = provider.total_cost
                    tokens_before = provider.total_tokens

                    result = provider.generate_structured(prompt, schema, system_prompt)

                    # Calculate cost delta
                    cost_delta = provider.total_cost - cost_before
                    tokens_delta = provider.total_tokens - tokens_before

                    # Track at client level
                    self.total_cost += cost_delta
                    self.request_count += 1

                    logger.info(f"Structured generation successful: {model.provider}/{model.model_name} "
                               f"(tokens: {tokens_delta}, cost: ${cost_delta:.4f})")
                    return result

                except Exception as e:
                    last_error = e

                    # Check if quota/rate limit error and log specific guidance
                    if _is_quota_error(e):
                        quota_guidance = _get_quota_guidance(model.model_name, model.provider)
                        logger.warning(f"Quota error for {model.provider}/{model.model_name}:{quota_guidance}")

                    # SECURITY: Sanitize exception message to prevent API key leakage (Cursor Bot Bug #2)
                    logger.warning(_sanitize_log_message(f"Structured generation attempt {attempt + 1} failed: {str(e)}"))

                    if attempt < self.config.max_retries - 1:
                        delay = self.config.retry_delay * (2 ** attempt)  # Exponential backoff
                        logger.debug(f"Retrying in {delay}s...")
                        time.sleep(delay)

        # All models in tier failed
        tier = "local (Ollama)" if model_config.provider.lower() == "ollama" else "cloud"
        error_msg = f"Structured generation failed for all {tier} models (tried {attempts_count} model(s))."

        # Check if last error was quota-related
        if last_error and _is_quota_error(last_error):
            # Show detection message + actual provider error (with light sanitization)
            error_msg += _get_quota_guidance(model_config.model_name, model_config.provider)
            error_msg += f"\nProvider message: {_sanitize_log_message(str(last_error))}"
        elif last_error:
            # Generic error with sanitized last error
            error_msg += f"\nLast error: {_sanitize_log_message(str(last_error))}"
            if tier == "local (Ollama)":
                error_msg += "\n→ Check Ollama server: http://localhost:11434/api/tags"
            else:
                error_msg += "\n→ Check API keys and network connectivity"
        else:
            # No attempts were made (e.g., primary model disabled and no same-tier fallbacks)
            error_msg += "\nNo enabled models available in this tier."
            if tier == "local (Ollama)":
                error_msg += "\n→ Check Ollama server: http://localhost:11434/api/tags"
            else:
                error_msg += "\n→ Check API keys and network connectivity"

        logger.error(error_msg)
        raise RuntimeError(error_msg)

    def get_stats(self) -> Dict[str, Any]:
        """Get usage statistics."""
        provider_stats = {}
        for key, provider in self.providers.items():
            provider_stats[key] = {
                "total_tokens": provider.total_tokens,
                "total_cost": provider.total_cost,
            }

        return {
            "total_requests": self.request_count,
            "total_cost": self.total_cost,
            "budget_remaining": self.config.max_cost_per_scan - self.total_cost,
            "providers": provider_stats,
        }

    def reset_stats(self) -> None:
        """Reset usage statistics."""
        self.total_cost = 0.0
        self.request_count = 0
        for provider in self.providers.values():
            provider.total_tokens = 0
            provider.total_cost = 0.0
