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

import json
import re
import sys
import time
from pathlib import Path
from typing import Dict, Optional, Any, Tuple

from core.hash import sha256_string
from core.logging import get_logger
from .config import LLMConfig, ModelConfig
from .providers import LLMProvider, LLMResponse, StructuredResponse, create_provider

# Import for type-based error detection (optional SDKs)
try:
    import openai as _openai_module
    _OPENAI_AVAILABLE = True
except ImportError:
    _OPENAI_AVAILABLE = False

try:
    import anthropic as _anthropic_module
    _ANTHROPIC_AVAILABLE = True
except ImportError:
    _ANTHROPIC_AVAILABLE = False

logger = get_logger()


def _sanitize_log_message(msg: str) -> str:
    """
    SECURITY: API Key Sanitization for Application Logs

    Defense-in-depth protection against API key leakage in error messages.

    Searchable tags: #SECURITY #API_KEY_PROTECTION #LOG_SANITIZATION
    Related: Cursor Bot Bug #2, PR #32, defense-in-depth best practice
    """
    # Redact private key material before shorter generic patterns. If a log line
    # is truncated before the END marker, redact through the end of the message.
    msg = re.sub(
        r'-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)',
        '[REDACTED-PRIVATE-KEY]',
        msg,
        flags=re.DOTALL,
    )
    # Redact Anthropic API keys first (sk-ant-*) before general sk-* pattern
    msg = re.sub(r'sk-ant-[a-zA-Z0-9-_]{20,}', '[REDACTED-API-KEY]', msg)
    # Redact OpenAI-style API keys (sk-*, pk-*)
    msg = re.sub(r'sk-[a-zA-Z0-9-_]{20,}', '[REDACTED-API-KEY]', msg)
    msg = re.sub(r'pk-[a-zA-Z0-9-_]{20,}', '[REDACTED-API-KEY]', msg)
    # Redact Google API keys (AIza*)
    msg = re.sub(r'AIza[a-zA-Z0-9-_]{30,}', '[REDACTED-API-KEY]', msg)
    # Redact common authorization header schemes from SDK/tool errors.
    msg = re.sub(
        r'Bearer [a-zA-Z0-9._~+/-]{20,}={0,2}',
        'Bearer [REDACTED]',
        msg,
        flags=re.IGNORECASE,
    )
    msg = re.sub(
        r'Basic\s+[A-Za-z0-9+/]{8,}={0,2}',
        'Basic [REDACTED]',
        msg,
        flags=re.IGNORECASE,
    )
    # Redact GitHub tokens that may appear in git/gh subprocess output
    msg = re.sub(r'gh[oprsu]_[a-zA-Z0-9_]{36,}', '[REDACTED-API-KEY]', msg)
    msg = re.sub(r'github_pat_[a-zA-Z0-9_]{20,}', '[REDACTED-API-KEY]', msg)
    # Redact AWS access key IDs that commonly appear in tool output/traces
    msg = re.sub(r'\b(?:AKIA|ASIA)[A-Z0-9]{16}\b', '[REDACTED-API-KEY]', msg)
    # Redact key/value or JSON-ish assignments such as API_KEY=*** or "token": "***".
    # Keep these field names intentionally bounded to avoid redacting metadata
    # such as PASSWORD_POLICY, SECRET_ROTATION_DAYS, MAX_API_KEY_LENGTH, or
    # pagination cursors like page_token/next_token.
    secret_field = (
        r'(?:[A-Za-z0-9_-]*(?:API[_-]?KEY|PASSWORD|'
        r'SECRET[_-]?KEY|SECRET[_-]?ACCESS[_-]?KEY)'
        r'|(?:CLIENT|APP|SHARED|API|CONSUMER)[_-]?SECRET'
        r'|(?:ACCESS|AUTH|BEARER|ID|REFRESH|SESSION|SERVICE)[_-]?TOKEN)'
    )
    # Quoted values may be short or contain spaces/commas; the field name marks them sensitive.
    msg = re.sub(
        rf'(\b{secret_field}\b["\']?\s*[:=]\s*)(["\'])(.*?)(\2)',
        r'\1\2[REDACTED-API-KEY]\4',
        msg,
        flags=re.IGNORECASE,
    )
    # Unquoted values end at common log/JSON delimiters.
    msg = re.sub(
        rf'(\b{secret_field}\b\s*[:=]\s*)([^"\'\s,}}]+)',
        r'\1[REDACTED-API-KEY]',
        msg,
        flags=re.IGNORECASE,
    )
    return msg


def _is_auth_error(error: Exception) -> bool:
    """
    Detect authentication/authorization errors from LLM providers.

    Checks both OpenAI and Anthropic SDK exception types, with
    string-based fallback for edge cases.

    Args:
        error: Exception from provider SDK

    Returns:
        True if error appears to be an auth/key error
    """
    if _OPENAI_AVAILABLE:
        try:
            if isinstance(error, _openai_module.AuthenticationError):
                return True
        except AttributeError:
            pass

    if _ANTHROPIC_AVAILABLE:
        try:
            if isinstance(error, _anthropic_module.AuthenticationError):
                return True
        except AttributeError:
            pass

    error_str = str(error).lower()
    return any(indicator in error_str for indicator in [
        "401", "403", "authentication", "unauthorized", "invalid api key",
        "invalid x-api-key", "api key not valid", "incorrect api key",
        "permission denied", "access denied",
    ])


def _is_quota_error(error: Exception) -> bool:
    """
    Detect quota/rate limit errors using type-based + string-based detection.

    Checks both OpenAI and Anthropic SDK exception types.

    Args:
        error: Exception from provider SDK

    Returns:
        True if error appears to be quota/rate limit related
    """
    if _OPENAI_AVAILABLE:
        try:
            if isinstance(error, _openai_module.RateLimitError):
                return True
        except AttributeError:
            pass

    if _ANTHROPIC_AVAILABLE:
        try:
            if isinstance(error, _anthropic_module.RateLimitError):
                return True
        except AttributeError:
            pass

    error_str = str(error).lower()
    return any([
        "429" in error_str,
        "quota exceeded" in error_str,
        "quota" in error_str and "exceeded" in error_str,
        "rate limit" in error_str,
        "generate_content_free_tier" in error_str,  # Gemini-specific
    ])


def _is_retryable_error(error: Exception) -> bool:
    """Check if an error is transient and worth retrying.

    Retryable: rate limits, timeouts, server errors (5xx), connection errors.
    Non-retryable: schema validation, auth errors (401/403), bad request (400),
    Instructor failures, Pydantic validation errors.
    """
    # Rate limits are retryable (with backoff)
    if _is_quota_error(error):
        return True

    # Check exception types
    error_type = type(error).__name__
    retryable_types = ("Timeout", "ConnectionError", "APIConnectionError",
                       "InternalServerError", "ServiceUnavailableError")
    if any(t in error_type for t in retryable_types):
        return True

    # Check error message for retryable patterns
    error_str = str(error).lower()
    retryable_patterns = ("timeout", "connection", "502", "503", "504",
                          "internal server error", "service unavailable")
    if any(p in error_str for p in retryable_patterns):
        return True

    # Everything else is non-retryable (schema errors, 400, 401, 403, 404,
    # Instructor failures, Pydantic validation, etc.)
    return False


def _get_quota_guidance(model_name: str, provider: str) -> str:
    """
    Get simple, clear detection message for quota/rate limit errors.

    Args:
        model_name: Model that hit quota limit (for display only)
        provider: Provider name (anthropic, openai, gemini, google, ollama, etc.)

    Returns:
        Simple detection message indicating quota/rate limit error
    """
    provider_lower = provider.lower()

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


class LLMClient:
    """Unified LLM client with multi-provider support and fallback."""

    def __init__(self, config: Optional[LLMConfig] = None):
        import threading
        self.config = config or LLMConfig()
        self.providers: Dict[str, LLMProvider] = {}
        self.total_cost = 0.0
        self.request_count = 0
        self.task_type_costs: Dict[str, float] = {}  # task_type → cumulative cost
        self._stats_lock = threading.RLock()
        # Per-cache-key locks. Two threads issuing the same cache key
        # serialise on its lock so only one calls the provider; the
        # second observes the first's freshly-written cache entry on
        # its own check. Bounded by distinct keys this client sees in
        # its lifetime — sha256-keyed locks are ~80 B each so 100k
        # distinct keys is ~8 MB, an acceptable upper bound for what
        # is in practice a single-run object.
        self._key_locks: Dict[str, threading.Lock] = {}
        self._key_locks_guard = threading.Lock()

        # HEALTH CHECK: Warn if no API keys configured
        from .detection import detect_llm_availability
        availability = detect_llm_availability()
        if not availability.external_llm:
            logger.warning(
                "No external LLM available (no API keys, no config file, no Ollama). "
                "LLMClient constructed but calls will likely fail. "
                "For production use, configure at least one LLM provider."
            )

        # Initialize cache
        if self.config.enable_caching:
            try:
                self.config.cache_dir.mkdir(parents=True, exist_ok=True)
            except OSError:
                self.config.enable_caching = False
                logger.warning(f"Cannot create cache dir {self.config.cache_dir} — caching disabled")

        logger.info("LLM Client initialized")
        if self.config.primary_model:
            logger.info(f"Primary model: {self.config.primary_model.provider}/{self.config.primary_model.model_name}")
        else:
            logger.warning("LLM Client initialized with no primary model — all calls will fail")
        if self.config.enable_fallback:
            logger.info(f"Fallback models: {len(self.config.fallback_models)}")

        # Warn if using Ollama for exploit generation
        if self.config.primary_model and self.config.primary_model.provider.lower() == "ollama":
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

    @property
    def primary_provider(self) -> LLMProvider:
        """The :class:`LLMProvider` for the configured ``primary_model``.

        Exposed publicly so consumers that need direct provider access
        — typically for tool-use loops via :class:`core.llm.tool_use.ToolUseLoop` —
        can reach it without going through :meth:`generate`. Cached;
        the same instance is returned across calls.

        Raises ``RuntimeError`` if no primary model is configured (the
        client should normally not have been constructed in that
        case — :func:`packages.llm_analysis.get_client` returns
        ``None`` instead).
        """
        if self.config.primary_model is None:
            raise RuntimeError(
                "LLMClient has no primary_model configured; cannot "
                "expose primary_provider. Use packages.llm_analysis."
                "get_client() which returns None when no provider is "
                "available, instead of constructing LLMClient directly."
            )
        return self._get_provider(self.config.primary_model)

    def _key_lock(self, cache_key: str) -> "threading.Lock":
        """Return (creating if needed) a per-key lock used to dedupe
        concurrent calls with the same cache key. The guard lock is
        only held briefly to insert into the dict; the per-key lock
        itself is acquired by the caller for the duration of the
        check-call-save sequence."""
        import threading
        with self._key_locks_guard:
            lock = self._key_locks.get(cache_key)
            if lock is None:
                lock = threading.Lock()
                self._key_locks[cache_key] = lock
            return lock

    @staticmethod
    def _kwargs_for_cache_key(kwargs: Optional[Dict[str, Any]]) -> str:
        """Canonicalise generation kwargs (temperature, max_tokens, …)
        for inclusion in a cache key.

        Without this, two calls that share prompt + system_prompt + model
        but differ in temperature collide in the cache and the second
        caller silently gets the first caller's result. Sorted JSON
        keeps the digest order-independent; ``default=str`` swallows
        any non-serialisable values a future caller might pass."""
        if not kwargs:
            return ""
        try:
            return json.dumps(kwargs, sort_keys=True, default=str)
        except (TypeError, ValueError):
            # Schemas should always serialise; fall back to a stable
            # repr if a caller passes something weird.
            return repr(sorted(kwargs.items()))

    def _get_cache_key(
        self, prompt: str, system_prompt: Optional[str], model: str,
        kwargs: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Generate cache key for prompt."""
        content = (
            f"{model}:{system_prompt or ''}:{prompt}:"
            f"{self._kwargs_for_cache_key(kwargs)}"
        )
        return sha256_string(content)

    def _is_entry_stale(self, data: Dict[str, Any]) -> bool:
        """Return True if a cache entry's ``timestamp`` is older than
        ``cache_ttl_seconds``. Entries without a timestamp are treated
        as fresh — they predate this version of the code and we can't
        say how old they are; better to honour them than mass-evict on
        upgrade."""
        ttl = self.config.cache_ttl_seconds
        if not ttl:
            return False
        ts = data.get("timestamp")
        if not isinstance(ts, (int, float)):
            return False
        return (time.time() - ts) > ttl

    def _get_cached_response(self, cache_key: str) -> Optional[str]:
        """Retrieve cached response if available."""
        if not self.config.enable_caching:
            return None

        from core.json import load_json
        cache_file = self.config.cache_dir / f"{cache_key}.json"
        # Non-strict: corrupt cache is silently skipped (regenerated on next call)
        data = load_json(cache_file)
        if data is None:
            return None
        if self._is_entry_stale(data):
            logger.debug(f"Cache stale (TTL): {cache_key}")
            return None
        logger.debug(f"Cache hit: {cache_key}")
        return data.get("content")

    def _save_to_cache(self, cache_key: str, response: LLMResponse) -> None:
        """Save response to cache."""
        if not self.config.enable_caching:
            return

        from core.json import save_json
        cache_file = self.config.cache_dir / f"{cache_key}.json"
        try:
            save_json(cache_file, {
                    "content": response.content,
                    "model": response.model,
                    "provider": response.provider,
                    "tokens_used": response.tokens_used,
                    "timestamp": time.time(),
                })
        except Exception as e:
            logger.warning(f"Cache write error: {e}")
            return
        self._maybe_evict_cache()

    def _maybe_evict_cache(self) -> None:
        """If ``cache_max_entries`` is configured, drop the oldest
        entries (by mtime) until at or under the cap. Called from the
        savers after a successful write. Walks both unstructured and
        ``structured-`` files in the same cache dir so the cap applies
        across the namespace as a whole — operators reason about a
        single budget, not two."""
        cap = self.config.cache_max_entries
        if not cap:
            return
        try:
            entries = list(self.config.cache_dir.glob("*.json"))
        except OSError:
            return
        if len(entries) <= cap:
            return
        # Stat each file once. A file may disappear between glob and
        # stat (concurrent eviction in another process); treat missing
        # as already-gone.
        with_mtime: list[Tuple[float, Path]] = []
        for p in entries:
            try:
                with_mtime.append((p.stat().st_mtime, p))
            except OSError:
                continue
        with_mtime.sort(key=lambda pair: pair[0])
        drop = len(with_mtime) - cap
        for _, victim in with_mtime[:drop]:
            try:
                victim.unlink()
            except OSError:
                # Lost a race with another process — that's fine, our
                # only job is to bring count down, and that's happening.
                continue

    def _get_structured_cache_key(
        self, prompt: str, system_prompt: Optional[str],
        model: str, schema: Dict[str, Any],
        kwargs: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Cache key for generate_structured. Includes schema so two callers
        who share a prompt but ask for different shapes don't collide,
        and includes generation kwargs so callers passing different
        temperatures (etc.) don't collide either — even though provider
        impls don't currently honour those kwargs, future plumbing is
        cache-correct from day one."""
        # sort_keys → stable digest regardless of dict insertion order.
        # default=str → swallow non-serialisable schema embellishments.
        try:
            schema_json = json.dumps(schema, sort_keys=True, default=str)
        except (TypeError, ValueError):
            # Schemas should always serialise; if a caller passes something
            # weird, fall back to repr — still deterministic for that caller.
            schema_json = repr(schema)
        content = (
            f"{model}:{system_prompt or ''}:{prompt}:{schema_json}:"
            f"{self._kwargs_for_cache_key(kwargs)}"
        )
        return sha256_string(content)

    def _get_cached_structured_response(
        self, cache_key: str,
    ) -> Optional[Tuple[Dict[str, Any], str]]:
        """Retrieve cached (result_dict, raw) tuple if available."""
        if not self.config.enable_caching:
            return None

        from core.json import load_json
        cache_file = self.config.cache_dir / f"structured-{cache_key}.json"
        data = load_json(cache_file)
        if data is None:
            return None
        # Both fields are required for a usable replay; treat partial
        # entries (e.g. truncated by an interrupted writer) as a miss.
        if "result" not in data or "raw" not in data:
            return None
        if self._is_entry_stale(data):
            logger.debug(f"Structured cache stale (TTL): {cache_key}")
            return None
        logger.debug(f"Structured cache hit: {cache_key}")
        return data["result"], data["raw"]

    def _save_structured_to_cache(
        self, cache_key: str, response: "StructuredResponse",
    ) -> None:
        """Persist a successful structured response for later replay."""
        if not self.config.enable_caching:
            return

        from core.json import save_json
        cache_file = self.config.cache_dir / f"structured-{cache_key}.json"
        try:
            save_json(cache_file, {
                "result": response.result,
                "raw": response.raw,
                "model": response.model,
                "provider": response.provider,
                "tokens_used": response.tokens_used,
                "timestamp": time.time(),
            })
        except Exception as e:
            logger.warning(f"Structured cache write error: {e}")
            return
        self._maybe_evict_cache()

    def _check_budget(self, estimated_cost: float = 0.1) -> bool:
        """Check if we're within budget (thread-safe)."""
        if not self.config.enable_cost_tracking:
            return True

        with self._stats_lock:
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
            task_type: Task type for model selection
            **kwargs: Additional generation parameters
                model_config: Optional ModelConfig to override default model selection

        Returns:
            LLMResponse with generated content

        Thread-safe: stats tracking uses _stats_lock for concurrent access.
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

        # Warn if prompt likely exceeds context window (~4 chars per token)
        estimated_tokens = (len(prompt) + len(system_prompt or "")) // 4
        if estimated_tokens > model_config.max_context * 0.8:
            logger.warning(
                f"Prompt ~{estimated_tokens} tokens may exceed {model_config.model_name} "
                f"context window ({model_config.max_context})")

        # Check cache. Generation kwargs (temperature, max_tokens, …)
        # are part of the cache key — without that, two callers with
        # the same prompt but different temperatures would collide.
        cache_key = self._get_cache_key(
            prompt, system_prompt, model_config.model_name, kwargs,
        )
        # Per-key lock dedupes concurrent identical calls: the first
        # arrival pays the provider round-trip; serial-ordered followers
        # observe its freshly-written cache entry on their own check
        # below. Without this, N concurrent threads on the same key all
        # miss the cache, all call the provider, and all write — burning
        # N× the cost for a result they'd have shared.
        with self._key_lock(cache_key):
            cached_content = self._get_cached_response(cache_key)
            if cached_content:
                logger.debug(f"Using cached response for {model_config.provider}/{model_config.model_name}")
                with self._stats_lock:
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
            attempts_count = 0
            for model_idx, model in enumerate(models_to_try):
                if not model.enabled:
                    continue

                attempts_count += 1

                if model_idx == 0:
                    logger.debug(f"Using model: {model.provider}/{model.model_name}")
                else:
                    logger.warning(f"Falling back to: {model.provider}/{model.model_name}")
                if model.provider.lower() == "ollama":
                    logger.warning("Local model — exploit PoCs may be unreliable")

                logger.debug(f"Trying model: {model.provider}/{model.model_name}")

                for attempt in range(self.config.max_retries):
                    try:
                        if attempt > 0:
                            logger.info(f"Retrying {model.provider}/{model.model_name} (attempt {attempt + 1}/{self.config.max_retries})")

                        provider = self._get_provider(model)
                        t_start = time.time()
                        response = provider.generate(prompt, system_prompt, **kwargs)
                        duration = time.time() - t_start

                        # Track cost (thread-safe)
                        with self._stats_lock:
                            self.total_cost += response.cost
                            self.request_count += 1
                            if task_type:
                                self.task_type_costs[task_type] = self.task_type_costs.get(task_type, 0.0) + response.cost

                        # Cache response
                        self._save_to_cache(cache_key, response)

                        logger.debug(f"Generation successful: {model.provider}/{model.model_name} "
                                    f"(tokens: {response.tokens_used}, cost: ${response.cost:.4f}, "
                                    f"duration: {duration:.1f}s)")

                        return response

                    except Exception as e:
                        last_error = e

                        if _is_quota_error(e):
                            quota_guidance = _get_quota_guidance(model.model_name, model.provider)
                            logger.warning(f"Quota error for {model.provider}/{model.model_name}:{quota_guidance}")

                        logger.warning(f"Attempt {attempt + 1}/{self.config.max_retries} failed for "
                                     f"{model.provider}/{model.model_name}: {_sanitize_log_message(str(e))}")

                        if not _is_retryable_error(e):
                            logger.info(f"Non-retryable error — skipping remaining retries for {model.provider}/{model.model_name}")
                            break

                        if attempt < self.config.max_retries - 1:
                            delay = min(self.config.retry_delay * (2 ** attempt), 30)
                            logger.debug(f"Retrying in {delay}s...")
                            time.sleep(delay)

                logger.warning(f"All attempts failed for {model.provider}/{model.model_name}, trying next model...")

            # All models in tier failed
            tier = "local (Ollama)" if model_config.provider.lower() == "ollama" else "cloud"
            error_msg = f"All {tier} models failed (tried {attempts_count} model(s))."

            # Check if last error was quota-related
            if last_error and _is_quota_error(last_error):
                error_msg += _get_quota_guidance(model_config.model_name, model_config.provider)
                error_msg += f"\nProvider message: {_sanitize_log_message(str(last_error))}"
            elif last_error:
                error_msg += f"\nLast error: {_sanitize_log_message(str(last_error))}"
                if tier == "local (Ollama)":
                    error_msg += "\n→ Check Ollama server: http://localhost:11434/api/tags"
                else:
                    error_msg += "\n→ Check API keys and network connectivity"
            else:
                error_msg += "\nNo enabled models available in this tier."
                if tier == "local (Ollama)":
                    error_msg += "\n→ Check Ollama server: http://localhost:11434/api/tags"
                else:
                    error_msg += "\n→ Check API keys and network connectivity"

            logger.error(error_msg)
            raise RuntimeError(error_msg)

    def generate_structured(self, prompt: str, schema: Dict[str, Any],
                           system_prompt: Optional[str] = None,
                           task_type: Optional[str] = None, **kwargs):
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
            StructuredResponse with result dict, raw content, cost, and metadata.
            For backwards compatibility, can be unpacked as a 2-tuple: result, raw = ...

        Thread-safe: stats tracking uses _stats_lock for concurrent access.
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

        # Provider impls of generate_structured don't currently accept
        # **kwargs (signature is (prompt, schema, system_prompt)) — so
        # any temperature / max_tokens etc. passed by the caller is
        # silently dropped. Surface that explicitly so callers know
        # their hint isn't taking effect; cache key still differentiates
        # so behaviour stays correct if providers grow kwargs support.
        if kwargs:
            logger.warning(
                f"generate_structured: provider impls do not accept "
                f"{sorted(kwargs.keys())} — these kwargs are ignored. "
                f"Cache key still differentiates by them."
            )

        # Warn if prompt likely exceeds context window (~4 chars per token)
        estimated_tokens = (len(prompt) + len(system_prompt or "")) // 4
        if estimated_tokens > model_config.max_context * 0.8:
            logger.warning(
                f"Prompt ~{estimated_tokens} tokens may exceed {model_config.model_name} "
                f"context window ({model_config.max_context})")

        # Check cache. Key includes schema so two callers who share a
        # prompt but ask for different output shapes don't collide.
        # Pinned to model_config.model_name (the configured first-choice
        # model), not whichever fallback we actually use — replays come
        # back as if the configured model was queried, matching how
        # generate() does it.
        cache_key = self._get_structured_cache_key(
            prompt, system_prompt, model_config.model_name, schema, kwargs,
        )
        # Per-key lock dedupes concurrent identical calls (see generate()
        # for full rationale).
        with self._key_lock(cache_key):
            cached = self._get_cached_structured_response(cache_key)
            if cached is not None:
                cached_result, cached_raw = cached
                logger.debug(
                    f"Using cached structured response for "
                    f"{model_config.provider}/{model_config.model_name}"
                )
                with self._stats_lock:
                    self.request_count += 1
                return StructuredResponse(
                    result=cached_result,
                    raw=cached_raw,
                    cost=0.0,
                    tokens_used=0,
                    model=model_config.model_name,
                    provider=model_config.provider,
                    duration=0.0,
                    cached=True,
                )

            # Try models in order (same tier only: local→local, cloud→cloud)
            models_to_try = [model_config]
            if self.config.enable_fallback:
                is_local_primary = model_config.provider.lower() == "ollama"
                for fallback in self.config.fallback_models:
                    if not fallback.enabled:
                        continue
                    is_local_fallback = fallback.provider.lower() == "ollama"
                    if is_local_primary == is_local_fallback:
                        if fallback.model_name != model_config.model_name:
                            models_to_try.append(fallback)

            last_error = None
            attempts_count = 0
            for model_idx, model in enumerate(models_to_try):
                if not model.enabled:
                    continue

                attempts_count += 1

                if model_idx == 0:
                    logger.debug(f"Using model: {model.provider}/{model.model_name} (structured)")
                else:
                    logger.warning(f"Falling back to: {model.provider}/{model.model_name} (structured)")
                if model.provider.lower() == "ollama":
                    logger.warning("Local model — exploit PoCs may be unreliable")

                for attempt in range(self.config.max_retries):
                    try:
                        if attempt > 0:
                            logger.info(f"Retrying {model.provider}/{model.model_name} (attempt {attempt + 1}/{self.config.max_retries})")

                        provider = self._get_provider(model)

                        # Capture cost before call
                        cost_before = provider.total_cost
                        tokens_before = provider.total_tokens

                        t_start = time.time()
                        result_tuple = provider.generate_structured(prompt, schema, system_prompt)
                        duration = time.time() - t_start

                        # Calculate cost delta
                        cost_delta = provider.total_cost - cost_before
                        tokens_delta = provider.total_tokens - tokens_before

                        # Track at client level (thread-safe)
                        with self._stats_lock:
                            self.total_cost += cost_delta
                            self.request_count += 1
                            if task_type:
                                self.task_type_costs[task_type] = self.task_type_costs.get(task_type, 0.0) + cost_delta

                        logger.debug(f"Structured generation successful: {model.provider}/{model.model_name} "
                                    f"(tokens: {tokens_delta}, cost: ${cost_delta:.4f}, "
                                    f"duration: {duration:.1f}s)")

                        result_dict, raw = result_tuple
                        structured_response = StructuredResponse(
                            result=result_dict,
                            raw=raw,
                            cost=cost_delta,
                            tokens_used=tokens_delta,
                            model=model.model_name,
                            provider=model.provider,
                            duration=duration,
                        )
                        # Cache before returning so repeated identical calls
                        # short-circuit the provider entirely. Cache key is
                        # tied to model_config (the first-choice model), so
                        # a fallback's output is filed under the original
                        # request's identity — matches generate()'s behaviour.
                        self._save_structured_to_cache(cache_key, structured_response)
                        return structured_response

                    except Exception as e:
                        last_error = e

                        if _is_quota_error(e):
                            quota_guidance = _get_quota_guidance(model.model_name, model.provider)
                            logger.warning(f"Quota error for {model.provider}/{model.model_name}:{quota_guidance}")

                        logger.warning(_sanitize_log_message(f"Structured generation attempt {attempt + 1} failed: {str(e)}"))

                        if not _is_retryable_error(e):
                            logger.info(f"Non-retryable error — skipping remaining retries for {model.provider}/{model.model_name}")
                            break

                        if attempt < self.config.max_retries - 1:
                            delay = min(self.config.retry_delay * (2 ** attempt), 30)
                            logger.debug(f"Retrying in {delay}s...")
                            time.sleep(delay)

            # All models in tier failed
            tier = "local (Ollama)" if model_config.provider.lower() == "ollama" else "cloud"
            error_msg = f"Structured generation failed for all {tier} models (tried {attempts_count} model(s))."

            if last_error and _is_quota_error(last_error):
                error_msg += _get_quota_guidance(model_config.model_name, model_config.provider)
                error_msg += f"\nProvider message: {_sanitize_log_message(str(last_error))}"
            elif last_error:
                error_msg += f"\nLast error: {_sanitize_log_message(str(last_error))}"
                if tier == "local (Ollama)":
                    error_msg += "\n→ Check Ollama server: http://localhost:11434/api/tags"
                else:
                    error_msg += "\n→ Check API keys and network connectivity"
            else:
                error_msg += "\nNo enabled models available in this tier."
                if tier == "local (Ollama)":
                    error_msg += "\n→ Check Ollama server: http://localhost:11434/api/tags"
                else:
                    error_msg += "\n→ Check API keys and network connectivity"

            logger.error(error_msg)
            raise RuntimeError(error_msg)

    def get_stats(self) -> Dict[str, Any]:
        """Get usage statistics with per-provider, per-task-type, and token split breakdowns."""
        provider_stats = {}
        for key, provider in self.providers.items():
            avg_duration = (provider.total_duration / provider.call_count
                           if provider.call_count > 0 else 0.0)
            provider_stats[key] = {
                "call_count": provider.call_count,
                "total_tokens": provider.total_tokens,
                "input_tokens": provider.total_input_tokens,
                "output_tokens": provider.total_output_tokens,
                "total_cost": provider.total_cost,
                "total_duration": round(provider.total_duration, 2),
                "avg_duration": round(avg_duration, 2),
            }

        with self._stats_lock:
            return {
                "total_requests": self.request_count,
                "total_cost": self.total_cost,
                "budget_remaining": self.config.max_cost_per_scan - self.total_cost,
                "providers": provider_stats,
                "task_type_costs": dict(self.task_type_costs),
            }

    def reset_stats(self) -> None:
        """Reset usage statistics."""
        with self._stats_lock:
            self.total_cost = 0.0
            self.request_count = 0
            self.task_type_costs.clear()
        for provider in self.providers.values():
            provider.total_tokens = 0
            provider.total_input_tokens = 0
            provider.total_output_tokens = 0
            provider.total_cost = 0.0
            provider.call_count = 0
            provider.total_duration = 0.0
