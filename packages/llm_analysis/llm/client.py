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
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple

# Add parent directories to path for core imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from core.logging import get_logger
from .config import LLMConfig, ModelConfig
from .providers import LLMProvider, LLMResponse, create_provider

logger = get_logger()


class LLMClient:
    """Unified LLM client with multi-provider support and fallback."""

    def __init__(self, config: Optional[LLMConfig] = None):
        self.config = config or LLMConfig()
        self.providers: Dict[str, LLMProvider] = {}
        self.total_cost = 0.0
        self.request_count = 0

        # Initialize cache
        if self.config.enable_caching:
            self.config.cache_dir.mkdir(parents=True, exist_ok=True)

        logger.info("LLM Client initialized")
        logger.info(f"Primary model: {self.config.primary_model.provider}/{self.config.primary_model.model_name}")
        if self.config.enable_fallback:
            logger.info(f"Fallback models: {len(self.config.fallback_models)}")

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

        # Get appropriate model for task
        if task_type:
            model_config = self.config.get_model_for_task(task_type)
        else:
            model_config = self.config.primary_model

        # Check cache
        cache_key = self._get_cache_key(prompt, system_prompt, model_config.model_name)
        cached_content = self._get_cached_response(cache_key)
        if cached_content:
            self.request_count += 1
            return LLMResponse(
                content=cached_content,
                model=model_config.model_name,
                provider=model_config.provider,
                tokens_used=0,
                cost=0.0,
                finish_reason="cached",
            )

        # Try models in order with fallback
        models_to_try = [model_config]
        if self.config.enable_fallback:
            models_to_try.extend(self.config.get_available_models())

        last_error = None
        for model in models_to_try:
            if not model.enabled:
                continue

            logger.debug(f"Trying model: {model.provider}/{model.model_name}")

            for attempt in range(self.config.max_retries):
                try:
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
                    logger.warning(f"Attempt {attempt + 1}/{self.config.max_retries} failed for "
                                 f"{model.provider}/{model.model_name}: {e}")

                    if attempt < self.config.max_retries - 1:
                        base_delay = self.config.get_retry_delay(model.api_base)
                        delay = base_delay * (2 ** attempt)  # Exponential backoff
                        logger.debug(f"Retrying in {delay}s (base: {base_delay}s)...")
                        time.sleep(delay)

            logger.warning(f"All attempts failed for {model.provider}/{model.model_name}, trying next model...")

        # All models failed
        error_msg = f"All LLM providers failed. Last error: {last_error}"
        logger.error(error_msg)
        raise RuntimeError(error_msg)

    def generate_structured(self, prompt: str, schema: Dict[str, Any],
                           system_prompt: Optional[str] = None,
                           task_type: Optional[str] = None) -> Tuple[Dict[str, Any], str]:
        """
        Generate structured JSON output with automatic fallback.

        Args:
            prompt: User prompt
            schema: JSON schema for expected output
            system_prompt: System prompt
            task_type: Task type for model selection

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

        # Get appropriate model
        if task_type:
            model_config = self.config.get_model_for_task(task_type)
        else:
            model_config = self.config.primary_model

        # Try models in order
        models_to_try = [model_config]
        if self.config.enable_fallback:
            models_to_try.extend(self.config.get_available_models())

        last_error = None
        for model in models_to_try:
            if not model.enabled:
                continue

            for attempt in range(self.config.max_retries):
                try:
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
                    logger.warning(f"Structured generation attempt {attempt + 1} failed: {e}")

                    if attempt < self.config.max_retries - 1:
                        delay = self.config.get_retry_delay(model.api_base)
                        logger.debug(f"Retrying structured generation in {delay}s...")
                        time.sleep(delay)

        # All models failed
        error_msg = f"Structured generation failed for all providers. Last error: {last_error}"
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
