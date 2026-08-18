"""Thin resilient LLM client — delegates to core.llm substrate.

Until 2026-05-04 this module called the Anthropic SDK directly. Now it
delegates to ``core.llm.providers.create_provider`` which handles
provider abstraction (Anthropic / OpenAI-compat / Gemini / Ollama /
Claude Code subprocess), retry, and cost calculation. This module
preserves the public surface that the analyzer and agent loop depend on:

  * ``ResilientLLMClient`` — ``.complete(model_id, prompt, ...)``
  * ``LLMResponse`` — frozen dataclass with text, model_id, tokens, cost
  * ``LLMCallFailed`` / ``CostBudgetExceeded`` — exception types
  * ``MODEL_PRICES`` — agent loop's cost accounting (cache-aware pricing
    lives in the provider; this table is the loop's fast-path fallback)
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from core.llm.config import ModelConfig
from core.llm.providers import LLMProvider, create_provider

# Bare-alias fallback ONLY — core.llm.model_data.price_for() is the
# authoritative per-model table and consumers must try it first (see
# agent/loop.py:_price). This table catches class tokens ("opus") that
# price_for can't resolve. It had drifted badly: "opus" said $15/$75
# per M-token while every current Opus generation is $5/$25 — a 3x
# over-count that burned the loop's cost budget at triple speed.
MODEL_PRICES: dict[str, tuple[float, float]] = {
    "opus": (5.0, 25.0),
    "sonnet": (3.0, 15.0),
    "haiku": (1.0, 5.0),
}


@dataclass(frozen=True)
class LLMResponse:
    text: str
    model_id: str
    input_tokens: int
    output_tokens: int
    cost_usd: float


class LLMCallFailed(RuntimeError):
    pass


class CostBudgetExceeded(RuntimeError):
    """Raised when cumulative cost on a client instance hits ``max_cost_usd``."""


def _provider_for_model(model_id: str, timeout_s: float) -> LLMProvider:
    """Build a provider from a model id string.

    Resolves provider from the model id — so ``--model gpt-5`` actually
    calls OpenAI, ``--model gemini-2.5-pro`` calls Gemini, etc. Auth
    layers are: ``RAPTOR_LLM_SOCKET`` (dispatcher route) → provider's
    env var → Claude Code OAuth fallback for Anthropic models. See
    :mod:`cve_diff.llm.auth` for the full resolution rules.
    """
    from .auth import resolve_auth

    decision = resolve_auth(model_id)
    config = ModelConfig(
        provider=decision.provider,
        model_name=model_id,
        api_key=decision.api_key,
        timeout=int(timeout_s),
    )
    return create_provider(config)


@dataclass
class ResilientLLMClient:
    max_retries: int = 3
    backoff_factor: float = 2.0
    timeout_s: float = 120.0
    max_cost_usd: float = 0.10
    cumulative_cost_usd: float = field(default=0.0, init=False)

    _provider_cache: dict[str, LLMProvider] = field(
        default_factory=dict, init=False, repr=False
    )

    def _get_provider(self, model_id: str) -> LLMProvider:
        if model_id not in self._provider_cache:
            self._provider_cache[model_id] = _provider_for_model(
                model_id, self.timeout_s
            )
        return self._provider_cache[model_id]

    def complete(
        self,
        model_id: str,
        prompt: str,
        system: str | None = None,
        max_tokens: int = 2048,
        temperature: float | None = None,
    ) -> LLMResponse:
        if self.cumulative_cost_usd >= self.max_cost_usd:
            raise CostBudgetExceeded(
                f"cost budget ${self.max_cost_usd:.4f} reached "
                f"(cumulative ${self.cumulative_cost_usd:.4f}); aborting "
                "before next call"
            )

        provider = self._get_provider(model_id)
        kwargs: dict[str, object] = {"max_tokens": max_tokens}
        if temperature is not None:
            kwargs["temperature"] = temperature

        # Bounded retry — TRANSIENT failures only. The pre-fix loop
        # retried every exception blindly: hard auth failures (401/403),
        # billing caps, and content blocks burned all retries with
        # exponential sleeps and the real cause surfaced only after the
        # full backoff schedule. Classify first; non-retryable errors
        # raise immediately. (Classifier shared with core.llm's own
        # retry loop — same policy, one implementation.)
        from core.llm.client import _is_retryable_error

        attempt = 0
        while True:
            try:
                resp = provider.generate(prompt, system_prompt=system, **kwargs)
                break
            except Exception as exc:
                if attempt >= self.max_retries or not _is_retryable_error(exc):
                    raise LLMCallFailed(
                        f"LLM call ({model_id}) failed after "
                        f"{attempt + 1} attempt(s): {exc}"
                    ) from exc
                attempt += 1
                time.sleep(self.backoff_factor ** attempt)
                continue

        text = (resp.content or "").strip()
        in_t = resp.input_tokens
        out_t = resp.output_tokens
        cost = resp.cost
        self.cumulative_cost_usd += cost
        return LLMResponse(
            text=text,
            model_id=model_id,
            input_tokens=in_t,
            output_tokens=out_t,
            cost_usd=cost,
        )
