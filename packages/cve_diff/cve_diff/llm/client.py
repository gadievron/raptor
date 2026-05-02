"""Thin resilient LLM client — Anthropic SDK direct.

Until 2026-05-01 this module wrapped the OpenAI SDK pointed at a local
LiteLLM proxy. That added an operational dependency (running the proxy)
and a translation hop for every call, even though the agent loop
(``cve_diff/agent/loop.py``) already used the Anthropic SDK directly.
This module is now also Anthropic-direct so the whole project speaks
the same API.

Public surface preserved (analyzer + tests depend on it):

  * ``ResilientLLMClient`` — class with ``.complete(model_id, prompt,
    system=None, max_tokens=2048, temperature=None) -> LLMResponse``.
  * ``LLMResponse`` — frozen dataclass with text, model_id,
    input_tokens, output_tokens, retries, cost_usd.
  * ``LLMCallFailed`` — wraps unrecoverable errors (after retries).
  * ``CostBudgetExceeded`` — pre-flight block once cumulative cost
    crosses ``max_cost_usd``.
  * ``MODEL_PRICES`` — kept for the agent loop's cost accounting.

Retry policy: same as before. Transient = APIConnectionError or 429 /
5xx APIStatusError. Exponential backoff 2s, 4s, 8s. ``max_retries=3``
by default. Permanent (4xx other than 429) raises immediately.
"""

from __future__ import annotations

import sys
import time
from dataclasses import dataclass, field

from anthropic import (
    Anthropic,
    APIConnectionError,
    APIError,
    APIStatusError,
)


# Per-million-token USD prices. Keyed by substring matched
# case-insensitively against the model id passed to `.complete()`.
# Anthropic public list prices at 2026-04 — update here if they change.
# A missing entry is loud (warning + treated as $0 so cost-abort can't
# silently fail to fire).
MODEL_PRICES: dict[str, tuple[float, float]] = {
    "opus": (15.0, 75.0),
    "sonnet": (3.0, 15.0),
    "haiku": (0.80, 4.0),
}


@dataclass(frozen=True)
class LLMResponse:
    text: str
    model_id: str
    input_tokens: int
    output_tokens: int
    retries: int
    cost_usd: float


class LLMCallFailed(RuntimeError):
    pass


class CostBudgetExceeded(RuntimeError):
    """Raised when cumulative cost on a client instance hits ``max_cost_usd``.

    The call that crosses the budget returns normally; the *next* call
    is what gets blocked. A surprise-large response cannot be blocked
    pre-flight (we don't know its cost until the response is back), but
    subsequent calls in the same run cannot pile on.
    """


@dataclass
class ResilientLLMClient:
    max_retries: int = 3
    backoff_factor: float = 2.0
    timeout_s: float = 120.0
    max_cost_usd: float = 0.10
    cumulative_cost_usd: float = field(default=0.0, init=False)

    _warned_unknown_models: set[str] = field(
        default_factory=set, init=False, repr=False
    )

    def __post_init__(self) -> None:
        # ANTHROPIC_API_KEY is read from the environment by the SDK
        # itself; we don't pass it explicitly so the SDK's normal
        # credential discovery (env var, ~/.anthropic, etc.) keeps
        # working.
        self._client = Anthropic(timeout=self.timeout_s)

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

        # Anthropic API takes ``system`` as a top-level field, not a
        # message in the messages array. The OpenAI-compatible shim
        # we used to have here mapped {role: system} into the messages
        # list; we now pass it directly.
        kwargs: dict[str, object] = {
            "model": model_id,
            "max_tokens": max_tokens,
            "messages": [{"role": "user", "content": prompt}],
        }
        if system:
            kwargs["system"] = system
        if temperature is not None:
            kwargs["temperature"] = temperature

        for attempt in range(self.max_retries + 1):
            try:
                resp = self._client.messages.create(**kwargs)  # type: ignore[arg-type]
                # Concatenate every text block in case Anthropic returns
                # multiple. Today there's only one for non-tool-use
                # completions; tool-use isn't used by this client.
                text_parts: list[str] = []
                for block in resp.content:
                    if getattr(block, "type", None) == "text":
                        text_parts.append(block.text)
                text = "".join(text_parts).strip()
                in_t = getattr(resp.usage, "input_tokens", 0) if resp.usage else 0
                out_t = getattr(resp.usage, "output_tokens", 0) if resp.usage else 0
                cost = self._price_call(model_id, in_t, out_t)
                self.cumulative_cost_usd += cost
                return LLMResponse(
                    text=text,
                    model_id=model_id,
                    input_tokens=in_t,
                    output_tokens=out_t,
                    retries=attempt,
                    cost_usd=cost,
                )
            except (APIConnectionError, APIStatusError, APIError) as exc:
                if not _is_transient(exc) or attempt >= self.max_retries:
                    raise LLMCallFailed(
                        f"LLM call ({model_id}) failed after {attempt} retries: {exc}"
                    ) from exc
                time.sleep(self.backoff_factor ** (attempt + 1))
        raise LLMCallFailed(
            f"LLM call ({model_id}) exhausted retries without error — impossible"
        )

    def _price_call(
        self, model_id: str, input_tokens: int, output_tokens: int,
    ) -> float:
        key = model_id.lower()
        for token, (in_per_M, out_per_M) in MODEL_PRICES.items():
            if token in key:
                return (input_tokens * in_per_M + output_tokens * out_per_M) / 1_000_000
        if model_id not in self._warned_unknown_models:
            self._warned_unknown_models.add(model_id)
            print(
                f"warn: no price entry for model '{model_id}' — cost will be "
                "counted as $0 (cost abort cannot fire). Add an entry to "
                "cve_diff.llm.client.MODEL_PRICES to fix.",
                file=sys.stderr,
            )
        return 0.0


def _is_transient(exc: Exception) -> bool:
    if isinstance(exc, APIConnectionError):
        return True
    if isinstance(exc, APIStatusError):
        status = getattr(exc, "status_code", None)
        return status == 429 or (status is not None and 500 <= status < 600)
    return False
