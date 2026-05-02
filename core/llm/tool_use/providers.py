"""``ToolUseProvider`` Protocol.

Each backend (Anthropic / OpenAI / Gemini / Ollama) implements one
``turn()`` primitive that translates the provider-agnostic types in
:mod:`.types` to and from its native wire format. The
:class:`~.loop.ToolUseLoop` only ever talks to providers through this
Protocol — provider swaps are zero-churn at the call sites.

Capability flags drive the loop's behaviour without per-provider
branching: ``cache_control`` is only emitted when
:meth:`supports_prompt_caching` is True; missing capabilities degrade
gracefully (the loop emits the request without the unsupported field
rather than raising).
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any, Protocol, runtime_checkable

from .types import (
    CacheControl,
    Message,
    ToolDef,
    TurnResponse,
)


@runtime_checkable
class ToolUseProvider(Protocol):
    """Capability-flagged single-turn primitive over a tool-using LLM.

    Providers that don't support tool-use at all (e.g., a bare-bones
    Ollama install with a non-tool-capable model) raise
    :class:`NotImplementedError` from :meth:`turn`. Callers that care
    check :meth:`supports_tool_use` first.
    """

    # ------------------------------------------------------------------
    # Capability flags
    # ------------------------------------------------------------------

    def supports_tool_use(self) -> bool:
        """``True`` when the bound model accepts tool/function-call
        schemas in requests AND emits structured calls in responses."""
        ...

    def supports_prompt_caching(self) -> bool:
        """``True`` for providers with a per-region cache breakpoint
        mechanism (Anthropic). The loop only forwards
        :class:`CacheControl` when this returns True; other providers
        receive the struct but ignore it."""
        ...

    def supports_parallel_tools(self) -> bool:
        """``True`` when the provider can return multiple
        :class:`ToolCall` blocks in one assistant turn AND the loop
        can dispatch them in parallel. The loop currently dispatches
        sequentially regardless — this flag is informational for v1
        and gates a future parallel-dispatch optimisation."""
        ...

    def context_window(self) -> int:
        """Total tokens the model accepts in one request. Drives the
        loop's :class:`ContextPolicy` enforcement — silently falling
        back to a guess would mis-gate, so providers raise
        ``KeyError`` on unknown models in their constructor."""
        ...

    def estimate_tokens(self, text: str) -> int:
        """Cheap pre-flight token estimator. Used by the loop to
        decide truncate-or-raise before sending an oversized request.
        Doesn't need to be exact — within a factor of 2 is fine, since
        the policy gate fires only at full-window scale.

        Default heuristic for providers that don't ship a tokenizer:
        ``len(text) // 4`` (English/code averages ~4 chars/token).
        """
        ...

    def price_per_million(self) -> tuple[float, float]:
        """``(input_per_million_usd, output_per_million_usd)`` for the
        bound model. Cache-read / cache-write multipliers — when
        relevant — are applied inside :meth:`compute_cost`, not here,
        so the abstraction stays portable to providers without prompt
        caching."""
        ...

    # ------------------------------------------------------------------
    # Per-turn cost
    # ------------------------------------------------------------------

    def compute_cost(self, response: TurnResponse) -> float:
        """USD cost of ``response`` given the bound model's pricing.

        Lives on the provider so each backend's quirks (Anthropic's
        cache-read 0.1x / cache-write 1.25x multipliers, OpenAI's
        flat per-million rates, Gemini's tiered pricing for prompts
        ≤200K vs >200K, Ollama's $0) are handled where they belong.
        The loop only sees the final number.
        """
        ...

    # ------------------------------------------------------------------
    # The actual turn primitive
    # ------------------------------------------------------------------

    def turn(
        self,
        messages: Sequence[Message],
        tools: Sequence[ToolDef],
        *,
        system: str | None = None,
        max_tokens: int = 4096,
        cache_control: CacheControl = CacheControl(),
        **provider_specific: Any,
    ) -> TurnResponse:
        """Send one round-trip to the provider.

        :param messages: full conversation history. The provider
            translates to its native wire format (Anthropic accepts
            our ``Message`` shape almost directly; OpenAI splits user
            messages with multiple :class:`ToolResult`\\ s into N
            ``role:"tool"`` messages; Gemini / Ollama have their own
            quirks).
        :param tools: tool schemas the model is allowed to call. Empty
            sequence is valid — the model gets no tools and must reply
            with text only.
        :param system: top-level system prompt. ``None`` skips the
            system block. Providers without a system-block concept
            (some Ollama configurations) prepend it as a synthetic
            user-role turn.
        :param max_tokens: cap on response output. Providers clamp to
            their model's max-output limit if exceeded.
        :param cache_control: per-region cache opt-ins. Honoured by
            providers where :meth:`supports_prompt_caching` is True;
            others ignore.
        :param provider_specific: opt-in flags / overrides for
            backend-specific features that other providers can't
            express (Anthropic's ``anthropic_task_budget_beta=True``,
            OpenAI's ``parallel_tool_calls=False``, etc.). Receivers
            ignore unrecognised kwargs.
        """
        ...
