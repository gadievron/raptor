#!/usr/bin/env python3
"""
LLM Provider Implementations — OpenAI SDK + Anthropic SDK + Gemini SDK + Instructor

Native SDKs where available: Anthropic SDK for Anthropic, google-genai
for Gemini (with OpenAI shim fallback), and OpenAI SDK for everything else.
Instructor is used for structured output when available, with a universal
JSON-in-prompt fallback for providers that lack native structured support.
"""

import json
import os
import random
import re
import threading
import time
from abc import ABC, abstractmethod
from collections.abc import Iterator, Sequence
from inspect import isclass
from typing import Dict, Optional, Any, Tuple, Type, Union, TYPE_CHECKING
from dataclasses import dataclass

if TYPE_CHECKING:
    from pydantic import BaseModel

from core.logging import get_logger
from .config import ModelConfig
# Wire-shape types for tool-use turn primitive. These live in
# ``core.llm.tool_use.types`` (zero dependencies on this module);
# importing them here doesn't create a cycle.
from .tool_use.types import (
    CacheControl,
    Message,
    StopReason,
    StreamChunk,
    TextBlock,
    ToolCall,
    ToolDef,
    ToolResult,
    TurnResponse,
)

logger = get_logger()

_ZERO_PRICE_WARNED: set[str] = set()

# Instructor resilience: allow this many consecutive failures before
# permanently disabling tool-use structured output for a provider.
# A single transient error (dispatcher startup race, network hiccup)
# won't kill Instructor for the rest of the session.
_INSTRUCTOR_MAX_CONSEC_FAILURES = 3

_TEMPERATURE_DEPRECATED_FROM = (4, 7)
_CLAUDE_VERSION_RE = re.compile(r"claude-[a-z]+-(\d+)-(\d+)")


def supports_temperature(model_name: str) -> bool:
    """Whether ``model_name`` accepts the ``temperature`` request parameter.

    Anthropic deprecated ``temperature`` for the reasoning tier from 4.7:
    verified empirically that opus-4-7 / opus-4-8 reject it with a 400, while
    opus-4-6-and-older and all sonnet/haiku (<=4-6) still accept it. We gate on
    version >= 4.7 across tiers — every model that is actually >4.6 today is a
    deprecated opus, and omitting ``temperature`` is harmless (the model falls
    back to its default) whereas sending it to a deprecated model is a hard 400,
    so we err toward omitting for >=4.7 (over-omitting a future tier that still
    accepts it costs nothing). The regex matches the ``claude-<tier>-<major>-
    <minor>`` core anywhere in the identifier, so Bedrock region prefixes
    (``us.anthropic.claude-opus-4-7``) and dated snapshots
    (``claude-opus-4-7-20260301``) are handled. Non-claude / unparseable names
    keep ``temperature``.
    """
    m = _CLAUDE_VERSION_RE.search(model_name or "")
    if not m:
        return True
    return (int(m.group(1)), int(m.group(2))) < _TEMPERATURE_DEPRECATED_FROM


def _safe_float(value: Any, *, default: float) -> float:
    """`float(value)` with all error paths collapsed to `default`.

    The CC subprocess envelope nominally returns numeric `cost_usd` /
    `_tokens`, but a future CC change or an upstream parser bug could
    surface a string like `"1.23abc"`, `"NaN"`, `True`, `None`, or
    even a dict. Pre-fix `float(parsed.get("cost_usd") or 0.0)`
    raised ValueError on the non-numeric-string case mid-stack and
    aborted the entire turn. Track the failure in debug logs so a
    real upstream regression is visible without crashing the run.

    Delegates to :func:`core.coerce.to_float_safe` with a CC-
    envelope-specific ``on_error`` so the debug log line stays
    scoped to this producer.
    """
    from core.llm.coerce import to_float_safe

    def _log(v, d):
        logger.debug(
            "CC envelope: non-numeric cost/tokens value %r — using %r",
            v, d,
        )

    return to_float_safe(value, default=default, on_error=_log)


def _safe_int(value: Any, *, default: int) -> int:
    """Same as `_safe_float` for int conversion."""
    from core.llm.coerce import to_int_safe

    def _log(v, d):
        logger.debug(
            "CC envelope: non-int tokens value %r — using %r", v, d,
        )

    return to_int_safe(value, default=default, on_error=_log)


# SDK availability flags (canonical source is detection.py)
from .detection import OPENAI_SDK_AVAILABLE, ANTHROPIC_SDK_AVAILABLE, GENAI_SDK_AVAILABLE  # noqa: E402

# Re-import the actual modules where available (config.py only sets flags)
if OPENAI_SDK_AVAILABLE:
    from openai import OpenAI
if ANTHROPIC_SDK_AVAILABLE:
    import anthropic
if GENAI_SDK_AVAILABLE:
    from google import genai as _genai_module

try:
    import instructor
    INSTRUCTOR_AVAILABLE = True
except ImportError:
    INSTRUCTOR_AVAILABLE = False


@dataclass
class LLMResponse:
    """Standardised LLM response."""
    content: str
    model: str
    provider: str
    tokens_used: int
    cost: float
    finish_reason: str
    input_tokens: int = 0
    output_tokens: int = 0
    thinking_tokens: int = 0
    duration: float = 0.0
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0
    # The concrete model snapshot the provider actually served, lifted from
    # the SDK response when it exposes one (e.g. alias "gemini-2.5-pro" →
    # "gemini-2.5-pro-002"). None when the provider doesn't surface it — the
    # provenance manifest then records the alias only, never a guess.
    resolved_model: Optional[str] = None


@dataclass
class StructuredResponse:
    """Response from generate_structured() with metadata.

    Iterable for backwards compatibility: result, raw = response
    """
    result: Dict[str, Any]
    raw: str
    cost: float = 0.0
    tokens_used: int = 0
    model: str = ""
    provider: str = ""
    duration: float = 0.0
    cached: bool = False
    # Concrete model snapshot the provider served (see LLMResponse.resolved_model).
    resolved_model: Optional[str] = None

    def __iter__(self):
        """Allow unpacking as 2-tuple for backwards compatibility."""
        return iter((self.result, self.raw))


def extract_resolved_model(raw: Any) -> Optional[str]:
    """Best-effort: the concrete model id from a provider SDK response object.

    Providers are configured with floating aliases ("gemini-2.5-pro"); the SDK
    response usually echoes the snapshot the provider actually served
    ("gemini-2.5-pro-002"). That snapshot is the only honest record of *which*
    model ran, so we lift it when present. Returns None when the SDK doesn't
    surface it — callers then fall back to the alias and never fabricate a
    snapshot. Never raises; provenance must not break a generation.
    """
    if raw is None:
        return None
    # OpenAI / litellm / Anthropic SDK response objects expose `.model`;
    # Google genai exposes `.model_version`.
    for attr in ("model", "model_version"):
        try:
            value = getattr(raw, attr, None)
        except Exception:
            value = None
        if isinstance(value, str) and value:
            return value
    return None


class LLMProvider(ABC):
    """Abstract base class for LLM providers."""

    def __init__(self, config: ModelConfig):
        import threading
        self.config = config
        self.total_tokens = 0
        self.total_input_tokens = 0
        self.total_output_tokens = 0
        self.total_cost = 0.0
        self.call_count = 0
        self.total_duration = 0.0
        self.total_cache_read_tokens = 0
        self.total_cache_write_tokens = 0
        self._usage_lock = threading.Lock()

    @abstractmethod
    def generate(self, prompt: str, system_prompt: Optional[str] = None,
                 **kwargs) -> LLMResponse:
        """Generate completion from the model."""
        pass

    @abstractmethod
    def generate_structured(self, prompt: str, schema: Dict[str, Any],
                           system_prompt: Optional[str] = None,
                           **kwargs) -> "StructuredResponse":
        """Generate structured output matching the provided schema.

        Returns a ``StructuredResponse`` (which unpacks as a ``(result, raw)``
        2-tuple via ``__iter__`` for backwards compatibility, and carries the
        resolved model snapshot).

        ``**kwargs`` accepts per-call generation overrides — most
        notably ``temperature``. Pre-fix the abstract signature did
        NOT accept kwargs, so callers passing
        ``provider.generate_structured(prompt, schema, sp,
        temperature=0.2)`` would TypeError, forcing
        ``LLMClient.generate_structured`` to drop the kwarg with a
        warning. The result: every task's `task.temperature` was
        silently ignored on the structured-output path while
        appearing to be honoured on the freeform path. Concrete
        impls should prefer
        ``kwargs.get("temperature", self.config.temperature)``.
        """
        pass

    # ------------------------------------------------------------------
    # Tool-use primitives — opt-in per provider.
    # ------------------------------------------------------------------
    #
    # Single-turn round-trip used by the agentic ``ToolUseLoop``
    # runner in :mod:`core.llm.tool_use.loop`. Providers that natively
    # support tool / function calling override :meth:`turn` and flip
    # :meth:`supports_tool_use` to ``True``. Providers that can't
    # (e.g., :class:`ClaudeCodeProvider`'s subprocess dispatcher) keep
    # the defaults — calling :meth:`turn` raises ``NotImplementedError``.
    #
    # This is the same shape the now-retired ``ToolUseProvider``
    # Protocol had; absorbing it onto :class:`LLMProvider` removes the
    # parallel hierarchy + duplicate Anthropic SDK wiring that
    # ``AnthropicToolUseProvider`` introduced.

    def supports_tool_use(self) -> bool:
        """``True`` when the bound model accepts tool/function-call
        schemas in requests AND emits structured calls in responses.
        Default ``False``; concrete providers override."""
        return False

    def supports_prompt_caching(self) -> bool:
        """``True`` for providers with a per-region cache breakpoint
        mechanism (Anthropic). The :class:`ToolUseLoop` only forwards
        :class:`CacheControl` when this returns True; other providers
        receive the struct but ignore it."""
        return False

    def supports_parallel_tools(self) -> bool:
        """``True`` when the provider can return multiple
        :class:`ToolCall` blocks in one assistant turn AND the loop
        can dispatch them in parallel. The loop dispatches
        sequentially today regardless — informational flag for v1."""
        return False

    def context_window(self) -> int:
        """Total tokens the model accepts. Drives the loop's context-
        policy enforcement. Sourced from :mod:`core.llm.model_data`
        by default; raises ``KeyError`` on unknown models so
        misconfiguration surfaces immediately."""
        from .model_data import context_window_for
        return context_window_for(self.config.model_name)

    def estimate_tokens(self, text: str) -> int:
        """Cheap pre-flight token estimator. Default heuristic
        (4 chars/token) is good enough for the loop's context-policy
        gate; providers with a real tokenizer can override for
        accuracy."""
        return max(len(text) // 4, 1)

    def price_per_million(self) -> tuple[float, float]:
        """``(input_per_million_usd, output_per_million_usd)`` for the
        bound model. Cache-read / cache-write multipliers — when
        relevant — are applied inside :meth:`compute_cost`, not here."""
        from .model_data import price_for
        return price_for(self.config.model_name, default=(0.0, 0.0))

    def compute_cost(self, response: TurnResponse) -> float:
        """USD cost of ``response`` given the bound model's pricing.

        If ``response.cost_usd`` is already populated (some providers
        — e.g., Claude Code via the synthesis fallback — surface the
        exact envelope cost), that value is returned directly so the
        loop's budget tracking matches the provider's own ledger.
        Otherwise: standard input/output tokens at the model's per-M
        rates, ignoring cache fields. Anthropic overrides to add the
        documented 1.25× cache-write and 0.1× cache-read multipliers.
        """
        if response.cost_usd is not None:
            return response.cost_usd
        in_per_m, out_per_m = self.price_per_million()
        if in_per_m == 0.0 and out_per_m == 0.0 and (response.input_tokens or response.output_tokens):
            if self.config.model_name not in _ZERO_PRICE_WARNED:
                _ZERO_PRICE_WARNED.add(self.config.model_name)
                logger.warning(
                    "no pricing for model %s — cost tracking disabled, "
                    "max_cost_usd budget cap will not trigger",
                    self.config.model_name,
                )
        return (
            response.input_tokens * in_per_m
            + response.output_tokens * out_per_m
        ) / 1_000_000.0

    def turn(
        self,
        messages: Sequence[Message],
        tools: Sequence[ToolDef],
        *,
        system: Optional[str] = None,
        max_tokens: int = 4096,
        cache_control: CacheControl = CacheControl(),
        **provider_specific: Any,
    ) -> TurnResponse:
        """Send one round-trip with tool/function-call schemas.

        Default implementation raises ``NotImplementedError`` —
        providers that can do tool-use override this method. Callers
        that need to gate behaviour use :meth:`supports_tool_use`.
        """
        raise NotImplementedError(
            f"{type(self).__name__} does not support tool-use; "
            f"check ``supports_tool_use()`` before calling ``turn()``"
        )

    def supports_streaming(self) -> bool:
        """``True`` when ``turn_stream()`` yields real-time chunks
        from the provider's API rather than wrapping ``turn()``."""
        return False

    def turn_stream(
        self,
        messages: Sequence[Message],
        tools: Sequence[ToolDef],
        *,
        system: Optional[str] = None,
        max_tokens: int = 4096,
        cache_control: CacheControl = CacheControl(),
        **provider_specific: Any,
    ) -> Iterator[StreamChunk]:
        """Streaming variant of :meth:`turn`.

        Default implementation wraps ``turn()`` — all chunks arrive
        in one burst with no real-time benefit. Providers with native
        streaming override both this and :meth:`supports_streaming`.
        """
        response = self.turn(
            messages, tools, system=system,
            max_tokens=max_tokens, cache_control=cache_control,
            **provider_specific,
        )
        for block in response.content:
            if isinstance(block, TextBlock):
                yield StreamChunk(type="text_delta", text=block.text)
            elif isinstance(block, ToolCall):
                yield StreamChunk(
                    type="tool_call_start",
                    tool_call_id=block.id,
                    tool_call_name=block.name,
                )
                if block.input:
                    yield StreamChunk(
                        type="tool_call_delta",
                        tool_call_id=block.id,
                        tool_call_input_delta=json.dumps(block.input),
                    )
                yield StreamChunk(
                    type="tool_call_end", tool_call_id=block.id,
                )
        yield StreamChunk(
            type="usage",
            input_tokens=response.input_tokens,
            output_tokens=response.output_tokens,
            cache_read_tokens=response.cache_read_tokens,
            cache_write_tokens=response.cache_write_tokens,
        )
        yield StreamChunk(type="done", stop_reason=response.stop_reason)

    def track_usage(self, tokens: int, cost: float,
                    input_tokens: int = 0, output_tokens: int = 0,
                    duration: float = 0.0,
                    cache_read_tokens: int = 0,
                    cache_write_tokens: int = 0) -> None:
        """Track token usage, cost, and call duration (thread-safe)."""
        with self._usage_lock:
            self.total_tokens += tokens
            self.total_input_tokens += input_tokens
            self.total_output_tokens += output_tokens
            self.total_cache_read_tokens += cache_read_tokens
            self.total_cache_write_tokens += cache_write_tokens
            self.total_cost += (cost or 0.0)
            self.call_count += 1
            self.total_duration += duration
        logger.debug("LLM usage: %s tokens, $%.4f (total: %s tokens, $%.4f)", tokens, cost or 0.0, self.total_tokens, self.total_cost)

    def _calculate_cost_split(self, input_tokens: int, output_tokens: int,
                              thinking_tokens: int = 0,
                              cache_read_tokens: int = 0,
                              cache_write_tokens: int = 0) -> float:
        """Calculate cost using split input/output pricing.

        Thinking/reasoning tokens are billed at the output rate on all
        providers (OpenAI, Google, Anthropic).

        When ``cache_read_tokens`` or ``cache_write_tokens`` are non-zero,
        Anthropic cache multipliers (0.1x read, 1.25x write at the input
        rate) are applied. Non-Anthropic providers never pass these so
        the cost formula stays unchanged for them.

        Pre-fix the unknown-model fallback returned 0.0 silently when
        `cost_per_1k_tokens` was also 0 (the dataclass default). For
        a model name absent from `MODEL_COSTS` AND no caller-supplied
        rate, every call recorded $0 cost. Budget caps that depended
        on cumulative cost were silently defeated — the model burned
        tokens forever without tripping the cap. Operators saw
        "current cost: $0.00" and assumed nothing was being spent.

        Warn-once per model when the fallback rate is 0 so the
        operator gets ONE log line per unknown model, not a flood.
        Use a class-level set so the warn-once persists across
        instances of the same provider.
        """
        from .model_data import MODEL_COSTS, _strip_dated_alias
        rates = MODEL_COSTS.get(self.config.model_name) or MODEL_COSTS.get(
            _strip_dated_alias(self.config.model_name),
        )
        if not rates:
            rate = self.config.cost_per_1k_tokens or 0.0
            # ``math.isclose`` with abs_tol collapses ±epsilon to
            # "zero" — pre-fix ``rate == 0.0`` missed the warning
            # when ``cost_per_1k_tokens`` was a computed near-zero
            # float (e.g. a tiny config value or arithmetic result
            # that didn't land exactly on the int representation).
            import math
            if math.isclose(rate, 0.0, abs_tol=1e-12):
                self._warn_unknown_model_once(self.config.model_name)
            return ((input_tokens + output_tokens + thinking_tokens) / 1000) * rate
        base = (
            (input_tokens / 1000) * rates["input"]
            + ((output_tokens + thinking_tokens) / 1000) * rates["output"]
        )
        if cache_read_tokens or cache_write_tokens:
            from .model_data import (
                ANTHROPIC_CACHE_READ_MULTIPLIER,
                ANTHROPIC_CACHE_WRITE_MULTIPLIER,
            )
            base += (cache_read_tokens / 1000) * rates["input"] * ANTHROPIC_CACHE_READ_MULTIPLIER
            base += (cache_write_tokens / 1000) * rates["input"] * ANTHROPIC_CACHE_WRITE_MULTIPLIER
        return base

    # Class-level (NOT instance-level) so we warn once per model name
    # across the whole process, even when callers create fresh
    # provider instances per request (a common pattern in the agentic
    # dispatch path).
    _warned_unknown_models: set = set()
    _warned_unknown_models_lock = threading.Lock()

    @classmethod
    def _warn_unknown_model_once(cls, model_name: str) -> None:
        with cls._warned_unknown_models_lock:
            if model_name in cls._warned_unknown_models:
                return
            cls._warned_unknown_models.add(model_name)
        logger.warning(
            f"cost tracking: model {model_name!r} not in MODEL_COSTS "
            f"and no cost_per_1k_tokens set — every call records $0. "
            f"Budget caps based on cumulative cost are NOT enforced "
            f"for this model. Add a rate to model_data.MODEL_COSTS "
            f"or pass cost_per_1k_tokens to the LLMConfig."
        )

    def _structured_fallback(self, prompt: str, schema: Dict[str, Any],
                             pydantic_model, system_prompt: Optional[str] = None
                             ) -> Tuple[Dict[str, Any], str]:
        """
        Universal fallback: ask for JSON in the prompt, validate
        with Pydantic. Works with any LLM that can produce JSON.
        Usage is tracked by self.generate() — no double counting.
        """
        schema_json = json.dumps(schema, indent=2)
        schema_block = (
            f"\n\n## Output format\n"
            f"Respond with JSON matching this schema:\n"
            f"```json\n{schema_json}\n```\n"
            f"Return ONLY valid JSON, no other text."
        )
        augmented_system = (
            (system_prompt or "") + schema_block
        )
        response = self.generate(prompt, augmented_system)
        if response.finish_reason in ("max_tokens", "length"):
            raise json.JSONDecodeError(
                "Response truncated (output token limit reached)",
                response.content[:200] if response.content else "",
                0,
            )
        try:
            content = response.content.strip()
            # Strip markdown fences: ```json\n...\n``` or ```\n...\n```
            if content.startswith("```") and content.endswith("```"):
                if "\n" in content:
                    content = content.split("\n", 1)[1]
                else:
                    content = content[3:]
                    # Single-line: strip language tag (e.g. "json", "ql")
                    content = content.lstrip("abcdefghijklmnopqrstuvwxyz")
                content = content.rsplit("```", 1)[0]
            elif content.startswith("```"):
                if "\n" in content:
                    content = content.split("\n", 1)[1]
                else:
                    content = content[3:]
                    content = content.lstrip("abcdefghijklmnopqrstuvwxyz")
            content = content.strip()
            parsed = json.loads(content)
            parsed = _coerce_to_schema(parsed, _normalize_schema(schema))
            validated = pydantic_model.model_validate(parsed)
            result_dict = validated.model_dump()
            # Carry the resolved model from the underlying generate() call so
            # the JSON-fallback path attributes correctly too.
            return StructuredResponse(
                result=result_dict,
                raw=json.dumps(result_dict, indent=2),
                resolved_model=response.resolved_model,
            )
        except Exception as e:
            # Pre-fix the logger interpolated `e` directly into the
            # log line. For `pydantic.ValidationError` (the typical
            # failure here), the exception message embeds the
            # offending input value — which IS the LLM's raw
            # content. That content can carry prompt-injection
            # markers, ANSI escape sequences, BIDI overrides, or
            # control bytes that — when the log line renders to an
            # operator's TTY or a downstream log aggregator — let
            # an attacker forge log entries / smuggle terminal
            # repaints / bypass audit displays.
            #
            # Defang the rendered exception text via
            # `escape_nonprintable` before logging. The exception
            # itself is still re-raised unchanged so caller error
            # handling sees the same type and propagated message.
            from core.security.prompt_output_sanitise import escape_nonprintable
            _safe_msg = escape_nonprintable(str(e))[:1024]
            logger.error(
                f"Structured fallback failed (JSON parse or validation): {_safe_msg}"
            )
            raise

    # ------------------------------------------------------------------
    # Tool-use fallback — JSON-in-prompt protocol over plain generate().
    # ------------------------------------------------------------------
    #
    # Synthesises a single tool-use turn for providers that can produce
    # text but lack native tool/function calling (e.g., the Claude Code
    # subprocess transport). Subclasses opt in by overriding ``turn`` to
    # delegate here and flipping ``supports_tool_use`` to True.
    #
    # Limitations vs. native:
    #   * one tool call per turn (parallel calls aren't reliably
    #     synthesisable — the prompt asks for one at a time)
    #   * ``CacheControl`` is ignored
    #   * token counts come from the underlying ``generate()`` response;
    #     cost flows through whatever ``track_usage`` records
    # The loop itself is unchanged — it sees the same ``TurnResponse``
    # shape native ``turn`` impls produce.

    def _tool_use_fallback(
        self,
        messages: Sequence[Message],
        tools: Sequence[ToolDef],
        *,
        system: Optional[str] = None,
        max_tokens: int = 4096,
        cache_control: CacheControl = CacheControl(),
        **provider_specific: Any,
    ) -> TurnResponse:
        """Synthesise one tool-use round-trip via plain ``generate()``."""
        del cache_control, provider_specific  # unused by fallback
        tool_protocol = self._render_tool_protocol(tools) if tools else ""
        sys_combined = "\n\n".join(s for s in (system, tool_protocol) if s) or None
        rendered_prompt = self._render_messages_as_prompt(messages)

        response = self.generate(
            rendered_prompt,
            system_prompt=sys_combined,
            max_tokens=max_tokens,
        )

        text = response.content if response and response.content else ""
        block, stop_reason = self._parse_fallback_response(text, tools)

        # Surface the underlying generate() cost on the TurnResponse so
        # loop-side budget tracking reflects the actual provider charge,
        # not a token-derived estimate that may be 0 (e.g., when the CC
        # subprocess uses a model name absent from MODEL_COSTS).
        cost = getattr(response, "cost", None)
        return TurnResponse(
            content=[block],
            stop_reason=stop_reason,
            input_tokens=getattr(response, "input_tokens", 0) or 0,
            output_tokens=getattr(response, "output_tokens", 0) or 0,
            cost_usd=float(cost) if cost is not None else None,
        )

    @staticmethod
    def _render_tool_protocol(tools: Sequence[ToolDef]) -> str:
        """Render tool defs as a JSON-call protocol the model is asked
        to follow. The model is told to emit one JSON object per call;
        the parser tolerates ```json fences and surrounding whitespace
        but not interleaved prose."""
        lines = [
            "You have access to the following tools. To call a tool,",
            "respond with ONLY a JSON object in this exact shape:",
            "```json",
            '{"tool": "<tool_name>", "input": {...}}',
            "```",
            "Call only one tool per response. If you don't need a tool,",
            "respond with normal text and no JSON.",
            "",
            "Available tools:",
        ]
        for t in tools:
            schema_json = json.dumps(t.input_schema, indent=2)
            lines.append(f"- name: {t.name}")
            lines.append(f"  description: {t.description}")
            lines.append(f"  input_schema: {schema_json}")
        return "\n".join(lines)

    @staticmethod
    def _render_messages_as_prompt(messages: Sequence[Message]) -> str:
        """Flatten conversation history into a single prompt string.

        Tool calls/results are rendered as tagged sections so the model
        can follow the protocol on subsequent turns. The role labels
        match what we ask for in :meth:`_render_tool_protocol`."""
        parts: list[str] = []
        for msg in messages:
            for block in msg.content:
                if isinstance(block, TextBlock):
                    parts.append(f"{msg.role}: {block.text}")
                elif isinstance(block, ToolCall):
                    parts.append(
                        f"assistant called tool {block.name!r} "
                        f"with input {json.dumps(block.input)}"
                    )
                elif isinstance(block, ToolResult):
                    err = " [ERROR]" if block.is_error else ""
                    parts.append(
                        f"tool_result{err} for {block.tool_use_id}: "
                        f"{block.content}"
                    )
        return "\n\n".join(parts)

    @staticmethod
    def _parse_fallback_response(
        text: str, tools: Sequence[ToolDef],
    ) -> tuple[Union[TextBlock, ToolCall], StopReason]:
        """Extract a tool call (if any) or fall back to a text block.

        Uses :func:`core.llm.cc_adapter.strip_json_fences` to find a
        JSON payload inside ```json fences anywhere in the response —
        not just at the start — so a model that adds short prose
        before/after the fenced JSON still has its call recognised.
        """
        if not text or not tools:
            return TextBlock(text=text or ""), StopReason.COMPLETE

        from .cc_adapter import strip_json_fences
        candidate = strip_json_fences(text).strip()
        try:
            parsed = json.loads(candidate)
        except (json.JSONDecodeError, ValueError):
            return TextBlock(text=text), StopReason.COMPLETE

        if not isinstance(parsed, dict):
            return TextBlock(text=text), StopReason.COMPLETE

        name = parsed.get("tool")
        inp = parsed.get("input")
        if not isinstance(name, str) or not isinstance(inp, dict):
            return TextBlock(text=text), StopReason.COMPLETE

        if not any(t.name == name for t in tools):
            # Model hallucinated a tool name — surface the raw text so
            # the loop can see what happened rather than dispatching a
            # bogus call.
            return TextBlock(text=text), StopReason.COMPLETE

        import uuid as _uuid
        call_id = f"call_{_uuid.uuid4().hex[:12]}"
        return ToolCall(id=call_id, name=name, input=inp), StopReason.NEEDS_TOOL_CALL


def _coerce_to_schema(data: Dict[str, Any], schema: Dict[str, Any]) -> Dict[str, Any]:
    """Coerce LLM output values to match schema types before Pydantic validation.

    LLMs (especially via JSON-in-prompt fallback) often return wrong types:
    - "not_a_bool" or "true" instead of true for booleans
    - "0.85" instead of 0.85 for numbers
    - null instead of "" for strings

    This coercion step fixes common mismatches so Pydantic validation succeeds.
    """
    properties = schema.get("properties", {})
    if not properties:
        return data

    coerced = dict(data)
    for field_name, field_spec in properties.items():
        if field_name not in coerced:
            continue

        value = coerced[field_name]
        raw_type = field_spec.get("type", "string")

        # Handle nullable types: ["string", "null"] or ["boolean", "null"]
        nullable = isinstance(raw_type, list) and "null" in raw_type
        if isinstance(raw_type, list):
            if value is None and nullable:
                continue  # null is valid
            # Use the non-null type for coercion
            field_type = next((t for t in raw_type if t != "null"), "string")
        else:
            field_type = raw_type

        if field_type == "boolean" and not isinstance(value, bool):
            if isinstance(value, str):
                coerced[field_name] = value.lower() in ("true", "yes", "1")
            elif isinstance(value, (int, float)):
                coerced[field_name] = bool(value)
            else:
                coerced[field_name] = False

        elif field_type == "number" and (
            not isinstance(value, (int, float))
            or isinstance(value, bool)
        ):
            try:
                coerced[field_name] = float(value)
            except (ValueError, TypeError):
                if nullable:
                    coerced[field_name] = None
                else:
                    logger.debug(
                        "_coerce_to_schema: unparseable number for "
                        "field %r, value %r — defaulting to 0.0",
                        field_name, value,
                    )
                    coerced[field_name] = 0.0

        elif field_type == "integer" and (
            # Pre-fix the check was just `not isinstance(value, int)`.
            # Python booleans ARE ints (`isinstance(True, int) == True`)
            # because `bool` is a subclass of `int`. An LLM
            # emitting `true` / `false` for an integer-typed
            # schema slot then bypassed coercion entirely, and
            # the boolean leaked into the consumer's "integer"
            # field. Pydantic validation accepts bool-as-int via
            # the same subclass relationship, so the bug only
            # surfaced when the consumer's downstream arithmetic
            # produced surprising results (`True + 1 == 2` but
            # `(True).bit_length() == 1`, etc.) or when the value
            # was JSON-serialised back out and the report showed
            # `"count": true` instead of `"count": 1`.
            #
            # Explicit `or isinstance(value, bool)` forces bool
            # values through the int(value) coercion path
            # (int(True) == 1, int(False) == 0) so the slot
            # ends up with a real int.
            not isinstance(value, int)
            or isinstance(value, bool)
        ):
            try:
                coerced[field_name] = int(value)
            except (ValueError, TypeError):
                if nullable:
                    coerced[field_name] = None
                else:
                    logger.debug(
                        "_coerce_to_schema: unparseable integer for "
                        "field %r, value %r — defaulting to 0",
                        field_name, value,
                    )
                    coerced[field_name] = 0

        elif field_type == "string" and value is None:
            coerced[field_name] = ""

        # Recurse into nested objects
        if field_type == "object" and "properties" in field_spec and isinstance(value, dict):
            coerced[field_name] = _coerce_to_schema(value, field_spec)

        # Recurse into array items that are objects
        if (
            field_type == "array"
            and isinstance(value, list)
            and "items" in field_spec
            and isinstance(field_spec["items"], dict)
            and "properties" in field_spec["items"]
        ):
            coerced[field_name] = [
                _coerce_to_schema(item, field_spec["items"])
                if isinstance(item, dict) else item
                for item in value
            ]

    return coerced


def _normalize_schema(schema: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize simple format schema to JSON Schema format.

    Simple format: {"field": "type description"}
    JSON Schema format: {"properties": {...}, "required": [...]}

    Returns the schema unchanged if already in JSON Schema format.
    """
    if "properties" in schema:
        return schema  # Already JSON Schema

    type_aliases = {
        "bool": "boolean", "str": "string", "int": "integer",
        "float": "number", "list": "array", "dict": "object",
    }

    properties = {}
    for field_name, field_desc in schema.items():
        if isinstance(field_desc, dict):
            properties[field_name] = field_desc
            continue

        field_desc_str = str(field_desc)
        parts = field_desc_str.split()
        field_type = parts[0].strip() if parts else "string"
        field_type = type_aliases.get(field_type, field_type)

        desc_lower = field_desc_str.lower()
        # Detect nullable: "string or null", "float or null"
        if " or null" in desc_lower:
            prop = {"type": [field_type, "null"]}
        elif desc_lower.startswith("null or "):
            # "null or string" — extract the actual type from the second word
            actual = parts[2].strip() if len(parts) > 2 else "string"
            actual = type_aliases.get(actual, actual)
            prop = {"type": [actual, "null"]}
        else:
            prop = {"type": field_type}

        # Arrays need an items definition for Gemini
        if field_type == "array":
            prop["items"] = {"type": "string"}

        # Extract description
        if " - " in field_desc_str:
            prop["description"] = field_desc_str.split(" - ", 1)[1].strip()
        elif "(" in field_desc_str:
            prop["description"] = field_desc_str[field_desc_str.find("("):].strip()

        properties[field_name] = prop

    required = []
    for field_name, field_desc in schema.items():
        if isinstance(field_desc, dict):
            required.append(field_name)
            continue
        desc_lower = str(field_desc).lower()
        if "optional" not in desc_lower and "or null" not in desc_lower:
            required.append(field_name)
    return {"properties": properties, "required": required}


def _schema_to_gemini(schema: Dict[str, Any]) -> Dict[str, Any]:
    """Convert JSON Schema to Gemini-compatible schema.

    The google-genai SDK rejects nullable union types like ["string", "null"].
    Gemini expects single type strings ("STRING") with a separate "nullable" flag.
    """
    TYPE_MAP = {
        "string": "STRING", "number": "NUMBER", "integer": "INTEGER",
        "boolean": "BOOLEAN", "array": "ARRAY", "object": "OBJECT", "null": "NULL",
    }

    def convert_property(prop: Dict[str, Any]) -> Dict[str, Any]:
        out = {}
        prop_type = prop.get("type")
        if isinstance(prop_type, list):
            # ["string", "null"] → type="STRING", nullable=True
            non_null = [t for t in prop_type if t != "null"]
            out["type"] = TYPE_MAP.get(non_null[0], non_null[0]) if non_null else "STRING"
            if "null" in prop_type:
                out["nullable"] = True
        elif prop_type:
            out["type"] = TYPE_MAP.get(prop_type, prop_type)

        if "description" in prop:
            out["description"] = prop["description"]
        if "enum" in prop:
            out["enum"] = prop["enum"]
        if "items" in prop:
            out["items"] = convert_property(prop["items"])
        if "properties" in prop:
            out["properties"] = {k: convert_property(v) for k, v in prop["properties"].items()}
            if "required" in prop:
                out["required"] = prop["required"]
        return out

    result = {"type": "OBJECT"}
    if "properties" in schema:
        result["properties"] = {k: convert_property(v) for k, v in schema["properties"].items()}
    if "required" in schema:
        result["required"] = schema["required"]
    return result


def _dict_schema_to_pydantic(schema: Union[Dict[str, Any], Type['BaseModel']], _model_name: str = 'DynamicSchema'):
    """
    Convert dict schema or Pydantic model to Pydantic model class.

    Supports hybrid approach:
    - If already Pydantic model class: return as-is
    - If dict: convert to dynamic Pydantic model

    Supports TWO dict formats:
    1. Simple format: {"field_name": "type description"}
       Example: {"is_exploitable": "boolean", "score": "float (0.0-1.0)"}

    2. JSON Schema format: {"properties": {...}, "required": [...]}
       Example: {"properties": {"is_exploitable": {"type": "boolean"}}, "required": ["is_exploitable"]}

    Args:
        schema: Either simple dict, JSON Schema dictionary, or Pydantic BaseModel class

    Returns:
        Pydantic BaseModel class

    Raises:
        ValueError: If schema is invalid or empty
    """
    from pydantic import BaseModel, create_model

    # Check if already a Pydantic model class
    if isclass(schema) and issubclass(schema, BaseModel):
        return schema  # Already Pydantic, return as-is

    # Validate it's a dict if not Pydantic
    if not isinstance(schema, dict):
        raise ValueError(
            f"Schema must be dict or Pydantic BaseModel class, "
            f"got {type(schema).__name__}"
        )

    # Normalize simple format to JSON Schema
    schema = _normalize_schema(schema)

    properties = schema.get("properties", {})
    required_fields = schema.get("required", [])
    has_required_key = "required" in schema

    # Type mapping from JSON Schema to Python types
    type_map = {
        "string": str,
        "integer": int,
        "number": float,
        "boolean": bool,
        "array": list,
        "object": dict,
        "null": type(None)
    }

    # Build field definitions for create_model
    field_definitions = {}

    for field_name, field_spec in properties.items():
        field_type = field_spec.get("type", "string")

        # Handle nullable types: ["string", "null"] → Optional[str]
        nullable = False
        if isinstance(field_type, list):
            nullable = "null" in field_type
            non_null = [t for t in field_type if t != "null"]
            field_type = non_null[0] if non_null else "string"

        enum_values = field_spec.get("enum")
        if enum_values:
            from typing import Literal
            python_type = Literal[tuple(enum_values)]
        elif field_type == "object" and "properties" in field_spec:
            nested_name = f"{_model_name}_{field_name.title().replace('_', '')}"
            python_type = _dict_schema_to_pydantic(field_spec, _model_name=nested_name)
        elif field_type == "array":
            items_spec = field_spec.get("items", {})
            if items_spec.get("type") == "object" and "properties" in items_spec:
                item_name = f"{_model_name}_{field_name.title().replace('_', '')}Item"
                item_type = _dict_schema_to_pydantic(items_spec, _model_name=item_name)
            elif items_spec.get("enum"):
                from typing import Literal
                item_type = Literal[tuple(items_spec["enum"])]
            else:
                item_type = type_map.get(items_spec.get("type", "string"), str)
            from typing import List
            python_type = List[item_type]
        else:
            python_type = type_map.get(field_type, str)

        if nullable:
            from typing import Optional as Opt
            python_type = Opt[python_type]

        # Get default value if present
        default_value = field_spec.get("default", ...)

        # Determine if field is required:
        # - If schema has "required" key: only those fields are required
        # - If no "required" key: all fields optional (JSON Schema default;
        #   LLMs routinely omit sub-fields of optional nested objects)
        is_required = has_required_key and (field_name in required_fields)

        # If field is not required and has no default, make it Optional
        if not is_required and default_value is ...:
            from typing import Optional as Opt
            python_type = Opt[python_type]
            default_value = None

        # Nullable + REQUIRED: keep `...` (no default) so Pydantic
        # enforces presence — the LLM must emit the field, even if the
        # value is `null`. The previous behaviour of forcing
        # `default_value = None` for every nullable field silently
        # accepted omission, defeating the schema's `required` set.
        # Nullable + NOT required: default to None (the omission case
        # is what "not required" means; LLMs habitually omit
        # null-valued non-required fields and we should accept that).
        if nullable and default_value is ... and not is_required:
            default_value = None

        # Create field definition
        if default_value is ...:
            field_definitions[field_name] = (python_type, ...)
        else:
            field_definitions[field_name] = (python_type, default_value)

    # Create and return Pydantic model
    model = create_model(_model_name, **field_definitions)
    return model


# OpenAI reasoning-tier detection. Gated on the version *number*, not a
# literal name list, so gpt-6 / o5 are caught when they ship — mirrors
# ``supports_temperature``'s version-threshold approach. The whole o-series
# is reasoning; gpt is reasoning from major version 5.
_OPENAI_REASONING_GPT_FROM = 5
_OPENAI_GPT_VERSION_RE = re.compile(r"^gpt-(\d+)")
_OPENAI_OSERIES_RE = re.compile(r"^o\d")


def _is_openai_reasoning_model(model_name: str) -> bool:
    """True for OpenAI reasoning-tier models (gpt-5+ and the o-series).

    These models changed the chat.completions contract: they reject the
    legacy ``max_tokens`` param (require ``max_completion_tokens``) and only
    accept the default ``temperature`` (1) — passing ``temperature=0.7``
    returns HTTP 400.

    Future-proofed like ``supports_temperature``: we gate on the version
    *number*, not a literal name list, so gpt-6 / o5 are caught automatically
    when they ship. The whole o-series is reasoning; gpt is reasoning from
    major version >= 5 (gpt-4o / gpt-4.1 stay classic). Matched on the bare
    model name so aggregator/provider prefixes (``openai/gpt-5.5``) and date
    suffixes are tolerated. Non-OpenAI compat models (Ollama ``qwen3``,
    ``olmo``, ``claude-*`` via compat) do not match and keep the legacy params.
    """
    m = (model_name or "").lower().rsplit("/", 1)[-1]
    if _OPENAI_OSERIES_RE.match(m):
        return True
    gm = _OPENAI_GPT_VERSION_RE.match(m)
    return bool(gm) and int(gm.group(1)) >= _OPENAI_REASONING_GPT_FROM


def _openai_sampling_kwargs(
    model_name: str,
    max_tokens: int,
    temperature: Optional[float] = None,
) -> Dict[str, Any]:
    """Return the correct token-limit (+ optional temperature) kwargs for an
    OpenAI chat.completions call, branching on the reasoning-model contract.

    Reasoning models → ``max_completion_tokens`` and NO temperature (default
    only). Classic models → ``max_tokens`` and the requested temperature.
    """
    if _is_openai_reasoning_model(model_name):
        return {"max_completion_tokens": max_tokens}
    kw: Dict[str, Any] = {"max_tokens": max_tokens}
    if temperature is not None:
        kw["temperature"] = temperature
    return kw


class OpenAICompatibleProvider(LLMProvider):
    """
    LLM provider using the OpenAI SDK.

    Works with any OpenAI-compatible API: OpenAI, Ollama, vLLM, LM Studio,
    Gemini (via OpenAI compat), Mistral, etc.
    """

    def __init__(self, config: ModelConfig):
        super().__init__(config)
        if not OPENAI_SDK_AVAILABLE:
            raise ImportError(
                "OpenAI SDK not installed. Run: pip install openai"
            )

        # Dispatcher route only when (a) dispatcher session is set,
        # (b) provider is OpenAI proper (not Ollama / vLLM / LM Studio),
        # AND (c) ``api_base`` is None — i.e., default upstream is
        # ``api.openai.com``. Operators routing through a custom
        # OpenAI-compatible gateway (e.g. corporate proxy at
        # ``my-corp-gw/v1``) keep their ``api_base`` and the
        # dispatcher's hard-coded ``api.openai.com`` upstream would
        # be the wrong destination — fall back to env-direct in
        # that case.
        use_dispatcher = (
            os.environ.get("RAPTOR_LLM_SOCKET")
            and config.provider == "openai"
            and not config.api_base
        )
        if use_dispatcher:
            from core.llm.dispatcher.client import make_openai_client
            self.client = make_openai_client(timeout=config.timeout)
            logger.debug("OpenAICompatibleProvider: routing via credential-isolation dispatcher")
        else:
            _client_kwargs = {}
            # Loopback gateways (Ollama, vLLM, LM Studio): the SDK's
            # default httpx client honours proxy env (trust_env), so
            # on mandatory-proxy hosts whose NO_PROXY lacks loopback,
            # every localhost call detours through the corporate
            # proxy and fails. Pin a trust_env=False transport for
            # loopback bases; remote bases keep proxy-env behaviour.
            from core.llm.egress import url_is_loopback
            if config.api_base and url_is_loopback(config.api_base):
                import httpx as _httpx
                _client_kwargs["http_client"] = _httpx.Client(
                    timeout=config.timeout, trust_env=False,
                )
            self.client = OpenAI(
                api_key=config.api_key or "unused",
                base_url=config.api_base,
                timeout=config.timeout,
                **_client_kwargs,
            )
            logger.debug(
                f"OpenAICompatibleProvider: direct SDK (no dispatcher) provider={config.provider}"
            )

        self.instructor_client = None
        self._instructor_consec_failures = 0
        self._instructor_lock = threading.Lock()
        self._instructor_backed = None  # stashed client during backoff
        if INSTRUCTOR_AVAILABLE:
            self.instructor_client = instructor.from_openai(self.client)
        else:
            logger.warning(
                "Instructor not installed — structured output will use JSON-in-prompt fallback. "
                "For more reliable structured output: pip install instructor"
            )

        # Flips on first detection that this provider's bound model
        # rejects function-calling (older Ollama models, smaller
        # Mistrals, custom finetunes, vLLM-served models without
        # tool support, etc.). Subsequent ``turn()`` calls then go
        # straight to the JSON-protocol synthesis fallback rather
        # than wasting another round-trip. Per-instance, not
        # persisted — a fresh process re-detects on first turn.
        self._tool_use_unsupported = False

        logger.debug("Initialized OpenAICompatibleProvider: %s (base_url=%s)", config.model_name, config.api_base)

    def generate(self, prompt: str, system_prompt: Optional[str] = None,
                 **kwargs) -> LLMResponse:
        """Generate completion using the OpenAI SDK."""
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        try:
            t_start = time.monotonic()
            response = self.client.chat.completions.create(
                model=self.config.model_name,
                messages=messages,
                **_openai_sampling_kwargs(
                    self.config.model_name,
                    kwargs.get("max_tokens", self.config.max_tokens),
                    kwargs.get("temperature", self.config.temperature),
                ),
            )
            duration = time.monotonic() - t_start

            if not response.choices:
                raise RuntimeError("OpenAI returned empty choices")
            message = response.choices[0].message
            content = message.content or ""
            # Ollama thinking models (qwen3, etc.) put responses in reasoning_content
            if not content:
                content = getattr(message, 'reasoning_content', '') or ""
            finish_reason = response.choices[0].finish_reason or "complete"

            # Detect content filter blocks and model refusals
            refusal = getattr(message, 'refusal', None)
            if refusal:
                raise RuntimeError(
                    f"Model refused request: {refusal}"
                )
            if finish_reason == "content_filter":
                if not content:
                    raise RuntimeError(
                        "Response blocked by content filter. "
                        "This typically happens with exploit code or attack scenario prompts."
                    )
                logger.warning("Response truncated by content filter")

            input_tokens = 0
            output_tokens = 0
            thinking_tokens = 0
            cache_read_tokens = 0
            if response.usage:
                input_tokens = response.usage.prompt_tokens or 0
                output_tokens = response.usage.completion_tokens or 0
                # Extract thinking/reasoning tokens (o3, o4-mini, etc.)
                details = getattr(response.usage, 'completion_tokens_details', None)
                if details:
                    thinking_tokens = getattr(details, 'reasoning_tokens', 0) or 0
                    # Reasoning tokens are included in completion_tokens — subtract
                    # to get actual output tokens for display, but bill both as output
                    output_tokens = output_tokens - thinking_tokens
                prompt_details = getattr(response.usage, 'prompt_tokens_details', None)
                if prompt_details:
                    cache_read_tokens = getattr(prompt_details, 'cached_tokens', 0) or 0

            tokens_used = input_tokens + output_tokens + thinking_tokens
            cost = self._calculate_cost_split(input_tokens, output_tokens, thinking_tokens)

            self.track_usage(
                tokens_used, cost, input_tokens, output_tokens, duration,
                cache_read_tokens=cache_read_tokens,
            )
            logger.debug("[OpenAI] model=%s, tokens=%s, cost=$%.4f, duration=%.2fs%s",
                         self.config.model_name, tokens_used, cost, duration,
                         (", thinking=%d" % thinking_tokens) if thinking_tokens else "")

            return LLMResponse(
                content=content,
                model=self.config.model_name,
                provider=self.config.provider.lower(),
                tokens_used=tokens_used,
                cost=cost,
                finish_reason=finish_reason,
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                thinking_tokens=thinking_tokens,
                duration=duration,
                cache_read_tokens=cache_read_tokens,
                resolved_model=extract_resolved_model(response),
            )

        except Exception as e:
            # APIError exception bodies routinely include the request
            # body (which may carry the prompt) and on 400/401 may echo
            # Authorization / x-api-key headers in verbose-debug mode.
            # Also defang ANSI/BIDI/control bytes that could forge log
            # entries on operator TTYs.
            from core.security.log_sanitisation import escape_nonprintable
            from core.security.redaction import redact_secrets
            # DEBUG, not ERROR: the LLMClient retry loop catches this
            # exception and emits its own WARNING ("Attempt N/M failed
            # for openai/<model>: <reason>") with the same fact at
            # the operator-relevant abstraction layer. Logging both
            # produces a 3-line cluster per upstream failure — see
            # the log-noise commit history. DEBUG keeps the deep-
            # debugging detail (escaped + redacted exception body)
            # available with ``-v`` / RAPTOR_LOG_LEVEL=DEBUG without
            # spamming normal runs.
            logger.debug("OpenAI completion failed: %s",
                         escape_nonprintable(redact_secrets(str(e)))[:1024])
            raise

    def generate_structured(self, prompt: str, schema: Dict[str, Any],
                           system_prompt: Optional[str] = None,
                           **kwargs) -> Tuple[Dict[str, Any], str]:
        """Generate structured output using Instructor (or JSON fallback)."""
        pydantic_model = _dict_schema_to_pydantic(schema)
        # Honour caller-supplied temperature so DispatchTask's
        # `temperature = 0.2` (analysis), `0.3` (consensus), etc.
        # actually reach the API. Falls back to configured default.
        temperature = kwargs.get("temperature", self.config.temperature)

        # Try Instructor first (skip for Anthropic via OpenAI-compat — response_format is ignored)
        is_anthropic_compat = self.config.provider.lower() == "anthropic"
        if self.instructor_client is not None and not is_anthropic_compat:
            try:
                messages = []
                if system_prompt:
                    messages.append({"role": "system", "content": system_prompt})
                messages.append({"role": "user", "content": prompt})

                t_start = time.monotonic()
                result, completion = self.instructor_client.chat.completions.create_with_completion(
                    model=self.config.model_name,
                    response_model=pydantic_model,
                    messages=messages,
                    **_openai_sampling_kwargs(
                        self.config.model_name,
                        self.config.max_tokens,
                        temperature,
                    ),
                )
                duration = time.monotonic() - t_start

                result_dict = result.model_dump()
                full_response = json.dumps(result_dict, indent=2)

                input_tokens = 0
                output_tokens = 0
                thinking_tokens = 0
                cache_read_tokens = 0
                if completion.usage:
                    input_tokens = completion.usage.prompt_tokens or 0
                    output_tokens = completion.usage.completion_tokens or 0
                    details = getattr(completion.usage, 'completion_tokens_details', None)
                    if details:
                        thinking_tokens = getattr(details, 'reasoning_tokens', 0) or 0
                        output_tokens = output_tokens - thinking_tokens
                    prompt_details = getattr(completion.usage, 'prompt_tokens_details', None)
                    if prompt_details:
                        cache_read_tokens = getattr(prompt_details, 'cached_tokens', 0) or 0

                tokens_used = input_tokens + output_tokens + thinking_tokens
                cost = self._calculate_cost_split(input_tokens, output_tokens, thinking_tokens)
                self.track_usage(
                    tokens_used, cost, input_tokens, output_tokens, duration,
                    cache_read_tokens=cache_read_tokens,
                )

                with self._instructor_lock:
                    self._instructor_consec_failures = 0
                return StructuredResponse(
                    result=result_dict,
                    raw=full_response,
                    resolved_model=extract_resolved_model(completion),
                )

            except Exception as e:
                with self._instructor_lock:
                    self._instructor_consec_failures += 1
                    consec = self._instructor_consec_failures
                from core.security.log_sanitisation import escape_nonprintable as _esc
                logger.warning(
                    "Instructor structured generation failed for %s/%s (%d/%d). "
                    "Exception (%s): %s",
                    self.config.provider, self.config.model_name,
                    consec, _INSTRUCTOR_MAX_CONSEC_FAILURES,
                    type(e).__name__, _esc(str(e))[:512],
                )
                if consec >= _INSTRUCTOR_MAX_CONSEC_FAILURES:
                    logger.warning(
                        "Instructor disabled for %s/%s after %d consecutive failures",
                        self.config.provider, self.config.model_name,
                        consec,
                    )
                    self._instructor_backed = self.instructor_client
                    self.instructor_client = None

        # Fallback: JSON-in-prompt
        return self._structured_fallback(prompt, schema, pydantic_model, system_prompt)

    # ------------------------------------------------------------------
    # Tool-use turn primitive — OpenAI function-calling shape.
    # ------------------------------------------------------------------
    #
    # Covers OpenAI / Gemini (via /openai compat) / Ollama / Mistral
    # via the same SDK + base_url override that ``generate()`` uses.
    # Function-calling shape: ``tools=[{type:"function", function:{...}}]``,
    # response carries ``message.tool_calls = [{id, function:{name,arguments}}]``.
    # No prompt caching (capability flag returns False); ``CacheControl``
    # is silently ignored. Parallel tool calls are supported by OpenAI
    # but not exploited by the loop today.

    def supports_tool_use(self) -> bool:
        # Flips after a runtime-detected tool-rejection from the
        # bound model — see ``turn()``.
        return not self._tool_use_unsupported
    def supports_prompt_caching(self) -> bool: return False
    def supports_parallel_tools(self) -> bool: return True

    def turn(
        self,
        messages: Sequence[Message],
        tools: Sequence[ToolDef],
        *,
        system: Optional[str] = None,
        max_tokens: int = 4096,
        cache_control: CacheControl = CacheControl(),
        max_retries: int = 3,
        backoff_factor: float = 2.0,
        **_unused: Any,
    ) -> TurnResponse:
        """Send one round-trip via OpenAI-compatible function calling.

        ``cache_control`` is accepted but ignored — OpenAI-compat
        endpoints don't expose a per-region cache mechanism. Caching
        on the actual OpenAI endpoint is automatic (server-side) and
        not driven by request fields.

        Auto-detects tool-use rejection: if the bound model returns a
        4xx error referencing tools/functions on the first attempt,
        flips :attr:`_tool_use_unsupported` and routes through
        :meth:`_tool_use_fallback` for this and all subsequent turns
        (per-instance state). Models that natively support function
        calling never hit this path.
        """
        if _unused:
            logger.debug(
                f"OpenAICompatibleProvider.turn: ignoring unrecognised "
                f"kwargs: {sorted(_unused)}"
            )

        # Already detected this provider rejects tool/function calling.
        # Synthesise via the ABC's JSON-protocol fallback rather than
        # paying another wasted round-trip.
        if self._tool_use_unsupported and tools:
            return self._tool_use_fallback(
                messages, tools,
                system=system, max_tokens=max_tokens,
                cache_control=cache_control,
            )

        # ---- tools (function-calling shape) --------------------------
        tool_schemas: list[Dict[str, Any]] = [
            {
                "type": "function",
                "function": {
                    "name": t.name,
                    "description": t.description,
                    "parameters": t.input_schema,
                },
            }
            for t in tools
        ]

        # ---- messages (OpenAI flat list with role markers) ----------
        wire_messages: list[Dict[str, Any]] = []
        if system:
            wire_messages.append({"role": "system", "content": system})
        for m in messages:
            wire_messages.extend(_message_to_openai_wire(m))

        # ---- dispatch (with retry on transient errors) ---------------
        kwargs: Dict[str, Any] = {
            "model": self.config.model_name,
            "messages": wire_messages,
            **_openai_sampling_kwargs(self.config.model_name, max_tokens),
        }
        if tool_schemas:
            kwargs["tools"] = tool_schemas

        from openai import (                                # type: ignore[import-not-found]
            APIConnectionError,
            APIStatusError,
        )
        t_start = time.monotonic()
        for attempt in range(max_retries + 1):
            try:
                resp = self.client.chat.completions.create(**kwargs)
                break
            except (APIConnectionError, APIStatusError) as exc:
                # Bound model doesn't support tool/function calling?
                # Flip the per-instance flag and synthesise via the
                # JSON-protocol fallback rather than retrying or
                # giving up. Skips noise on the rest of the run.
                if (
                    tools
                    and isinstance(exc, APIStatusError)
                    and _is_tool_use_unsupported_error(exc)
                ):
                    logger.warning(
                        f"OpenAICompatibleProvider.turn: model "
                        f"{self.config.model_name!r} rejected tools — "
                        f"falling back to JSON-protocol synthesis for "
                        f"this provider instance: {exc}"
                    )
                    self._tool_use_unsupported = True
                    return self._tool_use_fallback(
                        messages, tools,
                        system=system, max_tokens=max_tokens,
                        cache_control=cache_control,
                    )
                if is_credit_exhausted(exc):
                    raise  # let callers fail fast
                if _is_rate_limit(exc):
                    from core.llm.throttle import broadcast_rate_limit
                    broadcast_rate_limit()
                if not _is_transient_openai(exc) or attempt >= max_retries:
                    kind = "transient" if _is_transient_openai(exc) else "permanent"
                    # escape_nonprintable — exc is from the SDK and
                    # can carry ANSI / BIDI / control bytes that
                    # forge log entries on operator TTYs. Defang
                    # before the warning + the TurnResponse.error.
                    from core.security.log_sanitisation import escape_nonprintable
                    err_msg = f"{kind} error after {attempt + 1} attempt(s): {escape_nonprintable(str(exc))}"
                    logger.warning("OpenAICompatibleProvider.turn: %s", err_msg)
                    return TurnResponse(
                        content=[],
                        stop_reason=StopReason.ERROR,
                        input_tokens=0,
                        output_tokens=0,
                        error_message=err_msg,
                    )
                delay = (backoff_factor ** attempt) * (0.5 + random.random())
                logger.info(
                    f"OpenAICompatibleProvider.turn: transient error attempt "
                    f"{attempt + 1}, retrying in {delay:.1f}s: {exc}"
                )
                time.sleep(delay)
        # No `else:` branch — the for/else here was dead. Every
        # exception path either returns early (permanent error,
        # tool-use unsupported, retries exhausted) or continues to
        # retry. Success path breaks. The for/else body would only
        # fire if the loop exhausted naturally without break, which
        # is unreachable: `attempt >= max_retries` in the except
        # triggers the early return before the loop would naturally
        # terminate.
        duration = time.monotonic() - t_start

        # ---- normalise response --------------------------------------
        if not resp.choices:
            return TurnResponse(
                content=[], stop_reason=StopReason.ERROR,
                input_tokens=0, output_tokens=0,
                error_message="empty choices in response",
            )
        choice = resp.choices[0]
        msg = choice.message
        stop = _OPENAI_FINISH_REASON_MAP.get(
            choice.finish_reason or "", StopReason.ERROR,
        )

        out_blocks: list = []
        if msg.content:
            out_blocks.append(TextBlock(text=msg.content))
        for tc in (msg.tool_calls or []):
            # Pre-fix `args = json.loads(tc.function.arguments)`
            # silently fell back to `args = {}` on JSON parse
            # failure. The downstream tool handler then received
            # an EMPTY argument dict and either:
            #   * failed schema validation with a confusing
            #     "missing required field" message that didn't
            #     hint at "the LLM emitted malformed JSON";
            #   * succeeded with default values and produced a
            #     wrong result that the LLM then doubled down
            #     on in subsequent turns.
            #
            # Log the parse failure with the raw arguments
            # snippet so operators see WHY the tool call
            # missed its arguments. Truncate the raw text to
            # avoid flooding logs with massive malformed
            # payloads.
            try:
                args = json.loads(tc.function.arguments)
            except (TypeError, ValueError) as _arg_exc:
                _raw = str(getattr(tc.function, "arguments", ""))[:400]
                _name = getattr(tc.function, "name", "?")
                _tcid = getattr(tc, "id", "?")
                logger.warning(
                    "OpenAI-compat tool-call arguments unparseable for "
                    "tool=%r (id=%r): %s. Raw: %r",
                    _name, _tcid, _arg_exc, _raw,
                )
                args = {}
            out_blocks.append(ToolCall(
                id=tc.id, name=tc.function.name, input=args,
            ))

        usage = resp.usage
        turn_response = TurnResponse(
            content=out_blocks,
            stop_reason=stop,
            input_tokens=(getattr(usage, "prompt_tokens", 0) or 0) if usage else 0,
            output_tokens=(getattr(usage, "completion_tokens", 0) or 0) if usage else 0,
            # OpenAI-compat doesn't surface per-region cache tokens.
            cache_read_tokens=0,
            cache_write_tokens=0,
        )
        # Track usage so multi-turn loop spend rolls into provider
        # stats. Symmetric with ``generate()`` and the Anthropic
        # ``turn()`` impl. Without this, ``LLMClient.get_stats()``
        # reports 0 cost / 0 tokens for tool-use no matter how many
        # turns the loop ran for.
        cost = self.compute_cost(turn_response)
        self.track_usage(
            tokens=turn_response.input_tokens + turn_response.output_tokens,
            cost=cost,
            input_tokens=turn_response.input_tokens,
            output_tokens=turn_response.output_tokens,
            duration=duration,
        )
        return turn_response

    def supports_streaming(self) -> bool:
        return not self._tool_use_unsupported

    def turn_stream(
        self,
        messages: Sequence[Message],
        tools: Sequence[ToolDef],
        *,
        system: Optional[str] = None,
        max_tokens: int = 4096,
        cache_control: CacheControl = CacheControl(),
        max_retries: int = 3,
        **_unused: Any,
    ) -> Iterator[StreamChunk]:
        """Streaming turn via OpenAI ``stream=True``."""
        if _unused:
            logger.debug(
                "OpenAICompatibleProvider.turn_stream: ignoring "
                "unrecognised kwargs: %s", sorted(_unused),
            )

        if self._tool_use_unsupported and tools:
            yield from LLMProvider.turn_stream(
                self, messages, tools, system=system,
                max_tokens=max_tokens, cache_control=cache_control,
            )
            return

        # ---- tools (same as turn) ----------------------------------------
        tool_schemas: list[Dict[str, Any]] = [
            {
                "type": "function",
                "function": {
                    "name": t.name,
                    "description": t.description,
                    "parameters": t.input_schema,
                },
            }
            for t in tools
        ]

        # ---- messages ----------------------------------------------------
        wire_messages: list[Dict[str, Any]] = []
        if system:
            wire_messages.append({"role": "system", "content": system})
        for m in messages:
            wire_messages.extend(_message_to_openai_wire(m))

        # ---- dispatch with stream=True -----------------------------------
        kwargs: Dict[str, Any] = {
            "model": self.config.model_name,
            "messages": wire_messages,
            "stream": True,
            **_openai_sampling_kwargs(self.config.model_name, max_tokens),
        }
        if tool_schemas:
            kwargs["tools"] = tool_schemas

        from openai import (                                    # type: ignore[import-not-found]
            APIConnectionError,
            APIStatusError,
        )
        t_start = time.monotonic()
        resp = None
        for attempt in range(max_retries + 1):
            try:
                resp = self.client.chat.completions.create(**kwargs)
                break
            except (APIConnectionError, APIStatusError) as exc:
                if (
                    tools
                    and isinstance(exc, APIStatusError)
                    and _is_tool_use_unsupported_error(exc)
                ):
                    self._tool_use_unsupported = True
                    yield from LLMProvider.turn_stream(
                        self, messages, tools, system=system,
                        max_tokens=max_tokens,
                        cache_control=cache_control,
                    )
                    return
                if is_credit_exhausted(exc):
                    raise  # let callers fail fast
                if _is_rate_limit(exc):
                    from core.llm.throttle import broadcast_rate_limit
                    broadcast_rate_limit()
                if not _is_transient_openai(exc) or attempt >= max_retries:
                    from core.security.log_sanitisation import (
                        escape_nonprintable,
                    )
                    logger.warning(
                        "OpenAICompatibleProvider.turn_stream: %s",
                        escape_nonprintable(str(exc)),
                    )
                    yield StreamChunk(
                        type="done", stop_reason=StopReason.ERROR,
                    )
                    return
                time.sleep(2.0 ** attempt)

        if resp is None:
            yield StreamChunk(type="done", stop_reason=StopReason.ERROR)
            return

        # ---- consume stream ----------------------------------------------
        tool_calls_seen: Dict[int, str] = {}
        input_tokens = output_tokens = 0
        stop = StopReason.ERROR

        try:
            for chunk in resp:
                if not chunk.choices:
                    if chunk.usage:
                        input_tokens = (
                            getattr(chunk.usage, "prompt_tokens", 0) or 0
                        )
                        output_tokens = (
                            getattr(chunk.usage, "completion_tokens", 0) or 0
                        )
                    continue

                choice = chunk.choices[0]
                delta = choice.delta

                if delta and getattr(delta, "content", None):
                    yield StreamChunk(
                        type="text_delta", text=delta.content,
                    )

                if delta and getattr(delta, "tool_calls", None):
                    for tc in delta.tool_calls:
                        idx = tc.index
                        if tc.id:
                            tool_calls_seen[idx] = tc.id
                            yield StreamChunk(
                                type="tool_call_start",
                                tool_call_id=tc.id,
                                tool_call_name=(
                                    getattr(tc.function, "name", "") or ""
                                ),
                            )
                        if (
                            tc.function
                            and getattr(tc.function, "arguments", None)
                        ):
                            yield StreamChunk(
                                type="tool_call_delta",
                                tool_call_id=tool_calls_seen.get(idx, ""),
                                tool_call_input_delta=tc.function.arguments,
                            )

                if choice.finish_reason:
                    stop = _OPENAI_FINISH_REASON_MAP.get(
                        choice.finish_reason, StopReason.ERROR,
                    )
                    for idx in sorted(tool_calls_seen):
                        yield StreamChunk(
                            type="tool_call_end",
                            tool_call_id=tool_calls_seen[idx],
                        )
        finally:
            resp.close()

        duration = time.monotonic() - t_start

        yield StreamChunk(
            type="usage",
            input_tokens=input_tokens,
            output_tokens=output_tokens,
        )

        cost = self._calculate_cost_split(input_tokens, output_tokens)
        self.track_usage(
            tokens=input_tokens + output_tokens,
            cost=cost,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            duration=duration,
        )

        yield StreamChunk(type="done", stop_reason=stop)


# ---------------------------------------------------------------------------
# OpenAI tool-use helpers
# ---------------------------------------------------------------------------

# OpenAI's native finish_reason → our enum.
_OPENAI_FINISH_REASON_MAP = {
    "stop": StopReason.COMPLETE,
    "tool_calls": StopReason.NEEDS_TOOL_CALL,
    "length": StopReason.MAX_TOKENS,
    "content_filter": StopReason.REFUSED,
    "function_call": StopReason.NEEDS_TOOL_CALL,            # legacy alias
}


def _is_transient_openai(exc: BaseException) -> bool:
    """Same shape as the Anthropic helper. 429 + 5xx retryable;
    permanent 4xx fails fast."""
    from openai import APIConnectionError, APIStatusError    # type: ignore[import-not-found]
    if isinstance(exc, APIConnectionError):
        return True
    if isinstance(exc, APIStatusError):
        status = getattr(exc, "status_code", None)
        return status == 429 or (status is not None and 500 <= status < 600)
    return False


def _is_tool_use_unsupported_error(exc: BaseException) -> bool:
    """Heuristic: does ``exc`` look like a 4xx rejection from the
    bound model saying it doesn't support tool / function calling?

    Conservative by design — false positives make us synthesise when
    native would have worked (cheaper outcome — synthesis still
    produces correct results, just slower per turn). False negatives
    keep the existing fail-fast behaviour, which is what users see
    without this detection at all.

    Detects 4xx (not 429) responses whose error body mentions a
    tool/function keyword alongside an unsupported/not-supported
    phrase. Covers Ollama (``model 'X' does not support tools``),
    Mistral, vLLM, and similar shims. OpenAI and Anthropic models
    never produce this error class — every current model on those
    providers supports tool-use natively.
    """
    from openai import APIStatusError                        # type: ignore[import-not-found]
    if not isinstance(exc, APIStatusError):
        return False
    status = getattr(exc, "status_code", None)
    if status is None or status >= 500 or status == 429:
        return False                                         # transient or server-side

    text = str(exc).lower()
    body = getattr(exc, "body", None)
    if isinstance(body, dict):
        err = body.get("error", body)
        if isinstance(err, dict):
            text += " " + str(err.get("message", "")).lower()
        elif isinstance(err, str):
            text += " " + err.lower()

    # Tighter heuristic — pre-fix `"does not" in text` matched
    # unrelated 4xx negations (`does not have permission`, `does not
    # include billing`, `does not match expected schema`) producing
    # false-positive synthesis fallback when native tool-use was
    # actually broken for an UNRELATED reason. Require a phrase that
    # actually links the negation to tool/function support.
    has_unsupported_phrase = any(
        phrase in text for phrase in (
            "does not support tools",
            "does not support tool",
            "does not support function",
            "doesn't support tools",
            "doesn't support tool",
            "doesn't support function",
            "no tool support",
            "no function support",
            "tools are not supported",
            "tool calls not supported",
            "tool calling not supported",
            "function calling not supported",
            "function calls not supported",
            "function calling is not supported",
            "function calls are not supported",
            "tools unsupported",
            "tool_use not supported",
        )
    )
    return has_unsupported_phrase


def _message_to_openai_wire(m: Message) -> list[Dict[str, Any]]:
    """One :class:`Message` → 1+ OpenAI wire dicts.

    OpenAI splits user messages with multiple :class:`ToolResult`\\ s
    into N separate ``role:"tool"`` messages (each carrying its own
    ``tool_call_id``), unlike Anthropic which packs them in one user
    message's content array.

    Empty assistant turns (``content=[]``, which the loop can produce
    on ``StopReason.ERROR``) emit ``{"role": "assistant",
    "content": ""}`` — most OpenAI-compatible backends reject an
    assistant message with neither ``content`` nor ``tool_calls``,
    so the empty-string is the safe wire form.

    Genuinely-empty user turns (no text, no tool results) symmetrically
    emit ``{"role": "user", "content": ""}``. Pre-fix this returned
    `[]` — most backends rejected the request as malformed (the
    next assistant turn followed an absent user turn).

    User turns carrying both text and tool_results emit the tool
    messages first, then a trailing ``role:"user"`` text message —
    OpenAI requires tool messages to immediately follow the prior
    assistant's ``tool_calls`` (text in between breaks the link).
    """
    if m.role == "assistant":
        text_parts: list[str] = []
        tool_calls: list[Dict[str, Any]] = []
        for b in m.content:
            if isinstance(b, TextBlock):
                text_parts.append(b.text)
            elif isinstance(b, ToolCall):
                tool_calls.append({
                    "id": b.id,
                    "type": "function",
                    "function": {
                        "name": b.name,
                        "arguments": json.dumps(b.input),
                    },
                })
        out: Dict[str, Any] = {"role": "assistant"}
        if text_parts:
            out["content"] = "".join(text_parts)
        if tool_calls:
            out["tool_calls"] = tool_calls
        if not text_parts and not tool_calls:
            out["content"] = ""
        return [out]
    # user role
    out_msgs: list[Dict[str, Any]] = []
    text_parts = []
    for b in m.content:
        if isinstance(b, TextBlock):
            text_parts.append(b.text)
        elif isinstance(b, ToolResult):
            out_msgs.append({
                "role": "tool",
                "tool_call_id": b.tool_use_id,
                "content": b.content,
            })
    if text_parts:
        out_msgs.append({"role": "user", "content": "".join(text_parts)})
    elif not out_msgs:
        # Genuinely empty user message — no text, no tool results.
        # Pre-fix returned `[]`, which produced a wire-shape with no
        # message for this turn at all. Most OpenAI-compat backends
        # then reject the request as malformed (assistant turn
        # without prior user). Symmetric with the assistant-role
        # branch above which also emits `{"content": ""}` for the
        # genuinely-empty case.
        out_msgs.append({"role": "user", "content": ""})
    return out_msgs


class AnthropicProvider(LLMProvider):
    """
    LLM provider using the Anthropic SDK.

    Native support for Claude models with proper system message handling
    and token counting.
    """

    def __init__(self, config: ModelConfig):
        super().__init__(config)
        if not ANTHROPIC_SDK_AVAILABLE:
            raise ImportError(
                "Anthropic SDK not installed. Run: pip install anthropic"
            )

        # Phase B: route through the credential-isolation dispatcher when
        # the worker has been spawned with one in place. Tie-breaker:
        # ``RAPTOR_LLM_SOCKET`` wins over ``config.api_key`` so the
        # dispatcher path actually gets exercised in opt-in workflows.
        # The env-direct fallback stays in place until Phase C drops the
        # API-key passthrough entirely.
        if os.environ.get("RAPTOR_LLM_SOCKET"):
            from core.llm.dispatcher.client import make_anthropic_client
            self.client = make_anthropic_client(timeout=config.timeout)
            logger.debug("AnthropicProvider: routing via credential-isolation dispatcher")
        else:
            self.client = anthropic.Anthropic(
                api_key=config.api_key,
                timeout=config.timeout,
            )
            logger.debug("AnthropicProvider: direct SDK (no dispatcher)")

        self.instructor_client = None
        self._instructor_consec_failures = 0
        self._instructor_lock = threading.Lock()
        self._instructor_backed = None  # stashed client during backoff
        if INSTRUCTOR_AVAILABLE:
            self.instructor_client = instructor.from_anthropic(self.client)
        else:
            logger.warning(
                "Instructor not installed — structured output will use JSON-in-prompt fallback. "
                "For more reliable structured output: pip install instructor"
            )

        # Per-instance flag: have we warned about silent cache-failure
        # for this model? Warns once per provider instance to avoid
        # spam, since the silent-failure is a model-level property
        # (claude-opus-4-5 and claude-opus-4-6 verified non-caching as
        # of 2026-05-04 — Anthropic accepts the cache_control marker
        # but doesn't honor it). See ``_maybe_warn_silent_cache_failure``.
        self._caching_warning_emitted = False

        logger.debug("Initialized AnthropicProvider: %s", config.model_name)

    def generate(self, prompt: str, system_prompt: Optional[str] = None,
                 **kwargs) -> LLMResponse:
        """Generate completion using the Anthropic SDK."""
        messages = [{"role": "user", "content": prompt}]

        create_kwargs = {
            "model": self.config.model_name,
            "messages": messages,
            "max_tokens": kwargs.get("max_tokens", self.config.max_tokens),
        }
        # Opus 4.7+ deprecated `temperature` (400 if sent); omit it for those.
        if supports_temperature(self.config.model_name):
            create_kwargs["temperature"] = kwargs.get("temperature", self.config.temperature)
        if system_prompt:
            create_kwargs["system"] = [{
                "type": "text",
                "text": system_prompt,
                "cache_control": {"type": "ephemeral"},
            }]

        try:
            t_start = time.monotonic()
            response = self.client.messages.create(**create_kwargs)
            duration = time.monotonic() - t_start

            # Extract text from response (guard against empty/non-text content)
            if not response.content:
                raise RuntimeError("Anthropic returned empty content")
            first_block = response.content[0]
            if not hasattr(first_block, 'text'):
                # `getattr` with default — pre-fix `first_block.type`
                # raised AttributeError mid-error-formatting if the
                # block lacked BOTH `text` AND `type` (a future SDK
                # shape change or unexpected response variant). The
                # AttributeError replaced the informative
                # "non-text content" message with a confusing
                # internal-state crash.
                block_type = getattr(first_block, 'type', '<unknown>')
                raise RuntimeError(f"Anthropic returned non-text content block: {block_type}")
            content = first_block.text
            finish_reason = response.stop_reason or "complete"

            input_tokens = 0
            output_tokens = 0
            thinking_tokens = 0
            cache_read_tokens = 0
            cache_write_tokens = 0
            if response.usage:
                input_tokens = response.usage.input_tokens or 0
                output_tokens = response.usage.output_tokens or 0
                thinking_tokens = getattr(response.usage, 'thinking_tokens', 0) or 0
                cache_read_tokens = getattr(response.usage, 'cache_read_input_tokens', 0) or 0
                cache_write_tokens = getattr(response.usage, 'cache_creation_input_tokens', 0) or 0
            tokens_used = input_tokens + output_tokens + thinking_tokens
            cost = self._calculate_cost_split(
                input_tokens, output_tokens, thinking_tokens,
                cache_read_tokens=cache_read_tokens,
                cache_write_tokens=cache_write_tokens,
            )

            self.track_usage(
                tokens_used, cost, input_tokens, output_tokens, duration,
                cache_read_tokens=cache_read_tokens,
                cache_write_tokens=cache_write_tokens,
            )
            logger.debug("[Anthropic] model=%s, tokens=%s, cost=$%.4f, duration=%.2fs", self.config.model_name, tokens_used, cost, duration)

            return LLMResponse(
                content=content,
                model=self.config.model_name,
                provider=self.config.provider.lower(),
                tokens_used=tokens_used,
                cost=cost,
                finish_reason=finish_reason,
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                thinking_tokens=thinking_tokens,
                duration=duration,
                cache_read_tokens=cache_read_tokens,
                cache_write_tokens=cache_write_tokens,
                resolved_model=extract_resolved_model(response),
            )

        except Exception as e:
            # Same hardening rationale as OpenAICompatibleProvider.generate
            # above — SDK exception bodies can include prompt + headers.
            from core.security.log_sanitisation import escape_nonprintable
            from core.security.redaction import redact_secrets
            # DEBUG, not ERROR — same rationale as OpenAI above:
            # the LLMClient retry loop emits an operator-visible
            # WARNING for the same failure.
            logger.debug("Anthropic completion failed: %s",
                         escape_nonprintable(redact_secrets(str(e)))[:1024])
            raise

    def generate_structured(self, prompt: str, schema: Dict[str, Any],
                           system_prompt: Optional[str] = None,
                           **kwargs) -> Tuple[Dict[str, Any], str]:
        """Generate structured output using Instructor (or JSON fallback)."""
        pydantic_model = _dict_schema_to_pydantic(schema)
        # See OpenAI provider — caller-supplied temperature must
        # reach the API for DispatchTask's per-task temperatures
        # (analysis 0.2, consensus 0.3) to take effect.
        temperature = kwargs.get("temperature", self.config.temperature)

        # Try Instructor first
        if self.instructor_client is not None:
            try:
                messages = [{"role": "user", "content": prompt}]

                create_kwargs = {
                    "model": self.config.model_name,
                    "response_model": pydantic_model,
                    "messages": messages,
                    "max_tokens": self.config.max_tokens,
                }
                # Opus 4.7+ deprecated `temperature` (400 if sent); omit it for those.
                if supports_temperature(self.config.model_name):
                    create_kwargs["temperature"] = temperature
                if system_prompt:
                    create_kwargs["system"] = [{
                        "type": "text",
                        "text": system_prompt,
                        "cache_control": {"type": "ephemeral"},
                    }]

                t_start = time.monotonic()
                result, completion = self.instructor_client.messages.create_with_completion(
                    **create_kwargs,
                )
                duration = time.monotonic() - t_start

                result_dict = result.model_dump()
                full_response = json.dumps(result_dict, indent=2)

                input_tokens = 0
                output_tokens = 0
                thinking_tokens = 0
                cache_read_tokens = 0
                cache_write_tokens = 0
                if completion.usage:
                    input_tokens = completion.usage.input_tokens or 0
                    output_tokens = completion.usage.output_tokens or 0
                    thinking_tokens = getattr(completion.usage, 'thinking_tokens', 0) or 0
                    cache_read_tokens = getattr(completion.usage, 'cache_read_input_tokens', 0) or 0
                    cache_write_tokens = getattr(completion.usage, 'cache_creation_input_tokens', 0) or 0
                tokens_used = input_tokens + output_tokens + thinking_tokens
                cost = self._calculate_cost_split(
                    input_tokens, output_tokens, thinking_tokens,
                    cache_read_tokens=cache_read_tokens,
                    cache_write_tokens=cache_write_tokens,
                )
                self.track_usage(
                    tokens_used, cost, input_tokens, output_tokens, duration,
                    cache_read_tokens=cache_read_tokens,
                    cache_write_tokens=cache_write_tokens,
                )

                with self._instructor_lock:
                    self._instructor_consec_failures = 0
                return StructuredResponse(
                    result=result_dict,
                    raw=full_response,
                    resolved_model=extract_resolved_model(completion),
                )

            except Exception as e:
                with self._instructor_lock:
                    self._instructor_consec_failures += 1
                    consec = self._instructor_consec_failures
                from core.security.log_sanitisation import escape_nonprintable as _esc
                logger.warning(
                    "Instructor structured generation failed for %s/%s (%d/%d). "
                    "Exception (%s): %s",
                    self.config.provider, self.config.model_name,
                    consec, _INSTRUCTOR_MAX_CONSEC_FAILURES,
                    type(e).__name__, _esc(str(e))[:512],
                )
                if consec >= _INSTRUCTOR_MAX_CONSEC_FAILURES:
                    logger.warning(
                        "Instructor disabled for %s/%s after %d consecutive failures",
                        self.config.provider, self.config.model_name,
                        consec,
                    )
                    self._instructor_backed = self.instructor_client
                    self.instructor_client = None

        # Fallback: JSON-in-prompt
        return self._structured_fallback(prompt, schema, pydantic_model, system_prompt)

    # ------------------------------------------------------------------
    # Tool-use turn primitive — Anthropic-native.
    # ------------------------------------------------------------------
    #
    # Honours all three Anthropic cache regions (system / tools /
    # history-through-index) via ``cache_control: {"type": "ephemeral"}``
    # markers. Cost computation accounts for ``cache_read`` (0.1x input
    # rate) and ``cache_creation`` (1.25x input rate) per Anthropic's
    # documented multipliers. Beta task-budget endpoint via
    # ``provider_specific={"anthropic_task_budget_beta": True,
    # "anthropic_task_budget_tokens": N}``.

    def supports_tool_use(self) -> bool: return True
    def supports_prompt_caching(self) -> bool: return True
    def supports_parallel_tools(self) -> bool: return True

    def compute_cost(self, response: TurnResponse) -> float:
        """Anthropic cost: standard input/output + cache_write (1.25x
        input) + cache_read (0.1x input) per Anthropic's pricing.

        ``response.cost_usd``, when set, takes precedence — same
        rationale as the ABC default.
        """
        if response.cost_usd is not None:
            return response.cost_usd
        from .model_data import (
            ANTHROPIC_CACHE_READ_MULTIPLIER,
            ANTHROPIC_CACHE_WRITE_MULTIPLIER,
        )
        in_per_m, out_per_m = self.price_per_million()
        return (
            response.input_tokens * in_per_m
            + response.output_tokens * out_per_m
            + response.cache_write_tokens * in_per_m * ANTHROPIC_CACHE_WRITE_MULTIPLIER
            + response.cache_read_tokens * in_per_m * ANTHROPIC_CACHE_READ_MULTIPLIER
        ) / 1_000_000.0

    def turn(
        self,
        messages: Sequence[Message],
        tools: Sequence[ToolDef],
        *,
        system: Optional[str] = None,
        max_tokens: int = 4096,
        cache_control: CacheControl = CacheControl(),
        anthropic_task_budget_beta: bool = False,
        anthropic_task_budget_tokens: Optional[int] = None,
        max_retries: int = 3,
        backoff_factor: float = 2.0,
        **_unused: Any,
    ) -> TurnResponse:
        """Send one round-trip to Anthropic.

        Provider-specific kwargs:
          * ``anthropic_task_budget_beta``: route via
            ``client.beta.messages.create`` (cost-cap beta endpoint).
            Activating the beta requires both this flag (sets the
            ``betas=["task-budgets-..."]`` header) AND
            ``anthropic_task_budget_tokens`` (sets the
            ``output_config.task_budget`` request body).
          * ``anthropic_task_budget_tokens``: total token budget
            communicated to the model via
            ``output_config: {task_budget: {type: "tokens", total: N}}``.
            Required when ``anthropic_task_budget_beta=True``.
          * ``max_retries`` / ``backoff_factor``: retry on transient
            errors (connection / 429 / 5xx). Permanent 4xx fails
            fast.
        """
        if anthropic_task_budget_beta and anthropic_task_budget_tokens is None:
            raise ValueError(
                "anthropic_task_budget_beta=True requires "
                "anthropic_task_budget_tokens=N (total token budget the "
                "model self-regulates against). Without it the beta "
                "endpoint accepts the request but no budget is enforced."
            )
        if _unused:
            logger.debug(
                f"AnthropicProvider.turn: ignoring unrecognised "
                f"kwargs: {sorted(_unused)}"
            )

        # ---- system block --------------------------------------------
        # Anthropic accepts a string OR a content list. Use the list
        # form when caching the system prompt so the cache_control
        # marker can attach to it; otherwise the simpler string form.
        system_arg: Optional[Union[str, list]]
        if system:
            if cache_control.system:
                system_arg = [{
                    "type": "text",
                    "text": system,
                    "cache_control": {"type": "ephemeral"},
                }]
            else:
                system_arg = system
        else:
            system_arg = None

        # ---- tools ---------------------------------------------------
        tool_schemas: list[Dict[str, Any]] = [
            {
                "name": t.name,
                "description": t.description,
                "input_schema": t.input_schema,
            }
            for t in tools
        ]
        if cache_control.tools and tool_schemas:
            last = dict(tool_schemas[-1])
            last["cache_control"] = {"type": "ephemeral"}
            tool_schemas[-1] = last

        # ---- messages ------------------------------------------------
        wire_messages = [_message_to_anthropic_wire(m) for m in messages]
        if (
            cache_control.history_through_index is not None
            and 0 <= cache_control.history_through_index < len(wire_messages)
        ):
            _attach_anthropic_cache_marker(
                wire_messages[cache_control.history_through_index],
            )

        # ---- dispatch (with retry on transient errors) ---------------
        # Routing to ``client.beta.messages.create`` is necessary but
        # not sufficient — the beta only activates when the beta name
        # appears in the ``betas=[...]`` request parameter.
        create_fn = (
            self.client.beta.messages.create
            if anthropic_task_budget_beta
            else self.client.messages.create
        )
        kwargs: Dict[str, Any] = {
            "model": self.config.model_name,
            "max_tokens": max_tokens,
            "messages": wire_messages,
            "tools": tool_schemas if tool_schemas else None,
        }
        if anthropic_task_budget_beta:
            kwargs["betas"] = [_ANTHROPIC_TASK_BUDGET_BETA]
            kwargs["output_config"] = {
                "task_budget": {
                    "type": "tokens",
                    "total": anthropic_task_budget_tokens,
                },
            }
        if system_arg is not None:
            kwargs["system"] = system_arg
        send_kwargs = {k: v for k, v in kwargs.items() if v is not None}

        from anthropic import (                              # type: ignore[import-not-found]
            APIConnectionError,
            APIError,
            APIStatusError,
        )
        t_start = time.monotonic()
        for attempt in range(max_retries + 1):
            try:
                resp = create_fn(**send_kwargs)
                break
            except (APIConnectionError, APIStatusError, APIError) as exc:
                if is_credit_exhausted(exc):
                    raise  # let callers fail fast
                if _is_rate_limit(exc):
                    from core.llm.throttle import broadcast_rate_limit
                    broadcast_rate_limit()
                if not _is_transient_anthropic(exc) or attempt >= max_retries:
                    kind = "transient" if _is_transient_anthropic(exc) else "permanent"
                    # escape_nonprintable — see OpenAICompatibleProvider.turn
                    # above for the rationale.
                    from core.security.log_sanitisation import escape_nonprintable
                    err_msg = f"{kind} error after {attempt + 1} attempt(s): {escape_nonprintable(str(exc))}"
                    logger.warning("AnthropicProvider.turn: %s", err_msg)
                    return TurnResponse(
                        content=[],
                        stop_reason=StopReason.ERROR,
                        input_tokens=0,
                        output_tokens=0,
                        error_message=err_msg,
                    )
                delay = (backoff_factor ** attempt) * (0.5 + random.random())
                logger.info(
                    f"AnthropicProvider.turn: transient error attempt "
                    f"{attempt + 1}, retrying in {delay:.1f}s: {exc}"
                )
                time.sleep(delay)
        # No `else:` branch — the for/else here was dead. Every
        # exception path either returns early (permanent error,
        # tool-use unsupported, retries exhausted) or continues to
        # retry. Success path breaks. The for/else body would only
        # fire if the loop exhausted naturally without break, which
        # is unreachable: `attempt >= max_retries` in the except
        # triggers the early return before the loop would naturally
        # terminate.
        duration = time.monotonic() - t_start

        # ---- normalise response --------------------------------------
        stop = _ANTHROPIC_STOP_REASON_MAP.get(
            resp.stop_reason or "", StopReason.ERROR,
        )
        out_blocks: list = []
        for block in resp.content:
            block_type = getattr(block, "type", None)
            if block_type == "text":
                out_blocks.append(TextBlock(text=block.text))
            elif block_type == "tool_use":
                out_blocks.append(ToolCall(
                    id=block.id,
                    name=block.name,
                    input=dict(block.input) if block.input else {},
                ))

        usage = resp.usage
        turn_response = TurnResponse(
            content=out_blocks,
            stop_reason=stop,
            input_tokens=(getattr(usage, "input_tokens", 0) or 0) if usage else 0,
            output_tokens=(getattr(usage, "output_tokens", 0) or 0) if usage else 0,
            cache_read_tokens=(
                getattr(usage, "cache_read_input_tokens", 0) or 0
            ) if usage else 0,
            cache_write_tokens=(
                getattr(usage, "cache_creation_input_tokens", 0) or 0
            ) if usage else 0,
        )
        # Track usage so multi-turn loop spend shows up alongside
        # generate() in provider stats. Without this, ``LLMClient.
        # get_stats()`` reports 0 cost / 0 tokens for tool-use even
        # when the loop ran for many turns. Cost via ``compute_cost``
        # so cache multipliers (1.25x write, 0.1x read) apply.
        cost = self.compute_cost(turn_response)
        self.track_usage(
            tokens=turn_response.input_tokens + turn_response.output_tokens,
            cost=cost,
            input_tokens=turn_response.input_tokens,
            output_tokens=turn_response.output_tokens,
            duration=duration,
            cache_read_tokens=turn_response.cache_read_tokens,
            cache_write_tokens=turn_response.cache_write_tokens,
        )
        self._maybe_warn_silent_cache_failure(turn_response, cache_control)
        return turn_response

    def _maybe_warn_silent_cache_failure(
        self,
        response: TurnResponse,
        cache_control: CacheControl,
    ) -> None:
        """Detect when ``cache_control`` markers are silently no-op'd.

        Anthropic's published cacheable-region minimum is 1024 tokens
        (Opus / Sonnet) or 2048 (Haiku 3.5). Empirically (2026-05-04)
        some model versions enforce a higher de-facto minimum and
        return ``cache_creation_input_tokens=0,
        cache_read_input_tokens=0`` for cache_control opt-ins below
        that minimum, with no error — silent no-op. Consumers planning
        cost budgets around cache savings (cve-diff is the headline
        case) won't see the savings, with no signal until the bill
        comes in.

        Warn once per provider instance when all conditions hold:
          * ``cache_control`` was opt-in (caller asked for caching)
          * ``input_tokens >= 8192`` — well above any observed model's
            de-facto minimum, so a zero-cache outcome is a real signal,
            not a "your request was too small" false positive
          * ``cache_creation_input_tokens == 0`` AND
            ``cache_read_input_tokens == 0``

        The 8192 floor trades sensitivity for specificity: smaller
        cacheable regions that legitimately fall below a model's
        minimum won't trigger spurious warnings, but real silent-
        no-op cases on production-sized prompts (cve-diff: 5K+ tokens
        of system + tools) still surface.

        Scope: per-provider-instance. Each ``LLMClient`` builds its
        own provider via ``_get_provider``, and a fresh agentic run
        typically constructs a fresh client. Operators running the
        same setup repeatedly will see the warning once per run —
        loud enough to act on, not so loud as to hide in noise. A
        cross-process / cross-run dedup would need module-level
        state and isn't worth the complexity for a one-time signal.
        """
        if self._caching_warning_emitted:
            return
        requested = (
            cache_control.system
            or cache_control.tools
            or cache_control.history_through_index is not None
        )
        if not requested:
            return
        if response.input_tokens < 8192:
            return                                          # below threshold
        if response.cache_read_tokens > 0 or response.cache_write_tokens > 0:
            return                                          # caching is working
        logger.warning(
            f"AnthropicProvider: model {self.config.model_name!r} did not "
            f"populate cache fields on a turn with cache_control opt-in "
            f"and {response.input_tokens} input tokens — cache savings "
            f"won't apply for requests this size. Common causes: (1) "
            f"this model's de-facto cacheable-region minimum is higher "
            f"than the documented 1024 tokens; (2) the cacheable subset "
            f"(system + tools when those are opted in) is below the "
            f"model's minimum even though total input is above 8192. "
            f"Try a different model (claude-opus-4-7, "
            f"claude-sonnet-4-5-20250929) or increase the cacheable "
            f"region size. This warning fires once per provider instance."
        )
        self._caching_warning_emitted = True

    def supports_streaming(self) -> bool:
        return True

    def turn_stream(
        self,
        messages: Sequence[Message],
        tools: Sequence[ToolDef],
        *,
        system: Optional[str] = None,
        max_tokens: int = 4096,
        cache_control: CacheControl = CacheControl(),
        **_unused: Any,
    ) -> Iterator[StreamChunk]:
        """Streaming turn via ``client.messages.stream()``.

        Same argument construction as :meth:`turn` but yields
        :class:`StreamChunk` objects as the API response arrives.
        Does not support the task-budget beta endpoint (use
        non-streaming :meth:`turn` for that).
        """
        if _unused:
            logger.debug(
                "AnthropicProvider.turn_stream: ignoring unrecognised "
                "kwargs: %s", sorted(_unused),
            )

        # ---- system block (same as turn) --------------------------------
        system_arg: Optional[Union[str, list]]
        if system:
            if cache_control.system:
                system_arg = [{
                    "type": "text",
                    "text": system,
                    "cache_control": {"type": "ephemeral"},
                }]
            else:
                system_arg = system
        else:
            system_arg = None

        # ---- tools -------------------------------------------------------
        tool_schemas: list[Dict[str, Any]] = [
            {
                "name": t.name,
                "description": t.description,
                "input_schema": t.input_schema,
            }
            for t in tools
        ]
        if cache_control.tools and tool_schemas:
            last = dict(tool_schemas[-1])
            last["cache_control"] = {"type": "ephemeral"}
            tool_schemas[-1] = last

        # ---- messages ----------------------------------------------------
        wire_messages = [_message_to_anthropic_wire(m) for m in messages]
        if (
            cache_control.history_through_index is not None
            and 0 <= cache_control.history_through_index < len(wire_messages)
        ):
            _attach_anthropic_cache_marker(
                wire_messages[cache_control.history_through_index],
            )

        # ---- build send_kwargs -------------------------------------------
        kwargs: Dict[str, Any] = {
            "model": self.config.model_name,
            "max_tokens": max_tokens,
            "messages": wire_messages,
            "tools": tool_schemas if tool_schemas else None,
        }
        if system_arg is not None:
            kwargs["system"] = system_arg
        send_kwargs = {k: v for k, v in kwargs.items() if v is not None}

        # ---- stream ------------------------------------------------------
        t_start = time.monotonic()
        current_tool_id = ""
        input_tokens = output_tokens = cache_read = cache_write = 0
        stop = StopReason.ERROR

        with self.client.messages.stream(**send_kwargs) as stream:
            for event in stream:
                event_type = getattr(event, "type", "")

                if event_type == "content_block_start":
                    cb = getattr(event, "content_block", None)
                    if cb and getattr(cb, "type", "") == "tool_use":
                        current_tool_id = getattr(cb, "id", "")
                        yield StreamChunk(
                            type="tool_call_start",
                            tool_call_id=current_tool_id,
                            tool_call_name=getattr(cb, "name", ""),
                        )
                elif event_type == "text":
                    yield StreamChunk(
                        type="text_delta",
                        text=getattr(event, "text", ""),
                    )
                elif event_type == "input_json":
                    yield StreamChunk(
                        type="tool_call_delta",
                        tool_call_id=current_tool_id,
                        tool_call_input_delta=getattr(
                            event, "partial_json", "",
                        ),
                    )
                elif event_type == "content_block_stop":
                    if current_tool_id:
                        yield StreamChunk(
                            type="tool_call_end",
                            tool_call_id=current_tool_id,
                        )
                        current_tool_id = ""
                elif event_type == "message_start":
                    msg = getattr(event, "message", None)
                    if msg:
                        u = getattr(msg, "usage", None)
                        if u:
                            input_tokens = (
                                getattr(u, "input_tokens", 0) or 0
                            )
                            cache_read = (
                                getattr(u, "cache_read_input_tokens", 0)
                                or 0
                            )
                            cache_write = (
                                getattr(u, "cache_creation_input_tokens", 0)
                                or 0
                            )
                elif event_type == "message_delta":
                    delta = getattr(event, "delta", None)
                    if delta:
                        sr = getattr(delta, "stop_reason", "")
                        stop = _ANTHROPIC_STOP_REASON_MAP.get(
                            sr or "", StopReason.ERROR,
                        )
                    u = getattr(event, "usage", None)
                    if u:
                        output_tokens = (
                            getattr(u, "output_tokens", 0) or 0
                        )

        duration = time.monotonic() - t_start

        yield StreamChunk(
            type="usage",
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cache_read_tokens=cache_read,
            cache_write_tokens=cache_write,
        )

        cost = self.compute_cost(TurnResponse(
            content=[], stop_reason=stop,
            input_tokens=input_tokens, output_tokens=output_tokens,
            cache_read_tokens=cache_read, cache_write_tokens=cache_write,
        ))
        self.track_usage(
            tokens=input_tokens + output_tokens,
            cost=cost,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            duration=duration,
            cache_read_tokens=cache_read,
            cache_write_tokens=cache_write,
        )

        yield StreamChunk(type="done", stop_reason=stop)


# ---------------------------------------------------------------------------
# Anthropic tool-use helpers (module-level — used by
# ``AnthropicProvider.turn``)
# ---------------------------------------------------------------------------

# Beta header name for Anthropic's task-budget endpoint. Activated by
# the ``anthropic_task_budget_beta=True`` provider-specific kwarg —
# routing to ``client.beta.messages.create`` is necessary BUT NOT
# SUFFICIENT; the ``betas=[...]`` parameter must also be passed for
# the server to actually honour the beta.
_ANTHROPIC_TASK_BUDGET_BETA = "task-budgets-2026-03-13"

# Anthropic's native stop_reason → our enum.
_ANTHROPIC_STOP_REASON_MAP = {
    "end_turn": StopReason.COMPLETE,
    "stop_sequence": StopReason.COMPLETE,
    "tool_use": StopReason.NEEDS_TOOL_CALL,
    "pause_turn": StopReason.PAUSE_TURN,
    "max_tokens": StopReason.MAX_TOKENS,
    "refusal": StopReason.REFUSED,
}


def _is_transient_anthropic(exc: BaseException) -> bool:
    """``True`` when ``exc`` is a connection / 429 / 5xx error worth
    retrying. Permanent 4xx (auth, schema, not-found) are False so
    callers fail fast instead of burning budget on hopeless retries."""
    from anthropic import APIConnectionError, APIStatusError    # type: ignore[import-not-found]
    if isinstance(exc, APIConnectionError):
        return True
    if isinstance(exc, APIStatusError):
        status = getattr(exc, "status_code", None)
        return status == 429 or (status is not None and 500 <= status < 600)
    return False


def _is_rate_limit(exc: BaseException) -> bool:
    """``True`` when ``exc`` is specifically a 429 rate-limit error.

    Provider-agnostic: checks ``status_code`` attribute regardless of
    the SDK exception type.  Used to signal the adaptive throttle
    (halve concurrency) — distinct from ``_is_transient_*`` which
    also covers 5xx and connection errors.
    """
    return getattr(exc, "status_code", None) == 429


def is_credit_exhausted(exc: BaseException) -> bool:
    """``True`` when ``exc`` indicates the API account has run out of
    credit or has a billing problem that no amount of retrying will fix.

    Provider-agnostic: checks the exception message for credit/billing
    keywords across Anthropic (400 ``credit balance is too low``),
    OpenAI (429 ``exceeded your current quota``), and generic shims.
    """
    status = getattr(exc, "status_code", None)
    # Only 400/401/402/403/429 carry billing errors — 5xx never does.
    if status is not None and status >= 500:
        return False
    text = str(exc).lower()
    body = getattr(exc, "body", None)
    if isinstance(body, dict):
        err = body.get("error", body)
        if isinstance(err, dict):
            text += " " + str(err.get("message", "")).lower()
        elif isinstance(err, str):
            text += " " + err.lower()
    return any(phrase in text for phrase in (
        "credit balance is too low",
        "exceeded your current quota",
        "insufficient_quota",
        "billing hard limit",
        "account has been deactivated",
        "billing not active",
        "reached your specified api usage limits",
    ))


def _message_to_anthropic_wire(m: Message) -> Dict[str, Any]:
    """Our :class:`Message` → Anthropic wire dict.

    Anthropic accepts mixed content lists per turn — text, tool_use,
    and tool_result blocks all live in the same ``content`` array;
    role determines which subset is valid (assistant: text + tool_use;
    user: text + tool_result).

    Empty :class:`Message`\\ s (``content=[]``) — which the loop can
    produce when a turn returns ``StopReason.ERROR`` with no blocks —
    are emitted as ``[{"type": "text", "text": ""}]`` so the wire
    shape stays valid if a caller resumes from a failed run.
    """
    out_content: list[Dict[str, Any]] = []
    for block in m.content:
        if isinstance(block, TextBlock):
            out_content.append({"type": "text", "text": block.text})
        elif isinstance(block, ToolCall):                  # assistant role only
            out_content.append({
                "type": "tool_use",
                "id": block.id,
                "name": block.name,
                "input": block.input,
            })
        elif isinstance(block, ToolResult):                # user role only
            out_content.append({
                "type": "tool_result",
                "tool_use_id": block.tool_use_id,
                "content": block.content,
                "is_error": block.is_error,
            })
    if not out_content:
        out_content.append({"type": "text", "text": ""})
    return {"role": m.role, "content": out_content}


def _attach_anthropic_cache_marker(message: Dict[str, Any]) -> None:
    """Mutate ``message["content"][-1]`` in-place to carry a
    cache_control marker. Anthropic places the marker on the LAST
    block of a region to cache everything preceding it within that
    message."""
    if not message["content"]:
        return
    last = dict(message["content"][-1])
    last["cache_control"] = {"type": "ephemeral"}
    message["content"][-1] = last


class GeminiProvider(LLMProvider):
    """Native Google Gemini provider using the google-genai SDK.

    Advantages over the OpenAI-compatible shim:
    - Exposes thoughts_token_count for accurate cost tracking
    - Native schema-constrained JSON output (server-side grammar enforcement)
    - No dependency on Google's OpenAI compatibility layer

    Falls back to OpenAICompatibleProvider if google-genai is not installed.
    """

    def __init__(self, config: ModelConfig):
        super().__init__(config)
        if not GENAI_SDK_AVAILABLE:
            raise RuntimeError(
                "google-genai SDK not installed: pip install google-genai"
            )

        import threading
        self._clients_lock = threading.Lock()
        # {thread_id: Client} — bounded by live-thread reaping.
        self._clients: Dict[int, Any] = {}
        logger.debug(
            f"Initialized GeminiProvider: {config.model_name}"
        )

    @property
    def client(self):
        """Per-thread client -- google-genai is not thread-safe."""
        import threading
        tid = threading.get_ident()
        with self._clients_lock:
            c = self._clients.get(tid)
            if c is not None:
                return c
            # Reap clients for dead threads to prevent leaks.
            alive = {t.ident for t in threading.enumerate()}
            dead = [k for k in self._clients if k not in alive]
            for k in dead:
                self._clients.pop(k, None)
        # Build client outside the lock (may do I/O).
        if os.environ.get("RAPTOR_LLM_SOCKET"):
            from core.llm.dispatcher.client import (
                make_gemini_base_url,
            )
            from google.genai.types import HttpOptions
            base_url, http_client = make_gemini_base_url()
            new_client = _genai_module.Client(
                api_key="dummy-not-used",
                http_options=HttpOptions(
                    base_url=base_url,
                    httpx_client=http_client,
                ),
            )
            logger.debug(
                "GeminiProvider: routing via "
                "credential-isolation dispatcher"
            )
        else:
            new_client = _genai_module.Client(
                api_key=self.config.api_key,
            )
            logger.debug(
                "GeminiProvider: direct SDK (no dispatcher)"
            )
        with self._clients_lock:
            # Another thread may have raced us for same tid (not
            # possible in CPython, but harmless to check).
            self._clients.setdefault(tid, new_client)
            return self._clients[tid]

    def generate(self, prompt: str, system_prompt: Optional[str] = None,
                 **kwargs) -> LLMResponse:
        """Generate completion using the native Gemini SDK."""
        config_kwargs = {
            "temperature": kwargs.get("temperature", self.config.temperature),
            "max_output_tokens": kwargs.get("max_tokens", self.config.max_tokens),
        }

        contents = [{"role": "user", "parts": [{"text": prompt}]}]
        generate_kwargs = {
            "model": self.config.model_name,
            "contents": contents,
            "config": config_kwargs,
        }
        if system_prompt:
            generate_kwargs["config"]["system_instruction"] = system_prompt

        try:
            t_start = time.monotonic()
            response = self.client.models.generate_content(**generate_kwargs)
            duration = time.monotonic() - t_start

            if not response.text and not response.candidates:
                raise RuntimeError("Gemini returned empty response")

            content = response.text or ""
            finish_reason = "complete"
            if response.candidates and response.candidates[0].finish_reason:
                fr = response.candidates[0].finish_reason
                finish_reason = getattr(fr, 'name', str(fr)).lower()

            # Gemini safety filters block exploit/attack content — detect and raise
            # so the caller sees a clear error rather than empty content
            if not content and finish_reason in ('safety', 'recitation', 'blocked', 'other'):
                raise RuntimeError(
                    f"Gemini blocked response (finish_reason={finish_reason}). "
                    f"This typically happens with exploit code or attack scenario prompts."
                )

            input_tokens = 0
            output_tokens = 0
            thinking_tokens = 0
            if response.usage_metadata:
                input_tokens = response.usage_metadata.prompt_token_count or 0
                output_tokens = response.usage_metadata.candidates_token_count or 0
                thinking_tokens = getattr(response.usage_metadata, 'thoughts_token_count', 0) or 0

            tokens_used = input_tokens + output_tokens + thinking_tokens
            cost = self._calculate_cost_split(input_tokens, output_tokens, thinking_tokens)

            self.track_usage(tokens_used, cost, input_tokens, output_tokens, duration)
            logger.debug("[Gemini] model=%s, tokens=%s, cost=$%.4f, duration=%.2fs, thinking=%s",
                         self.config.model_name, tokens_used, cost, duration, thinking_tokens)

            return LLMResponse(
                content=content,
                model=self.config.model_name,
                provider="gemini",
                tokens_used=tokens_used,
                cost=cost,
                finish_reason=finish_reason,
                resolved_model=extract_resolved_model(response),
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                thinking_tokens=thinking_tokens,
                duration=duration,
            )

        except Exception as e:
            # Same hardening rationale as OpenAICompatibleProvider.generate.
            from core.security.log_sanitisation import escape_nonprintable
            from core.security.redaction import redact_secrets
            # DEBUG, not ERROR — same rationale as OpenAI above:
            # the LLMClient retry loop emits an operator-visible
            # WARNING for the same failure.
            logger.debug("Gemini completion failed: %s",
                         escape_nonprintable(redact_secrets(str(e)))[:1024])
            raise

    def generate_structured(self, prompt: str, schema: Dict[str, Any],
                           system_prompt: Optional[str] = None,
                           **kwargs) -> Tuple[Dict[str, Any], str]:
        """Generate structured output using Gemini's native JSON mode."""
        # Normalize simple schema to JSON Schema format so both pydantic and
        # Gemini schema conversion see the same structure
        normalized = _normalize_schema(schema)
        pydantic_model = _dict_schema_to_pydantic(normalized)

        max_out = kwargs.pop("max_tokens", None) or self.config.max_tokens
        config_kwargs = {
            "temperature": kwargs.get("temperature", self.config.temperature),
            "max_output_tokens": max_out,
            "response_mime_type": "application/json",
            "response_schema": _schema_to_gemini(normalized),
        }

        if max_out >= 16384:
            try:
                from google.genai.types import ThinkingConfig
                raw_budget = max_out - 16384
                if "flash" in self.config.model_name.lower():
                    budget = min(raw_budget, 24576)
                else:
                    budget = min(raw_budget, 32768)
                budget = max(budget, 128)
                config_kwargs["thinking_config"] = ThinkingConfig(
                    thinkingBudget=budget,
                )
            except (ImportError, TypeError):
                pass

        contents = [{"role": "user", "parts": [{"text": prompt}]}]
        generate_kwargs = {
            "model": self.config.model_name,
            "contents": contents,
            "config": config_kwargs,
        }
        if system_prompt:
            generate_kwargs["config"]["system_instruction"] = system_prompt

        try:
            t_start = time.monotonic()
            response = self.client.models.generate_content(**generate_kwargs)
            duration = time.monotonic() - t_start

            input_tokens = 0
            output_tokens = 0
            thinking_tokens = 0
            if response.usage_metadata:
                input_tokens = response.usage_metadata.prompt_token_count or 0
                output_tokens = response.usage_metadata.candidates_token_count or 0
                thinking_tokens = getattr(response.usage_metadata, 'thoughts_token_count', 0) or 0

            tokens_used = input_tokens + output_tokens + thinking_tokens
            cost = self._calculate_cost_split(input_tokens, output_tokens, thinking_tokens)
            self.track_usage(tokens_used, cost, input_tokens, output_tokens, duration)

            logger.debug("[Gemini] structured model=%s, tokens=%s, cost=$%.4f, duration=%.2fs, thinking=%s",
                         self.config.model_name, tokens_used, cost, duration, thinking_tokens)

            finish_reason = "complete"
            if response.candidates and response.candidates[0].finish_reason:
                fr = response.candidates[0].finish_reason
                finish_reason = getattr(fr, 'name', str(fr)).lower()

            if finish_reason in ("max_tokens", "length"):
                raise RuntimeError(
                    "Gemini native structured response truncated "
                    f"(finish_reason={finish_reason}, "
                    f"output_tokens={output_tokens})"
                )

            content = (response.text or "").strip()
            if content.startswith("```") and content.endswith("```"):
                if "\n" in content:
                    content = content.split("\n", 1)[1]
                else:
                    content = content[3:]
                    content = content.lstrip("abcdefghijklmnopqrstuvwxyz")
                content = content.rsplit("```", 1)[0].strip()
            elif content.startswith("```"):
                if "\n" in content:
                    content = content.split("\n", 1)[1]
                else:
                    content = content[3:]
                    content = content.lstrip("abcdefghijklmnopqrstuvwxyz")
                content = content.strip()
            parsed = json.loads(content)
            if not parsed:
                raise ValueError("Gemini returned empty object in structured mode")
            parsed = _coerce_to_schema(parsed, normalized)
            validated = pydantic_model.model_validate(parsed)
            result_dict = validated.model_dump()
            full_response = json.dumps(result_dict, indent=2)

            return StructuredResponse(
                result=result_dict,
                raw=full_response,
                resolved_model=extract_resolved_model(response),
            )

        except (json.JSONDecodeError, ValueError, KeyError) as e:
            # Schema/parsing error — native mode incompatible, fall back to JSON-in-prompt
            logger.warning("Gemini native structured generation failed (falling back): %s", e)
            return self._structured_fallback(prompt, schema, pydantic_model, system_prompt)
        except Exception:
            # Auth, network, quota — don't waste a second call
            raise

    # ------------------------------------------------------------------
    # Tool-use via JSON-protocol synthesis.
    # ------------------------------------------------------------------
    #
    # The native google-genai SDK exposes Gemini's function-calling but
    # this provider doesn't wire that up — operators wanting native
    # function-calling install ``openai`` alongside ``google-genai`` and
    # the factory routes through :class:`OpenAICompatibleProvider`
    # against Gemini's OpenAI-compat endpoint.
    #
    # For users who installed ONLY the google-genai SDK (chosen for
    # accurate ``thoughts_token_count`` cost tracking, server-side
    # schema-constrained JSON), the synthesis fallback gives them
    # tool-use without forcing an additional SDK install. Same pattern
    # as :class:`ClaudeCodeLLMProvider`.

    def supports_tool_use(self) -> bool: return True
    def supports_prompt_caching(self) -> bool: return False
    def supports_parallel_tools(self) -> bool: return False

    def turn(
        self,
        messages: Sequence[Message],
        tools: Sequence[ToolDef],
        *,
        system: Optional[str] = None,
        max_tokens: int = 4096,
        cache_control: CacheControl = CacheControl(),
        **provider_specific: Any,
    ) -> TurnResponse:
        """Tool-use via the ABC's JSON-protocol fallback."""
        return self._tool_use_fallback(
            messages, tools,
            system=system, max_tokens=max_tokens,
            cache_control=cache_control, **provider_specific,
        )


class ClaudeCodeProvider:
    """
    LLM provider stub that signals 'Claude Code will handle this.'

    Returns None from all generation methods. When the agentic pipeline
    runs inside Claude Code with no external LLM configured, this provider
    is used instead of LLMClient. The Python pipeline does mechanical prep
    work (SARIF parsing, code extraction, dataflow analysis) and returns
    structured findings for Claude Code to reason over.

    Callers handle None returns gracefully — the same code path used when
    an external LLM call fails.

    Not a subclass of LLMProvider (returns None instead of LLMResponse),
    but provides the same tracking attributes for stats compatibility.
    Use `is_stub_provider()` to distinguish from real providers.
    """

    is_stub = True  # Distinguishes from real providers

    def __init__(self):
        self.total_tokens = 0
        self.total_input_tokens = 0
        self.total_output_tokens = 0
        self.total_cost = 0.0
        self.call_count = 0
        self.total_duration = 0.0

    def generate(self, prompt: str, system_prompt: Optional[str] = None,
                 **kwargs):
        """Returns None — Claude Code will do the reasoning."""
        return None

    def generate_structured(self, prompt: str, schema: Dict[str, Any],
                           system_prompt: Optional[str] = None,
                           **kwargs):
        """Returns (None, None) — Claude Code will do the reasoning.

        Accepts and ignores ``**kwargs`` (notably ``temperature``):
        the `claude` CLI doesn't expose a temperature flag, so any
        per-call override is structurally a no-op here. Accepting
        kwargs prevents TypeError when callers route through the
        unified `LLMClient.generate_structured` plumbing.
        """
        return None, None

    def get_stats(self) -> Dict[str, Any]:
        """Return zero stats."""
        return {
            "total_requests": 0,
            "total_cost": 0.0,
            "budget_remaining": 0.0,
            "providers": {},
        }


def _safe_subprocess_stderr(stderr: Optional[str], *, limit: int = 500) -> str:
    """Sanitise subprocess stderr for inclusion in operator-facing
    ``RuntimeError`` messages.

    Per ``project_log_sanitisation_adoption.md`` (threats A + B):
    redact credentials that the child process may have echoed
    (``ANTHROPIC_API_KEY``, bearer tokens, ``user:pass@`` URLs) and
    escape non-printable bytes (ANSI / BIDI / control bytes) so the
    error message can't corrupt operator terminals or be reshared
    with secrets intact.

    Truncation happens *after* sanitisation so the limit applies to
    the rendered length, not the raw byte count.
    """
    if not stderr:
        return ""
    from core.security.log_sanitisation import escape_nonprintable
    from core.security.redaction import redact_secrets
    return escape_nonprintable(redact_secrets(stderr))[:limit]


class ClaudeCodeLLMProvider(LLMProvider):
    """Claude Code subprocess transport as a real :class:`LLMProvider`.

    Wraps ``claude -p`` (via :mod:`core.llm.cc_adapter`) so consumers
    that hold a :class:`ModelConfig` can transparently use the Claude
    Code CLI when no SDK API key is configured. Supports tool-use via
    the ABC's :meth:`_tool_use_fallback` (JSON-in-prompt protocol over
    plain ``generate()``) — slower than native tool/function calling
    and one tool call per turn, but functional on any backend that
    just emits text.

    Distinct from the :class:`ClaudeCodeProvider` stub above: this is
    a real provider that does generation; the stub returns ``None`` to
    signal "the surrounding orchestrator handles reasoning" and is
    used by :mod:`packages.llm_analysis.agent` for prep-only mode.
    """

    is_stub = False

    def __init__(
        self,
        config: ModelConfig,
        *,
        claude_bin: Optional[str] = None,
        # Per-CALL abort ceiling (claude -p --max-budget-usd), not a
        # run budget — orchestrators cap total spend via --max-cost.
        # Audit-sized structured reviews (system prompt + context
        # slice + schema) measure $0.9-1.3 per call on Opus-class
        # models; the old "1.00" default aborted them mid-response
        # with subtype error_max_budget_usd.
        budget_usd: str = "5.00",
        timeout_s: Optional[int] = None,
        resumable: bool = False,
    ) -> None:
        super().__init__(config)
        self._claude_bin = claude_bin or "claude"
        self._budget_usd = budget_usd
        self._resumable = resumable
        self._session_id: Optional[str] = None
        self._messages_seen: int = 0
        # Per-call timeout: prefer explicit kwarg, then ModelConfig.timeout,
        # then a generous default (Claude Code subprocess + tool-use can
        # take several minutes on real workloads).
        #
        # `0` is the documented "no timeout" sentinel — operator
        # explicitly opting out of the cap (a long-running tool-use
        # session, an unattended overnight scan). Pre-fix the
        # `timeout_s or ...` chain treated 0 as falsy and overrode it
        # with the 600s default — silently re-enforcing the cap the
        # operator just disabled. Use explicit `is None` for kwarg
        # absence and `<= 0` to honour the no-timeout sentinel.
        if timeout_s is not None:
            self._timeout_s = None if timeout_s <= 0 else timeout_s
        elif config.timeout is not None:
            self._timeout_s = None if config.timeout <= 0 else config.timeout
        else:
            self._timeout_s = 600

    def reset_session(self) -> None:
        """Discard resume state so the next ``turn()`` starts fresh."""
        self._session_id = None
        self._messages_seen = 0

    def context_window(self) -> int:
        return self.config.max_context

    def _cli_model(self) -> Optional[str]:
        """Model name to pass as ``claude -p --model``.

        ``None`` (omit the flag; the subprocess inherits the CLI
        session's own default model) when the config carries the
        claudecode fallback sentinel rather than an operator-chosen
        name — a hardcoded name breaks backends (Bedrock/Vertex)
        that don't serve bare Anthropic model IDs.
        """
        from .config import CLAUDECODE_SESSION_MODEL
        if self.config.model_name == CLAUDECODE_SESSION_MODEL:
            return None
        return self.config.model_name

    def _effective_timeout_s(
        self, override: Optional[int],
    ) -> Optional[int]:
        """Resolve the timeout for one call.

        ``override`` is the per-call ``timeout_s`` kwarg — callers
        whose call class is known to outlive the provider default
        (e.g. checker synthesis: huge system prompt + JSON-schema
        output, measured >600s on Bedrock-backed CLIs) pass their
        own ceiling. Same ``<= 0`` = "no timeout" sentinel as
        ``__init__``; ``None`` means "not overridden".
        """
        if override is None:
            return self._timeout_s
        return None if override <= 0 else override

    def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        **kwargs: Any,
    ) -> LLMResponse:
        """Dispatch a prompt to ``claude -p`` via stream-json and parse
        the response."""
        from .cc_adapter import (
            CCDispatchConfig,
            build_cc_command,
            run_cc_streaming,
        )
        import subprocess
        import time as _time

        call_timeout = self._effective_timeout_s(kwargs.pop("timeout_s", None))

        # Pass the user prompt as-is and route the system prompt
        # through CC's `--system-prompt` flag (see CCDispatchConfig.system_prompt
        # comment for the prompt-injection rationale).
        cc_config = CCDispatchConfig(
            claude_bin=self._claude_bin,
            # Used as a pure-LLM substrate: disable CC's internal tools
            # (Read/Grep/Glob default) so the subprocess can't scan cwd
            # before answering. Tool-use happens at the loop layer above
            # us via _tool_use_fallback's JSON-protocol synthesis.
            tools="",
            budget_usd=self._budget_usd,
            timeout_s=call_timeout,
            capture_json_envelope=False,
            stream_json=True,
            system_prompt=system_prompt,
            model=self._cli_model(),
        )
        cmd = build_cc_command(cc_config)

        # Sanitised baseline (get_safe_env strips shell-evaluated
        # vars a poisoned dotfile might set) + the backend env
        # families (CLAUDE_CODE_*/ANTHROPIC_*/AWS_*) the CLI needs
        # to reach its provider — a bare get_safe_env() left a
        # Bedrock-backed CLI child with no credentials/model
        # mapping, hanging every call until timeout. See
        # cc_subprocess_env's docstring.
        from .cc_adapter import cc_subprocess_env
        _cc_env = cc_subprocess_env()

        # monotonic() — wall clock can jump under NTP/DST, producing
        # negative durations on long CC calls.
        start = _time.monotonic()
        try:
            sr = run_cc_streaming(
                cmd, prompt, env=_cc_env, timeout_s=call_timeout,
            )
        except subprocess.TimeoutExpired as e:
            raise RuntimeError(f"claude -p timed out after {call_timeout}s") from e
        duration = _time.monotonic() - start

        if sr.error:
            raise RuntimeError(sr.error)

        total_tokens = sr.input_tokens + sr.output_tokens
        self.track_usage(
            tokens=total_tokens,
            cost=sr.cost_usd,
            input_tokens=sr.input_tokens,
            output_tokens=sr.output_tokens,
            cache_read_tokens=sr.cache_read_tokens,
            cache_write_tokens=sr.cache_creation_tokens,
            duration=duration,
        )

        # The claude-code harness reports the model it used in the
        # stream-json output; treat that as the resolved snapshot. But
        # CC may set it to a comma-joined list (main + tool-routing
        # helper) — that's not a single snapshot, so leave
        # resolved_model None rather than emit a bogus multi-value
        # "version" into the manifest/scorecard.
        resolved = sr.model if (sr.model and "," not in sr.model) else None

        return LLMResponse(
            content=sr.content,
            model=sr.model or self.config.model_name,
            provider="claudecode",
            tokens_used=total_tokens,
            cost=sr.cost_usd,
            finish_reason="stop",
            resolved_model=resolved,
            input_tokens=sr.input_tokens,
            output_tokens=sr.output_tokens,
            duration=duration,
        )

    def generate_structured(
        self,
        prompt: str,
        schema: Dict[str, Any],
        system_prompt: Optional[str] = None,
        **kwargs,
    ) -> Tuple[Dict[str, Any], str]:
        """Dispatch with ``--json-schema`` for structured output via
        stream-json.

        Accepts and ignores ``**kwargs`` — `claude` CLI has no
        temperature flag (see ClaudeCodeProvider.generate_structured).
        """
        from .cc_adapter import (
            CCDispatchConfig,
            build_cc_command,
            run_cc_streaming,
        )
        import subprocess
        import time as _time

        # Route system_prompt through CC's `--system-prompt` flag instead of
        # concatenating into the user prompt. Pre-fix this path used
        # `f"{system_prompt}\n\n{prompt}"`, mixing the trusted system
        # message into the same channel as user content. The
        # generate() path above (the freeform sibling of this method)
        # already uses `--system-prompt` correctly. The structured path's
        # f-string concat:
        #
        #   * Drops the trust separation that CC's `--system-prompt` flag
        #     gives us — operator system instructions and finding
        #     content arrive on the SAME channel from the model's
        #     perspective.
        #   * Loses CC's own role-separated rendering — the
        #     subprocess's prompt-injection defences (which key off
        #     the role boundary) treated the whole thing as user
        #     content.
        #
        # Bring this site in line with generate(): full_prompt is
        # the user content; system_prompt routes through
        # CCDispatchConfig.system_prompt (which build_cc_command
        # converts into a `--system-prompt` flag).
        call_timeout = self._effective_timeout_s(kwargs.pop("timeout_s", None))

        cc_config = CCDispatchConfig(
            claude_bin=self._claude_bin,
            tools="",                                # see generate() comment
            budget_usd=self._budget_usd,
            timeout_s=call_timeout,
            json_schema=schema,
            capture_json_envelope=False,
            stream_json=True,
            system_prompt=system_prompt,
            model=self._cli_model(),
        )
        cmd = build_cc_command(cc_config)

        # Sanitised baseline (get_safe_env strips shell-evaluated
        # vars a poisoned dotfile might set) + the backend env
        # families (CLAUDE_CODE_*/ANTHROPIC_*/AWS_*) the CLI needs
        # to reach its provider — a bare get_safe_env() left a
        # Bedrock-backed CLI child with no credentials/model
        # mapping, hanging every call until timeout. See
        # cc_subprocess_env's docstring.
        from .cc_adapter import cc_subprocess_env
        _cc_env = cc_subprocess_env()

        start = _time.monotonic()
        try:
            sr = run_cc_streaming(
                cmd, prompt, env=_cc_env, timeout_s=call_timeout,
            )
        except subprocess.TimeoutExpired as e:
            raise RuntimeError(f"claude -p timed out after {call_timeout}s") from e
        duration = _time.monotonic() - start

        if sr.error:
            raise RuntimeError(sr.error)

        result = self._parse_stream_content(sr.content)
        if isinstance(result, dict) and "error" in result and result["error"]:
            raise RuntimeError(f"claude -p structured parse failed: {result['error']}")

        total_tokens = sr.input_tokens + sr.output_tokens
        self.track_usage(
            tokens=total_tokens,
            cost=sr.cost_usd,
            input_tokens=sr.input_tokens,
            output_tokens=sr.output_tokens,
            cache_read_tokens=sr.cache_read_tokens,
            cache_write_tokens=sr.cache_creation_tokens,
            duration=duration,
        )

        return StructuredResponse(
            result=result,
            raw=json.dumps(result, indent=2),
            cost=sr.cost_usd,
            tokens_used=total_tokens,
            model=sr.model or self.config.model_name,
            provider="claudecode",
            duration=duration,
        )

    def supports_tool_use(self) -> bool: return True
    def supports_prompt_caching(self) -> bool: return False
    def supports_parallel_tools(self) -> bool: return False

    # ------------------------------------------------------------------
    # Tool-use via ``--json-schema`` structured output.
    # ------------------------------------------------------------------
    #
    # The ABC's JSON-in-prompt synthesis (``_tool_use_fallback``) does
    # *not* work for Claude Code. CC has anti-prompt-injection training
    # that refuses to roleplay as a different agent system when a system
    # prompt says "you have these tools, emit JSON to call them" — that
    # framing is indistinguishable from an attacker injecting a fake
    # tool schema, and CC correctly refuses.
    #
    # The fix: reframe the task as *structured output* via CC's
    # ``--json-schema`` flag. Anti-injection guards roleplay, not
    # form-filling. We give CC a discriminated-union schema (either
    # ``tool_call`` or ``complete``) plus the tool catalog as
    # reference material, and CC fills in the form. Verified
    # empirically: CC honours the schema and produces valid tool
    # calls or final answers for typical agent flows.

    # Class-level latch for the provider_specific-ignored warning so
    # we don't log per-turn (one ToolUseLoop run can fire dozens of
    # turns with the same kwargs).
    _provider_specific_warned: bool = False

    def turn(
        self,
        messages: Sequence[Message],
        tools: Sequence[ToolDef],
        *,
        system: Optional[str] = None,
        max_tokens: int = 4096,
        cache_control: CacheControl = CacheControl(),
        **provider_specific: Any,
    ) -> TurnResponse:
        """Tool-use via ``generate_structured`` with a discriminated
        schema. Each turn, CC chooses either to call a tool (returning
        name + input) or to finalise (returning text)."""
        # `del cache_control` — no caching at the CC layer (the
        # subprocess re-launches per turn).
        del cache_control
        # `provider_specific` — silently dropped pre-fix. A caller
        # passing `temperature=`, `top_p=`, `frequency_penalty=`, etc.
        # via the ToolUseLoop saw their values quietly ignored when
        # the bound provider was CC (CC's subprocess interface doesn't
        # expose those flags). Warn ONCE per process so the operator
        # can decide whether to switch providers or accept the gap.
        if provider_specific and not type(self)._provider_specific_warned:
            type(self)._provider_specific_warned = True
            _kwargs_list = sorted(provider_specific.keys())
            logger.warning(
                "ClaudeCodeLLMProvider.turn: ignoring provider_specific "
                "kwargs %s — CC's subprocess interface doesn't expose these. "
                "If you need per-turn control over temperature/top_p/etc., "
                "switch to AnthropicProvider (set ANTHROPIC_API_KEY).",
                _kwargs_list,
            )

        # No tools → plain text generation. Skip the schema overhead.
        if not tools:
            rendered = LLMProvider._render_messages_as_prompt(messages)
            response = self.generate(
                rendered,
                system_prompt=system,
                max_tokens=max_tokens,
            )
            cost = getattr(response, "cost", None)
            return TurnResponse(
                content=[TextBlock(text=(response.content if response else "") or "")],
                stop_reason=StopReason.COMPLETE,
                input_tokens=getattr(response, "input_tokens", 0) or 0,
                output_tokens=getattr(response, "output_tokens", 0) or 0,
                cost_usd=float(cost) if cost is not None else None,
            )

        if self._resumable:
            return self._turn_resumable(messages, tools, system=system)

        return self._turn_stateless(messages, tools, system=system)

    def _turn_stateless(
        self,
        messages: Sequence[Message],
        tools: Sequence[ToolDef],
        *,
        system: Optional[str] = None,
    ) -> TurnResponse:
        """Original per-subprocess turn with no session state."""
        schema = self._build_turn_schema(tools)
        sys_combined = self._build_turn_system_prompt(tools, extra=system)
        rendered_history = self._render_history_for_cc(messages)

        try:
            response = self.generate_structured(
                prompt=rendered_history,
                schema=schema,
                system_prompt=sys_combined,
            )
        except RuntimeError as exc:
            err_msg = f"subprocess error: {exc}"
            logger.warning(f"ClaudeCodeLLMProvider.turn: {err_msg}")
            return TurnResponse(
                content=[],
                stop_reason=StopReason.ERROR,
                input_tokens=0,
                output_tokens=0,
                error_message=err_msg,
            )

        if isinstance(response, StructuredResponse):
            result = response.result
            cost_usd = response.cost
            tokens = response.tokens_used
        else:
            result, _ = response
            cost_usd = 0.0
            tokens = 0

        return self._parse_turn_structured_result(
            result,
            tools,
            cost_usd=cost_usd,
            input_tokens=0,
            output_tokens=tokens,
        )

    def _turn_resumable(
        self,
        messages: Sequence[Message],
        tools: Sequence[ToolDef],
        *,
        system: Optional[str] = None,
        _retry: bool = False,
    ) -> TurnResponse:
        """Resume-based turn: CC preserves conversation state across
        subprocess invocations via ``--resume <session_id>``.

        Turn 1 sends the full system prompt, tool catalogue, and message
        history. Subsequent turns send only the new messages (typically
        the tool result from the previous call). Prompt caching gives
        near-zero input cost on turn 2+.

        Uses ``--output-format stream-json`` for streaming responses
        and proper input/output token accounting.
        """
        from .cc_adapter import (
            CCDispatchConfig,
            build_cc_command,
            run_cc_streaming,
        )
        import subprocess
        import time as _time

        schema = self._build_turn_schema(tools)
        first_turn = self._session_id is None

        if first_turn:
            sys_combined = self._build_turn_system_prompt(tools, extra=system)
            prompt = self._render_history_for_cc(messages)
        else:
            sys_combined = None
            new_msgs = messages[self._messages_seen :]
            prompt = self._render_history_for_cc(new_msgs) if new_msgs else ""

        cc_config = CCDispatchConfig(
            claude_bin=self._claude_bin,
            tools="",
            budget_usd=self._budget_usd,
            timeout_s=self._timeout_s,
            json_schema=schema,
            capture_json_envelope=False,
            stream_json=True,
            system_prompt=sys_combined,
            model=self._cli_model(),
            session_id=self._session_id,
            persist_session=True,
        )
        cmd = build_cc_command(cc_config)

        from .cc_adapter import cc_subprocess_env

        _cc_env = cc_subprocess_env()

        start = _time.monotonic()
        try:
            sr = run_cc_streaming(
                cmd, prompt, env=_cc_env, timeout_s=self._timeout_s,
            )
        except subprocess.TimeoutExpired:
            err_msg = f"claude -p timed out after {self._timeout_s}s"
            logger.warning(f"ClaudeCodeLLMProvider._turn_resumable: {err_msg}")
            return TurnResponse(
                content=[],
                stop_reason=StopReason.ERROR,
                input_tokens=0,
                output_tokens=0,
                error_message=err_msg,
            )
        duration = _time.monotonic() - start

        if sr.error:
            err_msg = sr.error
            logger.warning(f"ClaudeCodeLLMProvider._turn_resumable: {err_msg}")
            if first_turn and sr.session_id:
                self._session_id = sr.session_id
            if (
                not first_turn
                and not _retry
                and "deferred tool marker" in err_msg.lower()
            ):
                logger.info(
                    "CC resume marker stale — resetting session and "
                    "retrying as fresh turn",
                )
                self.reset_session()
                return self._turn_resumable(
                    messages, tools, system=system, _retry=True,
                )
            return TurnResponse(
                content=[],
                stop_reason=StopReason.ERROR,
                input_tokens=0,
                output_tokens=0,
                error_message=err_msg,
            )

        self._messages_seen = len(messages)

        if first_turn and sr.session_id:
            self._session_id = sr.session_id
            logger.info(
                "CC resume session established: %s", self._session_id,
            )

        content_text = sr.content
        if not content_text:
            return TurnResponse(
                content=[],
                stop_reason=StopReason.ERROR,
                input_tokens=sr.input_tokens,
                output_tokens=sr.output_tokens,
                error_message="empty response from stream-json",
            )

        self.track_usage(
            tokens=sr.input_tokens + sr.output_tokens,
            cost=sr.cost_usd,
            input_tokens=sr.input_tokens,
            output_tokens=sr.output_tokens,
            cache_read_tokens=sr.cache_read_tokens,
            cache_write_tokens=sr.cache_creation_tokens,
            duration=duration,
        )

        result = self._parse_stream_content(content_text)
        if isinstance(result, dict) and "error" in result and result["error"]:
            return TurnResponse(
                content=[],
                stop_reason=StopReason.ERROR,
                input_tokens=sr.input_tokens,
                output_tokens=sr.output_tokens,
                error_message=f"structured parse: {result['error']}",
            )

        return self._parse_turn_structured_result(
            result,
            tools,
            cost_usd=sr.cost_usd,
            input_tokens=sr.input_tokens,
            output_tokens=sr.output_tokens,
        )

    @staticmethod
    def _parse_stream_content(text: str) -> dict[str, Any]:
        """Extract the structured JSON object from stream-json content text."""
        from .cc_adapter import strip_json_fences
        import json

        text = strip_json_fences(text.strip())
        try:
            obj = json.loads(text)
            if isinstance(obj, dict):
                return obj
        except json.JSONDecodeError:
            pass
        try:
            decoder = json.JSONDecoder()
            idx = text.index("{")
            obj, _ = decoder.raw_decode(text, idx)
            if isinstance(obj, dict):
                return obj
        except (ValueError, json.JSONDecodeError):
            pass
        return {"error": f"unparseable stream content: {text[:200]}"}

    # ------------------------------------------------------------------
    # turn() helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _build_turn_schema(tools: Sequence[ToolDef]) -> Dict[str, Any]:
        """Discriminated-union schema CC fills in for one turn.

        ``tool_name`` is constrained to the registered tool set so CC
        can't hallucinate a name. ``tool_input`` is left as a generic
        object — per-tool input validation happens at dispatch time
        in :class:`ToolUseLoop`."""
        return {
            "type": "object",
            "properties": {
                "type": {
                    "type": "string",
                    "enum": ["tool_call", "complete"],
                    "description": (
                        "tool_call to invoke a tool; complete to "
                        "deliver the final answer."
                    ),
                },
                "tool_name": {
                    "type": "string",
                    "enum": [t.name for t in tools],
                    "description": (
                        "Name of the tool to invoke (only when "
                        "type=tool_call)."
                    ),
                },
                "tool_input": {
                    "type": "object",
                    "description": (
                        "Arguments object for the tool, matching its "
                        "input_schema (only when type=tool_call)."
                    ),
                },
                "final_text": {
                    "type": "string",
                    "description": (
                        "Final answer text (only when type=complete)."
                    ),
                },
            },
            "required": ["type"],
        }

    @staticmethod
    def _build_turn_system_prompt(
        tools: Sequence[ToolDef],
        *,
        extra: Optional[str] = None,
    ) -> str:
        # The "do not invent values" instruction is critical and
        # substrate-level (not consumer-specific): without it, the
        # model sometimes calls verification tools (e.g.
        # ``gh_commit_detail(slug=..., sha=...)``) with hallucinated
        # arguments before the discovery tool that produces those
        # values has been called. The mitigation costs nothing and
        # generalises across consumers; per-consumer guardrails
        # (cve-diff's verified-SHA gate, etc.) remain the
        # belt-and-braces second line.
        lines = [
            "Decide the next action for an agentic tool-use loop. "
            "Either invoke a tool to gather more information or "
            "deliver a final answer. Output JSON matching the "
            "provided schema.",
            "",
            "RULES:",
            "1. When invoking a tool, the values you put in tool_input "
            "MUST come from either the conversation history or the "
            "user's request. Do not guess, invent, or recall from "
            "training data — even values that look plausible (slugs, "
            "SHAs, URLs, IDs, package names).",
            "2. If you don't have a value the next tool needs, call "
            "a discovery tool first to obtain it.",
            "3. Call only one tool per response.",
            "",
            "TOOL CATALOG:",
        ]
        for t in tools:
            lines.append(f"- {t.name}: {t.description}")
            lines.append(
                f"  input_schema: {json.dumps(t.input_schema)}"
            )
        if extra:
            lines.extend(["", extra])
        return "\n".join(lines)

    @staticmethod
    def _render_history_for_cc(messages: Sequence[Message]) -> str:
        """Flatten conversation history into a prompt CC reads as
        reference material. Roles labelled; tool-call/result blocks
        rendered as descriptive text."""
        parts: list[str] = ["CONVERSATION HISTORY:"]
        for msg in messages:
            for block in msg.content:
                if isinstance(block, TextBlock):
                    parts.append(f"{msg.role}: {block.text}")
                elif isinstance(block, ToolCall):
                    parts.append(
                        f"assistant called tool {block.name!r} with "
                        f"input {json.dumps(block.input)}"
                    )
                elif isinstance(block, ToolResult):
                    err = " [error]" if block.is_error else ""
                    parts.append(
                        f"tool_result{err} for {block.tool_use_id}: "
                        f"{block.content}"
                    )
        return "\n\n".join(parts)

    def _parse_turn_structured_result(
        self,
        result: Dict[str, Any],
        tools: Sequence[ToolDef],
        *,
        cost_usd: float = 0.0,
        input_tokens: int = 0,
        output_tokens: int = 0,
    ) -> TurnResponse:
        """Translate CC's structured response into a
        :class:`TurnResponse`. Defensive against malformed output —
        falls back to a text block if the result doesn't fit either
        branch of the discriminated schema."""
        usd: Optional[float] = float(cost_usd) if cost_usd is not None else None
        rtype = result.get("type")
        if rtype == "tool_call":
            name = result.get("tool_name")
            inp = result.get("tool_input")
            if (
                isinstance(name, str)
                and isinstance(inp, dict)
                and any(t.name == name for t in tools)
            ):
                import uuid as _uuid
                call_id = f"call_{_uuid.uuid4().hex[:12]}"
                return TurnResponse(
                    content=[ToolCall(id=call_id, name=name, input=inp)],
                    stop_reason=StopReason.NEEDS_TOOL_CALL,
                    input_tokens=input_tokens,
                    output_tokens=output_tokens,
                    cost_usd=usd,
                )
            # Malformed tool_call — surface the raw result as text so
            # callers can see what went wrong rather than silently
            # dropping it.
            return TurnResponse(
                content=[TextBlock(text=json.dumps(result))],
                stop_reason=StopReason.COMPLETE,
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                cost_usd=usd,
            )
        # Default to "complete" for type="complete" and any other
        # unexpected discriminator value.
        text = result.get("final_text") or ""
        return TurnResponse(
            content=[TextBlock(text=text)],
            stop_reason=StopReason.COMPLETE,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cost_usd=usd,
        )


def create_provider(config: ModelConfig) -> LLMProvider:
    """
    Factory function to create appropriate provider.

    Uses native SDKs where available: AnthropicProvider for Anthropic,
    GeminiProvider for Gemini (with OpenAI shim fallback), and
    OpenAICompatibleProvider for everything else.

    Args:
        config: ModelConfig specifying provider and model

    Returns:
        LLMProvider instance
    """
    provider = config.provider.lower()
    if provider in (
        "claudecode-resumable",
        "claude_code_resumable",
        "claude-code-resumable",
    ):
        return ClaudeCodeLLMProvider(config, resumable=True)
    if provider in ("claudecode", "claude_code", "claude-code"):
        return ClaudeCodeLLMProvider(config)
    if provider == "bedrock":
        # AWS Bedrock — routed via the dispatcher's bedrock rule.  Two
        # API surfaces are available; the operator chooses with
        # ``ModelConfig.bedrock_api`` (default = Mantle):
        #
        # * ``"mantle"`` — Bedrock Mantle's Anthropic-Messages endpoint
        #   (``bedrock-mantle.<region>.api.aws/anthropic/v1/messages``).
        #   Bare model IDs (``anthropic.claude-opus-4-8``), native SSE
        #   streaming, tool use, prompt caching.
        # * ``"runtime"`` — Legacy InvokeModel
        #   (``bedrock-runtime.<region>.amazonaws.com/model/<id>/
        #   invoke``).  Required for models not on Mantle or for
        #   cross-region inference profile IDs (``us.``/``eu.``/
        #   ``global.``).
        #
        # In both cases the worker speaks plain Anthropic Messages; the
        # dispatcher attaches AWS auth (bearer or SigV4) and rewrites
        # the request to match the chosen API's contract.
        if not ANTHROPIC_SDK_AVAILABLE:
            raise RuntimeError(
                "Bedrock provider requires: pip install anthropic"
            )
        if not os.environ.get("RAPTOR_LLM_SOCKET"):
            raise RuntimeError(
                "Bedrock provider requires the RAPTOR LLM dispatcher "
                "(RAPTOR_LLM_SOCKET).  Workers do not hold AWS "
                "credentials; the dispatcher attaches them at the "
                "parent's trust boundary."
            )
        api = getattr(config, "bedrock_api", "mantle") or "mantle"
        if api not in ("mantle", "runtime"):
            raise RuntimeError(
                f"Bedrock provider: unknown bedrock_api={api!r}; "
                "expected 'mantle' or 'runtime'"
            )
        # AnthropicProvider already wires through the dispatcher when
        # RAPTOR_LLM_SOCKET is set; we just swap its client for the
        # Bedrock-routed one so the request goes to
        # ``/bedrock/<api>/...`` not ``/anthropic/...`` in the
        # dispatcher.  Same Anthropic SDK shape everywhere — body +
        # response unchanged.
        from core.llm.dispatcher.client import make_bedrock_client
        provider_instance = AnthropicProvider(config)
        provider_instance.client = make_bedrock_client(
            api=api, timeout=config.timeout,
        )
        if INSTRUCTOR_AVAILABLE:
            provider_instance.instructor_client = instructor.from_anthropic(
                provider_instance.client,
            )
        logger.debug(
            "Bedrock provider: routing via dispatcher /bedrock/%s", api,
        )
        return provider_instance
    if provider == "anthropic":
        if ANTHROPIC_SDK_AVAILABLE:
            return AnthropicProvider(config)
        elif OPENAI_SDK_AVAILABLE:
            logger.warning(
                "Anthropic SDK not installed — using OpenAI-compatible endpoint. "
                "Structured output will use Pydantic fallback (response_format is ignored by Anthropic). "
                "For best results: pip install anthropic"
            )
            from dataclasses import replace
            compat_config = replace(config, api_base="https://api.anthropic.com/v1")
            return OpenAICompatibleProvider(compat_config)
        else:
            raise RuntimeError(
                "Anthropic provider requires: pip install anthropic (or) pip install openai"
            )
    if provider == "gemini":
        if GENAI_SDK_AVAILABLE:
            return GeminiProvider(config)
        elif OPENAI_SDK_AVAILABLE:
            logger.info("google-genai SDK not installed — using OpenAI-compatible endpoint for Gemini. "
                        "For accurate thinking token tracking: pip install google-genai")
            return OpenAICompatibleProvider(config)
        else:
            raise RuntimeError(
                "Gemini provider requires: pip install google-genai (or) pip install openai"
            )
    if OPENAI_SDK_AVAILABLE:
        return OpenAICompatibleProvider(config)
    raise RuntimeError(
        f"Provider '{provider}' requires: pip install openai"
    )


# Backward compatibility
ClaudeProvider = AnthropicProvider if ANTHROPIC_SDK_AVAILABLE else type('ClaudeProvider', (), {})
OpenAIProvider = OpenAICompatibleProvider if OPENAI_SDK_AVAILABLE else type('OpenAIProvider', (), {})
OllamaProvider = OpenAICompatibleProvider if OPENAI_SDK_AVAILABLE else type('OllamaProvider', (), {})
