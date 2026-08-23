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
from dataclasses import dataclass
from inspect import isclass
from typing import TYPE_CHECKING, Any, ClassVar

if TYPE_CHECKING:
    from pydantic import BaseModel

from core.json import dumps_display
from core.logging import get_logger

from .cc_adapter import strip_json_fences
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

# Shared default for ``turn()``-family signatures (B008): CacheControl
# is a frozen dataclass, so one instance is safe to share.
_DEFAULT_CACHE_CONTROL = CacheControl()

logger = get_logger()

_ZERO_PRICE_WARNED: set[str] = set()

# Instructor resilience: allow this many consecutive failures before
# permanently disabling tool-use structured output for a provider.
# A single transient error (dispatcher startup race, network hiccup)
# won't kill Instructor for the rest of the session.
_INSTRUCTOR_MAX_CONSEC_FAILURES = 3


def _instructor_refusal_stop(exc: Exception) -> str | None:
    """Stop reason when an instructor failure is really a model refusal.

    A hard refusal on the tool-use leg surfaces as tool args missing
    every field: the API ends the turn with ``stop_reason="refusal"``
    and no tool call, instructor parses ``{}``, and the resulting
    exception reads like a schema-validation flake — so instructor
    burns its re-asks against a model boundary an identical retry
    cannot move (observed live: 4 attempts per call, all ``{}``, then
    the JSON fallback got the explicit refusal on the same content).
    The raw completions ride on ``InstructorRetryException``
    (``last_completion`` + ``failed_attempts[*].completion``); any of
    them carrying a refusal stop reason makes the whole call a model
    boundary, not a shape failure. ``getattr``-probed so non-instructor
    exceptions fall through untouched.
    """
    completions = [getattr(exc, "last_completion", None)]
    completions.extend(getattr(attempt, "completion", None) for attempt in getattr(exc, "failed_attempts", None) or ())
    for completion in completions:
        if getattr(completion, "stop_reason", None) == "refusal":
            return "refusal"
    return None

_TEMPERATURE_DEPRECATED_FROM = (4, 7)
_CLAUDE_VERSION_RE = re.compile(r"claude-[a-z]+-(\d+)(?:-(\d+))?")


def supports_temperature(model_name: str) -> bool:
    """Whether ``model_name`` accepts the ``temperature`` request parameter.

    Anthropic deprecated ``temperature`` for the reasoning tier from 4.7:
    verified empirically that opus-4-7 / opus-4-8 reject it with a 400, while
    opus-4-6-and-older and all sonnet/haiku (<=4-6) still accept it. We gate on
    version >= 4.7 across tiers — every model that is actually >4.6 today is a
    deprecated opus, and omitting ``temperature`` is harmless (the model falls
    back to its default) whereas sending it to a deprecated model is a hard 400,
    so we err toward omitting for >=4.7 (over-omitting a future tier that still
    accepts it costs nothing). The regex matches the ``claude-<tier>-<major>``
    core (with an optional ``-<minor>``; absent = 0, so the 5-family's
    single-number versions gate as (5, 0) — verified live: they 400 on
    ``temperature`` too) anywhere in the identifier, so Bedrock region
    prefixes (``us.anthropic.claude-opus-4-7``), bare Bedrock ids
    (``anthropic.claude-sonnet-5``) and dated snapshots
    (``claude-opus-4-7-20260301``) are handled. Non-claude / unparseable names
    keep ``temperature``.
    """
    m = _CLAUDE_VERSION_RE.search(model_name or "")
    if not m:
        return True
    major = int(m.group(1))
    minor = int(m.group(2)) if m.group(2) is not None else 0
    return (major, minor) < _TEMPERATURE_DEPRECATED_FROM


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

    def _log(v, d) -> None:
        logger.debug(
            "CC envelope: non-numeric cost/tokens value %r — using %r",
            v, d,
        )

    return to_float_safe(value, default=default, on_error=_log)


def _safe_int(value: Any, *, default: int) -> int:
    """Same as `_safe_float` for int conversion."""
    from core.llm.coerce import to_int_safe

    def _log(v, d) -> None:
        logger.debug(
            "CC envelope: non-int tokens value %r — using %r", v, d,
        )

    return to_int_safe(value, default=default, on_error=_log)


def _endpoint_display(api_base: str | None) -> str:
    """Loggable form of a provider ``api_base``.

    Loopback endpoints print verbatim (diagnostic, not sensitive);
    anything remote collapses to a placeholder so operator-private
    inference endpoints (e.g. a remote Ollama server selected via
    OLLAMA_HOST) never reach logs — the project invariant is that a
    remote endpoint location is never disclosed in code, comments,
    or logs.
    """
    if not api_base:
        return "default"
    from core.llm.egress import url_is_loopback
    return api_base if url_is_loopback(api_base) else "[REMOTE-ENDPOINT]"


def _redact_endpoint(text: str, api_base: str | None) -> str:
    """Strip a remote ``api_base``'s host from *text* before logging.

    SDK / httpx exception bodies routinely embed the request URL.
    For a loopback base that is harmless; for a remote base it would
    write the endpoint location into WARNING-level logs and
    ``error_message`` fields that flow into shareable reports (same
    invariant as :func:`_endpoint_display`). Replaces the netloc
    (host:port) first, then the bare hostname, so partial forms are
    caught too.
    """
    if not text or not api_base:
        return text
    from urllib.parse import urlsplit

    from core.llm.egress import url_is_loopback
    if url_is_loopback(api_base):
        return text
    try:
        parts = urlsplit(api_base if "://" in api_base else f"//{api_base}")
    except ValueError:
        return text
    for token in (parts.netloc, parts.hostname):
        if token:
            text = text.replace(token, "[REMOTE-ENDPOINT]")
    return text


# SDK availability flags (canonical source is detection.py).  Placed
# after the helpers above rather than in the top import block; the
# conditional SDK re-imports below depend on these flags at module
# scope.
from .detection import (  # noqa: E402 — deliberate placement, see comment above
    ANTHROPIC_SDK_AVAILABLE,
    GENAI_SDK_AVAILABLE,
    OPENAI_SDK_AVAILABLE,
)

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
    resolved_model: str | None = None


@dataclass
class StructuredResponse:
    """Response from generate_structured() with metadata.

    Iterable for backwards compatibility: result, raw = response
    """
    result: dict[str, Any]
    raw: str
    cost: float = 0.0
    tokens_used: int = 0
    model: str = ""
    provider: str = ""
    duration: float = 0.0
    cached: bool = False
    # Token split + prompt-cache counters. Populated by the provider
    # from the SDK response's per-call usage when available; the
    # LLMClient falls back to aggregate provider-counter deltas ONLY
    # when a provider returns no per-call figures (bare-tuple legacy
    # paths) — counter deltas are racy under parallel workers, so
    # they are best-effort: 0 when the provider surfaces no usage.
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0
    # Concrete model snapshot the provider served (see LLMResponse.resolved_model).
    resolved_model: str | None = None

    def __iter__(self):
        """Allow unpacking as 2-tuple for backwards compatibility."""
        return iter((self.result, self.raw))

    def as_pair(self) -> tuple[dict[str, Any], str]:
        """Explicit ``(result, raw)`` unwrap — the same pair the
        2-tuple compatibility unpack yields, without relying on
        ``__iter__`` at the call site."""
        return (self.result, self.raw)


def extract_resolved_model(raw: Any) -> str | None:
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
        except Exception:  # noqa: BLE001 — SDK response shims may raise anything
            value = None
        if isinstance(value, str) and value:
            return value
    return None


class LLMProvider(ABC):
    """Abstract base class for LLM providers."""

    def __init__(self, config: ModelConfig) -> None:
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
    def generate(self, prompt: str, system_prompt: str | None = None,
                 **kwargs) -> LLMResponse:
        """Generate completion from the model."""

    @abstractmethod
    def generate_structured(self, prompt: str, schema: dict[str, Any],
                           system_prompt: str | None = None,
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

    def prefers_stable_system_prefix(self) -> bool:
        """``True`` when composing run-stable material into the system
        prompt pays off on this transport.

        Distinct from :meth:`supports_prompt_caching`, which is about
        the *request API* (can the caller place cache_control
        breakpoints). A transport can lack that API yet still benefit
        from byte-stable system prompts because its backend does
        server-side prefix caching — the claudecode subprocess is the
        canonical case. Default: same answer as
        ``supports_prompt_caching`` (a cache-breakpoint API implies
        stable prefixes pay off)."""
        return self.supports_prompt_caching()

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
        if (
            in_per_m == 0.0 and out_per_m == 0.0
            and (response.input_tokens or response.output_tokens)
            and self.config.model_name not in _ZERO_PRICE_WARNED
        ):
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
        system: str | None = None,
        max_tokens: int = 4096,
        cache_control: CacheControl = _DEFAULT_CACHE_CONTROL,
        **provider_specific: Any,
    ) -> TurnResponse:
        """Send one round-trip with tool/function-call schemas.

        Default implementation raises ``NotImplementedError`` —
        providers that can do tool-use override this method. Callers
        that need to gate behaviour use :meth:`supports_tool_use`.
        """
        msg = (
            f"{type(self).__name__} does not support tool-use; "
            f"check ``supports_tool_use()`` before calling ``turn()``"
        )
        raise NotImplementedError(msg)

    def supports_streaming(self) -> bool:
        """``True`` when ``turn_stream()`` yields real-time chunks
        from the provider's API rather than wrapping ``turn()``."""
        return False

    def turn_stream(
        self,
        messages: Sequence[Message],
        tools: Sequence[ToolDef],
        *,
        system: str | None = None,
        max_tokens: int = 4096,
        cache_control: CacheControl = _DEFAULT_CACHE_CONTROL,
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
        from .model_data import resolve_model_costs
        # Same four-step normalisation chain as ``context_window_for``:
        # exact -> dated alias -> bedrock strip -> both. Pre-fix the
        # bedrock steps were missing here, so a Bedrock-form id
        # (``anthropic.claude-mythos-5``) resolved limits but NOT
        # rates and fell into the $0 unknown-model path — budget caps
        # silently unenforced for every Bedrock-routed model.
        rates = resolve_model_costs(self.config.model_name)
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
    _warned_unknown_models: ClassVar[set] = set()
    _warned_unknown_models_lock = threading.Lock()

    @classmethod
    def _warn_unknown_model_once(cls, model_name: str) -> None:
        with cls._warned_unknown_models_lock:
            if model_name in cls._warned_unknown_models:
                return
            cls._warned_unknown_models.add(model_name)
        logger.warning(
            "cost tracking: model %r not in MODEL_COSTS and no cost_per_1k_tokens set — every call records $0. Budget caps based on cumulative cost are NOT enforced for this model. Add a rate to model_data.MODEL_COSTS or pass cost_per_1k_tokens to the LLMConfig.", model_name
        )

    def _init_instructor(self, make_client) -> None:
        """Shared Instructor wiring for SDK-backed providers.

        ``make_client`` builds the instructor-wrapped client when the
        library is installed; otherwise structured output uses the
        JSON-in-prompt fallback (warned once at construction).
        """
        self.instructor_client = None
        self._instructor_consec_failures = 0
        self._instructor_lock = threading.Lock()
        if INSTRUCTOR_AVAILABLE:
            self.instructor_client = make_client()
        else:
            logger.warning(
                "Instructor not installed — structured output will use JSON-in-prompt fallback. "
                "For more reliable structured output: pip install instructor"
            )

    def _note_instructor_success(self) -> None:
        """Reset the consecutive-failure counter after a good call."""
        with self._instructor_lock:
            self._instructor_consec_failures = 0

    def _note_instructor_failure(self, exc: Exception) -> None:
        """Count a consecutive Instructor failure; disable at the cap.

        A single transient error (dispatcher startup race, network
        hiccup) must not kill Instructor for the session — only
        ``_INSTRUCTOR_MAX_CONSEC_FAILURES`` in a row do. The disable
        is permanent for this provider instance: callers fall back to
        JSON-in-prompt for the rest of the session (there is no
        re-enable/backoff mechanism).
        """
        with self._instructor_lock:
            self._instructor_consec_failures += 1
            consec = self._instructor_consec_failures
        # redact_secrets + endpoint scrub, not just escape: this
        # funnel catches bare SDK exceptions whose bodies can echo
        # Authorization / x-api-key headers, the prompt, and the
        # request URL — same treatment as the generate() handlers.
        from core.security.log_sanitisation import escape_nonprintable as _esc
        from core.security.redaction import redact_secrets as _redact
        detail = _esc(_redact(_redact_endpoint(
            str(exc), getattr(self.config, "api_base", None),
        )))[:512]
        logger.warning(
            "Instructor structured generation failed for %s/%s (%d/%d). "
            "Exception (%s): %s",
            self.config.provider, self.config.model_name,
            consec, _INSTRUCTOR_MAX_CONSEC_FAILURES,
            type(exc).__name__, detail,
        )
        if consec >= _INSTRUCTOR_MAX_CONSEC_FAILURES:
            logger.warning(
                "Instructor disabled for %s/%s after %d consecutive failures",
                self.config.provider, self.config.model_name,
                consec,
            )
            self.instructor_client = None

    @staticmethod
    def _instructor_exception_route(exc: Exception) -> str:
        """Route an instructor-funnel failure by the failure taxonomy.

        Returns ``"fallback"`` when the JSON-in-prompt fallback is a
        sensible next step (shape/library failures — a different
        sampling may succeed), or a boundary label (``"blocked"``,
        ``"auth"``, ``"quota"``) for failures where instantly
        re-sending the SAME payload is wasteful or harmful:

        - refusals / content-filter blocks: a model boundary — an
          identical re-send cannot change the outcome and burns money
        - auth errors (401/403): every re-send fails identically
        - rate limits (429): the client's retry loop applies backoff;
          an instant fallback re-send hammers the limiter with zero
          backoff

        Boundary failures re-raise to the client's retry policy and do
        NOT count toward the instructor-disable strike counter — they
        say nothing about instructor's reliability.
        """
        from core.llm.structured_call import (
            is_auth_error_text,
            is_content_filter_text,
        )
        text = str(exc)
        if is_content_filter_text(text):
            return "blocked"
        type_name = type(exc).__name__
        lowered = text.lower()
        # Quota before auth: AUTH_KEYWORDS_RE deliberately covers
        # billing vocabulary ("quota", "rate limit"), so the
        # rate-limit check must win for the label to be honest.
        if (
            getattr(exc, "status_code", None) == 429
            or "RateLimitError" in type_name
            or "429" in text
            or "rate limit" in lowered
            or ("quota" in lowered and "exceeded" in lowered)
        ):
            return "quota"
        if "AuthenticationError" in type_name or is_auth_error_text(text):
            return "auth"
        return "fallback"

    def _book_instructor_failure_usage(
        self, exc: Exception, duration: float,
    ) -> None:
        """Book the spend of a failed instructor call.

        A pydantic-validation failure happens AFTER a completed (paid)
        API generation; instructor attaches the last completion to its
        retry exceptions. Without this, the failed attempt's spend
        reached neither ledger — the client books nothing on failure
        and relies on the provider ledger as the failed-attempt floor.
        Handles both OpenAI- and Anthropic-shaped usage objects; never
        raises.
        """
        try:
            completion = getattr(exc, "last_completion", None)
            usage = getattr(completion, "usage", None)
            if usage is None:
                return
            input_tokens = getattr(usage, "prompt_tokens", None)
            if input_tokens is None:
                input_tokens = getattr(usage, "input_tokens", 0)
            output_tokens = getattr(usage, "completion_tokens", None)
            if output_tokens is None:
                output_tokens = getattr(usage, "output_tokens", 0)
            input_tokens = int(input_tokens or 0)
            output_tokens = int(output_tokens or 0)
            if input_tokens <= 0 and output_tokens <= 0:
                return
            cost = self._calculate_cost_split(input_tokens, output_tokens, 0)
            self.track_usage(
                input_tokens + output_tokens, cost,
                input_tokens, output_tokens, duration,
            )
        except Exception as book_exc:  # noqa: BLE001 — best-effort booking
            logger.debug(
                "instructor failure usage booking skipped: %s", book_exc,
            )

    def _structured_fallback(self, prompt: str, schema: dict[str, Any],
                             pydantic_model, system_prompt: str | None = None,
                             timeout_s: float | None = None,
                             ) -> StructuredResponse:
        """
        Universal fallback: ask for JSON in the prompt, validate
        with Pydantic. Works with any LLM that can produce JSON.
        Usage is tracked by self.generate() — no double counting.
        ``timeout_s`` is the caller's per-call ceiling, forwarded to
        ``generate`` (providers without per-request timeout support
        ignore it there).
        """
        schema_json = dumps_display(schema)
        schema_block = (
            f"\n\n## Output format\n"
            f"Respond with JSON matching this schema:\n"
            f"```json\n{schema_json}\n```\n"
            f"Return ONLY valid JSON, no other text."
        )
        augmented_system = (
            (system_prompt or "") + schema_block
        )
        response = self.generate(prompt, augmented_system, timeout_s=timeout_s)
        if response.finish_reason in ("max_tokens", "length"):
            # RuntimeError, not json.JSONDecodeError: the client's
            # retry loop treats JSON decode failures as retryable, but
            # an identical retry at the same max_tokens re-truncates
            # deterministically — up to max_retries paid calls for the
            # same guaranteed failure. Non-retryable, matching the
            # Gemini native structured truncation guard. The message
            # keeps the "truncated (output token limit" phrasing the
            # audit orchestrator's _classify_error keys on.
            msg = (
                "Response truncated (output token limit reached, "
                f"finish_reason={response.finish_reason})"
            )
            raise RuntimeError(msg)
        try:
            # Strip markdown fences via the shared hardened helper.
            # It prefers the LAST fenced JSON block, defeating
            # prepend-prefix injection where attacker-influenced
            # prompt content coaxes the model into echoing a fake
            # fenced block before its real answer — the inline copy
            # this replaces kept the weaker first-block behaviour
            # (see strip_json_fences' docstring).
            content = strip_json_fences(response.content.strip()).strip()
            parsed = json.loads(content)
            parsed = _coerce_to_schema(parsed, _normalize_schema(schema))
            validated = pydantic_model.model_validate(parsed)
            result_dict = validated.model_dump()
            # Carry the resolved model AND the per-call usage from the
            # underlying generate() call so the JSON-fallback path
            # attributes correctly too (usage was tracked by
            # self.generate() — surfacing it here adds no double
            # counting; the client stops diffing shared aggregate
            # counters when per-call figures are present).
            return StructuredResponse(
                result=result_dict,
                raw=json.dumps(result_dict, indent=2),
                cost=response.cost,
                tokens_used=response.tokens_used,
                duration=response.duration,
                input_tokens=response.input_tokens,
                output_tokens=response.output_tokens,
                cache_read_tokens=response.cache_read_tokens,
                cache_write_tokens=response.cache_write_tokens,
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
                "Structured fallback failed (JSON parse or validation): %s", _safe_msg
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
        system: str | None = None,
        max_tokens: int = 4096,
        cache_control: CacheControl = _DEFAULT_CACHE_CONTROL,
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
            schema_json = dumps_display(t.input_schema)
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
                        f"with input {dumps_display(block.input, indent=None)}"
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
    ) -> tuple[TextBlock | ToolCall, StopReason]:
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


def _coerce_to_schema(data: dict[str, Any], schema: dict[str, Any]) -> dict[str, Any]:
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


def _normalize_schema(schema: dict[str, Any]) -> dict[str, Any]:
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
            # "null or string" — the type is the token after "null or",
            # i.e. parts[2] (parts[1] is always the literal "or")
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


def _schema_to_gemini(schema: dict[str, Any]) -> dict[str, Any]:
    """Convert JSON Schema to Gemini-compatible schema.

    The google-genai SDK rejects nullable union types like ["string", "null"].
    Gemini expects single type strings ("STRING") with a separate "nullable" flag.
    """
    TYPE_MAP = {
        "string": "STRING", "number": "NUMBER", "integer": "INTEGER",
        "boolean": "BOOLEAN", "array": "ARRAY", "object": "OBJECT", "null": "NULL",
    }

    def convert_property(prop: dict[str, Any]) -> dict[str, Any]:
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


def _dict_schema_to_pydantic(schema: dict[str, Any] | type['BaseModel'], _model_name: str = 'DynamicSchema'):
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
        msg = (
            f"Schema must be dict or Pydantic BaseModel class, "
            f"got {type(schema).__name__}"
        )
        raise ValueError(msg)  # noqa: TRY004 — callers catch ValueError; changing type breaks them

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
            python_type = list[item_type]
        else:
            python_type = type_map.get(field_type, str)

        if nullable:
            python_type = python_type | None

        # Get default value if present
        default_value = field_spec.get("default", ...)

        # Determine if field is required:
        # - If schema has "required" key: only those fields are required
        # - If no "required" key: all fields optional (JSON Schema default;
        #   LLMs routinely omit sub-fields of optional nested objects)
        is_required = has_required_key and (field_name in required_fields)

        # If field is not required and has no default, make it Optional
        if not is_required and default_value is ...:
            python_type = python_type | None
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
    return create_model(_model_name, **field_definitions)


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
    temperature: float | None = None,
) -> dict[str, Any]:
    """Return the correct token-limit (+ optional temperature) kwargs for an
    OpenAI chat.completions call, branching on the reasoning-model contract.

    Reasoning models → ``max_completion_tokens`` and NO temperature (default
    only). Classic models → ``max_tokens`` and the requested temperature.
    """
    if _is_openai_reasoning_model(model_name):
        return {"max_completion_tokens": max_tokens}
    kw: dict[str, Any] = {"max_tokens": max_tokens}
    if temperature is not None:
        kw["temperature"] = temperature
    return kw


class OpenAICompatibleProvider(LLMProvider):
    """
    LLM provider using the OpenAI SDK.

    Works with any OpenAI-compatible API: OpenAI, Ollama, vLLM, LM Studio,
    Gemini (via OpenAI compat), Mistral, etc.
    """

    def __init__(self, config: ModelConfig) -> None:
        super().__init__(config)
        if not OPENAI_SDK_AVAILABLE:
            msg = "OpenAI SDK not installed. Run: pip install openai"
            raise ImportError(msg)

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
            # Loopback gateways (Ollama, vLLM, LM Studio): the SDK's
            # default httpx client honours proxy env (trust_env), so
            # on mandatory-proxy hosts whose NO_PROXY lacks loopback,
            # every localhost call detours through the corporate
            # proxy and fails. Pin a trust_env=False transport for
            # loopback bases; remote bases keep proxy-env behaviour.
            # Both get the pooled transport (see core.llm.http_pool)
            # so idle keepalive outlives the inter-call gap.
            from core.llm.egress import url_is_loopback
            from core.llm.http_pool import sdk_http_client
            _loopback = bool(
                config.api_base and url_is_loopback(config.api_base)
            )
            self.client = OpenAI(
                api_key=config.api_key or "unused",
                base_url=config.api_base,
                timeout=config.timeout,
                # RAPTOR's own retry loops (LLMClient.generate /
                # generate_structured, the provider turn() loops) are
                # the single retry authority. The SDK default
                # (max_retries=2) stacks multiplicatively under them —
                # up to 3x the attempts per logical call, each burning
                # a full read timeout during an upstream brownout.
                max_retries=0,
                http_client=sdk_http_client(
                    config.timeout, trust_env=not _loopback,
                ),
            )
            logger.debug(
                "OpenAICompatibleProvider: direct SDK (no dispatcher) provider=%s", config.provider
            )

        self._init_instructor(lambda: instructor.from_openai(self.client))

        # Flips on first detection that this provider's bound model
        # rejects function-calling (older Ollama models, smaller
        # Mistrals, custom finetunes, vLLM-served models without
        # tool support, etc.). Subsequent ``turn()`` calls then go
        # straight to the JSON-protocol synthesis fallback rather
        # than wasting another round-trip. Per-instance, not
        # persisted — a fresh process re-detects on first turn.
        self._tool_use_unsupported = False

        # _endpoint_display, never the raw api_base: with OLLAMA_HOST
        # pointed at a remote inference server, the raw value would
        # write that server's location into the debug log.
        logger.debug(
            "Initialized OpenAICompatibleProvider: %s (base_url=%s)",
            config.model_name, _endpoint_display(config.api_base),
        )

    def generate(self, prompt: str, system_prompt: str | None = None,
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
                msg = "OpenAI returned empty choices"
                raise RuntimeError(msg)
            message = response.choices[0].message
            content = message.content or ""
            # Ollama thinking models (qwen3, etc.) put responses in reasoning_content
            if not content:
                content = getattr(message, 'reasoning_content', '') or ""
            finish_reason = response.choices[0].finish_reason or "complete"

            # Detect content filter blocks and model refusals
            refusal = getattr(message, 'refusal', None)
            if refusal:
                msg = f"Model refused request: {refusal}"
                raise RuntimeError(msg)
            if finish_reason == "content_filter":
                if not content:
                    msg = (
                        "Response blocked by content filter. "
                        "This typically happens with exploit code or attack scenario prompts."
                    )
                    raise RuntimeError(msg)
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
                         f", thinking={thinking_tokens}" if thinking_tokens else "")

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
            # available with ``-v`` / RAPTOR_LOG_FILE_LEVEL=DEBUG without
            # spamming normal runs.
            logger.debug(
                "OpenAI completion failed: %s",
                escape_nonprintable(redact_secrets(_redact_endpoint(
                    str(e), self.config.api_base,
                )))[:1024],
            )
            raise

    def generate_structured(self, prompt: str, schema: dict[str, Any],
                           system_prompt: str | None = None,
                           **kwargs) -> StructuredResponse:
        """Generate structured output using Instructor (or JSON fallback)."""
        pydantic_model = _dict_schema_to_pydantic(schema)
        # Honour caller-supplied temperature so DispatchTask's
        # `temperature = 0.2` (analysis), `0.3` (consensus), etc.
        # actually reach the API. Falls back to configured default.
        temperature = kwargs.get("temperature", self.config.temperature)

        # Try Instructor first (skip for Anthropic via OpenAI-compat — response_format is ignored)
        is_anthropic_compat = self.config.provider.lower() == "anthropic"
        if self.instructor_client is not None and not is_anthropic_compat:
            t_start = time.monotonic()
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

                self._note_instructor_success()
                # Per-call usage rides on the response — the client's
                # aggregate-counter before/after diff multiply-books
                # concurrent calls' spend under parallel workers (see
                # the Anthropic provider's identical note).
                return StructuredResponse(
                    result=result_dict,
                    raw=full_response,
                    cost=cost,
                    tokens_used=tokens_used,
                    duration=duration,
                    input_tokens=input_tokens,
                    output_tokens=output_tokens,
                    cache_read_tokens=cache_read_tokens,
                    resolved_model=extract_resolved_model(completion),
                )

            except Exception as e:
                # A completed-but-invalid generation still spent money.
                self._book_instructor_failure_usage(
                    e, time.monotonic() - t_start)
                route = self._instructor_exception_route(e)
                if route != "fallback":
                    # Boundary failure (blocked/auth/quota): re-sending
                    # the same payload via the JSON fallback is wasteful
                    # (auth/refusal fail identically; 429 needs the
                    # client's backoff, not an instant re-send). Not an
                    # instructor strike either.
                    logger.info(
                        "Instructor failure routed to caller (%s) for "
                        "%s/%s — skipping JSON fallback re-send",
                        route, self.config.provider, self.config.model_name,
                    )
                    raise
                self._note_instructor_failure(e)

        # Fallback: JSON-in-prompt
        return self._structured_fallback(prompt, schema, pydantic_model, system_prompt, timeout_s=kwargs.get("timeout_s"))

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
        system: str | None = None,
        max_tokens: int = 4096,
        cache_control: CacheControl = _DEFAULT_CACHE_CONTROL,
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
                "OpenAICompatibleProvider.turn: ignoring unrecognised kwargs: %s", sorted(_unused)
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
        tool_schemas: list[dict[str, Any]] = [
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
        wire_messages: list[dict[str, Any]] = []
        if system:
            wire_messages.append({"role": "system", "content": system})
        for m in messages:
            wire_messages.extend(_message_to_openai_wire(m))

        # ---- dispatch (with retry on transient errors) ---------------
        kwargs: dict[str, Any] = {
            "model": self.config.model_name,
            "messages": wire_messages,
            **_openai_sampling_kwargs(self.config.model_name, max_tokens),
        }
        if tool_schemas:
            kwargs["tools"] = tool_schemas

        from openai import (  # type: ignore[import-not-found]
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
                    # Same sanitisation as the terminal-error path
                    # below — this WARNING also interpolates a raw
                    # SDK exception body.
                    from core.security.log_sanitisation import (
                        escape_nonprintable as _esc,
                    )
                    from core.security.redaction import (
                        redact_secrets as _redact,
                    )
                    logger.warning(
                        "OpenAICompatibleProvider.turn: model %r rejected "
                        "tools — falling back to JSON-protocol synthesis "
                        "for this provider instance: %s",
                        self.config.model_name,
                        _esc(_redact(_redact_endpoint(
                            str(exc), self.config.api_base,
                        )))[:512],
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
                    # redact_secrets + endpoint scrub too: APIError
                    # bodies may echo Authorization / x-api-key
                    # headers, the prompt, and the request URL —
                    # symmetric with the generate() handler.
                    from core.security.log_sanitisation import escape_nonprintable
                    from core.security.redaction import redact_secrets
                    err_msg = (
                        f"{kind} error after {attempt + 1} attempt(s): "
                        f"{escape_nonprintable(redact_secrets(_redact_endpoint(str(exc), self.config.api_base)))}"
                    )
                    logger.warning("OpenAICompatibleProvider.turn: %s", err_msg)
                    return TurnResponse(
                        content=[],
                        stop_reason=StopReason.ERROR,
                        input_tokens=0,
                        output_tokens=0,
                        error_message=err_msg,
                    )
                delay = (backoff_factor ** attempt) * (0.5 + random.random())
                from core.security.log_sanitisation import escape_nonprintable
                from core.security.redaction import redact_secrets
                logger.info(
                    "OpenAICompatibleProvider.turn: transient error attempt "
                    "%d, retrying in %.1fs: %s",
                    attempt + 1, delay,
                    escape_nonprintable(redact_secrets(_redact_endpoint(
                        str(exc), self.config.api_base,
                    )))[:512],
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
        system: str | None = None,
        max_tokens: int = 4096,
        cache_control: CacheControl = _DEFAULT_CACHE_CONTROL,
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
        tool_schemas: list[dict[str, Any]] = [
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
        wire_messages: list[dict[str, Any]] = []
        if system:
            wire_messages.append({"role": "system", "content": system})
        for m in messages:
            wire_messages.extend(_message_to_openai_wire(m))

        # ---- dispatch with stream=True -----------------------------------
        kwargs: dict[str, Any] = {
            "model": self.config.model_name,
            "messages": wire_messages,
            "stream": True,
            # Without include_usage the OpenAI streaming API sends NO
            # usage payload at all — every streamed turn recorded zero
            # tokens/cost. Providers that reject the option (older
            # vLLM/Ollama builds) get it dropped + retried below.
            "stream_options": {"include_usage": True},
            **_openai_sampling_kwargs(self.config.model_name, max_tokens),
        }
        if tool_schemas:
            kwargs["tools"] = tool_schemas

        from openai import (  # type: ignore[import-not-found]
            APIConnectionError,
            APIStatusError,
        )
        t_start = time.monotonic()
        resp = None
        for attempt in range(max_retries + 1):
            try:
                resp = self.client.chat.completions.create(**kwargs)
                break
            except TypeError as exc:
                # SDK old enough not to know ``stream_options`` —
                # drop it and retry; usage stays zero for this
                # provider (warned once).
                if ("stream_options" in kwargs
                        and "stream_options" in str(exc)):
                    kwargs.pop("stream_options")
                    _warn_stream_options_unsupported_once(
                        self.config.provider, self.config.model_name,
                    )
                    continue
                raise
            except (APIConnectionError, APIStatusError) as exc:
                if (
                    "stream_options" in kwargs
                    and isinstance(exc, APIStatusError)
                    and "stream_options" in str(exc)
                ):
                    # Endpoint rejects include_usage (older
                    # vLLM/Ollama). Drop it and retry immediately —
                    # zero-usage streaming beats a dead stream; warn
                    # once per provider:model so the operator knows
                    # streamed cost is untracked there.
                    kwargs.pop("stream_options")
                    _warn_stream_options_unsupported_once(
                        self.config.provider, self.config.model_name,
                    )
                    continue
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
                    # redact_secrets + endpoint scrub, not just
                    # escape — same SDK exception class as turn()
                    # above (header/prompt/URL echo).
                    from core.security.log_sanitisation import (
                        escape_nonprintable,
                    )
                    from core.security.redaction import redact_secrets
                    logger.warning(
                        "OpenAICompatibleProvider.turn_stream: %s",
                        escape_nonprintable(redact_secrets(_redact_endpoint(
                            str(exc), self.config.api_base,
                        )))[:512],
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
        tool_calls_seen: dict[int, str] = {}
        input_tokens = output_tokens = 0
        stop = StopReason.ERROR

        try:
            for chunk in resp:
                # include_usage delivers usage on a final empty-choices
                # chunk; some compat servers attach it to the last
                # content chunk instead — read it wherever it appears.
                usage = getattr(chunk, "usage", None)
                if usage:
                    input_tokens = (
                        getattr(usage, "prompt_tokens", 0) or 0
                    )
                    output_tokens = (
                        getattr(usage, "completion_tokens", 0) or 0
                    )
                if not chunk.choices:
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

# Warn once per provider:model when an OpenAI-compat endpoint rejects
# ``stream_options.include_usage`` — streamed turns there report zero
# usage, so the operator should know cost tracking has a hole rather
# than seeing a warning flood.
_STREAM_OPTIONS_UNSUPPORTED_WARNED: set[str] = set()
_stream_options_warned_lock = threading.Lock()


def _warn_stream_options_unsupported_once(provider: str, model: str) -> None:
    key = f"{provider}:{model}"
    with _stream_options_warned_lock:
        if key in _STREAM_OPTIONS_UNSUPPORTED_WARNED:
            return
        _STREAM_OPTIONS_UNSUPPORTED_WARNED.add(key)
    logger.warning(
        "%s rejects stream_options.include_usage — streamed turns for "
        "%s report zero usage (cost untracked on this transport)",
        provider, model,
    )


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
    from openai import (  # type: ignore[import-not-found]
        APIConnectionError,
        APIStatusError,
    )
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
    from openai import APIStatusError  # type: ignore[import-not-found]
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
    return any(
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


def _message_to_openai_wire(m: Message) -> list[dict[str, Any]]:
    r"""One :class:`Message` → 1+ OpenAI wire dicts.

    OpenAI splits user messages with multiple :class:`ToolResult`\ s
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
        tool_calls: list[dict[str, Any]] = []
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
        out: dict[str, Any] = {"role": "assistant"}
        if text_parts:
            out["content"] = "".join(text_parts)
        if tool_calls:
            out["tool_calls"] = tool_calls
        if not text_parts and not tool_calls:
            out["content"] = ""
        return [out]
    # user role
    out_msgs: list[dict[str, Any]] = []
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


_STREAM_TRANSPORT_ENV = "RAPTOR_LLM_STREAM_TRANSPORT"


def _stream_transport_enabled() -> bool:
    """Opt-in: carry non-streaming Anthropic calls over the SDK's
    streaming transport (``messages.stream`` +
    ``get_final_message()`` — the identical ``Message`` object a
    plain ``create`` returns, so downstream parsing is unchanged).

    Why an operator would want it: a corporate proxy that applies an
    idle timer to relayed bytes kills tunnels that go quiet, and a
    thinking model is silent for minutes on a non-streamed call. SSE
    keeps bytes flowing for the whole generation, so the tunnel never
    looks idle — the fix TCP keepalive cannot provide (probes are not
    tunnel payload).

    Off by default, deliberately: flipping transports based on
    detected network topology would make proxied hosts silently
    exercise different code paths than direct hosts. The operator
    opts in per-deployment.
    """
    return os.environ.get(_STREAM_TRANSPORT_ENV, "").strip().lower() in (
        "1", "true", "yes", "on",
    )


# Per-call streaming opt-in (``generate_structured(..., stream=True)``).
# The env knob above is deliberately topology-neutral; this is the
# complementary CALLER-side justification — the caller knows its
# response is long (study batches, contract audits), which no amount
# of network sniffing can. Thread-local because the instructor path
# reaches the SDK through the rebound ``messages.create`` several
# frames below the call that opted in, and reviews run in parallel
# worker threads. Set/cleared around one synchronous provider call.
_STREAM_OVERRIDE = threading.local()


def _stream_override_active() -> bool:
    return bool(getattr(_STREAM_OVERRIDE, "on", False))


def _streamify_messages_create(client) -> None:
    """Extend the opt-in streaming transport to ``messages.create``
    callers on this client instance.

    ``generate()``/``turn()`` check ``_stream_transport_enabled()``
    themselves, but instructor's structured generation calls
    ``messages.create`` directly on the wrapped SDK client — the one
    call class large enough to hit upstream's non-streaming
    long-request abort (structured study batches on a thinking model
    generate for longer than the ~10-minute ceiling). Rebinding
    ``create`` here, BEFORE ``instructor.from_anthropic`` wraps it,
    carries that leg over ``messages.stream`` +
    ``get_final_message()`` — the identical ``Message`` object, so
    instructor's parsing/validation is unchanged.

    The env gate is evaluated per call, not at patch time, so the
    rebind is inert while the knob is off and long-lived clients
    honour knob changes. Never applied to SSE-incapable surfaces
    (Bedrock runtime/InvokeModel — see the construction-time warning).
    """
    messages = client.messages
    real_create = messages.create
    real_stream = messages.stream

    def _create_via_stream_transport(**kw):
        kw.pop("stream", None)
        if not (_stream_override_active() or _stream_transport_enabled()):
            return real_create(**kw)
        with real_stream(**kw) as _stream:
            return _stream.get_final_message()

    messages.create = _create_via_stream_transport


class AnthropicProvider(LLMProvider):
    """
    LLM provider using the Anthropic SDK.

    Native support for Claude models with proper system message handling
    and token counting.
    """

    def __init__(self, config: ModelConfig) -> None:
        super().__init__(config)
        if not ANTHROPIC_SDK_AVAILABLE:
            msg = "Anthropic SDK not installed. Run: pip install anthropic"
            raise ImportError(msg)

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
            from core.llm.http_pool import sdk_http_client
            self.client = anthropic.Anthropic(
                api_key=config.api_key,
                timeout=config.timeout,
                # RAPTOR's own retry loops (LLMClient.generate /
                # generate_structured, turn()'s transient-error loop)
                # are the single retry authority. The SDK default
                # (max_retries=2) stacks multiplicatively under them —
                # up to 3x the attempts per logical call, each burning
                # a full read timeout during an upstream brownout.
                max_retries=0,
                # Pooled transport whose idle keepalive outlives the
                # inter-call gap — the SDK default expires idle
                # connections after 5s, forcing a reconnect (and,
                # behind chained proxies, CONNECT negotiation per
                # hop) on nearly every call. See core.llm.http_pool.
                http_client=sdk_http_client(config.timeout),
            )
            logger.debug("AnthropicProvider: direct SDK (no dispatcher)")

        # Repair instructor's reask assembly before first use: a
        # completion carrying PARALLEL tool_use blocks otherwise
        # retries with unpaired ids and dies on a 400 (see
        # core.llm.instructor_reask).
        from core.llm.instructor_reask import ensure_anthropic_reask_pairing
        ensure_anthropic_reask_pairing()
        # Must precede from_anthropic so instructor wraps the
        # transport-aware ``create``.
        _streamify_messages_create(self.client)
        self._init_instructor(lambda: instructor.from_anthropic(self.client))

        # SSE capability for the per-call streaming opt-in. True for
        # the Anthropic API and the dispatcher's mantle route; the
        # Bedrock builder clears it on the runtime (InvokeModel)
        # surface, which has no SSE.
        self._stream_sse_ok = True

        # Per-instance flag: have we warned about silent cache-failure
        # for this model? Warns once per provider instance to avoid
        # spam, since the silent-failure is a model-level property
        # (claude-opus-4-5 and claude-opus-4-6 verified non-caching as
        # of 2026-05-04 — Anthropic accepts the cache_control marker
        # but doesn't honor it). See ``_maybe_warn_silent_cache_failure``.
        self._caching_warning_emitted = False

        logger.debug("Initialized AnthropicProvider: %s", config.model_name)

    def generate(self, prompt: str, system_prompt: str | None = None,
                 **kwargs) -> LLMResponse:
        """Generate completion using the Anthropic SDK."""
        messages = [{"role": "user", "content": prompt}]

        create_kwargs = {
            "model": self.config.model_name,
            "messages": messages,
            "max_tokens": kwargs.get("max_tokens", self.config.max_tokens),
        }
        # Per-call timeout ceiling. Call classes plumb ``timeout_s``
        # (REVIEW_TIMEOUT_S=480 for reviews, SHORT_CALL_TIMEOUT_S=120
        # for summaries) — previously only the claudecode transport
        # honoured it, so SDK calls ran at the client-level default
        # (120s): every deep-dive review needing >120s died in
        # 3 SDK attempts x 120s walls while its class ceiling said
        # 480. The SDK accepts a per-request ``timeout`` override.
        _timeout_s = kwargs.get("timeout_s")
        if _timeout_s:
            try:
                create_kwargs["timeout"] = float(_timeout_s)
            except (TypeError, ValueError):
                pass
        # Opus 4.7+ deprecated `temperature` (400 if sent); omit it for those.
        if supports_temperature(self.config.model_name):
            create_kwargs["temperature"] = kwargs.get("temperature", self.config.temperature)
        if system_prompt:
            create_kwargs["system"] = [{
                "type": "text",
                "text": system_prompt,
                "cache_control": {"type": "ephemeral"},
            }]

        # Per-call opt-in (``stream=True`` kwarg or the structured
        # path's thread-local) is gated on SSE capability — pipeline
        # callers opt in blind to the deployment's surface. The env
        # knob stays ungated: an operator who set it on a
        # non-streaming surface gets the documented loud 400, not a
        # silent transport downgrade.
        _call_stream = (
            (kwargs.get("stream") or _stream_override_active())
            and getattr(self, "_stream_sse_ok", True)
        )
        try:
            t_start = time.monotonic()
            if _call_stream or _stream_transport_enabled():
                with self.client.messages.stream(**create_kwargs) as _stream:
                    response = _stream.get_final_message()
            else:
                response = self.client.messages.create(**create_kwargs)
            duration = time.monotonic() - t_start

            # Extract text from response (guard against empty/non-text
            # content). Reasoning-tier models prepend thinking blocks —
            # the text block is not necessarily first, so take the
            # first block that HAS text rather than content[0].
            if not response.content:
                # Zero content blocks. The stop_reason says WHY, and
                # dropping it turned a diagnosable model boundary into
                # an opaque transport-looking failure (observed live:
                # a whole call class dying with "returned empty
                # content" while sibling classes succeeded on the
                # same route — no way to tell refusal from
                # truncation from the artifacts).
                stop = response.stop_reason or "unknown"
                if stop == "refusal":
                    # Hard refusal: the API ends the turn with
                    # stop_reason="refusal" and may return no content
                    # at all. Phrased with "model refused" so
                    # structured_call.classify_error_text buckets it
                    # 'blocked' and telemetry disposition reads
                    # "blocked" — a model boundary, not a transport
                    # failure; an identical retry cannot change it.
                    msg = (
                        "Anthropic model refused request "
                        "(stop_reason=refusal, empty content)"
                    )
                    raise RuntimeError(msg)
                if stop == "max_tokens":
                    msg = (
                        "Anthropic returned empty content with "
                        "stop_reason=max_tokens — output budget "
                        "exhausted before the first content block "
                        "(on reasoning-tier models thinking can "
                        "consume the entire budget)"
                    )
                    raise RuntimeError(msg)
                msg = (
                    f"Anthropic returned empty content "
                    f"(stop_reason={stop})"
                )
                raise RuntimeError(msg)
            text_block = next(
                (b for b in response.content if hasattr(b, 'text')), None,
            )
            if text_block is None:
                # `getattr` with default — pre-fix `first_block.type`
                # raised AttributeError mid-error-formatting if the
                # block lacked BOTH `text` AND `type` (a future SDK
                # shape change or unexpected response variant). The
                # AttributeError replaced the informative
                # "non-text content" message with a confusing
                # internal-state crash.
                block_types = ", ".join(
                    str(getattr(b, 'type', '<unknown>'))
                    for b in response.content
                )
                msg = (
                    f"Anthropic returned no text content block "
                    f"(got: {block_types}; stop_reason="
                    f"{response.stop_reason or 'unknown'})"
                )
                raise RuntimeError(msg)
            content = text_block.text
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

    def generate_structured(self, prompt: str, schema: dict[str, Any],
                           system_prompt: str | None = None,
                           **kwargs) -> StructuredResponse:
        """Generate structured output using Instructor (or JSON fallback).

        ``stream=True`` opts this one call onto the streaming
        transport (SSE-capable surfaces only): the caller knows its
        response is long — study batches on a thinking model exceed
        upstream's ~10-minute non-streaming abort — a justification
        the topology-neutral env knob cannot express. Scoped via a
        thread-local so both the instructor leg (which reaches the
        SDK through the rebound ``messages.create``) and the
        JSON-in-prompt fallback (which rides ``generate``) honour it.
        """
        _call_stream = (
            bool(kwargs.get("stream"))
            and getattr(self, "_stream_sse_ok", True)
        )
        if not _call_stream:
            return self._generate_structured_impl(
                prompt, schema, system_prompt=system_prompt, **kwargs)
        # Restore (not clear) on exit so a nested opted-in call cannot
        # switch the remainder of its outer call back to non-streaming.
        _prev = getattr(_STREAM_OVERRIDE, "on", False)
        _STREAM_OVERRIDE.on = True
        try:
            return self._generate_structured_impl(
                prompt, schema, system_prompt=system_prompt, **kwargs)
        finally:
            _STREAM_OVERRIDE.on = _prev

    def _generate_structured_impl(
            self, prompt: str, schema: dict[str, Any],
            system_prompt: str | None = None,
            **kwargs) -> StructuredResponse:
        pydantic_model = _dict_schema_to_pydantic(schema)
        # See OpenAI provider — caller-supplied temperature must
        # reach the API for DispatchTask's per-task temperatures
        # (analysis 0.2, consensus 0.3) to take effect.
        temperature = kwargs.get("temperature", self.config.temperature)

        # Try Instructor first
        if self.instructor_client is not None:
            t_start = time.monotonic()
            try:
                messages = [{"role": "user", "content": prompt}]

                create_kwargs = {
                    "model": self.config.model_name,
                    "response_model": pydantic_model,
                    "messages": messages,
                    # Per-call override honoured: callers cap
                    # structured generations (e.g. study batches) to
                    # stay inside non-streaming request limits — the
                    # config ceiling is the default, not a floor.
                    "max_tokens": kwargs.get(
                        "max_tokens", self.config.max_tokens),
                }
                # Per-call timeout ceiling (see ``generate``): without
                # it structured review calls ran at the client-level
                # default (120s) while their class ceiling said 480s —
                # the exact calls large enough to need instructor were
                # the ones the wall killed. Instructor forwards unknown
                # kwargs to the underlying SDK ``messages.create``.
                _timeout_s = kwargs.get("timeout_s")
                if _timeout_s:
                    try:
                        create_kwargs["timeout"] = float(_timeout_s)
                    except (TypeError, ValueError):
                        pass
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

                self._note_instructor_success()
                # Per-call usage rides on the response. The client
                # previously re-derived it by diffing the provider's
                # SHARED aggregate counters before/after the call —
                # under parallel workers that delta swallows every
                # concurrent call's spend and multiply-books the same
                # money (observed live: a $38 run enforced as $85+ and
                # terminated at 25/40 reviews). The exact figures are
                # computed right here; return them.
                return StructuredResponse(
                    result=result_dict,
                    raw=full_response,
                    cost=cost,
                    tokens_used=tokens_used,
                    duration=duration,
                    input_tokens=input_tokens,
                    output_tokens=output_tokens,
                    cache_read_tokens=cache_read_tokens,
                    cache_write_tokens=cache_write_tokens,
                    resolved_model=extract_resolved_model(completion),
                )

            except Exception as e:
                # A completed-but-invalid generation still spent money.
                self._book_instructor_failure_usage(
                    e, time.monotonic() - t_start)
                refusal = _instructor_refusal_stop(e)
                if refusal is not None:
                    # Hard refusal surfaced through the tool-use leg as
                    # empty tool args. Not instructor unreliability —
                    # don't count it toward the instructor-disable cap —
                    # and not retryable — don't re-send the same content
                    # via the JSON fallback. Phrased with "model
                    # refused" so classify_error_text buckets it
                    # 'blocked' (same contract as generate()'s
                    # empty-content refusal path).
                    msg = (
                        "Anthropic model refused request "
                        f"(stop_reason={refusal}, instructor tool-use "
                        "leg — tool args empty)"
                    )
                    raise RuntimeError(msg) from e
                route = self._instructor_exception_route(e)
                if route != "fallback":
                    # Boundary failure (blocked/auth/quota): see the
                    # OpenAI-shape funnel — no fallback re-send, no
                    # instructor strike.
                    logger.info(
                        "Instructor failure routed to caller (%s) for "
                        "%s/%s — skipping JSON fallback re-send",
                        route, self.config.provider, self.config.model_name,
                    )
                    raise
                self._note_instructor_failure(e)

        # Fallback: JSON-in-prompt
        return self._structured_fallback(prompt, schema, pydantic_model, system_prompt, timeout_s=kwargs.get("timeout_s"))

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
        system: str | None = None,
        max_tokens: int = 4096,
        cache_control: CacheControl = _DEFAULT_CACHE_CONTROL,
        anthropic_task_budget_beta: bool = False,
        anthropic_task_budget_tokens: int | None = None,
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
            msg = (
                "anthropic_task_budget_beta=True requires "
                "anthropic_task_budget_tokens=N (total token budget the "
                "model self-regulates against). Without it the beta "
                "endpoint accepts the request but no budget is enforced."
            )
            raise ValueError(msg)
        if _unused:
            logger.debug(
                "AnthropicProvider.turn: ignoring unrecognised kwargs: %s", sorted(_unused)
            )

        # ---- system block --------------------------------------------
        # Anthropic accepts a string OR a content list. Use the list
        # form when caching the system prompt so the cache_control
        # marker can attach to it; otherwise the simpler string form.
        system_arg: str | list | None
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
        tool_schemas: list[dict[str, Any]] = [
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
        kwargs: dict[str, Any] = {
            "model": self.config.model_name,
            "max_tokens": max_tokens,
            "messages": wire_messages,
            "tools": tool_schemas or None,
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

        from anthropic import (  # type: ignore[import-not-found]
            APIConnectionError,
            APIError,
            APIStatusError,
        )
        # Stream-transport opt-in never applies to the task-budget
        # beta — the beta endpoint is create-only (see turn_stream's
        # docstring for the same constraint on real streaming).
        use_stream_transport = (
            _stream_transport_enabled() and not anthropic_task_budget_beta
        )
        t_start = time.monotonic()
        for attempt in range(max_retries + 1):
            try:
                if use_stream_transport:
                    with self.client.messages.stream(
                        **send_kwargs,
                    ) as _stream:
                        resp = _stream.get_final_message()
                else:
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
                    # escape_nonprintable + redact_secrets — see
                    # OpenAICompatibleProvider.turn above for the
                    # rationale (APIError bodies may echo auth
                    # headers and the prompt).
                    from core.security.log_sanitisation import escape_nonprintable
                    from core.security.redaction import redact_secrets
                    err_msg = (
                        f"{kind} error after {attempt + 1} attempt(s): "
                        f"{escape_nonprintable(redact_secrets(_redact_endpoint(str(exc), self.config.api_base)))}"
                    )
                    logger.warning("AnthropicProvider.turn: %s", err_msg)
                    return TurnResponse(
                        content=[],
                        stop_reason=StopReason.ERROR,
                        input_tokens=0,
                        output_tokens=0,
                        error_message=err_msg,
                    )
                delay = (backoff_factor ** attempt) * (0.5 + random.random())
                from core.security.log_sanitisation import escape_nonprintable
                from core.security.redaction import redact_secrets
                # WARNING with cumulative elapsed, not INFO: during an
                # upstream brownout each attempt burns a full read
                # timeout, and at INFO the operator sees a silent stall
                # (observed: a 50-minute review-loop hang diagnosable
                # only by SIGTERM). Same level the OpenAI loop uses.
                logger.warning(
                    "AnthropicProvider.turn: transient error attempt "
                    "%d/%d (%.0fs elapsed), retrying in %.1fs: %s",
                    attempt + 1, max_retries + 1,
                    time.monotonic() - t_start, delay,
                    escape_nonprintable(redact_secrets(_redact_endpoint(
                        str(exc), self.config.api_base,
                    )))[:512],
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
            "AnthropicProvider: model %r did not populate cache fields on a turn with cache_control opt-in and %s input tokens — cache savings won't apply for requests this size. Common causes: (1) this model's de-facto cacheable-region minimum is higher than the documented 1024 tokens; (2) the cacheable subset (system + tools when those are opted in) is below the model's minimum even though total input is above 8192. Try a different model (claude-opus-4-7, claude-sonnet-4-5-20250929) or increase the cacheable region size. This warning fires once per provider instance.", self.config.model_name, response.input_tokens
        )
        self._caching_warning_emitted = True

    def supports_streaming(self) -> bool:
        return True

    def turn_stream(
        self,
        messages: Sequence[Message],
        tools: Sequence[ToolDef],
        *,
        system: str | None = None,
        max_tokens: int = 4096,
        cache_control: CacheControl = _DEFAULT_CACHE_CONTROL,
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
        system_arg: str | list | None
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
        tool_schemas: list[dict[str, Any]] = [
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
        kwargs: dict[str, Any] = {
            "model": self.config.model_name,
            "max_tokens": max_tokens,
            "messages": wire_messages,
            "tools": tool_schemas or None,
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
    from anthropic import (  # type: ignore[import-not-found]
        APIConnectionError,
        APIStatusError,
    )
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


def _message_to_anthropic_wire(m: Message) -> dict[str, Any]:
    r"""Our :class:`Message` → Anthropic wire dict.

    Anthropic accepts mixed content lists per turn — text, tool_use,
    and tool_result blocks all live in the same ``content`` array;
    role determines which subset is valid (assistant: text + tool_use;
    user: text + tool_result).

    Empty :class:`Message`\ s (``content=[]``) — which the loop can
    produce when a turn returns ``StopReason.ERROR`` with no blocks —
    are emitted as ``[{"type": "text", "text": ""}]`` so the wire
    shape stays valid if a caller resumes from a failed run.
    """
    out_content: list[dict[str, Any]] = []
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


def _attach_anthropic_cache_marker(message: dict[str, Any]) -> None:
    """Mutate ``message["content"][-1]`` in-place to carry a
    cache_control marker. Anthropic places the marker on the LAST
    block of a region to cache everything preceding it within that
    message."""
    if not message["content"]:
        return
    last = dict(message["content"][-1])
    last["cache_control"] = {"type": "ephemeral"}
    message["content"][-1] = last


def _pooled_gemini_http_options(timeout: float):
    """``HttpOptions`` carrying a pooled httpx client, or ``None``
    when this google-genai version has no ``httpx_client`` injection
    point.

    Feature-detected rather than version-pinned: ``httpx_client`` is
    the same field the dispatcher route relies on, but the direct
    route must keep working (with the SDK's own transport) on
    versions that predate it.
    """
    try:
        from google.genai.types import HttpOptions
    except ImportError:
        return None
    if "httpx_client" not in getattr(HttpOptions, "model_fields", {}):
        return None
    from core.llm.http_pool import sdk_http_client
    return HttpOptions(httpx_client=sdk_http_client(timeout))


class GeminiProvider(LLMProvider):
    """Native Google Gemini provider using the google-genai SDK.

    Advantages over the OpenAI-compatible shim:
    - Exposes thoughts_token_count for accurate cost tracking
    - Native schema-constrained JSON output (server-side grammar enforcement)
    - No dependency on Google's OpenAI compatibility layer

    Falls back to OpenAICompatibleProvider if google-genai is not installed.
    """

    def __init__(self, config: ModelConfig) -> None:
        super().__init__(config)
        if not GENAI_SDK_AVAILABLE:
            msg = "google-genai SDK not installed: pip install google-genai"
            raise RuntimeError(msg)

        import threading
        self._clients_lock = threading.Lock()
        # {thread_id: Client} — bounded by live-thread reaping.
        self._clients: dict[int, Any] = {}
        logger.debug(
            "Initialized GeminiProvider: %s", config.model_name
        )

        # Pre-build safety settings once.  RAPTOR is a security research
        # tool — Gemini's default safety filter for "dangerous content"
        # blocks exploit code, ASan crash reports, and vulnerability
        # analysis prompts.  Disable that single category so the model
        # can reason about the same material a human analyst would read.
        from google.genai.types import SafetySetting
        self._safety_settings = [
            SafetySetting(
                category="HARM_CATEGORY_DANGEROUS_CONTENT",
                threshold="BLOCK_NONE",
            ),
        ]

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
            from google.genai.types import HttpOptions

            from core.llm.dispatcher.client import (
                make_gemini_base_url,
            )
            # Thread the configured per-model timeout through to the
            # worker→dispatcher httpx client — Gemini thinking calls
            # routinely exceed the 60s httpx default it was pinned to.
            base_url, http_client = make_gemini_base_url(
                timeout=self.config.timeout,
            )
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
            # Pooled transport whose idle keepalive outlives the
            # inter-call gap (see core.llm.http_pool); falls back to
            # the SDK's own transport when this google-genai version
            # has no httpx_client injection point.
            _http_options = _pooled_gemini_http_options(
                self.config.timeout,
            )
            if _http_options is not None:
                new_client = _genai_module.Client(
                    api_key=self.config.api_key,
                    http_options=_http_options,
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

    def generate(self, prompt: str, system_prompt: str | None = None,
                 **kwargs) -> LLMResponse:
        """Generate completion using the native Gemini SDK."""
        config_kwargs = {
            "temperature": kwargs.get("temperature", self.config.temperature),
            "max_output_tokens": kwargs.get("max_tokens", self.config.max_tokens),
        }

        contents = [{"role": "user", "parts": [{"text": prompt}]}]
        config_kwargs["safetySettings"] = self._safety_settings
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
                # Surface prompt_feedback when available — it explains
                # why Gemini returned nothing (safety block, etc.).
                pf = getattr(response, 'prompt_feedback', None)
                pf_reason = ""
                if pf:
                    br = getattr(pf, 'block_reason', None)
                    if br:
                        pf_reason = f" (blocked: {br})"
                msg = f"Gemini returned empty response{pf_reason}"
                raise RuntimeError(msg)

            content = response.text or ""
            finish_reason = "complete"
            if response.candidates and response.candidates[0].finish_reason:
                fr = response.candidates[0].finish_reason
                finish_reason = getattr(fr, 'name', str(fr)).lower()

            # Gemini safety filters block exploit/attack content — detect and raise
            # so the caller sees a clear error rather than empty content
            if not content and finish_reason in ('safety', 'recitation', 'blocked', 'other'):
                msg = (
                    f"Gemini blocked response (finish_reason={finish_reason}). "
                    f"This typically happens with exploit code or attack scenario prompts."
                )
                raise RuntimeError(msg)

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

    def generate_structured(self, prompt: str, schema: dict[str, Any],
                           system_prompt: str | None = None,
                           **kwargs) -> StructuredResponse:
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
        config_kwargs["safetySettings"] = self._safety_settings
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
                msg = (
                    "Gemini native structured response truncated "
                    f"(finish_reason={finish_reason}, "
                    f"output_tokens={output_tokens})"
                )
                raise RuntimeError(msg)

            # Safety/prohibited-content block: empty text with a
            # blocking finish_reason previously fell through to
            # json.loads("") → JSONDecodeError → silent JSON-in-prompt
            # fallback re-send of the same payload (which usually
            # blocks again — double spend). Raise with the "blocked
            # response" phrasing so the failure classifies as blocked
            # (non-retryable, own disposition), matching generate().
            _blocked_reasons = (
                "safety", "recitation", "blocked", "prohibited_content",
                "other",
            )
            if not (response.text or "").strip() and (
                finish_reason in _blocked_reasons
            ):
                msg = (
                    f"Gemini blocked response (finish_reason="
                    f"{finish_reason}). This typically happens with "
                    f"exploit code or attack scenario prompts."
                )
                raise RuntimeError(msg)

            # Shared hardened fence-stripping (last-block preference
            # — see _structured_fallback for the injection rationale).
            content = strip_json_fences((response.text or "").strip()).strip()
            parsed = json.loads(content)
            if not parsed:
                msg = "Gemini returned empty object in structured mode"
                raise ValueError(msg)
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
            # Schema/parsing error — native mode incompatible, fall back
            # to JSON-in-prompt. Sanitise before logging: the rendered
            # exception can embed the model's raw output (control
            # bytes / secret-shaped tokens) — same funnel class as the
            # _structured_fallback handler.
            from core.security.log_sanitisation import escape_nonprintable
            from core.security.redaction import redact_secrets
            logger.warning(
                "Gemini native structured generation failed (falling back): %s",
                escape_nonprintable(redact_secrets(str(e)))[:512],
            )
            return self._structured_fallback(prompt, schema, pydantic_model, system_prompt, timeout_s=kwargs.get("timeout_s"))
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
        system: str | None = None,
        max_tokens: int = 4096,
        cache_control: CacheControl = _DEFAULT_CACHE_CONTROL,
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

    def __init__(self) -> None:
        self.total_tokens = 0
        self.total_input_tokens = 0
        self.total_output_tokens = 0
        self.total_cost = 0.0
        self.call_count = 0
        self.total_duration = 0.0

    def generate(self, prompt: str, system_prompt: str | None = None,
                 **kwargs):
        """Returns None — Claude Code will do the reasoning."""
        return

    def generate_structured(self, prompt: str, schema: dict[str, Any],
                           system_prompt: str | None = None,
                           **kwargs):
        """Returns (None, None) — Claude Code will do the reasoning.

        Accepts and ignores ``**kwargs`` (notably ``temperature``):
        the `claude` CLI doesn't expose a temperature flag, so any
        per-call override is structurally a no-op here. Accepting
        kwargs prevents TypeError when callers route through the
        unified `LLMClient.generate_structured` plumbing.
        """
        return None, None

    def get_stats(self) -> dict[str, Any]:
        """Return zero stats."""
        return {
            "total_requests": 0,
            "total_cost": 0.0,
            "budget_remaining": 0.0,
            "providers": {},
        }


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
        claude_bin: str | None = None,
        # Per-CALL abort ceiling (claude -p --max-budget-usd), not a
        # run budget — orchestrators cap total spend via --max-cost.
        # Audit-sized structured reviews (system prompt + context
        # slice + schema) measure $0.9-1.3 per call on Opus-class
        # models; the old "1.00" default aborted them mid-response
        # with subtype error_max_budget_usd. On pricier backends the
        # biggest call classes (Mode 2 checker synthesis: multi-KB
        # system prompt, no cross-process cache reuse) can exceed
        # "5.00" too — RAPTOR_CC_BUDGET_USD overrides the default
        # without touching call sites.
        budget_usd: str | None = None,
        timeout_s: int | None = None,
        resumable: bool = False,
    ) -> None:
        super().__init__(config)
        if claude_bin is None:
            # Resolve ONCE at construction via the realpath-pinning
            # helper. The old bare-"claude" default was re-resolved
            # against PATH by every Popen — each spawn carrying
            # backend credentials in its env — so an attacker-writable
            # PATH entry ahead of the real CLI substituted the binary.
            # Pinning here locks the spawn target in; run_cc_streaming
            # additionally refuses non-absolute argv[0] at spawn time.
            from .cc_adapter import resolve_claude_cli
            claude_bin = resolve_claude_cli()
        self._claude_bin = claude_bin or "claude"
        if budget_usd is None:
            budget_usd = os.environ.get("RAPTOR_CC_BUDGET_USD", "5.00")
            try:
                float(budget_usd)
            except ValueError:
                logger.warning(
                    "RAPTOR_CC_BUDGET_USD=%r is not a number — using 5.00",
                    budget_usd,
                )
                budget_usd = "5.00"
        self._budget_usd = budget_usd
        self._resumable = resumable
        self._session_id: str | None = None
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

    def _cli_model(self) -> str | None:
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
        self, override: int | None,
    ) -> int | None:
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
        system_prompt: str | None = None,
        **kwargs: Any,
    ) -> LLMResponse:
        """Dispatch a prompt to ``claude -p`` via stream-json and parse
        the response."""
        import subprocess
        import time as _time

        from .cc_adapter import (
            CCDispatchConfig,
            build_cc_command,
            run_cc_streaming,
            system_prompt_file_for,
        )

        call_timeout = self._effective_timeout_s(kwargs.pop("timeout_s", None))

        # Pass the user prompt as-is and route the system prompt
        # through CC's system-prompt channel (see CCDispatchConfig.system_prompt
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
            # System prompt rides a 0600 tempfile + --system-prompt-file
            # so it never appears in the child's world-readable
            # /proc/<pid>/cmdline (see build_cc_command's hygiene
            # contract). Spawn AND wait stay inside the CM: the file
            # must outlive the child.
            with system_prompt_file_for(cc_config) as _sys_prompt_path:
                cmd = build_cc_command(
                    cc_config, system_prompt_file=_sys_prompt_path,
                )
                sr = run_cc_streaming(
                    cmd, prompt, env=_cc_env, timeout_s=call_timeout,
                )
        except subprocess.TimeoutExpired as e:
            msg = f"claude -p timed out after {call_timeout}s"
            raise RuntimeError(msg) from e
        duration = _time.monotonic() - start

        # Book usage BEFORE the error check: a failed call (budget
        # abort, API refusal) still spent real money — up to the
        # per-call budget cap. The client books nothing on failure
        # and relies on this provider ledger as the failed-attempt
        # floor (``_effective_spent_locked`` reads
        # ``max(total_cost, provider_spend)``), so raising first
        # made the spend invisible to max-cost enforcement.
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

        if sr.error:
            raise RuntimeError(sr.error)

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
            # Surface the per-call prompt-cache counters on the
            # response itself (not only the provider aggregate) so the
            # client's per-call telemetry can report cache hit rates.
            cache_read_tokens=sr.cache_read_tokens,
            cache_write_tokens=sr.cache_creation_tokens,
            duration=duration,
        )

    def generate_structured(
        self,
        prompt: str,
        schema: dict[str, Any],
        system_prompt: str | None = None,
        **kwargs,
    ) -> StructuredResponse:
        """Dispatch with ``--json-schema`` for structured output via
        stream-json.

        Accepts and ignores ``**kwargs`` — `claude` CLI has no
        temperature flag (see ClaudeCodeProvider.generate_structured).
        """
        import subprocess
        import time as _time

        from .cc_adapter import (
            CCDispatchConfig,
            build_cc_command,
            run_cc_streaming,
            system_prompt_file_for,
        )

        # Route system_prompt through CC's system-prompt channel instead
        # of concatenating into the user prompt. Pre-fix this path used
        # `f"{system_prompt}\n\n{prompt}"`, mixing the trusted system
        # message into the same channel as user content. The
        # generate() path above (the freeform sibling of this method)
        # already uses the system-prompt channel correctly. The
        # structured path's f-string concat:
        #
        #   * Drops the trust separation that CC's system-prompt flag
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
        # converts into a `--system-prompt-file` flag).
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
            # System prompt via 0600 tempfile + --system-prompt-file —
            # never in the child's world-readable /proc/<pid>/cmdline
            # (see build_cc_command's hygiene contract). Spawn AND
            # wait stay inside the CM.
            with system_prompt_file_for(cc_config) as _sys_prompt_path:
                cmd = build_cc_command(
                    cc_config, system_prompt_file=_sys_prompt_path,
                )
                sr = run_cc_streaming(
                    cmd, prompt, env=_cc_env, timeout_s=call_timeout,
                )
        except subprocess.TimeoutExpired as e:
            msg = f"claude -p timed out after {call_timeout}s"
            raise RuntimeError(msg) from e
        duration = _time.monotonic() - start

        # Book usage BEFORE the error/parse checks: a failed call
        # (budget abort, API refusal, unparseable output) still spent
        # real money. The client books nothing on failure and relies
        # on this provider ledger as the failed-attempt floor
        # (``_effective_spent_locked`` reads
        # ``max(total_cost, provider_spend)``), so raising first
        # made the spend invisible to max-cost enforcement.
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

        if sr.error:
            raise RuntimeError(sr.error)

        if sr.structured_output is not None:
            result = sr.structured_output
        else:
            result = self._parse_stream_content(sr.content)
            if isinstance(result, dict) and "error" in result and result["error"]:
                msg = f"claude -p structured parse failed: {result['error']}"
                raise RuntimeError(msg)

        return StructuredResponse(
            result=result,
            raw=json.dumps(result, indent=2),
            cost=sr.cost_usd,
            tokens_used=total_tokens,
            model=sr.model or self.config.model_name,
            provider="claudecode",
            duration=duration,
            input_tokens=sr.input_tokens,
            output_tokens=sr.output_tokens,
            cache_read_tokens=sr.cache_read_tokens,
            cache_write_tokens=sr.cache_creation_tokens,
        )

    def supports_tool_use(self) -> bool: return True

    def supports_prompt_caching(self) -> bool:
        """False: ``claude -p`` exposes no cache_control breakpoint
        API to this process — callers cannot mark cache regions."""
        return False

    def prefers_stable_system_prefix(self) -> bool:
        """True: the CLI's backend does server-side prefix caching
        across separate ``claude -p`` children when the prefix is
        byte-stable (measured on this transport: 19k cache-read
        tokens and ~13x input-cost drop on the second
        identical-prefix call — see cc_adapter.CCDispatchConfig).
        The system prompt travels via ``--system-prompt-file`` and the
        audit composes it once per run, so run-stable material moved
        into it bills at the cached-input rate from the second call
        on. Per-call cache-read/-write counters stream back in the
        usage events and flow through telemetry, so the realised hit
        rate is measurable on live runs."""
        return True

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
        system: str | None = None,
        max_tokens: int = 4096,
        cache_control: CacheControl = _DEFAULT_CACHE_CONTROL,
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
        system: str | None = None,
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
            logger.warning("ClaudeCodeLLMProvider.turn: %s", err_msg)
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
            # Preserve the real input/output split —
            # generate_structured populates both fields, and
            # ToolUseLoop records per-turn (input, output) pairs plus
            # separate totals. Collapsing the sum into output_tokens
            # (as this path once did) skewed all of them.
            input_tokens = response.input_tokens
            output_tokens = response.output_tokens
        else:
            result, _ = response
            cost_usd = 0.0
            input_tokens = 0
            output_tokens = 0

        return self._parse_turn_structured_result(
            result,
            tools,
            cost_usd=cost_usd,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
        )

    def _turn_resumable(
        self,
        messages: Sequence[Message],
        tools: Sequence[ToolDef],
        *,
        system: str | None = None,
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
        import subprocess
        import time as _time

        from .cc_adapter import (
            CCDispatchConfig,
            build_cc_command,
            run_cc_streaming,
            system_prompt_file_for,
        )

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

        from .cc_adapter import cc_subprocess_env

        _cc_env = cc_subprocess_env()

        start = _time.monotonic()
        try:
            # System prompt via 0600 tempfile + --system-prompt-file —
            # never in the child's world-readable /proc/<pid>/cmdline
            # (see build_cc_command's hygiene contract). Spawn AND
            # wait stay inside the CM.
            with system_prompt_file_for(cc_config) as _sys_prompt_path:
                cmd = build_cc_command(
                    cc_config, system_prompt_file=_sys_prompt_path,
                )
                sr = run_cc_streaming(
                    cmd, prompt, env=_cc_env, timeout_s=self._timeout_s,
                )
        except subprocess.TimeoutExpired:
            err_msg = f"claude -p timed out after {self._timeout_s}s"
            logger.warning("ClaudeCodeLLMProvider._turn_resumable: %s", err_msg)
            return TurnResponse(
                content=[],
                stop_reason=StopReason.ERROR,
                input_tokens=0,
                output_tokens=0,
                error_message=err_msg,
            )
        duration = _time.monotonic() - start

        # Book usage BEFORE the error/empty-content returns: a failed
        # turn (budget abort, refusal) still spent real money, and
        # budget enforcement reads this ledger as the failed-attempt
        # floor. The retry path below issues a SECOND call which books
        # its own spend — two calls, two bookings.
        self.track_usage(
            tokens=sr.input_tokens + sr.output_tokens,
            cost=sr.cost_usd,
            input_tokens=sr.input_tokens,
            output_tokens=sr.output_tokens,
            cache_read_tokens=sr.cache_read_tokens,
            cache_write_tokens=sr.cache_creation_tokens,
            duration=duration,
        )

        if sr.error:
            err_msg = sr.error
            logger.warning("ClaudeCodeLLMProvider._turn_resumable: %s", err_msg)
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
        if not content_text and sr.structured_output is None:
            return TurnResponse(
                content=[],
                stop_reason=StopReason.ERROR,
                input_tokens=sr.input_tokens,
                output_tokens=sr.output_tokens,
                error_message="empty response from stream-json",
            )

        if sr.structured_output is not None:
            result = sr.structured_output
        else:
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
        import json

        from .cc_adapter import strip_json_fences

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
    def _build_turn_schema(tools: Sequence[ToolDef]) -> dict[str, Any]:
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
        extra: str | None = None,
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
            (
                "Decide the next action for an agentic tool-use loop. "
                "Either invoke a tool to gather more information or "
                "deliver a final answer. Output JSON matching the "
                "provided schema."
            ),
            "",
            "RULES:",
            (
                "1. When invoking a tool, the values you put in tool_input "
                "MUST come from either the conversation history or the "
                "user's request. Do not guess, invent, or recall from "
                "training data — even values that look plausible (slugs, "
                "SHAs, URLs, IDs, package names)."
            ),
            (
                "2. If you don't have a value the next tool needs, call "
                "a discovery tool first to obtain it."
            ),
            "3. Call only one tool per response.",
            "",
            "TOOL CATALOG:",
        ]
        for t in tools:
            lines.append(f"- {t.name}: {t.description}")
            lines.append(
                f"  input_schema: {dumps_display(t.input_schema, indent=None)}"
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
                        f"input {dumps_display(block.input, indent=None)}"
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
        result: dict[str, Any],
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
        usd: float | None = float(cost_usd) if cost_usd is not None else None
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
                content=[TextBlock(text=dumps_display(result, indent=None))],
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


class ModelTransportMismatchError(RuntimeError):
    """A model id is provider-shaped for a DIFFERENT transport than
    the one about to serve it (e.g. a Bedrock inference-profile id on
    the direct-API / claudecode path).

    Raised at provider CONSTRUCTION, before any request is built:
    shipping the id upstream yields a bare HTTP 400 with none of the
    routing context, and burns a billable call on backends that
    partially process the request.  Non-retryable by design (the
    message deliberately avoids the transient-error vocabulary
    ``_is_retryable_error`` matches on), so the fallback chain moves
    on immediately and the operator sees THIS message, not a generic
    400.
    """


def _guard_transport_model_shape(
    config: ModelConfig, *, transport: str,
) -> None:
    """Fail loud when ``config.model_name`` cannot be served by
    ``transport``.

    Covers the observed misroute: resolution falls back from a
    dispatcher-only Bedrock entry to the claudecode transport (or a
    direct-API entry borrows a Bedrock id), and ``claude -p --model
    us.anthropic...`` / the Anthropic SDK then hits the direct API --
    HTTP 400 with no hint that the id was Bedrock-shaped.

    Never trips on legitimate ids for the transport: bare catalog
    names, the ``session-default`` sentinel, aliases and Vertex ids
    are not Bedrock-shaped, and a Bedrock-backed claude CLI
    (``CLAUDE_CODE_USE_BEDROCK`` set -- the same signal
    ``cc_subprocess_env`` gates its AWS overlay on; settings.json-only
    Bedrock setups must export it, documented trade-off) serves
    Bedrock ids natively.  Custom ``api_base`` endpoints are the
    operator's own gateway contract and are exempt.
    """
    from core.llm.bedrock_prefixes import bedrock_shaped_model_id

    if not bedrock_shaped_model_id(config.model_name):
        return
    if transport == "claudecode":
        if os.environ.get("CLAUDE_CODE_USE_BEDROCK"):
            return
        msg = (
            f"model id {config.model_name!r} is Bedrock-shaped but is "
            "routed to the claudecode transport on a NON-Bedrock "
            "claude CLI (CLAUDE_CODE_USE_BEDROCK is unset) -- "
            "`claude -p --model` would send it to the direct Anthropic "
            "API, which rejects Bedrock ids with a bare HTTP 400. "
            "Remedies: add a models.json entry with \"provider\": "
            "\"bedrock\" so the RAPTOR dispatcher routes it (SigV4/"
            "bearer), or export CLAUDE_CODE_USE_BEDROCK=1 if the "
            "claude CLI really is Bedrock-backed (settings.json-only "
            "Bedrock installs must export it), or pin a direct-API "
            "model name instead."
        )
        raise ModelTransportMismatchError(msg)
    if transport == "anthropic":
        if config.api_base:
            # Operator-supplied gateway -- their endpoint, their
            # id vocabulary.
            return
        msg = (
            f"model id {config.model_name!r} is Bedrock-shaped but is "
            "configured on the direct Anthropic API path (provider "
            "\"anthropic\"), which serves bare claude-* ids only -- "
            "the request would fail upstream with a bare HTTP 400. "
            "Remedies: set \"provider\": \"bedrock\" on the "
            "models.json entry so the RAPTOR dispatcher routes it "
            "(SigV4/bearer), or use the direct-API model name."
        )
        raise ModelTransportMismatchError(msg)


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
        "claudecode", "claude_code", "claude-code",
    ):
        _guard_transport_model_shape(config, transport="claudecode")
        return ClaudeCodeLLMProvider(
            config,
            resumable=provider.replace("_", "-").endswith("-resumable"),
        )
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
            msg = "Bedrock provider requires: pip install anthropic"
            raise RuntimeError(msg)
        if not os.environ.get("RAPTOR_LLM_SOCKET"):
            msg = (
                "Bedrock provider requires the RAPTOR LLM dispatcher "
                "(RAPTOR_LLM_SOCKET).  Workers do not hold AWS "
                "credentials; the dispatcher attaches them at the "
                "parent's trust boundary."
            )
            raise RuntimeError(msg)
        api = getattr(config, "bedrock_api", "mantle") or "mantle"
        if api not in ("mantle", "runtime"):
            msg = (
                f"Bedrock provider: unknown bedrock_api={api!r}; "
                "expected 'mantle' or 'runtime'"
            )
            raise RuntimeError(msg)
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
        if api == "mantle":
            # Mantle streams natively; runtime (InvokeModel) has no
            # SSE surface, so its instructor leg stays on plain
            # ``create`` (matching the construction-time warning).
            _streamify_messages_create(provider_instance.client)
        if INSTRUCTOR_AVAILABLE:
            provider_instance.instructor_client = instructor.from_anthropic(
                provider_instance.client,
            )
        if api == "runtime":
            # InvokeModel has no SSE surface; the dispatcher rejects
            # ``stream`` with a 400 mid-run. Surface the capability
            # limit at construction time so a streaming consumer's
            # failure isn't the first hint. Per-call stream opt-ins
            # (pipeline callers, blind to the surface) degrade to
            # plain create here rather than 400ing every study batch.
            provider_instance._stream_sse_ok = False
            logger.warning(
                "Bedrock runtime surface is non-streaming (InvokeModel)"
                " — streaming consumers will get a 400; use "
                "bedrock_api=mantle for SSE streaming",
            )
        logger.debug(
            "Bedrock provider: routing via dispatcher /bedrock/%s", api,
        )
        return provider_instance
    if provider == "anthropic":
        _guard_transport_model_shape(config, transport="anthropic")
        if ANTHROPIC_SDK_AVAILABLE:
            return AnthropicProvider(config)
        if OPENAI_SDK_AVAILABLE:
            logger.warning(
                "Anthropic SDK not installed — using OpenAI-compatible endpoint. "
                "Structured output will use Pydantic fallback (response_format is ignored by Anthropic). "
                "For best results: pip install anthropic"
            )
            from dataclasses import replace
            compat_config = replace(config, api_base="https://api.anthropic.com/v1")
            return OpenAICompatibleProvider(compat_config)
        msg = "Anthropic provider requires: pip install anthropic (or) pip install openai"
        raise RuntimeError(msg)
    if provider == "gemini":
        if GENAI_SDK_AVAILABLE:
            return GeminiProvider(config)
        if OPENAI_SDK_AVAILABLE:
            logger.info("google-genai SDK not installed — using OpenAI-compatible endpoint for Gemini. "
                        "For accurate thinking token tracking: pip install google-genai")
            return OpenAICompatibleProvider(config)
        msg = "Gemini provider requires: pip install google-genai (or) pip install openai"
        raise RuntimeError(msg)
    if OPENAI_SDK_AVAILABLE:
        return OpenAICompatibleProvider(config)
    msg = f"Provider '{provider}' requires: pip install openai"
    raise RuntimeError(msg)


# Backward compatibility
ClaudeProvider = AnthropicProvider if ANTHROPIC_SDK_AVAILABLE else type('ClaudeProvider', (), {})
OpenAIProvider = OpenAICompatibleProvider if OPENAI_SDK_AVAILABLE else type('OpenAIProvider', (), {})
OllamaProvider = OpenAICompatibleProvider if OPENAI_SDK_AVAILABLE else type('OllamaProvider', (), {})
