"""Provider-agnostic types for the tool-use loop.

This module is the single source of truth for the wire-shapes the
:class:`ToolUseLoop` and any provider implementation pass between
themselves. Every provider in ``core.llm.tool_use.providers`` translates
its native wire format (Anthropic ``tool_use``/``tool_result`` blocks,
OpenAI ``tool_calls``/``role:"tool"`` messages, Gemini's
``function_call``/``function_response``, Ollama's tool-call shape) into
the dataclasses defined here, and back out, on each turn.

Design choices captured here that are easy to miss when reading code
without context:

- ``Message.content`` is heterogeneous (``TextBlock | ToolCall | ToolResult``)
  but the *valid* mix depends on ``role`` — assistant turns may carry text
  + tool_calls, user turns may carry text + tool_results. Type-checking
  this strictly (``AssistantContent`` / ``UserContent`` newtypes) was
  considered and rejected: the conversion code in each provider already
  validates per-role, and lifting the constraint into the type system
  pushes complexity to every consumer with no real win.

- Tool ``handler`` is sync-only. Async / cancellation come via a parallel
  ``AsyncToolUseLoop`` if/when a real consumer needs it. Wrapping
  long-running work with ``tool_timeout_s`` at the loop level is the
  v1 escape hatch.

- ``StopReason`` is a provider-agnostic enum, not a string union. Each
  provider maps its native vocabulary onto these five values; the loop
  consumes the enum directly. Anthropic-only literals were deliberately
  rejected so multi-provider downstreams don't silently drift.

- ``CacheControl`` is per-region opt-in (system / tools /
  history-through-index) rather than a single bool. This matches
  Anthropic's actual cache-breakpoint semantics; providers that don't
  support caching ignore it entirely (capability flag is False, the
  loop still passes the struct through unchanged).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
from typing import Any, Literal, Union


# ---------------------------------------------------------------------------
# Stop reasons
# ---------------------------------------------------------------------------


class StopReason(Enum):
    """Provider-agnostic terminal state of one turn.

    Mappings (provider-side, in their respective ``turn()`` impls):

    +------------------+------------------+----------------+----------------+
    | This             | Anthropic        | OpenAI         | Gemini         |
    +==================+==================+================+================+
    | COMPLETE         | end_turn,        | stop           | STOP           |
    |                  | stop_sequence    |                |                |
    +------------------+------------------+----------------+----------------+
    | NEEDS_TOOL_CALL  | tool_use         | tool_calls     | FUNCTION_CALL  |
    +------------------+------------------+----------------+----------------+
    | PAUSE_TURN       | pause_turn       | (none —        | (none —        |
    |                  |                  | length covers) | length covers) |
    +------------------+------------------+----------------+----------------+
    | MAX_TOKENS       | max_tokens       | length         | MAX_TOKENS     |
    +------------------+------------------+----------------+----------------+
    | REFUSED          | refusal          | content_filter | SAFETY         |
    +------------------+------------------+----------------+----------------+
    | ERROR            | (transport fail, anything that doesn't map cleanly) |
    +------------------+----------------------------------+-----------------+

    ``PAUSE_TURN`` is Anthropic's signal that extended-thinking output
    paused mid-stream and the client should re-send the conversation
    (with the partial assistant turn appended) to resume. The
    :class:`~.loop.ToolUseLoop` treats it as "continue" rather than
    "terminate" — without that, long-thinking turns would terminate
    prematurely as ``ERROR``.
    """

    COMPLETE = "complete"
    NEEDS_TOOL_CALL = "needs_tool_call"
    PAUSE_TURN = "pause_turn"
    MAX_TOKENS = "max_tokens"
    REFUSED = "refused"
    ERROR = "error"


# ---------------------------------------------------------------------------
# Tool definitions + call/result wire format
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ToolDef:
    """A tool the model can call.

    ``handler`` runs synchronously when :class:`ToolUseLoop` dispatches
    a model-emitted :class:`ToolCall`. Returning a ``str`` is the wire
    format: JSON-encode structured data when the model expects more
    than free text. The loop wraps handler exceptions per the
    ``terminate_on_handler_error`` policy on the loop (default: feed
    the exception text back to the model as a ``ToolResult`` with
    ``is_error=True`` so the model can adapt).

    **x-source provenance** (optional): each property in
    ``input_schema`` may carry ``"x-source": "prompt"`` (value from
    the operator prompt — trusted, not validated) or
    ``"x-source": "discovered"`` (value from prior tool output —
    validated against ``known_values`` before dispatch). Tools
    without annotations are dispatched unconditionally.
    """

    name: str
    description: str
    input_schema: dict[str, Any]
    handler: Callable[[dict[str, Any]], str]


@dataclass(frozen=True)
class ToolCall:
    """Model-emitted request to call a tool. Surfaced as one of the
    content blocks of an assistant-role :class:`Message`."""

    id: str
    name: str
    input: dict[str, Any]


@dataclass(frozen=True)
class ToolResult:
    """Caller's response to a :class:`ToolCall`, fed back to the model
    on the next turn. Carried as a content block of a user-role
    :class:`Message`. ``is_error=True`` lets the model distinguish
    legitimate empty results from handler failures."""

    tool_use_id: str
    content: str
    is_error: bool = False


@dataclass(frozen=True)
class TextBlock:
    """Plain text emitted by either role."""

    text: str


# ---------------------------------------------------------------------------
# Conversation history
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Message:
    """One turn of conversation history.

    ``content`` is heterogeneous and provider-agnostic:

      * Assistant turns may contain :class:`TextBlock` + :class:`ToolCall`
        items, in any order — the model emits text and tool calls
        intermixed.
      * User turns may contain :class:`TextBlock` + :class:`ToolResult`
        items. Most often they're a single text block (the initial
        prompt) or a list of results (mid-loop response to one or more
        tool calls).

    The "wrong" combinations (e.g., a :class:`ToolResult` in an
    assistant message) are caught by each provider's wire-format
    converter, which knows how to translate role-appropriate content
    only.
    """

    role: Literal["user", "assistant"]
    content: list[TextBlock | ToolCall | ToolResult]


# ---------------------------------------------------------------------------
# Per-turn response (one provider round-trip)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TurnResponse:
    """Result of one :meth:`ToolUseProvider.turn` call.

    The :class:`ToolUseLoop` inspects ``content`` to decide whether to
    dispatch tools (any :class:`ToolCall` present → dispatch and append
    results to history) or terminate (text-only with
    ``stop_reason == COMPLETE``).

    Cache-token fields are 0 on providers that lack prompt caching;
    this is informational, not a capability check — callers test
    ``provider.supports_prompt_caching()`` for capability.

    ``cost_usd`` is populated when the provider already knows the
    exact cost — e.g., Claude Code returns ``total_cost_usd`` in its
    envelope; the fallback synthesis path plumbs that through. When
    set, :meth:`LLMProvider.compute_cost` returns it directly and
    skips the per-token formula. ``None`` (default) for native turn()
    impls that compute cost from token counts.
    """

    content: list[TextBlock | ToolCall]
    stop_reason: StopReason
    input_tokens: int
    output_tokens: int
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0
    cost_usd: float | None = None
    error_message: str | None = None


# ---------------------------------------------------------------------------
# Cache-control opt-ins
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CacheControl:
    """Per-region cache opt-ins for providers that support prompt caching.

    Anthropic places one cache breakpoint per opted-in region. Other
    providers ignore this entirely (their ``turn()`` implementations
    don't read any field, capability flag
    :meth:`ToolUseProvider.supports_prompt_caching` returns False).

    ``history_through_index``: when set to ``i``, the cache breakpoint
    is placed on the last block of ``messages[i]`` — Anthropic caches
    everything up to and including that point. Use to cache the stable
    prefix of a long conversation while leaving the rolling tail
    uncached. ``None`` skips history caching entirely.
    """

    system: bool = True
    tools: bool = True
    history_through_index: int | None = None


# ---------------------------------------------------------------------------
# Context-window policy
# ---------------------------------------------------------------------------


class ContextPolicy(Enum):
    """How the loop handles a turn whose request would exceed the
    model's context window.

    ``RAISE`` is the v1 default — fail loud rather than silently drop
    history that the model needed for correctness. ``TRUNCATE_OLDEST``
    is the escape hatch for long-running agents that accept lossy
    history; it drops oldest user/assistant turn pairs (preserving
    pairing so tool-results don't dangle without their tool-calls).
    """

    RAISE = "raise"
    TRUNCATE_OLDEST = "truncate_oldest"
    # SUMMARISE — deferred. Needs a separate LLM call to compress
    # history into a synopsis turn; design TBD when a consumer asks.


class ContextOverflow(RuntimeError):
    """Raised by the loop when ``ContextPolicy.RAISE`` is in effect and
    the next turn's request would exceed the provider's context
    window."""


# ---------------------------------------------------------------------------
# Cost-budget enforcement
# ---------------------------------------------------------------------------


class CostBudgetExceeded(RuntimeError):
    """Raised pre-flight when the next turn's cost estimate would push
    cumulative cost past ``ToolUseLoop(max_cost_usd=...)``. Parity with
    cve-diff's existing per-CVE cost cap.

    Pre-flight only: a single surprise-large response cannot be blocked
    until we know its cost, but subsequent calls in the same loop run
    cannot pile on once the cap is reached.
    """


class ToolHandlerTimeout(RuntimeError):
    """Raised when a tool handler exceeds ``tool_timeout_s`` AND the
    loop is configured with ``terminate_on_handler_error=True``.

    Symmetric with the loop's behaviour for handler exceptions in the
    same mode: both fail-fast paths re-raise rather than feeding the
    error back to the model. Without ``terminate_on_handler_error``
    the loop converts a timeout into an ``is_error=True``
    :class:`ToolResult` and continues.
    """


# ---------------------------------------------------------------------------
# Structured event stream (first-class observability)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TurnStarted:
    iteration: int
    input_token_estimate: int
    cache_breakpoints: int


@dataclass(frozen=True)
class TurnCompleted:
    iteration: int
    response: TurnResponse
    cost_usd: float


@dataclass(frozen=True)
class ToolCallDispatched:
    iteration: int
    call: ToolCall


@dataclass(frozen=True)
class ToolCallReturned:
    iteration: int
    call_id: str
    result: ToolResult
    duration_s: float


@dataclass(frozen=True)
class ToolCallBlocked:
    """x-source validation blocked a tool call before dispatch.

    One or more ``discovered`` fields contained values not present in
    ``known_values`` (seeded from prompt + prior tool outputs). The
    loop returns an ``is_error=True`` :class:`ToolResult` so the model
    can discover the values first.
    """

    iteration: int
    call: ToolCall
    blocked_fields: dict[str, str]


@dataclass(frozen=True)
class LoopTerminated:
    """Emitted as the final event of a :meth:`ToolUseLoop.run` call.

    ``reason`` mirrors :attr:`ToolLoopResult.terminated_by` — the same
    string is in both places so consumers can either subscribe to
    events live or inspect the result after the fact.

    ``iterations`` always reports turns completed: pre-flight gate
    termination at iteration N reports ``N`` (N turns 0..N-1 done);
    post-turn termination at iteration N reports ``N+1`` (N+1 turns
    0..N done). Same convention as :attr:`ToolLoopResult.iterations`.
    """

    reason: Literal[
        "complete",                  # COMPLETE response from model
        "terminal_tool",             # model called designated terminal tool
        "max_iterations",            # loop hit max_iterations cap
        "max_cost_usd",              # cumulative cost crossed cap
        "max_seconds",               # wall-clock budget exceeded
        "max_total_tokens",          # cumulative input+output tokens crossed cap
        "max_tokens",                # provider truncated response (no tool calls)
        "refused",                   # provider safety / content filter
        "tool_error",                # handler exception or timeout under terminate_on_handler_error
        "tool_timeout",              # handler timeout, not configured to terminate
        "context_overflow",          # request would exceed context window
        "provider_error",            # transport / API failure after retries
    ]
    iterations: int
    total_cost_usd: float
    error_message: str | None = None


LoopEvent = Union[
    TurnStarted,
    TurnCompleted,
    ToolCallDispatched,
    ToolCallBlocked,
    ToolCallReturned,
    LoopTerminated,
]


# ---------------------------------------------------------------------------
# Final loop result
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ToolLoopResult:
    """Final outcome of a :meth:`ToolUseLoop.run` call.

    ``final_text`` is the joined :class:`TextBlock` text from the
    LAST assistant turn. For ``COMPLETE`` termination this is the
    model's final answer. For ``terminal_tool`` termination it's the
    model's commentary text adjacent to the terminating tool call —
    typically empty (model just calls the tool) or a short reasoning
    note. Use :attr:`terminal_tool_input` for the structured payload.

    ``terminal_tool_input`` is the dict the model passed as ``input``
    to its designated ``terminal_tool``. cve-diff's ``submit_result``
    pattern uses this to surface validated SHAs / verdicts as a typed
    dict instead of relying on the model to repeat them in free text.
    ``None`` for runs that didn't terminate via terminal tool.

    ``iterations`` reports turns completed (same convention as
    :attr:`LoopTerminated.iterations`). For ``max_iterations`` it
    equals the configured cap; for ``complete`` / ``terminal_tool``
    it's the iteration index of the final turn + 1.
    """

    final_text: str
    terminal_tool_input: dict[str, Any] | None
    messages: list[Message]
    iterations: int
    tool_calls_made: int
    total_input_tokens: int
    total_output_tokens: int
    total_cost_usd: float
    terminated_by: Literal[
        "complete",
        "terminal_tool",
        "max_iterations",
        "max_cost_usd",
        "max_seconds",
        "max_total_tokens",
        "max_tokens",
        "refused",
        "tool_error",
        "tool_timeout",
        "context_overflow",
        "provider_error",
    ]
    error_message: str | None = None
