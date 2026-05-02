"""Anthropic ``messages.create`` backed :class:`ToolUseProvider`.

Native tool-use shape — Anthropic's API maps almost directly onto the
provider-agnostic types in :mod:`.types`. This is the v1 reference
implementation: every other provider's ``turn()`` translates from its
native shape onto and back from these wire types, so getting the
mapping right here matters.

Honoured features:

  * Per-region prompt caching (system / tools / history-through-index)
    via ``cache_control: {"type": "ephemeral"}`` markers. Anthropic
    treats each marker as a cache breakpoint; we follow their
    documented "the last block in each opted-in region carries the
    marker" pattern.
  * Cost-aware token accounting that splits cache reads (0.1x input
    rate) and cache writes (1.25x input rate) per Anthropic's
    documented multipliers — the loop's ``max_cost_usd`` cap stays
    accurate when caching is in use.
  * Beta ``client.beta.messages.create`` task-budget endpoint via
    ``provider_specific={"anthropic_task_budget_beta": True}`` for
    consumers (cve-diff today) that opted into the beta.

Not yet exposed (deferred until a consumer asks):

  * Streaming (``stream=True``) — the loop is sync-buffered per turn.
  * Vision content blocks (image inputs).
  * Multi-block ``tool_result.content`` (Anthropic accepts a list of
    text/image blocks; we send the simpler ``str`` shape that maps
    cleanly to other providers).
"""

from __future__ import annotations

import logging
import time
from collections.abc import Sequence
from typing import Any

from core.llm.model_data import (
    ANTHROPIC_CACHE_READ_MULTIPLIER,
    ANTHROPIC_CACHE_WRITE_MULTIPLIER,
    context_window_for,
    price_for,
)

from .types import (
    CacheControl,
    Message,
    StopReason,
    TextBlock,
    ToolCall,
    ToolDef,
    ToolResult,
    TurnResponse,
)

logger = logging.getLogger(__name__)


# Optional import — anthropic SDK is a soft dep. Constructor raises a
# clean error when it's missing rather than failing at module-import.
try:
    from anthropic import (                           # type: ignore[import-not-found]
        Anthropic,
        APIConnectionError,
        APIError,
        APIStatusError,
    )
    _ANTHROPIC_AVAILABLE = True
except ImportError:                                    # pragma: no cover
    _ANTHROPIC_AVAILABLE = False
    Anthropic = None                                   # type: ignore[misc]
    APIConnectionError = APIStatusError = APIError = Exception  # type: ignore[misc]


# Anthropic's native stop_reason → our enum.
_STOP_REASON_MAP = {
    "end_turn": StopReason.COMPLETE,
    "stop_sequence": StopReason.COMPLETE,
    "tool_use": StopReason.NEEDS_TOOL_CALL,
    "pause_turn": StopReason.PAUSE_TURN,
    "max_tokens": StopReason.MAX_TOKENS,
    "refusal": StopReason.REFUSED,
}

# Beta header name for Anthropic's task-budget endpoint. Activated by
# the ``anthropic_task_budget_beta=True`` provider-specific kwarg —
# routing to ``client.beta.messages.create`` is necessary BUT NOT
# SUFFICIENT; the ``betas=[...]`` parameter must also be passed for
# the server to actually honour the beta. This constant is the
# current version cve-diff uses (matches its agent loop).
_TASK_BUDGET_BETA = "task-budgets-2026-03-13"


def _is_transient(exc: BaseException) -> bool:
    """``True`` when ``exc`` is a connection / 429 / 5xx error worth
    retrying. Permanent 4xx (auth, schema, not-found) are False so
    callers fail fast instead of burning budget on hopeless retries.
    """
    if isinstance(exc, APIConnectionError):
        return True
    if isinstance(exc, APIStatusError):
        status = getattr(exc, "status_code", None)
        return status == 429 or (status is not None and 500 <= status < 600)
    return False


class AnthropicToolUseProvider:
    """``ToolUseProvider`` over Anthropic's ``messages.create``.

    Construct one per ``model``. The bound model's context window and
    pricing come from :mod:`core.llm.model_data` — unknown models raise
    ``KeyError`` at construction so misconfiguration surfaces immediately
    instead of mid-run.
    """

    def __init__(
        self,
        model: str,
        *,
        api_key: str | None = None,
        timeout_s: float = 120.0,
        max_retries: int = 3,
        backoff_factor: float = 2.0,
    ) -> None:
        """``max_retries`` is the count of *additional* attempts after
        the first on transient errors (connection refused, 429, 5xx).
        ``backoff_factor`` controls exponential delay between attempts:
        delay = ``backoff_factor ** attempt`` seconds. Permanent errors
        (4xx other than 429) fail fast without retrying.
        """
        if not _ANTHROPIC_AVAILABLE:
            raise RuntimeError(
                "AnthropicToolUseProvider requires the ``anthropic`` "
                "package; install with: pip install anthropic"
            )
        # Both lookups raise KeyError on unknown models — caller-visible.
        self._context_window = context_window_for(model)
        self._price = price_for(
            model, default=(0.0, 0.0),
        )
        self._model = model
        self._max_retries = max_retries
        self._backoff_factor = backoff_factor
        self._client = Anthropic(api_key=api_key, timeout=timeout_s)

    # ------------------------------------------------------------------
    # Capability flags
    # ------------------------------------------------------------------

    def supports_tool_use(self) -> bool: return True
    def supports_prompt_caching(self) -> bool: return True
    def supports_parallel_tools(self) -> bool: return True
    def context_window(self) -> int: return self._context_window
    def price_per_million(self) -> tuple[float, float]: return self._price

    def estimate_tokens(self, text: str) -> int:
        """Cheap pre-flight estimator. Anthropic's tokenizer averages
        ~3.5 chars/token; we round up to 4 to bias toward over-estimation
        (which only triggers the context-policy gate slightly early —
        the safe direction)."""
        return max(len(text) // 4, 1)

    # ------------------------------------------------------------------
    # Cost computation (cache-aware)
    # ------------------------------------------------------------------

    def compute_cost(self, response: TurnResponse) -> float:
        """USD cost per Anthropic's documented rates.

        Cache writes are billed at 1.25x the base input rate; cache
        reads at 0.1x. Output tokens are billed at the standard output
        rate. ``input_tokens`` already excludes cache_read /
        cache_creation tokens per Anthropic's API contract — we add
        the cache contributions on top rather than substituting.
        """
        in_per_m, out_per_m = self._price
        cost = (
            response.input_tokens * in_per_m
            + response.output_tokens * out_per_m
            + response.cache_write_tokens * in_per_m * ANTHROPIC_CACHE_WRITE_MULTIPLIER
            + response.cache_read_tokens * in_per_m * ANTHROPIC_CACHE_READ_MULTIPLIER
        ) / 1_000_000.0
        return cost

    # ------------------------------------------------------------------
    # The turn primitive
    # ------------------------------------------------------------------

    def turn(
        self,
        messages: Sequence[Message],
        tools: Sequence[ToolDef],
        *,
        system: str | None = None,
        max_tokens: int = 4096,
        cache_control: CacheControl = CacheControl(),
        anthropic_task_budget_beta: bool = False,
        **_unused: Any,
    ) -> TurnResponse:
        """Send one round-trip to Anthropic.

        Provider-specific kwargs:
          * ``anthropic_task_budget_beta``: route via
            ``client.beta.messages.create`` (cost-cap beta endpoint).

        Transient errors (APIConnectionError, 429, 5xx) are retried
        internally with exponential backoff up to ``max_retries``
        configured at construction. Permanent errors (4xx other than
        429) fail fast and surface as ``StopReason.ERROR``.
        Unrecognised provider-specific kwargs are logged at debug
        level and ignored — preserves graceful degradation across
        consumers but makes typos discoverable.
        """
        if _unused:
            logger.debug(
                "anthropic.turn: ignoring unrecognised kwargs: %s",
                sorted(_unused),
            )
        # ---- system ----------------------------------------------------
        # Anthropic accepts a string OR a list-of-content-blocks. We use
        # the list form when caching the system prompt so we can attach
        # the cache_control marker; otherwise we send the simpler string.
        system_arg: str | list[dict[str, Any]] | None
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

        # ---- tools -----------------------------------------------------
        tool_schemas: list[dict[str, Any]] = [
            {
                "name": t.name,
                "description": t.description,
                "input_schema": t.input_schema,
            }
            for t in tools
        ]
        if cache_control.tools and tool_schemas:
            # Anthropic places the cache marker on the LAST tool —
            # caches the entire tools array up to and including it.
            last = dict(tool_schemas[-1])
            last["cache_control"] = {"type": "ephemeral"}
            tool_schemas[-1] = last

        # ---- messages --------------------------------------------------
        wire_messages = [_message_to_wire(m) for m in messages]
        if (
            cache_control.history_through_index is not None
            and 0 <= cache_control.history_through_index < len(wire_messages)
        ):
            _add_cache_marker_to_last_block(
                wire_messages[cache_control.history_through_index],
            )

        # ---- dispatch --------------------------------------------------
        # Routing to ``client.beta.messages.create`` is necessary but
        # not sufficient — Anthropic's beta endpoint only activates a
        # beta when its name appears in the ``betas=[...]`` request
        # parameter. Without it the call goes through but the beta is
        # not in effect, silently undoing the opt-in.
        create_fn = (
            self._client.beta.messages.create
            if anthropic_task_budget_beta
            else self._client.messages.create
        )
        kwargs: dict[str, Any] = {
            "model": self._model,
            "max_tokens": max_tokens,
            "messages": wire_messages,
            "tools": tool_schemas if tool_schemas else None,
        }
        if anthropic_task_budget_beta:
            kwargs["betas"] = [_TASK_BUDGET_BETA]
        if system_arg is not None:
            kwargs["system"] = system_arg

        # Retry loop: transient errors get up to ``self._max_retries``
        # additional attempts after the first, with exponential backoff.
        # Permanent errors (4xx other than 429) fail fast — burning the
        # cost budget on hopeless retries helps no-one.
        send_kwargs = {k: v for k, v in kwargs.items() if v is not None}
        resp = None
        last_exc: BaseException | None = None
        for attempt in range(self._max_retries + 1):
            try:
                resp = create_fn(**send_kwargs)
                break
            except (APIConnectionError, APIStatusError, APIError) as exc:
                last_exc = exc
                if not _is_transient(exc) or attempt >= self._max_retries:
                    logger.warning(
                        "anthropic.turn: %s error after %d attempt(s): %s",
                        "transient" if _is_transient(exc) else "permanent",
                        attempt + 1, exc,
                    )
                    return TurnResponse(
                        content=[],
                        stop_reason=StopReason.ERROR,
                        input_tokens=0,
                        output_tokens=0,
                    )
                delay = self._backoff_factor ** attempt
                logger.info(
                    "anthropic.turn: transient error attempt %d, "
                    "retrying in %.1fs: %s",
                    attempt + 1, delay, exc,
                )
                time.sleep(delay)
        if resp is None:
            # Defensive — should be unreachable since the loop either
            # breaks with resp set or returns on exhaustion.
            logger.warning(
                "anthropic.turn: retry loop exited without response: %s",
                last_exc,
            )
            return TurnResponse(
                content=[],
                stop_reason=StopReason.ERROR,
                input_tokens=0,
                output_tokens=0,
            )

        # ---- normalise -------------------------------------------------
        stop = _STOP_REASON_MAP.get(resp.stop_reason or "", StopReason.ERROR)
        out_blocks: list[TextBlock | ToolCall] = []
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
            # Other block types (e.g., thinking) are silently dropped —
            # they don't contribute to the loop's tool-dispatch logic.

        usage = resp.usage
        # ``cache_read_input_tokens`` and ``cache_creation_input_tokens``
        # are ``Optional[int]`` on the SDK's ``Usage`` model and arrive
        # as ``None`` when caching wasn't used. ``getattr(..., 0)``
        # only kicks in for *missing* attributes — None is a real value
        # there, so we ``or 0`` to coerce it to the int the
        # ``TurnResponse`` int-typed fields expect.
        return TurnResponse(
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


# ---------------------------------------------------------------------------
# Wire-format converters
# ---------------------------------------------------------------------------


def _message_to_wire(m: Message) -> dict[str, Any]:
    """One :class:`Message` → Anthropic wire dict.

    Anthropic accepts mixed content lists per turn — text, tool_use, and
    tool_result blocks all live in the same ``content`` array, role
    determines which subset is valid (assistant: text + tool_use; user:
    text + tool_result).
    """
    out_content: list[dict[str, Any]] = []
    for block in m.content:
        if isinstance(block, TextBlock):
            out_content.append({"type": "text", "text": block.text})
        elif isinstance(block, ToolCall):              # assistant role only
            out_content.append({
                "type": "tool_use",
                "id": block.id,
                "name": block.name,
                "input": block.input,
            })
        elif isinstance(block, ToolResult):            # user role only
            out_content.append({
                "type": "tool_result",
                "tool_use_id": block.tool_use_id,
                "content": block.content,
                "is_error": block.is_error,
            })
    return {"role": m.role, "content": out_content}


def _add_cache_marker_to_last_block(message: dict[str, Any]) -> None:
    """Mutate ``message["content"][-1]`` in-place to carry a cache_control
    marker. Anthropic places the marker on the LAST block of a region
    to cache everything preceding it within that message."""
    if not message["content"]:
        return
    last = dict(message["content"][-1])
    last["cache_control"] = {"type": "ephemeral"}
    message["content"][-1] = last
