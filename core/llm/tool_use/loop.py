"""Provider-agnostic agentic tool-use runner.

Multi-turn loop, in order per iteration:

1. Cost budget check: if cumulative cost ≥ ``max_cost_usd``, raise
   :class:`CostBudgetExceeded`.
2. Context window check: estimate request tokens; if it would overflow
   the model's context, apply :class:`ContextPolicy` — ``RAISE``
   raises :class:`ContextOverflow`, ``TRUNCATE_OLDEST`` drops oldest
   user/assistant pairs (then raises ``ContextOverflow`` if the
   trailing message itself can't fit).
3. Call ``provider.turn()`` with current messages + tools.
4. Append the model's response to messages.
5. If response ``stop_reason == COMPLETE``, terminate with reason
   ``complete`` and the joined text from this turn.
6. If response ``stop_reason == PAUSE_TURN``, continue to next
   iteration without dispatching anything (Anthropic extended-thinking
   pause; conversation resumes by re-sending the same messages).
7. If response carries no tool calls and is none of the above, the
   model gave up mid-turn — terminate with ``max_tokens``, ``refused``,
   or ``provider_error`` per the response's stop reason.
8. Otherwise, dispatch each :class:`ToolCall` block. Handler exception
   or :class:`ToolHandlerTimeout` either becomes an ``is_error=True``
   :class:`ToolResult` (default) or terminates the loop with reason
   ``tool_error`` and re-raises (``terminate_on_handler_error=True``).
9. Append tool results as one user message.
10. If any dispatched call had ``call.name == terminal_tool`` and
    succeeded, terminate with ``terminal_tool`` and surface the model's
    structured input via :attr:`ToolLoopResult.terminal_tool_input`.

Cap at ``max_iterations`` regardless.

Every termination emits a :class:`LoopTerminated` event and returns a
:class:`ToolLoopResult` (or raises, for ``CostBudgetExceeded`` /
``ContextOverflow`` / handler exceptions under
``terminate_on_handler_error=True``). Callers distinguish outcomes via
:attr:`ToolLoopResult.terminated_by` — same string set as
:attr:`LoopTerminated.reason`.
"""

from __future__ import annotations

import json
import re
import threading
import time
from collections.abc import Callable, Sequence
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from core.llm.providers import LLMProvider

from .types import (
    CacheControl,
    ContextOverflow,
    ContextPolicy,
    CostBudgetExceeded,
    LoopEvent,
    LoopTerminated,
    Message,
    StopReason,
    TextBlock,
    ToolCall,
    ToolCallBlocked,
    ToolCallDispatched,
    ToolCallReturned,
    ToolDef,
    ToolHandlerTimeout,
    ToolLoopResult,
    ToolResult,
    TurnCompleted,
    TurnResponse,
    TurnStarted,
)


class ToolUseLoop:
    """Run an agentic conversation until termination.

    Tools are static for the lifetime of one ``run()`` / ``run_with_history()``
    call. Phase-shifted toolsets (e.g., discovery tools early, refinement
    tools later) need a fresh :class:`ToolUseLoop` instance per phase —
    explicit by design, not an oversight.

    Handlers run synchronously; ``tool_timeout_s`` is enforced on a
    best-effort basis via a watchdog thread (the handler keeps running
    in the background if it doesn't honour cancellation, but the loop
    stops waiting for it). Async handlers / true cancellation come via
    a parallel ``AsyncToolUseLoop`` if/when a real consumer needs it.
    """

    def __init__(
        self,
        provider: "LLMProvider",
        tools: Sequence[ToolDef],
        *,
        system: str | None = None,
        terminal_tool: str | None = None,
        max_iterations: int = 50,
        max_cost_usd: float | None = None,
        max_seconds: float | None = None,
        max_total_tokens: int | None = None,
        tool_timeout_s: float | None = None,
        context_policy: ContextPolicy = ContextPolicy.RAISE,
        max_tokens_per_turn: int = 4096,
        cache_control: CacheControl = CacheControl(),
        events: Callable[[LoopEvent], None] | None = None,
        terminate_on_handler_error: bool = False,
        **provider_specific: Any,
    ) -> None:
        if not provider.supports_tool_use():
            raise ValueError(
                "ToolUseLoop requires a provider with tool-use support; "
                "the bound model rejects it"
            )
        self._provider = provider
        self._tools = list(tools)
        self._tools_by_name: dict[str, ToolDef] = {t.name: t for t in tools}
        if len(self._tools_by_name) != len(self._tools):
            raise ValueError(
                "ToolUseLoop tools must have unique names; "
                "duplicate handler binding would dispatch ambiguously"
            )
        if terminal_tool is not None and terminal_tool not in self._tools_by_name:
            raise ValueError(
                f"ToolUseLoop terminal_tool {terminal_tool!r} is not in the "
                "registered tools; loop would never terminate via that path"
            )
        if not isinstance(max_iterations, int) or max_iterations < 1:
            # Reject 0 (loop terminates before any work is done — looks
            # like a "max iterations hit" outcome but actually no LLM
            # call was made; misleading) and negative (loop would never
            # hit the cap — the comparison `iterations > max_iterations`
            # is always False for non-negative iters when max_iter is
            # negative, producing an infinite loop bounded only by the
            # cost / token / wall-clock caps if those happen to be set).
            raise ValueError(
                f"ToolUseLoop max_iterations must be a positive int; "
                f"got {max_iterations!r}"
            )

        self._system = system
        self._terminal_tool = terminal_tool
        self._max_iterations = max_iterations
        self._max_cost_usd = max_cost_usd
        self._max_seconds = max_seconds
        self._max_total_tokens = max_total_tokens
        self._tool_timeout_s = tool_timeout_s
        self._context_policy = context_policy
        self._max_tokens_per_turn = max_tokens_per_turn
        self._cache_control = cache_control
        self._events = events
        self._terminate_on_handler_error = terminate_on_handler_error
        self._provider_specific = provider_specific

    # ------------------------------------------------------------------
    # Public entrypoints
    # ------------------------------------------------------------------

    def run(self, prompt: str) -> ToolLoopResult:
        """Convenience wrapper — equivalent to
        ``run_with_history([], prompt)``. Use this when starting fresh."""
        return self.run_with_history([], prompt)

    def run_with_history(
        self,
        history: list[Message],
        next_message: str,
    ) -> ToolLoopResult:
        """Resume from a prior conversation. ``history`` is treated as
        immutable input — the returned :attr:`ToolLoopResult.messages`
        is a new list including ``history`` + everything appended this
        run, suitable for persisting back to disk.
        """
        messages: list[Message] = list(history)
        if next_message:
            messages.append(Message(
                role="user",
                content=[TextBlock(text=next_message)],
            ))

        total_input_tokens = 0
        total_output_tokens = 0
        total_cost_usd = 0.0
        tool_calls_made = 0
        terminal_tool_input: dict[str, Any] | None = None
        wall_start = time.monotonic()

        # x-source: seed known_values from prompt + history
        known_values: set[str] = set()
        if next_message:
            known_values |= _extract_tokens_from_text(next_message)
        for msg in history:
            for block in msg.content:
                if isinstance(block, TextBlock):
                    known_values |= _extract_tokens_from_text(block.text)
                elif isinstance(block, ToolResult) and not block.is_error:
                    known_values |= _extract_values_from_json(block.content)

        for iteration in range(self._max_iterations):
            # ---- pre-flight: cost budget --------------------------------
            if (
                self._max_cost_usd is not None
                and total_cost_usd >= self._max_cost_usd
            ):
                self._emit(LoopTerminated(
                    reason="max_cost_usd",
                    iterations=iteration,
                    total_cost_usd=total_cost_usd,
                ))
                raise CostBudgetExceeded(
                    f"cost budget ${self._max_cost_usd:.4f} reached "
                    f"(cumulative ${total_cost_usd:.4f}); aborting "
                    "before next turn"
                )

            # ---- pre-flight: wall-clock budget --------------------------
            # Caps the *whole run*, not per-turn. Useful when the loop
            # is bounded by API latency on slow days (e.g., Anthropic
            # 529-overloaded waves) where ``max_iterations`` and
            # ``max_cost_usd`` haven't fired but the operator-side
            # SLA has. Pre-flight only — a single in-flight ``turn()``
            # can blow past the cap because we don't preempt it.
            if (
                self._max_seconds is not None
                and (time.monotonic() - wall_start) >= self._max_seconds
            ):
                self._emit(LoopTerminated(
                    reason="max_seconds",
                    iterations=iteration,
                    total_cost_usd=total_cost_usd,
                ))
                return ToolLoopResult(
                    final_text="",
                    terminal_tool_input=None,
                    messages=messages,
                    iterations=iteration,
                    tool_calls_made=tool_calls_made,
                    total_input_tokens=total_input_tokens,
                    total_output_tokens=total_output_tokens,
                    total_cost_usd=total_cost_usd,
                    terminated_by="max_seconds",
                )

            # ---- pre-flight: total-tokens budget ------------------------
            # Sums input+output across turns. Cache-region tokens are
            # accounted in ``compute_cost`` (and thus ``max_cost_usd``)
            # but not added here — the cost cap is the load-bearing
            # gate; this is a belt-and-braces parity check with
            # consumer-side budgets like cve-diff's ``budget_tokens``.
            if (
                self._max_total_tokens is not None
                and (total_input_tokens + total_output_tokens)
                    >= self._max_total_tokens
            ):
                self._emit(LoopTerminated(
                    reason="max_total_tokens",
                    iterations=iteration,
                    total_cost_usd=total_cost_usd,
                ))
                return ToolLoopResult(
                    final_text="",
                    terminal_tool_input=None,
                    messages=messages,
                    iterations=iteration,
                    tool_calls_made=tool_calls_made,
                    total_input_tokens=total_input_tokens,
                    total_output_tokens=total_output_tokens,
                    total_cost_usd=total_cost_usd,
                    terminated_by="max_total_tokens",
                )

            # ---- pre-flight: context window -----------------------------
            request_estimate = self._estimate_request_tokens(messages)
            window = self._provider.context_window()
            if request_estimate >= window:
                if self._context_policy is ContextPolicy.RAISE:
                    self._emit(LoopTerminated(
                        reason="context_overflow",
                        iterations=iteration,
                        total_cost_usd=total_cost_usd,
                    ))
                    raise ContextOverflow(
                        f"request estimate ~{request_estimate} tokens "
                        f"would exceed model context window {window}; "
                        "set context_policy=TRUNCATE_OLDEST or shorten "
                        "input"
                    )
                # TRUNCATE_OLDEST: drop oldest user/assistant pair until
                # estimate fits. Pairing-aware so tool_use/tool_result
                # links can't dangle.
                messages = self._truncate_oldest(messages, window)

            cache_breakpoints = self._count_cache_breakpoints(messages)
            self._emit(TurnStarted(
                iteration=iteration,
                input_token_estimate=request_estimate,
                cache_breakpoints=cache_breakpoints,
            ))

            # ---- the turn -----------------------------------------------
            try:
                response = self._provider.turn(
                    messages,
                    self._tools,
                    system=self._system,
                    max_tokens=self._max_tokens_per_turn,
                    cache_control=self._cache_control,
                    **self._provider_specific,
                )
            except Exception:
                self._emit(LoopTerminated(
                    reason="provider_error",
                    iterations=iteration,
                    total_cost_usd=total_cost_usd,
                ))
                raise

            cost = self._provider.compute_cost(response)
            total_cost_usd += cost
            total_input_tokens += response.input_tokens
            total_output_tokens += response.output_tokens
            self._emit(TurnCompleted(
                iteration=iteration,
                response=response,
                cost_usd=cost,
            ))

            # Append the assistant turn to history.
            messages.append(Message(
                role="assistant",
                content=list(response.content),
            ))

            # ---- termination by stop_reason -----------------------------
            if response.stop_reason is StopReason.COMPLETE:
                final_text = _join_text(response.content)
                self._emit(LoopTerminated(
                    reason="complete",
                    iterations=iteration + 1,
                    total_cost_usd=total_cost_usd,
                ))
                return ToolLoopResult(
                    final_text=final_text,
                    terminal_tool_input=None,
                    messages=messages,
                    iterations=iteration + 1,
                    tool_calls_made=tool_calls_made,
                    total_input_tokens=total_input_tokens,
                    total_output_tokens=total_output_tokens,
                    total_cost_usd=total_cost_usd,
                    terminated_by="complete",
                )

            # ---- PAUSE_TURN: model pause-resumed extended thinking ----
            if response.stop_reason is StopReason.PAUSE_TURN:
                # The provider signalled an extended-thinking pause —
                # the conversation continues by re-sending the messages
                # array (including the partial assistant turn we just
                # appended) without a new user message. The loop falls
                # through to the next iteration; nothing to dispatch.
                continue

            # ---- gather tool calls --------------------------------------
            tool_calls = [b for b in response.content if isinstance(b, ToolCall)]
            if not tool_calls:
                # No tool calls AND not COMPLETE/PAUSE_TURN — model gave
                # up mid-turn. Map to the matching termination reason
                # (max_tokens / refused / provider_error) so callers can
                # tell the difference.
                term_reason = _stop_reason_to_term(response.stop_reason)
                # Forward error_message from the provider's TurnResponse
                # so callers can present the actual error rather than
                # only seeing it in warning logs.
                err = response.error_message
                self._emit(LoopTerminated(
                    reason=term_reason,
                    iterations=iteration + 1,
                    total_cost_usd=total_cost_usd,
                    error_message=err,
                ))
                return ToolLoopResult(
                    final_text=_join_text(response.content),
                    terminal_tool_input=None,
                    messages=messages,
                    iterations=iteration + 1,
                    tool_calls_made=tool_calls_made,
                    total_input_tokens=total_input_tokens,
                    total_output_tokens=total_output_tokens,
                    total_cost_usd=total_cost_usd,
                    terminated_by=term_reason,    # type: ignore[arg-type]
                    error_message=err,
                )

            # ---- dispatch tools -----------------------------------------
            # Both handler exceptions and handler timeouts behave the
            # same under ``terminate_on_handler_error=True``: emit
            # LoopTerminated(reason="tool_error") then re-raise (the
            # original exception for handler errors; ToolHandlerTimeout
            # for timeouts). Without that flag, both convert the failure
            # to an ``is_error=True`` ToolResult and continue.
            tool_results: list[ToolResult] = []
            for call in tool_calls:
                tool_calls_made += 1
                self._emit(ToolCallDispatched(iteration=iteration, call=call))

                # ---- x-source pre-dispatch validation ----
                discovered = _get_discovered_fields(
                    self._tools_by_name.get(call.name),
                )
                blocked: dict[str, str] = {}
                for field in discovered:
                    val = call.input.get(field)
                    if isinstance(val, str) and val not in known_values:
                        blocked[field] = val

                if blocked:
                    self._emit(ToolCallBlocked(
                        iteration=iteration,
                        call=call,
                        blocked_fields=blocked,
                    ))
                    result = ToolResult(
                        tool_use_id=call.id,
                        content=(
                            "x-source validation: "
                            + ", ".join(
                                f"{f}={v!r}" for f, v in sorted(blocked.items())
                            )
                            + " not found in prompt or prior tool outputs. "
                            "Discover these values first."
                        ),
                        is_error=True,
                    )
                    duration = 0.0
                else:
                    start = time.monotonic()
                    try:
                        result = self._dispatch_one(call)
                    except ToolHandlerTimeout as exc:
                        if self._terminate_on_handler_error:
                            self._emit(LoopTerminated(
                                reason="tool_error",
                                iterations=iteration + 1,
                                total_cost_usd=total_cost_usd,
                            ))
                            raise
                        result = ToolResult(
                            tool_use_id=call.id,
                            content=str(exc),
                            is_error=True,
                        )
                    except Exception as exc:
                        if self._terminate_on_handler_error:
                            self._emit(LoopTerminated(
                                reason="tool_error",
                                iterations=iteration + 1,
                                total_cost_usd=total_cost_usd,
                            ))
                            raise
                        result = ToolResult(
                            tool_use_id=call.id,
                            content=f"handler error: {exc}",
                            is_error=True,
                        )
                    duration = time.monotonic() - start

                self._emit(ToolCallReturned(
                    iteration=iteration,
                    call_id=call.id,
                    result=result,
                    duration_s=duration,
                ))
                tool_results.append(result)

                if (
                    self._terminal_tool is not None
                    and call.name == self._terminal_tool
                    and not result.is_error
                ):
                    terminal_tool_input = dict(call.input)

            # Append tool results as user message — this keeps multi-call
            # batches in one message, matching Anthropic's wire shape.
            messages.append(Message(role="user", content=list(tool_results)))

            # x-source: grow known_values from successful results
            for tr in tool_results:
                if not tr.is_error:
                    known_values |= _extract_values_from_json(tr.content)

            # ---- post-dispatch termination checks -----------------------
            if terminal_tool_input is not None:
                self._emit(LoopTerminated(
                    reason="terminal_tool",
                    iterations=iteration + 1,
                    total_cost_usd=total_cost_usd,
                ))
                return ToolLoopResult(
                    final_text=_join_text(response.content),
                    terminal_tool_input=terminal_tool_input,
                    messages=messages,
                    iterations=iteration + 1,
                    tool_calls_made=tool_calls_made,
                    total_input_tokens=total_input_tokens,
                    total_output_tokens=total_output_tokens,
                    total_cost_usd=total_cost_usd,
                    terminated_by="terminal_tool",
                )

        # ---- max_iterations hit -----------------------------------------
        self._emit(LoopTerminated(
            reason="max_iterations",
            iterations=self._max_iterations,
            total_cost_usd=total_cost_usd,
        ))
        return ToolLoopResult(
            final_text="",
            terminal_tool_input=None,
            messages=messages,
            iterations=self._max_iterations,
            tool_calls_made=tool_calls_made,
            total_input_tokens=total_input_tokens,
            total_output_tokens=total_output_tokens,
            total_cost_usd=total_cost_usd,
            terminated_by="max_iterations",
        )

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _emit(self, event: LoopEvent) -> None:
        if self._events is not None:
            self._events(event)

    def _dispatch_one(self, call: ToolCall) -> ToolResult:
        """Invoke the handler for ``call.name`` with optional timeout
        watchdog. Raises :class:`ToolHandlerTimeout` if the wall-clock
        deadline is exceeded; lets handler exceptions propagate so the
        caller can decide between feed-back-to-model (default) and
        terminate-on-error."""
        tool = self._tools_by_name.get(call.name)
        if tool is None:
            return ToolResult(
                tool_use_id=call.id,
                content=f"unknown tool: {call.name!r}",
                is_error=True,
            )

        if self._tool_timeout_s is None:
            content = tool.handler(call.input)
            return ToolResult(tool_use_id=call.id, content=content)

        # Best-effort timeout: run the handler on a thread; the parent
        # waits up to ``tool_timeout_s``. If the timeout fires the
        # handler keeps running but we stop waiting — leak documented
        # in the class docstring.
        result_holder: dict[str, Any] = {}
        exc_holder: dict[str, BaseException] = {}

        def _runner() -> None:
            try:
                result_holder["text"] = tool.handler(call.input)
            except BaseException as e:                    # noqa: BLE001
                exc_holder["exc"] = e

        thread = threading.Thread(target=_runner, daemon=True)
        thread.start()
        thread.join(self._tool_timeout_s)
        if thread.is_alive():
            raise ToolHandlerTimeout(
                f"tool {call.name!r} exceeded {self._tool_timeout_s}s timeout"
            )
        if "exc" in exc_holder:
            captured = exc_holder["exc"]
            if isinstance(captured, Exception):
                # Regular handler exception — re-raise as-is so the
                # loop's per-tool error path (terminate-on-error vs
                # feed-back-to-model) sees the original exception
                # type for logging / debugging.
                raise captured
            # BaseException-but-not-Exception (KeyboardInterrupt,
            # SystemExit, GeneratorExit) raised inside a daemon
            # thread is already weird — Python's signal handler
            # only fires on the main thread, so a Ctrl-C during a
            # tool call lands here. Re-raising the original on the
            # main thread would propagate out of the loop entirely
            # (BaseException isn't caught by the loop's
            # `except Exception`), which silently terminates the
            # whole orchestration. Wrap as a regular Exception so
            # the per-tool error path sees it like any other
            # handler failure; the operator can re-Ctrl-C if they
            # really want to abort.
            raise RuntimeError(
                f"tool {call.name!r} handler raised "
                f"{type(captured).__name__} (non-Exception BaseException)"
            ) from captured
        return ToolResult(tool_use_id=call.id, content=result_holder["text"])

    def _estimate_static_tokens(self) -> int:
        """System + tools cost. Doesn't change across iterations of a
        single ``run_with_history`` call, so cache the result on first
        compute. Tools are rendered as ``name + description + str(input_schema)``
        — a 4-char-per-token estimator over that text is good enough
        for the context-policy gate (over-estimating triggers the gate
        early, the safe direction)."""
        cached = getattr(self, "_static_tokens_cache", None)
        if cached is not None:
            return cached
        total = 0
        if self._system:
            total += self._provider.estimate_tokens(self._system)
        for t in self._tools:
            total += self._provider.estimate_tokens(
                t.name + t.description + str(t.input_schema)
            )
        self._static_tokens_cache = total                  # type: ignore[attr-defined]
        return total

    def _estimate_message_tokens(self, m: Message) -> int:
        """Estimate of one message's contribution to a request."""
        total = 0
        for block in m.content:
            if isinstance(block, TextBlock):
                total += self._provider.estimate_tokens(block.text)
            elif isinstance(block, ToolCall):
                total += self._provider.estimate_tokens(
                    block.name + str(block.input)
                )
            elif isinstance(block, ToolResult):
                total += self._provider.estimate_tokens(block.content)
        return total

    def _estimate_request_tokens(self, messages: Sequence[Message]) -> int:
        """Coarse pre-flight estimate — system + tools + every message.

        Used purely for the context-policy gate; an over-estimate just
        triggers the gate slightly early (truncation kicks in or RAISE
        fires) which is the safe direction.
        """
        return self._estimate_static_tokens() + sum(
            self._estimate_message_tokens(m) for m in messages
        )

    def _count_cache_breakpoints(self, messages: Sequence[Message]) -> int:
        """How many regions opted in for caching this turn. Reported in
        :class:`TurnStarted` events for telemetry; doesn't drive
        behaviour."""
        if not self._provider.supports_prompt_caching():
            return 0
        n = 0
        if self._cache_control.system and self._system:
            n += 1
        if self._cache_control.tools and self._tools:
            n += 1
        if (
            self._cache_control.history_through_index is not None
            and 0 <= self._cache_control.history_through_index < len(messages)
        ):
            n += 1
        return n

    def _truncate_oldest(
        self,
        messages: list[Message],
        window: int,
    ) -> list[Message]:
        """Drop oldest user/assistant pairs until estimate fits.

        Pairing-aware: a user-role message carrying :class:`ToolResult`\\ s
        is a *response* to the prior assistant turn. We never drop a
        ToolResult message without also dropping its matching ToolCall,
        otherwise the next ``provider.turn()`` rejects the conversation
        as malformed.

        Cost is computed incrementally — drop a message, subtract its
        per-message estimate, check total. Avoids re-walking the full
        history on every truncation step (was O(N²) in v1; now O(N)).

        Raises :class:`ContextOverflow` if even after dropping every
        droppable message the request would still exceed ``window`` —
        e.g., a single trailing user message larger than the model's
        context. Silently sending an oversized request would mis-gate.
        """
        static = self._estimate_static_tokens()
        per_msg = [self._estimate_message_tokens(m) for m in messages]
        total = static + sum(per_msg)

        while total >= window and len(messages) > 1:
            # Drop oldest message; track its cost to subtract.
            head = messages.pop(0)
            total -= per_msg.pop(0)
            # If the dropped message was an assistant turn that carried
            # tool_calls, the next message is the user turn carrying
            # matching tool_results — drop it too so the link doesn't
            # dangle (provider would reject a tool_result without a
            # matching tool_use).
            if (
                head.role == "assistant"
                and any(isinstance(b, ToolCall) for b in head.content)
                and messages
                and messages[0].role == "user"
                and any(isinstance(b, ToolResult) for b in messages[0].content)
            ):
                messages.pop(0)
                total -= per_msg.pop(0)

        if total >= window:
            raise ContextOverflow(
                f"request estimate ~{total} tokens still exceeds window "
                f"{window} after truncating to {len(messages)} message(s); "
                "the trailing message itself is too large — shorten the "
                "prompt or use a model with a bigger context"
            )
        return messages


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _join_text(content: Sequence[Any]) -> str:
    """Concatenate :class:`TextBlock` items in ``content``, ignoring
    other block types. Used for ``ToolLoopResult.final_text``."""
    return "".join(b.text for b in content if isinstance(b, TextBlock))


def _stop_reason_to_term(reason: StopReason) -> str:
    """Map a :class:`StopReason` from a turn that emitted no tool calls
    to a :attr:`ToolLoopResult.terminated_by` value.

    Each reason is preserved distinctly — callers care about the
    difference between a content-filter refusal, a truncated response,
    and a transport error. Collapsing them all to ``provider_error``
    (as the v1 mapping did) lost information the caller needed.

    ``NEEDS_TOOL_CALL`` and ``PAUSE_TURN`` are filtered out before this
    function is called (they're continue-not-terminate states), but
    they're mapped here defensively in case future callers route
    differently.
    """
    return {
        StopReason.COMPLETE: "complete",
        StopReason.MAX_TOKENS: "max_tokens",
        StopReason.REFUSED: "refused",
        StopReason.ERROR: "provider_error",
        StopReason.NEEDS_TOOL_CALL: "provider_error",  # impossible-state
        StopReason.PAUSE_TURN: "provider_error",       # impossible-state
    }.get(reason, "provider_error")


# ---------------------------------------------------------------------------
# x-source provenance helpers
# ---------------------------------------------------------------------------

_TOKEN_SPLIT = re.compile(r"[\s,;|\"'`(){}\[\]]+")
_MIN_TOKEN_LEN = 3
_MAX_KNOWN_VALUES = 50_000


def _extract_tokens_from_text(text: str) -> set[str]:
    """Split free text into candidate known-value tokens.

    Splits on whitespace/punctuation, strips edge junk, includes
    slash-split components (``"owner/repo"`` yields both the whole
    string and ``"owner"``, ``"repo"``).
    """
    values: set[str] = set()
    for raw in _TOKEN_SPLIT.split(text):
        token = raw.strip(".,;:!?()[]{}\"'<>")
        if len(token) < _MIN_TOKEN_LEN:
            continue
        values.add(token)
        if "/" in token:
            for part in token.split("/"):
                if len(part) >= _MIN_TOKEN_LEN:
                    values.add(part)
    return values


def _extract_values_from_json(text: str) -> set[str]:
    """Walk a JSON tool result and collect leaf strings."""
    try:
        obj = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return _extract_tokens_from_text(text)

    values: set[str] = set()

    def _walk(node: Any, depth: int = 0) -> None:
        if depth > 20 or len(values) >= _MAX_KNOWN_VALUES:
            return
        if isinstance(node, dict):
            for v in node.values():
                _walk(v, depth + 1)
        elif isinstance(node, list):
            for v in node:
                _walk(v, depth + 1)
        elif isinstance(node, str) and len(node) >= _MIN_TOKEN_LEN:
            values.add(node)
            if "/" in node:
                for part in node.split("/"):
                    if len(part) >= _MIN_TOKEN_LEN:
                        values.add(part)

    _walk(obj)
    return values


def _get_discovered_fields(tool: ToolDef | None) -> set[str]:
    """Return field names annotated ``"x-source": "discovered"``."""
    if tool is None:
        return set()
    props = tool.input_schema.get("properties", {})
    return {
        name
        for name, schema in props.items()
        if isinstance(schema, dict) and schema.get("x-source") == "discovered"
    }
