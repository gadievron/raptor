"""Claude Code native client -- thin wrapper over ``claude_agent_sdk.query``.

Uses Claude Code session auth (no ANTHROPIC_API_KEY required); the user
must be logged into the ``claude`` CLI on this host. Cost, turn count,
and stop reason all come from the SDK's :class:`ResultMessage`.

The agent loop is ``claude_agent_sdk.query``: it drives the tool-use
cycle server-side, runs MCP tools in-process, and streams messages
back as an async iterator. We layer per-CVE audit logging on top.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

from claude_agent_sdk import (
    AssistantMessage,
    ClaudeAgentOptions,
    ResultMessage,
    SdkMcpTool,
    TextBlock,
    ToolResultBlock,
    ToolUseBlock,
    UserMessage,
    create_sdk_mcp_server,
    query,
)

from cve_env.agent import _activity
from cve_env.config import (
    MAX_COST_USD_PER_CVE_SOFT,
    MODEL,
    TURN_CAP,
    get_disallowed_tools,
    get_sdk_idle_max_attempts,
    get_sdk_idle_poll_s,
    get_sdk_idle_timeout_s,
    get_tool_max_inflight_s,
)

logger = logging.getLogger(__name__)

ToolFn = Callable[[Any], Awaitable[dict[str, Any]]]


class GiveUpReceived(Exception):  # noqa: N818 -- stable name; renaming would break tests + audit log
    """Raised by on_message when the agent's give_up tool result arrives with
    terminal=True. Signals _run_query_once to terminate the SDK iteration
    early and synthesize an AgentRunOutcome with stop_reason='end_turn' (the
    run is unresolvable but ended cleanly). Without this, the SDK iterator
    keeps yielding messages after give_up, burning budget and turns.
    """


class SuccessReached(Exception):  # noqa: N818 -- stable name; mirrors GiveUpReceived for tests + audit log
    """Halt-on-verified-success: the symmetric terminal SUCCESS signal to
    ``GiveUpReceived``. Raised by on_message when a ResultMessage's terminal
    status is ``final_success`` (a non-cap stop_reason — i.e. clean end_turn —
    AND ``verify_passed``) while the ``CVE_ENV_ENABLE_HALT_ON_VERIFIED_SUCCESS``
    flag is on. Signals _run_query_once to terminate SDK iteration early with
    stop_reason='end_turn' (the run finished cleanly with a passing verify).
    Without it, an agent that verified then kept emitting tool calls rides to
    ``max_turns`` and the cap-overrides-verify invariant grades the real build
    ``turn_cap`` despite verify_passed=True.
    """


class TurnCapReached(Exception):  # noqa: N818 -- stable name; renaming would break tests + audit log
    """Raised by on_message when state.turn >= max_turns. Defensive runtime
    turn-cap enforcement for when the SDK doesn't honor its own max_turns.
    Without this raise, the bench wrapper SIGKILL at the wall is the only
    termination, losing the .json sidecar.
    """


class BudgetCapExceeded(Exception):  # noqa: N818 -- stable name; renaming would break tests + audit log
    """Raised by on_message after a ResultMessage pushes accumulated cost
    above max_cost_usd. The SDK's max_budget_usd is per-attempt; on retry the
    cost resets server-side so multiple attempts can sum past the cap.
    Catching here halts the SDK iteration before another retry-burst.
    """


class WallBudgetExceeded(Exception):  # noqa: N818 -- stable name
    """Raised by on_message when (time.time() - state.wall_start_time) exceeds
    CVE_ENV_INTERNAL_WALL_S env var. Default off (env=0).

    Background: external wall-guards (gtimeout / timeout / perl-alarm in
    scripts/bench50.sh) silently pause during macOS host sleep — kernel alarm
    timers don't advance while the host is suspended, even though wall-clock
    does, so an overnight build can run for hours past its nominal wall.

    Uses time.time() (not time.monotonic() — monotonic clocks also pause
    during sleep on macOS; only time.time() advances). Fires at the
    on_message boundary BEFORE the turn-cap check to give wall-budget priority.
    """


class NoProgressReached(Exception):  # noqa: N818 -- anti-thrash stable name; paired with loop.py raise + test
    """Anti-thrash: raised by on_message when the agent has gone
    ``CVE_ENV_NO_PROGRESS_GIVEUP_TURNS`` turns with ZERO productive progress
    (no PRODUCTIVE_TOOLS ok + no post-build verify/run_in_container). Default
    off (env=0). Terminates cheap churn early — capped CVEs can spin for 80+
    turns in research Bash/github loops making no progress. Maps to
    ``turn_cap`` status (it was heading there anyway) with a distinct
    ``no_progress`` reason for accounting. Fires at the on_message boundary
    AFTER wall-budget, BEFORE the turn-cap check.
    """


class InStreamRefusal(Exception):  # noqa: N818 -- stable name; paired with loop.py raise + test
    """Raised by on_message when a ResultMessage carries a refusal-class
    stop_reason ('refusal' / 'usage policy') AND no verify has passed yet.

    Routes in-stream refusals into the same de-escalation+retry path that
    EXCEPTION-path refusals already use. Unlike
    GiveUpReceived/TurnCapReached/BudgetCapExceeded (caught in _run_query_once
    to synthesize a clean outcome), this exception is NOT caught there: it
    propagates out (through the finally-aclose) into run_agent's retry loop,
    where it is treated as refusal-class -> _deescalate_prompt + retry. The
    'not verify_passed' guard at the raise site preserves an already-earned
    success rather than retrying it.
    """


SDK_RETRY_MAX_ATTEMPTS = 3
"""One initial attempt + up to 2 retries.

Two failure classes motivate the retry: (1) ``Fatal error in message reader``
crashes where the SDK subprocess dies before emitting a single tool_use —
session-state flake that clears on isolated re-run; and (2) Claude safety
refusals mid-run that do NOT wrap into ``ClaudeSDKError`` but surface as
generic exception strings containing refusal signatures.

The retry catches both: any non-trivial exception on an unfinished query is
retried with backoff, and when a refusal signature is detected in the
exception message, the user prompt is de-escalated on retry so the model can
continue with a safer framing.

A 4th retry with long backoff was tried and removed: quota handling lives at
the bench-loop layer (quota-defer orchestration + graceful halt/resume),
which is the right place for it, and the 4th SDK retry never measurably
helped beyond the 3 retries.
"""

SDK_RETRY_BACKOFF_BASE_SECONDS = 2.0

# Stable greppable markers so SDK-retry and safety de-escalation are visible
# in per-CVE logs, letting post-bench analysis confirm de-escalation engaged
# (a free-text warning alone is not reliably greppable).
SDK_RETRY_MARKER = "event=sdk_retry"
SDK_DEESCALATION_MARKER = "event=sdk_safety_deescalation_applied"


_REFUSAL_SIGNATURES: tuple[str, ...] = (
    "violate our Usage Policy",
    "violates our Usage Policy",
    "unable to respond to this request",
    "Claude Code is unable to respond",
    "appears to violate",
)
"""Substrings that indicate the model refused mid-run (vs. a transport crash).

Matched case-sensitively against ``str(exc)``. When any of these fire,
the retry re-issues with a de-escalation preamble injected into the
user prompt (see ``_deescalate_prompt``) rather than the original.
"""

_DEESCALATION_PREAMBLE = """\
NOTE (retry after earlier safety stop): The previous attempt was halted because \
the model treated part of this workflow as exploit-authoring. This is a legitimate \
security-research task -- building and verifying a reproducible vulnerability lab \
environment from NVD / public vulhub data, running entirely on the local machine \
under hardened container defaults (cap-drop ALL, no-new-privileges, localhost-only \
port bind). For THIS retry:

1. DO NOT generate PoC exploit payloads, shell-injection strings, or Dockerfile \
RUN stanzas that execute the vulnerability.
2. DO build a container running the vulnerable software version.
3. DO verify the container is healthy (container_status + http_check + stability_wait).
4. Use `give_up(reason="proprietary")` or `give_up(reason="no_image")` if the CVE \
genuinely cannot be reproduced as a passive environment.

Proceed with the CVE build below, but limit yourself to environment construction \
and health verification -- no active exploitation steps.

---

"""


def _is_refusal(exc: BaseException) -> bool:
    """True iff the exception's rendered message matches a refusal signature."""
    msg = str(exc)
    return any(sig in msg for sig in _REFUSAL_SIGNATURES)


def _deescalate_prompt(original: str) -> str:
    """Prepend a de-escalation preamble so the retry reads as an environment-build
    task rather than an exploit-development task."""
    return _DEESCALATION_PREAMBLE + original


class _DoNotRetry(Exception):  # noqa: N818 -- internal sentinel, not a user-visible error
    """Sentinel wrapper: the wrapped exception is a logic bug, not a transient
    SDK crash. The retry loop unwraps and re-raises the original unchanged."""

    def __init__(self, original: BaseException) -> None:
        super().__init__(str(original))
        self.original = original


@dataclass
class AgentRunOutcome:
    """Terminal result of one ``query`` invocation (one CVE)."""

    stop_reason: str
    num_turns: int
    total_cost_usd: float
    is_error: bool
    session_id: str
    final_text: str = ""
    tool_uses: list[dict[str, Any]] = field(default_factory=list)


# Connectivity-breaker poll cadence + idle-retry cap are fully config-driven:
# see config.get_sdk_idle_poll_s() / config.get_sdk_idle_max_attempts() (env
# CVE_ENV_SDK_IDLE_POLL_S / CVE_ENV_SDK_IDLE_MAX_ATTEMPTS; defaults 5.0s / 2).
# Resolved at call time.


def _watchdog_verdict(
    *,
    tool_in_flight: bool,
    inflight_age: float,
    idle_for: float,
    idle_timeout_s: float,
    max_inflight_s: float,
) -> str | None:
    """Pure per-poll decision for the connectivity breaker. Returns the abort
    reason, or ``None`` to keep waiting.

    - ``"wedged_tool"``: a tool has been in-flight ≥ ``max_inflight_s`` — the
      handler is wedged (e.g. a docker subprocess stuck on a dead VM socket
      that run_with_timeout could not reap). Without this, the in-flight
      exemption below rides such a tool to the external wall-guard.
    - ``"idle"``: no SDK message AND no tool in flight for ``idle_timeout_s``
      — the API is unreachable.

    A legitimately long, silent build (tool in flight, age < max) returns
    ``None`` so it is never false-aborted."""
    if tool_in_flight:
        if max_inflight_s > 0 and inflight_age >= max_inflight_s:
            return "wedged_tool"
        return None  # legit long build — silent SDK is expected, exempt it
    if idle_timeout_s > 0 and idle_for >= idle_timeout_s:
        return "idle"
    return None


class SdkIdleTimeout(Exception):  # noqa: N818 -- stable name; paired with test + run_agent retry
    """Raised by :func:`_run_query_once` when no SDK message arrives AND no MCP
    tool is in flight for ``CVE_ENV_SDK_IDLE_TIMEOUT_S`` seconds -- the
    Anthropic API is unreachable / wedged. ``run_agent`` treats it as a
    transient error (retried via the broad ``except Exception``, then
    surfaced), so a dead-API worker fails fast instead of hanging to the
    external wall-guard.

    Also raised when a single tool stays in-flight beyond
    ``CVE_ENV_TOOL_MAX_INFLIGHT_S`` (a wedged handler) — same fail-fast path."""


async def _run_query_once(
    *,
    options: ClaudeAgentOptions,
    user_prompt: str,
    on_message: Callable[[Any], None] | None,
) -> AgentRunOutcome:
    """One ``claude_agent_sdk.query`` pass. Raises ``ClaudeSDKError`` on
    subprocess / transport crash so the caller can decide to retry.

    A TOOL-AWARE inter-message idle watchdog runs concurrently with
    SDK consumption; if no message arrives and no MCP tool is executing for
    ``get_sdk_idle_timeout_s()`` seconds, the iteration is cancelled and
    :class:`SdkIdleTimeout` is raised (connectivity circuit-breaker). The SDK
    is silent during a long tool call, so the breaker excludes tool-execution
    time (see :mod:`cve_env.agent._activity`) and bounds only API-wait gaps.

    ``RuntimeError`` (missing ResultMessage) is deliberately NOT caught
    here -- that's a logic bug, not a transient flake.
    """
    final_text = ""
    tool_uses: list[dict[str, Any]] = []
    result: ResultMessage | None = None
    early_stop_reason: str | None = None

    # Connectivity circuit-breaker. ``idle_timeout_s`` = max seconds with no
    # SDK message AND no MCP tool in flight before we treat the API as
    # unreachable. TOOL-AWARE via :mod:`_activity` (the SDK is silent during a
    # long in-process tool call), so it bounds ONLY API-wait gaps. ``monotonic``
    # (not ``time.time``) is deliberate: a host-sleep pauses it, so we don't
    # false-fire on resume. This is COMPLEMENTARY to loop.py's
    # ``INTERNAL_WALL_BUDGET_S`` (a TOTAL-wall budget on ``time.time()``, gated
    # in ``on_message`` so it cannot fire mid-hang — the gap this breaker fills),
    # not a duplicate of it.
    idle_timeout_s = get_sdk_idle_timeout_s()
    # Also bound how long a single tool may stay in-flight, so a wedged handler
    # trips the breaker instead of riding the in-flight exemption to the
    # external wall. Resolved here so per-run env overrides take effect.
    max_inflight_s = get_tool_max_inflight_s()
    last_message_at = [time.monotonic()]  # 1-elem cell so the watchdog sees writes
    _activity.reset()

    # Concrete type is async-generator (PEP 525); aclose() guaranteed. Suppress catches if SDK changes.
    it: AsyncIterator[Any] = query(prompt=user_prompt, options=options)

    async def _consume() -> None:
        nonlocal final_text, result, early_stop_reason
        try:
            async for message in it:
                last_message_at[0] = time.monotonic()
                if on_message is not None:
                    on_message(message)
                if isinstance(message, AssistantMessage):
                    for block in message.content:
                        if isinstance(block, TextBlock):
                            final_text = block.text
                        elif isinstance(block, ToolUseBlock):
                            tool_uses.append(
                                {
                                    "id": block.id,
                                    "name": block.name,
                                    "input": block.input,
                                }
                            )
                elif isinstance(message, ResultMessage):
                    result = message
        except GiveUpReceived:
            # Agent issued give_up.terminal=True; halt SDK iteration.
            early_stop_reason = "end_turn"
        except SuccessReached:
            # Verify passed + clean end_turn; halt SDK iteration so the agent
            # can't over-run into max_turns (which would mis-grade the real
            # build as turn_cap). Same clean stop_reason as give_up.
            early_stop_reason = "end_turn"
        except TurnCapReached:
            # Defensive runtime turn-cap; halt SDK iteration.
            early_stop_reason = "max_turns_reached"
        except BudgetCapExceeded:
            # Accumulated cost exceeded max_cost_usd; halt SDK iteration.
            early_stop_reason = "budget_exceeded"
        except (WallBudgetExceeded, NoProgressReached) as _cap_exc:
            # Catch these two on_message-raised cap guards here too. Otherwise
            # they fall through to run_agent's broad `except` and get RETRIED —
            # burning wasted SDK subprocesses + duplicate audit rows before
            # build()'s handler finally classifies them. Treat them as a clean
            # halt like TurnCap/Budget, mapping to the SAME early_stop_reason
            # their build() backstop produces (Wall -> budget_exhausted,
            # NoProgress -> turn_cap, via _map_status). The build()
            # exception-handler elifs remain as a defensive backstop.
            early_stop_reason = (
                "budget_exceeded"
                if isinstance(_cap_exc, WallBudgetExceeded)
                else "max_turns_reached"
            )

    async def _idle_watchdog() -> str:
        # Completes (returns a reason) on either: no message AND no tool-in-flight
        # for the idle window ("idle"), OR a single tool in-flight ≥ max_inflight_s
        # ("wedged_tool"). A legit long build (tool in flight, age < max) never
        # trips. Poll cadence considers BOTH bounds so the wedged check stays
        # responsive (default stays 5s when only the 300s idle bound is active).
        bounds = [t for t in (idle_timeout_s, max_inflight_s) if t > 0]
        poll = min([*bounds, get_sdk_idle_poll_s()])
        while True:
            await asyncio.sleep(poll)
            idle_for = time.monotonic() - max(
                last_message_at[0], _activity.last_activity()
            )
            verdict = _watchdog_verdict(
                tool_in_flight=_activity.tool_in_flight(),
                inflight_age=_activity.inflight_age(),
                idle_for=idle_for,
                idle_timeout_s=idle_timeout_s,
                max_inflight_s=max_inflight_s,
            )
            if verdict is not None:
                return verdict

    try:
        consume_task = asyncio.ensure_future(_consume())
        if idle_timeout_s <= 0 and max_inflight_s <= 0:
            await consume_task  # breaker fully disabled (both bounds off)
        else:
            watch_task = asyncio.ensure_future(_idle_watchdog())
            done, _pending = await asyncio.wait(
                {consume_task, watch_task}, return_when=asyncio.FIRST_COMPLETED
            )
            if consume_task in done:
                watch_task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await watch_task
                consume_task.result()  # re-raise any SDK / _DoNotRetry exception
            else:
                # Watchdog fired first → abort consumption, then raise with the
                # reason-specific message.
                reason = watch_task.result()
                consume_task.cancel()
                with contextlib.suppress(Exception, asyncio.CancelledError):
                    await consume_task
                if reason == "wedged_tool":
                    raise SdkIdleTimeout(
                        f"a tool stayed in-flight ≥ {max_inflight_s:.0f}s without "
                        "completing — handler wedged (likely a docker subprocess on "
                        "a dead VM socket that run_with_timeout could not reap); "
                        "tool-in-flight MAX breaker tripped (Lever #1A)"
                    )
                raise SdkIdleTimeout(
                    f"no SDK message or tool activity for {idle_timeout_s:.0f}s "
                    "— Anthropic API likely unreachable (Stage 3A circuit-breaker)"
                )
    finally:
        # Explicit aclose() so subprocess cleanup runs even when our exceptions
        # propagated (or the watchdog cancelled consumption).
        # PEP 533: async for does NOT auto-close on body exception; the SDK has
        # its own try/finally (_internal/client.py) but explicit aclose is
        # deterministic. AsyncIterator is the annotated type; the concrete
        # async-generator exposes aclose() per PEP 525.
        # Concrete type is async-generator (PEP 525); aclose() guaranteed. Suppress catches if SDK changes.
        with contextlib.suppress(Exception):
            await it.aclose()  # type: ignore[attr-defined]

    if result is None and early_stop_reason is None:  # pragma: no cover
        msg = "claude_agent_sdk.query did not produce a ResultMessage"
        raise _DoNotRetry(RuntimeError(msg))

    if early_stop_reason is not None:
        # Synthesize outcome from accumulated state. Cost/turns may be
        # partial (no final ResultMessage) but on_message recorded them
        # via state.last_cost_usd / state.last_num_turns aggregation.
        return AgentRunOutcome(
            stop_reason=early_stop_reason,
            num_turns=result.num_turns if result else 0,
            total_cost_usd=(result.total_cost_usd or 0.0) if result else 0.0,
            is_error=False,
            session_id=result.session_id if result else "",
            final_text=final_text,
            tool_uses=tool_uses,
        )

    # Reachable only when early_stop_reason is None AND result is not None
    # (the (None, None) case raises at the top of this block at line 229-231).
    # Narrow for mypy.
    assert result is not None
    return AgentRunOutcome(
        stop_reason=result.stop_reason or "",
        num_turns=result.num_turns,
        total_cost_usd=result.total_cost_usd or 0.0,
        is_error=result.is_error,
        session_id=result.session_id,
        final_text=final_text,
        tool_uses=tool_uses,
    )


async def run_agent(
    *,
    system_prompt: str,
    user_prompt: str,
    tools: list[SdkMcpTool[Any]],
    mcp_server_name: str = "cve_env",
    model: str = MODEL,
    max_turns: int = TURN_CAP,
    max_cost_usd: float = MAX_COST_USD_PER_CVE_SOFT,
    on_message: Callable[[Any], None] | None = None,
    max_sdk_attempts: int = SDK_RETRY_MAX_ATTEMPTS,
    resume: str | None = None,
    verify_passed_check: Callable[[], bool] | None = None,
) -> AgentRunOutcome:
    """Run one agent ``query`` end-to-end; return terminal outcome.

    Streams intermediate messages into ``on_message`` (for per-turn
    audit logging). All budget / turn enforcement is server-side via
    :class:`ClaudeAgentOptions`.

    ``setting_sources=[]`` and ``skills=[]`` prevent the Claude Code
    harness from loading the user's global rules, memory, or skills --
    the agent sees only our system prompt and our tools.

    SDK-crash retry: the inner :func:`_run_query_once` is re-invoked up
    to ``max_sdk_attempts`` times on :class:`ClaudeSDKError`. Each retry
    is a fresh SDK subprocess + fresh session. The MCP server is
    re-created with identical tools so no state bleeds across attempts.

    ``resume``: when set, passed to ``ClaudeAgentOptions(resume=...)`` so
    the SDK continues the prior session in-place. Used by the continuation
    loop in ``agent/loop.py`` to re-engage the same conversation after a
    premature ``end_turn``.
    """
    final_error: BaseException | None = None
    prompt_for_attempt = user_prompt
    for attempt in range(1, max_sdk_attempts + 1):
        # Recreate the server + options on each attempt: a crashed subprocess
        # may have left the MCP server in a bad state, so a clean rebuild
        # is the safer path.
        server = create_sdk_mcp_server(
            name=mcp_server_name, version="0.1.0", tools=tools
        )
        tool_names = [f"mcp__{mcp_server_name}__{t.name}" for t in tools]
        env: dict[str, str] = {}
        if api_key := os.environ.get("ANTHROPIC_API_KEY"):
            env["ANTHROPIC_API_KEY"] = api_key
        # Bound the built-in Bash tool so a stalled shell command (e.g. a manual
        # `docker pull`) is SIGTERM'd at the cap instead of hanging until the
        # bench's external wall-guard. The CLI honors
        # BASH_DEFAULT_TIMEOUT_MS / BASH_MAX_TIMEOUT_MS (ms; MAX is a hard cap the
        # model cannot exceed); the SDK forwards options.env → CLI env. Backstop
        # to the prompt rule (no raw Bash pulls) + the docker_run pull timeout —
        # a hung pull's Docker children may not always die cleanly (FD leaks),
        # so this is defense-in-depth, not the sole guard.
        _bash_timeout_ms = os.environ.get("CVE_ENV_BASH_TIMEOUT_MS", "600000")
        env["BASH_DEFAULT_TIMEOUT_MS"] = _bash_timeout_ms
        env["BASH_MAX_TIMEOUT_MS"] = _bash_timeout_ms
        options_kwargs: dict[str, Any] = {
            "model": model,
            "system_prompt": system_prompt,
            "mcp_servers": {mcp_server_name: server},
            "allowed_tools": tool_names,
            "max_turns": max_turns,
            "max_budget_usd": max_cost_usd,
            "permission_mode": "bypassPermissions",
            "setting_sources": [],
            "skills": [],
            "env": env,
        }
        # Operator dial to disable builtins (e.g. sub-Agent) that fuel the
        # research-spiral. Default empty → unchanged.
        if _disallowed := get_disallowed_tools():
            options_kwargs["disallowed_tools"] = _disallowed
        if resume:
            # resume reused across retries; a corrupted session may fail identically on all attempts.
            options_kwargs["resume"] = resume
        options = ClaudeAgentOptions(**options_kwargs)
        try:
            outcome = await _run_query_once(
                options=options,
                user_prompt=prompt_for_attempt,
                on_message=on_message,
            )
            # A run that TERMINATES on a refusal stop_reason (not an exception)
            # is otherwise NOT retried. Re-route it into the same de-escalation
            # retry path via InStreamRefusal — but only when no verify has
            # passed (else it's a recovered success per the salvage logic in
            # loop._map_status). Checking the FINAL stop_reason (after any
            # in-attempt refusal->recovery) avoids interrupting the SDK's own
            # mid-stream recovery.
            sr = (outcome.stop_reason or "").lower()
            if ("refusal" in sr or "usage policy" in sr) and (
                verify_passed_check is None or not verify_passed_check()
            ):
                raise InStreamRefusal(
                    f"terminal refusal stop_reason={outcome.stop_reason!r}"
                )
            return outcome
        except _DoNotRetry as wrapped:
            # Internal logic bug (e.g., SDK produced no ResultMessage).
            # Unwrap and re-raise -- retry would just hit the same bug.
            raise wrapped.original from None
        except Exception as exc:  # noqa: BLE001 -- intentionally broad: retry any unfinished-query failure
            final_error = exc
            # In-stream refusals (InStreamRefusal raised by on_message,
            # propagated out of _run_query_once) get the same de-escalation
            # retry as exception-path refusals.
            is_refusal = _is_refusal(exc) or isinstance(exc, InStreamRefusal)
            # A connectivity idle-timeout won't clear within the 2s/4s backoff,
            # and repeated idle waits could approach the external wall — cap it
            # at one retry (surface as error so the bench can pause/notify).
            if (
                isinstance(exc, SdkIdleTimeout)
                and attempt >= get_sdk_idle_max_attempts()
            ):
                logger.error(
                    "%s category=api-unreachable attempt=%d/%d — idle cap reached, "
                    "not retrying further (%s)",
                    SDK_RETRY_MARKER,
                    attempt,
                    max_sdk_attempts,
                    exc,
                )
                raise
            if attempt < max_sdk_attempts:
                # Exponential backoff (2s, 4s). A 4th retry with long backoff
                # was removed — quota handling lives at the bench-loop layer.
                # Delay = 2^(attempt-1) * base. Currently: 2s, 4s. If max_sdk_attempts grows, review cap.
                delay = SDK_RETRY_BACKOFF_BASE_SECONDS * (2 ** (attempt - 1))
                category = "safety-refusal" if is_refusal else "transient"
                logger.warning(
                    "%s category=%s attempt=%d/%d (%s: %s); retrying in %ss",
                    SDK_RETRY_MARKER,
                    category,
                    attempt,
                    max_sdk_attempts,
                    type(exc).__name__,
                    exc,
                    delay,
                )
                # For refusals, de-escalate the prompt for the retry. Only
                # apply once (don't stack preambles across multiple retries).
                if is_refusal and prompt_for_attempt == user_prompt:
                    prompt_for_attempt = _deescalate_prompt(user_prompt)
                    logger.warning(
                        "%s attempt=%d/%d — de-escalation preamble applied to retry",
                        SDK_DEESCALATION_MARKER,
                        attempt,
                        max_sdk_attempts,
                    )
                await asyncio.sleep(delay)
            else:
                logger.error(
                    "SDK failure on final attempt %d/%d (%s: %s); giving up",
                    attempt,
                    max_sdk_attempts,
                    type(exc).__name__,
                    exc,
                )
    # All attempts exhausted -- re-raise the last error so the caller
    # records status='error' (or relabels it if give_up fired).
    assert final_error is not None  # noqa: S101 -- defensive; unreachable otherwise
    raise final_error


__all__ = [
    "AgentRunOutcome",
    "AssistantMessage",
    "ResultMessage",
    "TextBlock",
    "ToolFn",
    "ToolResultBlock",
    "ToolUseBlock",
    "UserMessage",
    "run_agent",
]
