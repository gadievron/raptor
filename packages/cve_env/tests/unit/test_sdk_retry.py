"""Fix A (SDK retry): wrap ``claude_agent_sdk.query`` in a narrow
retry on :class:`ClaudeSDKError` so transient session-state crashes do
not drop CVEs.

The bench50 run saw 10/50 errors where the SDK subprocess died with
``Fatal error in message reader`` before emitting a single tool_use;
10/10 completed normally on isolated re-run. The retry wrapper makes
that recovery automatic.
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from claude_agent_sdk import ClaudeSDKError

from cve_env.agent.llm import (
    SDK_RETRY_MAX_ATTEMPTS,
    AgentRunOutcome,
    run_agent,
)


async def _noop_tool(args: Any) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": "ok"}]}


def _fake_outcome(**overrides: Any) -> AgentRunOutcome:
    defaults: dict[str, Any] = {
        "stop_reason": "end_turn",
        "num_turns": 5,
        "total_cost_usd": 0.10,
        "is_error": False,
        "session_id": "sess-1",
        "final_text": "",
        "tool_uses": [],
    }
    defaults.update(overrides)
    return AgentRunOutcome(**defaults)


def _run(coro: Any) -> Any:
    return asyncio.run(coro)


@patch("cve_env.agent.llm.asyncio.sleep", return_value=None)
@patch("cve_env.agent.llm._run_query_once")
def test_first_attempt_success_no_retry(mock_run_once: Any, mock_sleep: Any) -> None:
    mock_run_once.return_value = _fake_outcome()
    result = _run(
        run_agent(
            system_prompt="s",
            user_prompt="u",
            tools=[],
        )
    )
    assert result.stop_reason == "end_turn"
    # Only one attempt should have been made.
    assert mock_run_once.call_count == 1


@patch("cve_env.agent.llm.asyncio.sleep", return_value=None)
@patch("cve_env.agent.llm._run_query_once")
def test_bash_tool_timeout_env_injected_phase_b(mock_run_once: Any, mock_sleep: Any) -> None:
    """Phase B (docker-pull hang): run_agent bounds the built-in Bash tool via
    BASH_DEFAULT/MAX_TIMEOUT_MS in the SDK options env, so a hung shell command
    (e.g. a manual ``docker pull``) is SIGTERM'd at the cap instead of running
    until the bench's 1440s wall-guard. ``BASH_MAX_TIMEOUT_MS`` is a hard cap the
    model cannot exceed. The SDK forwards ``options.env`` → the CLI subprocess."""
    mock_run_once.return_value = _fake_outcome()
    _run(run_agent(system_prompt="s", user_prompt="u", tools=[]))
    options = mock_run_once.call_args.kwargs["options"]
    assert options.env.get("BASH_DEFAULT_TIMEOUT_MS") == "600000"
    assert options.env.get("BASH_MAX_TIMEOUT_MS") == "600000"


@patch("cve_env.agent.llm.asyncio.sleep", return_value=None)
@patch("cve_env.agent.llm._run_query_once")
def test_retry_recovers_after_transient_sdk_error(mock_run_once: Any, mock_sleep: Any) -> None:
    # First call fails (mimics the bench50 flake), second call succeeds.
    mock_run_once.side_effect = [
        ClaudeSDKError("Fatal error in message reader"),
        _fake_outcome(num_turns=7),
    ]
    result = _run(
        run_agent(
            system_prompt="s",
            user_prompt="u",
            tools=[],
        )
    )
    assert result.num_turns == 7
    assert mock_run_once.call_count == 2


@patch("cve_env.agent.llm.asyncio.sleep", return_value=None)
@patch("cve_env.agent.llm._run_query_once")
def test_retry_recovers_on_third_attempt(mock_run_once: Any, mock_sleep: Any) -> None:
    mock_run_once.side_effect = [
        ClaudeSDKError("crash 1"),
        ClaudeSDKError("crash 2"),
        _fake_outcome(num_turns=8),
    ]
    result = _run(
        run_agent(
            system_prompt="s",
            user_prompt="u",
            tools=[],
        )
    )
    assert result.num_turns == 8
    assert mock_run_once.call_count == 3


@patch("cve_env.agent.llm.asyncio.sleep", return_value=None)
@patch("cve_env.agent.llm._run_query_once")
def test_retry_gives_up_after_max_attempts(mock_run_once: Any, mock_sleep: Any) -> None:
    mock_run_once.side_effect = ClaudeSDKError("persistent crash")
    with pytest.raises(ClaudeSDKError, match="persistent crash"):
        _run(
            run_agent(
                system_prompt="s",
                user_prompt="u",
                tools=[],
            )
        )
    assert mock_run_once.call_count == SDK_RETRY_MAX_ATTEMPTS


@patch("cve_env.agent.llm.asyncio.sleep", return_value=None)
@patch("cve_env.agent.llm._run_query_once")
def test_retry_honors_custom_max_attempts(mock_run_once: Any, mock_sleep: Any) -> None:
    mock_run_once.side_effect = ClaudeSDKError("crash")
    with pytest.raises(ClaudeSDKError):
        _run(
            run_agent(
                system_prompt="s",
                user_prompt="u",
                tools=[],
                max_sdk_attempts=1,
            )
        )
    assert mock_run_once.call_count == 1


@patch("cve_env.agent.llm.asyncio.sleep")
@patch("cve_env.agent.llm._run_query_once")
def test_retry_uses_exponential_backoff(mock_run_once: Any, mock_sleep: Any) -> None:
    mock_run_once.side_effect = [
        ClaudeSDKError("crash 1"),
        ClaudeSDKError("crash 2"),
        _fake_outcome(),
    ]
    mock_sleep.return_value = MagicMock()

    async def immediate(_: Any) -> None:  # asyncio.sleep stand-in
        return None

    mock_sleep.side_effect = immediate
    _run(
        run_agent(
            system_prompt="s",
            user_prompt="u",
            tools=[],
        )
    )
    # First retry: 2s. Second retry: 4s. Final success: no sleep.
    sleep_delays = [call.args[0] for call in mock_sleep.call_args_list]
    assert sleep_delays == [2.0, 4.0]


# Phase 8's "final retry uses 60s long backoff" reverted in Phase 42.2 —
# DEAD code per Phase 39.1 audit. Test removed; quota handling lives at
# the bench-loop layer (Phase 0g + 17.4).


@patch("cve_env.agent.llm.asyncio.sleep", return_value=None)
@patch("cve_env.agent.llm._run_query_once")
def test_generic_exception_is_retried_per_fix1(mock_run_once: Any, mock_sleep: Any) -> None:
    """Fix #1 widened the catch from ClaudeSDKError to Exception so Claude
    safety refusals (which don't wrap in ClaudeSDKError) get retried."""
    mock_run_once.side_effect = [
        RuntimeError("transient-looking error"),
        _fake_outcome(num_turns=4),
    ]
    result = _run(run_agent(system_prompt="s", user_prompt="u", tools=[]))
    assert result.num_turns == 4
    assert mock_run_once.call_count == 2


@patch("cve_env.agent.llm.asyncio.sleep", return_value=None)
@patch("cve_env.agent.llm._run_query_once")
def test_do_not_retry_sentinel_propagates(mock_run_once: Any, mock_sleep: Any) -> None:
    """The internal ``_DoNotRetry`` wrapper unwraps and re-raises the original
    exception without consuming retries -- it's for our own logic bugs
    (e.g., SDK produced no ResultMessage)."""
    from cve_env.agent.llm import _DoNotRetry

    original = RuntimeError("missing ResultMessage -- our bug, not a flake")
    mock_run_once.side_effect = _DoNotRetry(original)
    with pytest.raises(RuntimeError, match="missing ResultMessage"):
        _run(run_agent(system_prompt="s", user_prompt="u", tools=[]))
    assert mock_run_once.call_count == 1


# -- refusal detection + de-escalation (Fix #1) -----------------------------


@patch("cve_env.agent.llm.asyncio.sleep", return_value=None)
@patch("cve_env.agent.llm._run_query_once")
def test_refusal_triggers_deescalated_retry(mock_run_once: Any, mock_sleep: Any) -> None:
    """A refusal exception on attempt 1 should trigger a retry with a
    de-escalation preamble prepended to the user prompt."""
    refusal = RuntimeError(
        "API Error: Claude Code is unable to respond to this request, "
        "which appears to violate our Usage Policy"
    )
    mock_run_once.side_effect = [refusal, _fake_outcome()]
    original_prompt = "Build CVE-2026-26830 env"

    _run(run_agent(system_prompt="s", user_prompt=original_prompt, tools=[]))

    # Attempt 1 must receive the original prompt; attempt 2 the de-escalated one.
    assert mock_run_once.call_count == 2
    first_call = mock_run_once.call_args_list[0]
    retry_call = mock_run_once.call_args_list[1]
    assert first_call.kwargs["user_prompt"] == original_prompt
    assert retry_call.kwargs["user_prompt"] != original_prompt
    assert original_prompt in retry_call.kwargs["user_prompt"]
    # The preamble mentions safety-stop / de-escalation framing.
    assert "safety stop" in retry_call.kwargs["user_prompt"]


@patch("cve_env.agent.llm.asyncio.sleep", return_value=None)
@patch("cve_env.agent.llm._run_query_once")
def test_transient_error_does_not_deescalate(
    mock_run_once: Any, mock_sleep: Any
) -> None:
    """Non-refusal transient errors should retry with the UNCHANGED prompt.
    De-escalation is specifically for safety refusals."""
    mock_run_once.side_effect = [
        RuntimeError("Fatal error in message reader"),
        _fake_outcome(),
    ]
    original_prompt = "Build CVE-X env"

    _run(run_agent(system_prompt="s", user_prompt=original_prompt, tools=[]))

    assert mock_run_once.call_count == 2
    # Both attempts should use the original prompt (no de-escalation).
    assert mock_run_once.call_args_list[0].kwargs["user_prompt"] == original_prompt
    assert mock_run_once.call_args_list[1].kwargs["user_prompt"] == original_prompt


@patch("cve_env.agent.llm.asyncio.sleep", return_value=None)
@patch("cve_env.agent.llm._run_query_once")
def test_deescalation_preamble_applied_once_not_stacked(
    mock_run_once: Any, mock_sleep: Any
) -> None:
    """If multiple refusals fire across retries, the preamble should be
    prepended exactly once -- not stacked with repeated copies."""
    refusal = RuntimeError("request appears to violate our Usage Policy")
    mock_run_once.side_effect = [refusal, refusal, _fake_outcome()]
    original_prompt = "Build CVE-Y env"

    _run(run_agent(system_prompt="s", user_prompt=original_prompt, tools=[]))
    assert mock_run_once.call_count == 3
    # Count the occurrences of the preamble marker in each attempt's prompt.
    final_prompt = mock_run_once.call_args_list[-1].kwargs["user_prompt"]
    # The preamble's marker phrase appears exactly once.
    assert final_prompt.count("retry after earlier safety stop") == 1


@patch("cve_env.agent.llm.asyncio.sleep", return_value=None)
@patch("cve_env.agent.llm._run_query_once")
def test_in_stream_refusal_triggers_deescalated_retry(
    mock_run_once: Any, mock_sleep: Any
) -> None:
    """D2: an in-stream refusal — ``InStreamRefusal`` raised by on_message and
    propagated out of ``_run_query_once`` — must trigger the SAME de-escalation
    retry as an exception-path refusal. Before D2, in-stream refusals were only
    latched (loop.py:1528) and classified ``interrupted`` with no retry."""
    from cve_env.agent.llm import InStreamRefusal

    mock_run_once.side_effect = [
        InStreamRefusal("stop_reason='refusal' at turn 12"),
        _fake_outcome(),
    ]
    original_prompt = "Build CVE-2026-26830 env"

    _run(run_agent(system_prompt="s", user_prompt=original_prompt, tools=[]))

    assert mock_run_once.call_count == 2
    assert mock_run_once.call_args_list[0].kwargs["user_prompt"] == original_prompt
    retry_prompt = mock_run_once.call_args_list[1].kwargs["user_prompt"]
    assert retry_prompt != original_prompt
    assert original_prompt in retry_prompt
    assert "safety stop" in retry_prompt


@patch("cve_env.agent.llm.asyncio.sleep", return_value=None)
@patch("cve_env.agent.llm._run_query_once")
def test_refusal_terminal_outcome_triggers_deescalated_retry(
    mock_run_once: Any, mock_sleep: Any
) -> None:
    """D2 (primary path): a run that RETURNS a refusal-class stop_reason
    (terminal in-stream refusal, unrecovered, no verify) is re-routed into the
    de-escalation retry. Checked on the FINAL stop_reason so the SDK's own
    in-attempt refusal->recovery (CVE-2018-16509) is NOT interrupted."""
    mock_run_once.side_effect = [_fake_outcome(stop_reason="refusal"), _fake_outcome()]
    original = "Build CVE-X env"

    out = _run(run_agent(system_prompt="s", user_prompt=original, tools=[]))

    assert mock_run_once.call_count == 2
    assert mock_run_once.call_args_list[1].kwargs["user_prompt"] != original
    assert "safety stop" in mock_run_once.call_args_list[1].kwargs["user_prompt"]
    assert out.stop_reason == "end_turn"  # recovered on the de-escalated retry


@patch("cve_env.agent.llm.asyncio.sleep", return_value=None)
@patch("cve_env.agent.llm._run_query_once")
def test_refusal_terminal_outcome_not_retried_when_verify_passed(
    mock_run_once: Any, mock_sleep: Any
) -> None:
    """D2 guard: a refusal-terminal stop_reason AFTER a verify passed is a
    recovered success (BUG-007/I3) — do NOT retry; return it unchanged."""
    mock_run_once.return_value = _fake_outcome(stop_reason="refusal")

    out = _run(
        run_agent(
            system_prompt="s", user_prompt="p", tools=[],
            verify_passed_check=lambda: True,
        )
    )

    assert mock_run_once.call_count == 1
    assert out.stop_reason == "refusal"


def test_is_refusal_detects_known_signatures() -> None:
    from cve_env.agent.llm import _is_refusal

    assert _is_refusal(RuntimeError("API Error: appears to violate our Usage Policy"))
    assert _is_refusal(RuntimeError("Claude Code is unable to respond"))
    assert _is_refusal(RuntimeError("unable to respond to this request"))
    assert not _is_refusal(RuntimeError("connection reset"))
    assert not _is_refusal(RuntimeError("Fatal error in message reader"))


# -- Phase 3b (2026-05-23): SDK retry / de-escalation visibility markers ----
# The exception-path de-escalation fired but emitted no stable, greppable
# marker, so post-bench analysis couldn't confirm it engaged ("0 visible
# markers" in the bench50-20260523-150347 forensic). Emit stable tokens.


@patch("cve_env.agent.llm.logger")
@patch("cve_env.agent.llm.asyncio.sleep", return_value=None)
@patch("cve_env.agent.llm._run_query_once")
def test_deescalation_emits_visibility_marker(
    mock_run_once: Any, mock_sleep: Any, mock_logger: Any
) -> None:
    from cve_env.agent.llm import SDK_DEESCALATION_MARKER, SDK_RETRY_MARKER

    refusal = RuntimeError("request appears to violate our Usage Policy")
    mock_run_once.side_effect = [refusal, _fake_outcome()]
    _run(run_agent(system_prompt="s", user_prompt="u", tools=[]))

    logged = " ".join(str(c) for c in mock_logger.warning.call_args_list)
    assert SDK_RETRY_MARKER in logged, "every retry must emit the retry marker"
    assert SDK_DEESCALATION_MARKER in logged, (
        "a safety-refusal retry must emit the de-escalation marker"
    )


@patch("cve_env.agent.llm.logger")
@patch("cve_env.agent.llm.asyncio.sleep", return_value=None)
@patch("cve_env.agent.llm._run_query_once")
def test_transient_retry_marker_without_deescalation(
    mock_run_once: Any, mock_sleep: Any, mock_logger: Any
) -> None:
    from cve_env.agent.llm import SDK_DEESCALATION_MARKER, SDK_RETRY_MARKER

    mock_run_once.side_effect = [
        RuntimeError("Fatal error in message reader"),
        _fake_outcome(),
    ]
    _run(run_agent(system_prompt="s", user_prompt="u", tools=[]))

    logged = " ".join(str(c) for c in mock_logger.warning.call_args_list)
    assert SDK_RETRY_MARKER in logged, "transient retry still emits the retry marker"
    assert SDK_DEESCALATION_MARKER not in logged, (
        "a non-refusal transient retry must NOT emit the de-escalation marker"
    )
