"""Stage 3A — connectivity circuit-breaker (RED test).

Root cause (behavioral-audit-2026-05-27.md F1, judge-verified): when the
Anthropic API is unreachable, the SDK subprocess can emit a message (even a
terminal ResultMessage) and then STALL — ``_run_query_once``'s ``async for
message in it`` (llm.py:233) awaits a next message that never arrives. No
exception, no StopAsyncIteration → the iterator blocks forever → ``run_agent``
never returns → ``build()`` never returns → the external 1440s wall SIGKILLs
the worker. In bench50-20260526-155359 this turned 115/142 wall_guards into
zero-turn / $0 zombies.

All Python guards live in ``on_message`` (loop.py:1145), which fires only
between SDK messages, so a stalled stream evades every cap. The fix is an
inter-message IDLE timeout around the SDK iteration in ``_run_query_once``:
if no message arrives within ``CVE_ENV_SDK_IDLE_TIMEOUT_S`` seconds, abort the
iteration and raise into ``run_agent``'s existing retry/terminate path.

This test is RED until that idle-timeout exists: with a stream that yields one
message then hangs, ``_run_query_once`` must abort promptly (near the idle
timeout), NOT hang until the outer safety bound.
"""

from __future__ import annotations

import asyncio
import contextlib
import time
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
pytest.importorskip("claude_agent_sdk")

from cve_env.agent import _activity, llm


async def _yield_then_hang() -> Any:
    """SDK stream stand-in: emit one message, then stall forever (the outage)."""
    yield MagicMock(name="assistant_message")
    await asyncio.Event().wait()  # never set → models the unreachable-API hang


async def _yield_then_hang_with_tool() -> Any:
    """Like the above, but a tool goes in-flight before the stall — models a
    legitimate long build (the SDK is silent while our MCP tool runs)."""
    yield MagicMock(name="tool_use_message")
    _activity.tool_start()  # a tool is now executing (never ends → stays in-flight)
    await asyncio.Event().wait()


async def _tool_in_flight_forever() -> Any:
    """A tool goes in-flight and NEVER ends — models a wedged handler (a docker
    subprocess stuck on a dead VM socket that run_with_timeout could not reap).
    Distinct from ``_yield_then_hang_with_tool``: used with a tiny TOOL_MAX so
    the tool-in-flight MAX backstop must fire (Lever #1A)."""
    yield MagicMock(name="tool_use_message")
    _activity.tool_start()  # in flight, never ends
    await asyncio.Event().wait()


def test_wedged_tool_trips_breaker_after_max_inflight(monkeypatch: Any) -> None:
    """Lever #1A: a tool in-flight beyond ``CVE_ENV_TOOL_MAX_INFLIGHT_S`` must
    trip the breaker with a ``wedged`` reason — instead of the in-flight
    exemption letting it run to the 1440s wall (the 8/16 docker_build hangs).

    RED (no tool-in-flight MAX): the in-flight exemption suppresses the breaker
    forever → only the 4s outer bound stops it → asyncio.TimeoutError, no
    SdkIdleTimeout. GREEN: SdkIdleTimeout('...wedged...') near 1s.
    """
    monkeypatch.setenv("CVE_ENV_SDK_IDLE_TIMEOUT_S", "300")  # idle path inactive here
    monkeypatch.setenv("CVE_ENV_TOOL_MAX_INFLIGHT_S", "1")  # wedged path: 1s
    monkeypatch.setattr(llm, "query", lambda **_kwargs: _tool_in_flight_forever())

    async def _drive() -> tuple[float, BaseException | None]:
        start = time.monotonic()
        raised: BaseException | None = None
        try:
            await asyncio.wait_for(
                llm._run_query_once(
                    options=MagicMock(), user_prompt="wedged build", on_message=None
                ),
                timeout=4.0,
            )
        except BaseException as exc:  # noqa: BLE001 -- capture either outcome
            raised = exc
        finally:
            _activity.reset()  # clear the never-ended tool for other tests
        return time.monotonic() - start, raised

    elapsed, raised = asyncio.run(_drive())
    assert isinstance(raised, llm.SdkIdleTimeout), (
        f"expected SdkIdleTimeout (wedged-tool), got {raised!r} after {elapsed:.1f}s "
        f"— the tool-in-flight MAX backstop did not fire."
    )
    assert "wedged" in str(raised).lower()
    assert elapsed < 3.0, f"wedged-tool breaker took {elapsed:.1f}s, expected ~1s"


def test_watchdog_verdict_policy() -> None:
    """Pure per-poll decision (fast, no async/sleep). Exhaustive over the cases:
    idle-only, in-flight exemption, wedged-tool trip, and MAX disabled."""
    v = llm._watchdog_verdict
    # idle, no tool, under timeout → keep waiting
    assert (
        v(
            tool_in_flight=False,
            inflight_age=0.0,
            idle_for=10.0,
            idle_timeout_s=300.0,
            max_inflight_s=900.0,
        )
        is None
    )
    # idle, no tool, past timeout → idle (API unreachable)
    assert (
        v(
            tool_in_flight=False,
            inflight_age=0.0,
            idle_for=300.0,
            idle_timeout_s=300.0,
            max_inflight_s=900.0,
        )
        == "idle"
    )
    # tool in flight, age < max → exempt even with a huge idle gap (legit build)
    assert (
        v(
            tool_in_flight=True,
            inflight_age=100.0,
            idle_for=9999.0,
            idle_timeout_s=300.0,
            max_inflight_s=900.0,
        )
        is None
    )
    # tool in flight, age >= max → wedged
    assert (
        v(
            tool_in_flight=True,
            inflight_age=900.0,
            idle_for=0.0,
            idle_timeout_s=300.0,
            max_inflight_s=900.0,
        )
        == "wedged_tool"
    )
    # MAX disabled (0) → never wedged, even in-flight forever
    assert (
        v(
            tool_in_flight=True,
            inflight_age=99999.0,
            idle_for=0.0,
            idle_timeout_s=300.0,
            max_inflight_s=0.0,
        )
        is None
    )


def test_idle_timeout_aborts_a_stalled_sdk_stream(monkeypatch: Any) -> None:
    """With a 1s idle timeout, a stalled stream must abort in ~1s, not hang.

    RED (no idle-timeout yet): the inner ``async for`` blocks; only the 6s
    outer safety bound stops it → elapsed ≈ 6s → assertion fails.
    GREEN (idle-timeout wired): ``_run_query_once`` raises near 1s → elapsed < 3s.
    """
    monkeypatch.setenv("CVE_ENV_SDK_IDLE_TIMEOUT_S", "1")
    # Replace the SDK query() with a stream that yields once then stalls.
    monkeypatch.setattr(llm, "query", lambda **_kwargs: _yield_then_hang())

    async def _drive() -> tuple[float, BaseException | None]:
        start = time.monotonic()
        raised: BaseException | None = None
        # Outer safety bound so the test itself can never hang the suite. Both
        # the RED TimeoutError and the GREEN SdkIdleTimeout are acceptable here;
        # the discriminator is the ELAPSED time, asserted below.
        try:
            await asyncio.wait_for(
                llm._run_query_once(
                    options=MagicMock(),
                    user_prompt="build CVE-X env",
                    on_message=None,
                ),
                timeout=6.0,
            )
        except BaseException as exc:  # noqa: BLE001 -- capture either outcome
            raised = exc
        return time.monotonic() - start, raised

    elapsed, raised = asyncio.run(_drive())
    assert elapsed < 3.0, (
        f"_run_query_once hung {elapsed:.1f}s on a stalled stream — the "
        f"inter-message idle-timeout (CVE_ENV_SDK_IDLE_TIMEOUT_S=1) did not fire "
        f"(expected abort near 1s). This is the 115-zombie circuit-breaker gap."
    )
    # Verify the exception was the expected idle timeout, not an unrelated fast failure
    assert raised is not None, "expected an exception from the stalled stream"
    assert "idle" in str(raised).lower() or isinstance(raised, llm.SdkIdleTimeout), (
        f"expected SdkIdleTimeout or idle-related exception, got {type(raised).__name__}: {raised}"
    )


def test_breaker_is_suppressed_while_a_tool_is_in_flight(monkeypatch: Any) -> None:
    """Tool-aware property (prevents false-aborts): a silent SDK gap while an
    MCP tool is executing must NOT trip the breaker — legit 600-900s builds are
    silent. With a tool in-flight the whole time, _run_query_once does NOT raise
    within the window, so the OUTER safety bound is what stops it.
    """
    monkeypatch.setenv("CVE_ENV_SDK_IDLE_TIMEOUT_S", "1")
    monkeypatch.setattr(llm, "query", lambda **_kwargs: _yield_then_hang_with_tool())

    async def _drive() -> None:
        try:
            await asyncio.wait_for(
                llm._run_query_once(
                    options=MagicMock(), user_prompt="long build", on_message=None
                ),
                timeout=3.0,
            )
        finally:
            _activity.reset()  # clear the never-ended tool so other tests are unaffected

    # Breaker suppressed (tool in flight) → the 1s idle never fires → the 3s
    # OUTER bound raises TimeoutError instead of a (fast) SdkIdleTimeout.
    with pytest.raises(asyncio.TimeoutError):
        asyncio.run(_drive())


@patch("cve_env.agent.llm.asyncio.sleep", return_value=None)
@patch("cve_env.agent.llm._run_query_once")
def test_idle_timeout_is_capped_at_one_retry(
    mock_run_once: Any, mock_sleep: Any
) -> None:
    """A connectivity SdkIdleTimeout is retried at most once (2 attempts), not
    the full SDK_RETRY_MAX_ATTEMPTS — a dead API won't recover in backoff and
    3×idle could approach the 1440s wall.
    """
    from cve_env.agent.llm import SdkIdleTimeout, run_agent

    mock_run_once.side_effect = SdkIdleTimeout("API unreachable")
    with pytest.raises(SdkIdleTimeout):
        asyncio.run(run_agent(system_prompt="s", user_prompt="u", tools=[]))
    assert mock_run_once.call_count == 2  # 1 try + 1 retry (capped), not 3


# ── Backlog #2 follow-up (2026-05-31): make the 3A breaker FULLY config-driven ──
# (poll cadence + idle-retry cap were hardcoded module constants), confirm the
# idle bound defaults to 5 min, and LOCK the zero-message pre-first-turn coverage.
# f1408e7's watchdog already seeds last_message_at + _activity.reset() at
# query-start and runs concurrently, so a zero-message startup hang IS caught —
# but the existing stall test (_yield_then_hang) emits ONE message first, so the
# true zero-message case had no committed test. These lock it against regression.


def test_idle_timeout_defaults_to_five_minutes(monkeypatch: Any) -> None:
    """The 3A connectivity-breaker idle bound defaults to 300s (5 min)."""
    from cve_env import config

    monkeypatch.delenv("CVE_ENV_SDK_IDLE_TIMEOUT_S", raising=False)
    assert config.get_sdk_idle_timeout_s() == 300.0


def test_idle_poll_seconds_configurable(monkeypatch: Any) -> None:
    """Watchdog poll cadence: env-overridable, default 5.0, invalid → default."""
    from cve_env import config

    monkeypatch.delenv("CVE_ENV_SDK_IDLE_POLL_S", raising=False)
    assert config.get_sdk_idle_poll_s() == 5.0
    monkeypatch.setenv("CVE_ENV_SDK_IDLE_POLL_S", "1.5")
    assert config.get_sdk_idle_poll_s() == 1.5
    monkeypatch.setenv("CVE_ENV_SDK_IDLE_POLL_S", "nonsense")
    assert config.get_sdk_idle_poll_s() == 5.0


def test_idle_max_attempts_configurable(monkeypatch: Any) -> None:
    """Idle-retry cap: env-overridable, default 2, invalid → default."""
    from cve_env import config

    monkeypatch.delenv("CVE_ENV_SDK_IDLE_MAX_ATTEMPTS", raising=False)
    assert config.get_sdk_idle_max_attempts() == 2
    monkeypatch.setenv("CVE_ENV_SDK_IDLE_MAX_ATTEMPTS", "3")
    assert config.get_sdk_idle_max_attempts() == 3
    monkeypatch.setenv("CVE_ENV_SDK_IDLE_MAX_ATTEMPTS", "nope")
    assert config.get_sdk_idle_max_attempts() == 2


async def _hang_no_message() -> Any:
    """SDK stream that yields NOTHING then stalls — the true pre-first-turn /
    zero-turn startup hang (dead API before any message arrives). Distinct from
    _yield_then_hang, which emits one message first."""
    await asyncio.Event().wait()
    if False:  # pragma: no cover — make this an async generator that yields nothing
        yield None


def test_zero_message_pre_first_turn_aborts(monkeypatch: Any) -> None:
    """LOCK (backlog #2): a stream that never yields ANY message must still abort
    near the idle bound, not ride to the outer safety bound. Prevents a silent
    regression of f1408e7's query-start-seeded watchdog."""
    monkeypatch.setenv("CVE_ENV_SDK_IDLE_TIMEOUT_S", "1")
    monkeypatch.setattr(llm, "query", lambda **_kwargs: _hang_no_message())

    async def _drive() -> float:
        start = time.monotonic()
        with contextlib.suppress(Exception):
            await asyncio.wait_for(
                llm._run_query_once(
                    options=MagicMock(), user_prompt="build CVE-X", on_message=None
                ),
                timeout=6.0,
            )
        return time.monotonic() - start

    elapsed = asyncio.run(_drive())
    assert elapsed < 3.0, (
        f"_run_query_once hung {elapsed:.1f}s on a ZERO-message stream — the "
        f"pre-first-turn idle bound did not fire (expected abort near 1s)."
    )
