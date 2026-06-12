"""P3-C-01 / W2-1 (2026-06-02 review): WallBudgetExceeded + NoProgressReached,
when raised by on_message, must be caught by ``_run_query_once._consume`` as a
CLEAN early-stop (exactly like GiveUpReceived / TurnCapReached / BudgetCapExceeded)
— NOT propagate out into ``run_agent``'s broad ``except`` retry loop, which burns
~2 wasted SDK subprocess retries + duplicate audit rows before the build() handler
finally classifies them. The final OutcomeStatus is unchanged (NoProgress ->
turn_cap via 'max_turns_reached'; Wall -> budget_exhausted via 'budget_exceeded');
the build() exception-handler elifs stay as a defensive backstop.

RED until the ``except (WallBudgetExceeded, NoProgressReached)`` clause exists in
_consume: today they propagate, so _run_query_once raises instead of returning a
clean early-stop outcome.
"""
from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import MagicMock

from cve_env.agent import _activity, llm
from cve_env.agent.llm import (
    NoProgressReached,
    WallBudgetExceeded,
    _run_query_once,
)


async def _yield_one() -> Any:
    """SDK stream stand-in: emit a single message (on_message fires, then raises)."""
    yield MagicMock(name="assistant_message")


def _drive(exc: BaseException, monkeypatch: Any) -> tuple[Any, int]:
    monkeypatch.setenv("CVE_ENV_SDK_IDLE_TIMEOUT_S", "300")  # idle watchdog inactive
    monkeypatch.setattr(llm, "query", lambda **_k: _yield_one())
    _activity.reset()
    calls = {"n": 0}

    def on_msg(_m: Any) -> None:
        calls["n"] += 1
        raise exc

    outcome = asyncio.run(
        _run_query_once(options=MagicMock(), user_prompt="u", on_message=on_msg)
    )
    return outcome, calls["n"]


def test_no_progress_is_clean_early_stop(monkeypatch: Any) -> None:
    outcome, n = _drive(NoProgressReached("test"), monkeypatch)
    assert outcome.stop_reason == "max_turns_reached", (
        f"NoProgressReached must early-stop as max_turns_reached, got {outcome.stop_reason!r}"
    )
    assert n == 1, "on_message fired once; no retry"


def test_wall_budget_is_clean_early_stop(monkeypatch: Any) -> None:
    outcome, n = _drive(WallBudgetExceeded("test"), monkeypatch)
    assert outcome.stop_reason == "budget_exceeded", (
        f"WallBudgetExceeded must early-stop as budget_exceeded, got {outcome.stop_reason!r}"
    )
    assert n == 1, "on_message fired once; no retry"
