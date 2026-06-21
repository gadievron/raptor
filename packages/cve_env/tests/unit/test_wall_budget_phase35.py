"""Phase 35 RED — Python-side internal wall-budget check tests.

Phase 34.9 /bug-research (`~/.claude/bug-research/runs/phase34-B1-wall-guard-non-firing/run.md`)
identified macOS host sleep as the B1 root cause: external kernel alarm timers
(gtimeout/timeout/perl-alarm) pause during host sleep while wall-clock advances.
CVE-2024-1061 ran 11241s (3.12hr) in `bench50-20260514-065709` with exit=1
because the external wall-guard chain in `scripts/bench50.sh:139-181` never fired.

Phase 35 fix: Python-side internal wall-budget check using `time.time()` (which
DOES advance during macOS sleep, unlike `time.monotonic()` and kernel timers).
Fires at on_message() boundary via `_check_wall_budget(start, budget, turn)`
helper. Default off (CVE_ENV_INTERNAL_WALL_S=0).

These tests ship RED via pytest.mark.xfail(strict=True). The GREEN flip lands
atomically in Phase 35.5 commit (helper + on_message integration + exception
handler).
"""

from __future__ import annotations

import pytest

pytest.importorskip("claude_agent_sdk")

import time

import pytest

def _try_import_helper():
    """Try to import the Phase 35 wall-budget helper.

    Returns None until Phase 35.5 ships the helper.
    """
    try:
        from cve_env.agent.loop import _check_wall_budget  # type: ignore

        return _check_wall_budget
    except ImportError:
        return None

def _try_import_exception():
    """Try to import the WallBudgetExceeded exception.

    Returns None until Phase 35.2 ships the exception class.
    """
    try:
        from cve_env.agent.llm import WallBudgetExceeded  # type: ignore

        return WallBudgetExceeded
    except ImportError:
        return None

def test_wall_budget_helper_raises_when_elapsed_exceeds() -> None:
    """When (now - start) > budget AND budget > 0, helper must raise
    WallBudgetExceeded with message naming the elapsed seconds + turn.

    Canonical use: agent run started 100s ago, budget is 50s -> raise.
    """
    helper = _try_import_helper()
    exc_class = _try_import_exception()
    assert helper is not None, "Phase 35.5 must ship _check_wall_budget"
    assert exc_class is not None, "Phase 35.2 must ship WallBudgetExceeded"

    started_100s_ago = time.time() - 100.0
    with pytest.raises(exc_class) as excinfo:
        helper(started_100s_ago, 50.0, turn=5)

    msg = str(excinfo.value)
    # Message must mention the budget value
    assert "50" in msg, f"budget not in message: {msg!r}"
    # Message must mention the turn
    assert "5" in msg, f"turn not in message: {msg!r}"

def test_wall_budget_disabled_when_budget_zero() -> None:
    """When budget == 0, helper MUST NOT raise regardless of elapsed.

    This is the default-off contract: users who don't set
    CVE_ENV_INTERNAL_WALL_S see no behavioral change (back-compat).
    """
    helper = _try_import_helper()
    assert helper is not None, "Phase 35.5 must ship _check_wall_budget"

    started_long_ago = time.time() - 100000.0  # 1 day in the past
    # Must not raise — budget=0 is the disabled sentinel
    helper(started_long_ago, 0.0, turn=999)

def test_wall_budget_does_not_raise_when_within() -> None:
    """When (now - start) <= budget, helper MUST NOT raise.

    Happy path: agent started 10s ago, budget is 100s.
    """
    helper = _try_import_helper()
    assert helper is not None, "Phase 35.5 must ship _check_wall_budget"

    started_10s_ago = time.time() - 10.0
    # Must not raise — well within budget
    helper(started_10s_ago, 100.0, turn=3)
