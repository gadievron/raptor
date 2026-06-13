"""BUG-1 (trace br-7e06a0b-costfloor): cost telemetry under-reports on a
non-clean exit (turn_cap / max_turns_reached) when the SDK reports neither a
plausible cost nor token usage — the Claude Code session-auth case, where
``usage`` is ``None`` on every message and the interrupted-run ResultMessage
carries an implausibly-low ``total_cost_usd``.

At HEAD the terminal Outcome floors ``total_cost_usd`` on
``max(last_cost_usd, token_estimate)`` only; with token usage absent the
estimate is 0 and the cost collapses to the SDK's low value while ``num_turns``
(from the authoritative ``state.turn``) stays correct — e.g. a 46-turn build
logged ``$0.013``.

Fix: a turns-based cost floor, gated to non-clean exits + absent token usage,
so correctly-reported ``success`` runs and API-key (token-bearing) runs are
untouched.
"""
from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import patch

import pytest

from cve_env.agent.loop import _floor_cost, build
from cve_env.config import MODEL, estimate_cost_from_tokens, estimate_cost_from_turns

# Reuse the canned-stream helpers (same dir). _result() emits usage=None,
# matching the session-auth case under test.
from .test_bench200_bug_fixes import (  # type: ignore[import-untyped]
    _assistant,
    _cve,
    _fake_run_agent_factory,
    _host,
    _result,
    _text_block,
)

# Every abnormal-termination status in the OutcomeStatus taxonomy (models.py)
# whose SDK cost is unreliable mid-run — the turns floor MUST fire for each.
_INTERRUPTED = [
    "turn_cap", "budget_exhausted", "error", "interrupted", "incomplete", "rate_limited",
]
# Clean end_turn exits with reliable SDK cost — the floor MUST NOT fire (else a
# correctly-reported cost is inflated, the verified_partial regression).
_CLEAN = ["success", "verified_partial", "verify_failed", "launched_no_verify", "unresolvable"]


@pytest.mark.parametrize("status", _INTERRUPTED)
def test_floor_fires_for_every_interrupted_status_with_no_token_usage(status: str) -> None:
    """The gate must cover ALL abnormal terminations, not just turn_cap — the
    exception path's default status is 'interrupted' and a 529 gives 'rate_limited'.
    With a low SDK cost + no token usage, each must be floored up by turns."""
    floored = _floor_cost(
        status, num_turns=40, last_cost_usd=0.01, cont_cost_usd=0.0,
        input_tokens=0, output_tokens=0, model=MODEL, effective_max_cost_usd=10.0,
    )
    assert floored > 0.01, f"{status!r} not floored: {floored}"
    assert floored >= estimate_cost_from_tokens(40 * 1000, 0, MODEL)


@pytest.mark.parametrize("status", _CLEAN)
def test_floor_does_not_fire_for_clean_exit_statuses(status: str) -> None:
    """Clean exits report cost reliably; the floor must leave a low reported cost
    untouched (it is only a floor for interrupted runs). Guards the verified_partial
    regression and its siblings."""
    floored = _floor_cost(
        status, num_turns=40, last_cost_usd=0.01, cont_cost_usd=0.0,
        input_tokens=0, output_tokens=0, model=MODEL, effective_max_cost_usd=10.0,
    )
    assert floored == 0.01, f"{status!r} wrongly floored to {floored}"


def test_turn_cap_cost_floored_by_turns_when_no_token_usage(tmp_path: Path) -> None:
    """RED: a turn_cap run whose ResultMessage reports a low cost ($0.013),
    46 turns, and usage=None must NOT log a cost far below what 46 turns imply.
    At HEAD outcome.total_cost_usd is stuck at $0.013."""
    messages = [
        _assistant(_text_block("working on it")),
        _result("max_turns_reached", cost_usd=0.013, turns=46),
    ]
    with patch("cve_env.agent.loop.run_agent", _fake_run_agent_factory(messages)):
        outcome = asyncio.run(
            build(
                _cve(),
                _host(),
                run_id="run-costfloor-red",
                audit_root=tmp_path,
                max_turns=96,
                max_cost_usd=10.0,  # high cap so the budget gate doesn't fire on the floored cost
                max_turn_extensions=0,
            )
        )

    assert outcome.status == "turn_cap", f"expected turn_cap, got {outcome.status!r}"
    assert outcome.num_turns >= 46, f"num_turns lost: {outcome.num_turns}"
    # The bug: cost stuck at the SDK's implausibly-low report despite 46 turns.
    assert outcome.total_cost_usd > 0.013, (
        f"cost not floored: total_cost_usd={outcome.total_cost_usd} still at the "
        f"SDK's $0.013 despite {outcome.num_turns} turns + no token usage"
    )
    # Floor must be turns-proportional — at least ~1000 input-tokens/turn worth
    # (well below the implementation's per-turn figure; decouples the test from
    # the exact constant).
    min_floor = estimate_cost_from_tokens(outcome.num_turns * 1000, 0, MODEL)
    assert outcome.total_cost_usd >= min_floor, (
        f"floor not turns-proportional: {outcome.total_cost_usd} < {min_floor}"
    )


def test_turn_cap_high_reported_cost_not_lowered_by_floor(tmp_path: Path) -> None:
    """Regression: the turns floor only RAISES cost (it is a floor via max()).
    A turn_cap run whose SDK cost ($1.00, under the budget cap) already exceeds
    the 2-turn estimate keeps its reported cost unchanged."""
    messages = [
        _assistant(_text_block("working")),
        _result("max_turns_reached", cost_usd=1.00, turns=2),
    ]
    with patch("cve_env.agent.loop.run_agent", _fake_run_agent_factory(messages)):
        outcome = asyncio.run(
            build(
                _cve(),
                _host(),
                run_id="run-costfloor-highcost",
                audit_root=tmp_path,
                max_turns=96,
                max_cost_usd=10.0,  # high cap so $1.00 doesn't trip budget_exhausted
                max_turn_extensions=0,
            )
        )

    assert outcome.status == "turn_cap"
    # Test assumption: the few-turn floor is well under the reported $1.00 at any
    # model rate, so max() must keep the reported cost.
    floor = estimate_cost_from_turns(outcome.num_turns, MODEL)
    assert floor < 1.00, f"test assumption broken: floor={floor} >= $1.00"
    assert outcome.total_cost_usd == 1.00, (
        f"floor wrongly altered a correctly-reported cost: {outcome.total_cost_usd}"
    )


def test_turn_cap_floor_bounded_by_budget_cap(tmp_path: Path) -> None:
    """The turns floor never exceeds the run's budget cap — a run can't cost more
    than its budget (else it would have ended budget_exhausted). 46 turns
    (uncapped floor ~$5) is bounded to the $1.20 cap."""
    messages = [
        _assistant(_text_block("working")),
        _result("max_turns_reached", cost_usd=0.013, turns=46),
    ]
    with patch("cve_env.agent.loop.run_agent", _fake_run_agent_factory(messages)):
        outcome = asyncio.run(
            build(
                _cve(),
                _host(),
                run_id="run-costfloor-bounded",
                audit_root=tmp_path,
                max_turns=96,
                max_cost_usd=1.20,
                max_turn_extensions=0,
            )
        )

    assert outcome.status == "turn_cap"
    assert outcome.total_cost_usd > 0.013, "floor did not lift the SDK's low value"
    assert outcome.total_cost_usd <= 1.20 + 1e-9, (
        f"floor exceeded the budget cap: {outcome.total_cost_usd} > 1.20"
    )
