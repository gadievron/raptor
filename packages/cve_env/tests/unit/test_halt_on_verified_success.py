"""Halt-on-verified-success (2026-06-08) — symmetric terminal SUCCESS signal.

Investigation trace cveenv-turncap-anomalies-20260608 (CVE-2022-30495): the loop
has a terminal FAILURE halt (``give_up`` -> ``GiveUpReceived``, loop.py F-13) but
NO terminal SUCCESS halt. A run that passed verify and emitted a clean ``end_turn``
could keep emitting tool calls until ``max_turns``; the cap-overrides-verify
invariant (``_map_status``) then graded the real build ``turn_cap``. CVE-2022-30495
verified at t126, emitted end_turn/final_success at t128, then wasted 6 research
turns -> max_turns(139) -> turn_cap despite ``verify_passed=True``.

Fix: ``SuccessReached`` raised when the per-ResultMessage terminal status is
``final_success`` (== non-cap stop_reason AND verify_passed), default-OFF behind
``CVE_ENV_ENABLE_HALT_ON_VERIFIED_SUCCESS``.

SAFETY (regression-lock): the cap branches in ``_terminal_status_for_result`` fire
BEFORE the verify-passed branch, so a cap signal (max_turns / budget) with
verify_passed=True yields ``final_turn_cap`` / ``budget_exhausted`` — NEVER
``final_success``. Therefore the halt can NEVER fire on the BUG-007/008 /
``bug008_verify_passed_then_turn_cap`` cap cases locked in test_map_status.py.
"""

from __future__ import annotations

import pytest

from cve_env import config
from cve_env.agent.llm import SuccessReached
from cve_env.agent.loop import (
    _StreamState,
    _should_halt_on_verified_success,
    _terminal_status_for_result,
)


def _state(*, verify_passed: bool = False) -> _StreamState:
    s = _StreamState()
    s.verify_passed = verify_passed
    return s


def test_success_reached_is_an_exception() -> None:
    assert issubclass(SuccessReached, Exception)


def test_flag_defaults_off() -> None:
    assert config.get_enable_halt_on_verified_success() is False


def test_halt_fires_on_final_success_when_enabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CVE_ENV_ENABLE_HALT_ON_VERIFIED_SUCCESS", "1")
    assert _should_halt_on_verified_success("final_success") is True


def test_no_halt_when_flag_off(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CVE_ENV_ENABLE_HALT_ON_VERIFIED_SUCCESS", raising=False)
    # default-OFF: even a final_success must NOT halt unless explicitly enabled
    assert _should_halt_on_verified_success("final_success") is False


@pytest.mark.parametrize(
    "status", ["final_turn_cap", "budget_exhausted", "final_no_verify", "final_give_up"]
)
def test_halt_never_fires_on_non_success(
    monkeypatch: pytest.MonkeyPatch, status: str
) -> None:
    # Even with the flag ON, only `final_success` triggers the halt.
    monkeypatch.setenv("CVE_ENV_ENABLE_HALT_ON_VERIFIED_SUCCESS", "1")
    assert _should_halt_on_verified_success(status) is False


def test_terminal_status_distinguishes_endturn_from_cap() -> None:
    """The SAFETY invariant the halt relies on: cap+verify_passed is NEVER
    final_success (so the halt cannot weaken BUG-007/008)."""
    # clean end_turn (non-cap) + verify_passed -> final_success (halt-eligible)
    assert (
        _terminal_status_for_result(_state(verify_passed=True), "end_turn")
        == "final_success"
    )
    # max_turns + verify_passed -> final_turn_cap (cap wins; NOT halt-eligible)
    assert (
        _terminal_status_for_result(_state(verify_passed=True), "max_turns_reached")
        == "final_turn_cap"
    )
    # budget + verify_passed -> budget_exhausted (cap wins; NOT halt-eligible)
    assert (
        _terminal_status_for_result(_state(verify_passed=True), "budget_exceeded")
        == "budget_exhausted"
    )
