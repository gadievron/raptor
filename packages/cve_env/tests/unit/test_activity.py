"""Tests for cve_env.agent._activity.inflight_age — the tool-in-flight MAX
backstop's age signal (Lever #1A).

Root cause (verified 2026-05-28): all 16/16 recent wall_guards did 15-65 turns
of real work and hung MID-RUN (8/16 on docker_build), NOT at startup. A wedged
tool handler never reaches ``finally: tool_end()`` → ``_in_flight`` stays >0 →
the connectivity breaker's ``if tool_in_flight(): continue`` exempts it to the
1440s wall. ``inflight_age()`` lets the breaker trip after a max instead.

RED until ``inflight_age`` exists (AttributeError).
"""

from __future__ import annotations

from typing import Any

import cve_env.agent._activity as activity


def _freeze(monkeypatch: Any, clock: list[float]) -> None:
    monkeypatch.setattr(activity.time, "monotonic", lambda: clock[0])


def test_inflight_age_zero_when_idle(monkeypatch: Any) -> None:
    clock = [1000.0]
    _freeze(monkeypatch, clock)
    activity.reset()
    assert activity.inflight_age() == 0.0


def test_inflight_age_grows_while_in_flight(monkeypatch: Any) -> None:
    clock = [1000.0]
    _freeze(monkeypatch, clock)
    activity.reset()
    activity.tool_start()
    clock[0] = 1007.0
    assert activity.inflight_age() == 7.0


def test_inflight_age_resets_after_tool_end(monkeypatch: Any) -> None:
    clock = [1000.0]
    _freeze(monkeypatch, clock)
    activity.reset()
    activity.tool_start()
    clock[0] = 1005.0
    activity.tool_end()
    assert activity.inflight_age() == 0.0


def test_inflight_age_tracks_oldest_for_nested_tools(monkeypatch: Any) -> None:
    """With nested start/start, age is measured from the FIRST (oldest) start
    and only resets when the in-flight count returns to zero."""
    clock = [1000.0]
    _freeze(monkeypatch, clock)
    activity.reset()
    activity.tool_start()  # oldest start = 1000
    clock[0] = 1003.0
    activity.tool_start()  # nested — oldest unchanged
    clock[0] = 1010.0
    assert activity.inflight_age() == 10.0  # from the first start, not the second
    activity.tool_end()  # still 1 in flight
    assert activity.inflight_age() == 10.0
    clock[0] = 1012.0
    activity.tool_end()  # -> 0 in flight
    assert activity.inflight_age() == 0.0
