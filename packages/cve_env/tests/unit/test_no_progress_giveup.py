"""RED → GREEN: anti-thrash no-progress early give-up (2026-06-02).

Investigation (cap-binding deep-dive, bench50-20260602-070917 + -135711):
of 38 turn_cap/budget_exhausted CVEs, 10 NEVER built and another ~18 made
*no productive progress* for the final 80+ turns — cheap churn (research
``Bash``/``github_fetch`` loops, e.g. CVE-2022-43234 github×8, CVE-2023-51423
Bash×11) at $0.16–$0.92 for 96 turns. They are NOT expensive-builds-that-ran-
out-of-budget (a reserve would buy more churn); they are stuck.

This detector terminates a CVE early once it has gone ``threshold`` turns with
ZERO productive progress (no PRODUCTIVE_TOOLS ok + no post-build verify/
run_in_container), reclaiming the wasted tail and freeing the worker slot.

**The threshold is DATA-DERIVED, not guessed.** Across 100 SUCCESS CVEs in the
two benches, the largest gap between consecutive productive events in a CVE
that *eventually succeeded* was **71 turns** (CVE-2020-15308). So any threshold
≤ 71 would kill an observed winner; the safe floor is **≥ 72** (we recommend 80
for margin). The default is **0 = OFF** — this is an opt-in operational knob
(efficiency only; it converts 0 losses → wins by construction), so the default
build path is unchanged. Reuses ``last_productive_turn`` (already tracked for
``should_extend_turn_cap``) and the established raise-based on_message guard
pattern (mirrors ``_check_wall_budget`` / ``WallBudgetExceeded``).
"""
from __future__ import annotations

import pytest


def _try_import_helper():
    try:
        from cve_env.agent.loop import _check_no_progress  # type: ignore
        return _check_no_progress
    except ImportError:
        return None


def _try_import_exception():
    try:
        from cve_env.agent.llm import NoProgressReached  # type: ignore
        return NoProgressReached
    except ImportError:
        return None


# ---- helper (raise-based on_message guard) ----

def test_no_progress_helper_raises_when_gap_exceeds() -> None:
    """gap (current_turn - last_productive_turn) > threshold AND threshold > 0
    → raise NoProgressReached. Canonical: never-productive thrash at turn 81,
    threshold 80."""
    helper = _try_import_helper()
    exc = _try_import_exception()
    assert helper is not None, "GREEN must ship loop._check_no_progress"
    assert exc is not None, "GREEN must ship llm.NoProgressReached"
    with pytest.raises(exc) as ei:
        helper(current_turn=81, last_productive_turn=0, threshold=80)
    msg = str(ei.value)
    assert "81" in msg, f"turn not in message: {msg!r}"
    assert "80" in msg, f"threshold not in message: {msg!r}"


def test_no_progress_disabled_when_threshold_zero() -> None:
    """threshold == 0 is the default-OFF sentinel: MUST NOT raise regardless of
    gap (back-compat — unchanged default build path)."""
    helper = _try_import_helper()
    assert helper is not None
    helper(current_turn=999, last_productive_turn=0, threshold=0)  # no raise


def test_no_progress_does_not_raise_within_threshold() -> None:
    """gap <= threshold → no raise (still making/recently-made progress)."""
    helper = _try_import_helper()
    assert helper is not None
    helper(current_turn=70, last_productive_turn=20, threshold=80)  # gap 50


def test_no_progress_boundary_is_strictly_greater() -> None:
    """gap == threshold must NOT raise — strictly-greater so the documented
    safe floor (≥72; winner CVE-2020-15308 had a 71-turn gap) is never violated
    at the boundary."""
    helper = _try_import_helper()
    exc = _try_import_exception()
    assert helper is not None and exc is not None
    helper(current_turn=80, last_productive_turn=0, threshold=80)  # gap == 80, no raise
    with pytest.raises(exc):
        helper(current_turn=81, last_productive_turn=0, threshold=80)  # gap 81


# ---- config getter (default OFF, env-driven, rejects junk) ----

def test_config_default_is_off() -> None:
    from cve_env.config import get_no_progress_giveup_turns  # type: ignore
    assert get_no_progress_giveup_turns() == 0


def test_config_reads_env(monkeypatch: pytest.MonkeyPatch) -> None:
    from cve_env import config
    monkeypatch.setenv("CVE_ENV_NO_PROGRESS_GIVEUP_TURNS", "80")
    assert config.get_no_progress_giveup_turns() == 80


def test_config_rejects_negative_and_junk(monkeypatch: pytest.MonkeyPatch) -> None:
    from cve_env import config
    monkeypatch.setenv("CVE_ENV_NO_PROGRESS_GIVEUP_TURNS", "-5")
    assert config.get_no_progress_giveup_turns() == 0
    monkeypatch.setenv("CVE_ENV_NO_PROGRESS_GIVEUP_TURNS", "abc")
    assert config.get_no_progress_giveup_turns() == 0


def test_module_constant_present_and_off_by_default() -> None:
    from cve_env import config
    assert config.NO_PROGRESS_GIVEUP_TURNS == 0


# ---- data-floor drift-lock: the safe threshold rationale must stay documented ----

def test_data_floor_documented_in_config() -> None:
    """A future edit must not silently drop the empirical safe-floor rationale
    (winner CVE-2020-15308's 71-turn productive gap). Lock the doc so the floor
    can't be lowered without re-deriving it."""
    import inspect

    from cve_env import config
    src = inspect.getsource(config.get_no_progress_giveup_turns)
    assert "71" in src or "CVE-2020-15308" in src, (
        "the data-derived safe floor (≥72; 71-turn winner gap) must be documented"
    )
