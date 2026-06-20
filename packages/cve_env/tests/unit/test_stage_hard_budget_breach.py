"""Phase 43.1.2 (2026-05-16): coverage gap closure for `stage_hard_budget_breach`.

Per Phase 42.5 coverage report — `stage_hard_budget_breach` was in the
MED-risk no-test category. The function at `src/cve_env/config.py:315`
walks stage_costs, returns the first stage in HARD mode whose cost
exceeds budget. First-triggered wins for determinism.

3 enforcement modes via `CVE_ENV_BUDGET_<STAGE>_MODE`:
- soft (default): telemetry only, no termination → breach returns None
- hard: over-budget triggers give_up_reason → breach returns stage name
- off: skip check entirely → breach returns None

Tests cover all 3 modes + edge cases (budget=0 unbounded, first-wins
determinism, invalid mode fallback).

Location: src/cve_env/config.py:315-325.
"""

from __future__ import annotations

import pytest

import cve_env.config as cve_config
from cve_env.config import stage_hard_budget_breach


def test_breach_returns_none_when_no_stages(monkeypatch: pytest.MonkeyPatch) -> None:
    """Empty stage_costs → None (no stages to evaluate)."""
    result = stage_hard_budget_breach({})
    assert result is None


def test_breach_returns_none_in_default_soft_mode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Default mode = soft → no termination even when cost exceeds budget."""
    # Ensure no env override for mode
    for stage in cve_config.STAGES:
        monkeypatch.delenv(f"CVE_ENV_BUDGET_{stage}_MODE", raising=False)
    # Force a very high cost vs default budget
    result = stage_hard_budget_breach({"RESEARCH": 999.0})
    assert result is None


def test_breach_returns_none_in_off_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    """off mode → skip the check entirely, even over-budget."""
    monkeypatch.setenv("CVE_ENV_BUDGET_RESEARCH_MODE", "off")
    monkeypatch.setenv("CVE_ENV_BUDGET_RESEARCH", "0.10")
    result = stage_hard_budget_breach({"RESEARCH": 999.0})
    assert result is None


def test_breach_returns_stage_in_hard_mode_when_over(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """hard mode + cost > budget → return stage name."""
    monkeypatch.setenv("CVE_ENV_BUDGET_RESEARCH_MODE", "hard")
    monkeypatch.setenv("CVE_ENV_BUDGET_RESEARCH", "0.10")
    result = stage_hard_budget_breach({"RESEARCH": 0.50})
    assert result == "RESEARCH"


def test_breach_returns_none_in_hard_mode_when_under(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """hard mode + cost < budget → None (no breach)."""
    monkeypatch.setenv("CVE_ENV_BUDGET_RESEARCH_MODE", "hard")
    monkeypatch.setenv("CVE_ENV_BUDGET_RESEARCH", "1.00")
    result = stage_hard_budget_breach({"RESEARCH": 0.50})
    assert result is None


def test_breach_returns_none_in_hard_mode_when_equal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """hard mode + cost == budget → None. Predicate is strictly `cost > budget`
    (config.py:323). Equality is NOT a breach."""
    monkeypatch.setenv("CVE_ENV_BUDGET_RESEARCH_MODE", "hard")
    monkeypatch.setenv("CVE_ENV_BUDGET_RESEARCH", "0.50")
    result = stage_hard_budget_breach({"RESEARCH": 0.50})
    assert result is None


def test_breach_returns_none_when_budget_zero_unbounded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """budget == 0 means unbounded; predicate at config.py:323 skips with
    `if budget > 0 and ...`. hard mode + budget=0 → never breaches."""
    monkeypatch.setenv("CVE_ENV_BUDGET_RESEARCH_MODE", "hard")
    monkeypatch.setenv("CVE_ENV_BUDGET_RESEARCH", "0")
    result = stage_hard_budget_breach({"RESEARCH": 999.0})
    assert result is None


def test_breach_first_triggered_wins_determinism(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Multiple stages in hard mode + multiple over → first iteration win.
    Dict insertion order is preserved in Python 3.7+. The function iterates
    `stage_costs.items()` and returns the FIRST match.
    """
    monkeypatch.setenv("CVE_ENV_BUDGET_RESEARCH_MODE", "hard")
    monkeypatch.setenv("CVE_ENV_BUDGET_ACQUIRE_MODE", "hard")
    monkeypatch.setenv("CVE_ENV_BUDGET_RESEARCH", "0.10")
    monkeypatch.setenv("CVE_ENV_BUDGET_ACQUIRE", "0.10")
    # Insertion order: RESEARCH first, ACQUIRE second; both over budget
    result = stage_hard_budget_breach({"RESEARCH": 0.50, "ACQUIRE": 0.50})
    assert result == "RESEARCH"


def test_breach_skips_non_hard_when_mixed_modes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Mixed modes — only HARD stages trigger; soft/off stages skipped."""
    monkeypatch.setenv("CVE_ENV_BUDGET_RESEARCH_MODE", "soft")
    monkeypatch.setenv("CVE_ENV_BUDGET_ACQUIRE_MODE", "hard")
    monkeypatch.setenv("CVE_ENV_BUDGET_RESEARCH", "0.10")
    monkeypatch.setenv("CVE_ENV_BUDGET_ACQUIRE", "0.10")
    # RESEARCH is over but in soft mode; ACQUIRE is over and in hard mode
    result = stage_hard_budget_breach({"RESEARCH": 0.50, "ACQUIRE": 0.50})
    assert result == "ACQUIRE"


def test_breach_invalid_mode_falls_back_to_soft(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Invalid mode value falls back to soft (config.py:310-311) → no breach
    even when over-budget. Documents the defensive fallback."""
    monkeypatch.setenv("CVE_ENV_BUDGET_RESEARCH_MODE", "garbage_value")
    monkeypatch.setenv("CVE_ENV_BUDGET_RESEARCH", "0.10")
    result = stage_hard_budget_breach({"RESEARCH": 0.50})
    assert result is None
