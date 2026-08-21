"""Behavior tests for the env-var config accessors in ``cve_env.config``.

Each numeric accessor follows the same parse-with-fallback contract:
  - a malformed env value (e.g. ``"abc"``) -> the documented default
  - an invalid value rejected by the predicate (e.g. ``"-1"`` / ``"0"``)
    -> the documented default
  - a valid override -> the parsed value
  - an unset env var -> the documented default

These tests assert the ACTUAL default constant (the contract), re-derived
from source, not merely "is not None". The string/set accessors
(``get_recovery_eligible_stages``, ``get_disallowed_tools``) and the
two-var ``get_token_rates`` / per-stage ``get_stage_budget`` follow
slightly different shapes and are covered separately.
"""

from __future__ import annotations

import pytest

from cve_env.config import (
    _DEFAULT_RECOVERY_ELIGIBLE_STAGES,
    get_image_resolve_budget_s,
    get_recovery_eligible_stages,
    get_recovery_gap_turns,
    get_stage_budget,
)

# (accessor, env_var, malformed_default, invalid_value, invalid_default,
#  valid_input, valid_expected, unset_default)
# malformed_default == invalid_default == unset_default for every accessor
# (the single documented default), kept as one column per case for clarity.
NUMERIC_CASES = [
    pytest.param(
        get_recovery_gap_turns,
        "CVE_ENV_RECOVERY_GAP_TURNS",
        "0",  # invalid: predicate is v > 0
        "5",
        5,
        20,
        id="recovery_gap_turns",
    ),
    pytest.param(
        get_image_resolve_budget_s,
        "CVE_ENV_IMAGE_RESOLVE_BUDGET_S",
        "-1",  # invalid: predicate is v >= 0
        "300",
        300.0,
        600.0,
        id="image_resolve_budget_s",
    ),
]


@pytest.mark.parametrize(
    (
        "accessor",
        "env_var",
        "invalid_value",
        "valid_input",
        "valid_expected",
        "default",
    ),
    NUMERIC_CASES,
)
def test_numeric_accessor_malformed_returns_default(
    accessor, env_var, invalid_value, valid_input, valid_expected, default, monkeypatch
) -> None:
    """A non-numeric env value falls through ``except ValueError`` to the default."""
    monkeypatch.setenv(env_var, "abc")
    assert accessor() == default


@pytest.mark.parametrize(
    (
        "accessor",
        "env_var",
        "invalid_value",
        "valid_input",
        "valid_expected",
        "default",
    ),
    NUMERIC_CASES,
)
def test_numeric_accessor_invalid_returns_default(
    accessor, env_var, invalid_value, valid_input, valid_expected, default, monkeypatch
) -> None:
    """A parseable-but-predicate-rejected value falls back to the default."""
    monkeypatch.setenv(env_var, invalid_value)
    assert accessor() == default


@pytest.mark.parametrize(
    (
        "accessor",
        "env_var",
        "invalid_value",
        "valid_input",
        "valid_expected",
        "default",
    ),
    NUMERIC_CASES,
)
def test_numeric_accessor_valid_override(
    accessor, env_var, invalid_value, valid_input, valid_expected, default, monkeypatch
) -> None:
    """A valid override is parsed and returned verbatim."""
    monkeypatch.setenv(env_var, valid_input)
    assert accessor() == valid_expected


@pytest.mark.parametrize(
    (
        "accessor",
        "env_var",
        "invalid_value",
        "valid_input",
        "valid_expected",
        "default",
    ),
    NUMERIC_CASES,
)
def test_numeric_accessor_unset_returns_default(
    accessor, env_var, invalid_value, valid_input, valid_expected, default, monkeypatch
) -> None:
    """With the env var unset, the documented default is returned."""
    monkeypatch.delenv(env_var, raising=False)
    assert accessor() == default


# --- get_recovery_eligible_stages (frozenset accessor) ----------------------


def test_recovery_eligible_stages_unset_returns_default(monkeypatch) -> None:
    monkeypatch.delenv("CVE_ENV_RECOVERY_ELIGIBLE_STAGES", raising=False)
    assert get_recovery_eligible_stages() == _DEFAULT_RECOVERY_ELIGIBLE_STAGES


def test_recovery_eligible_stages_empty_returns_default(monkeypatch) -> None:
    """An empty / whitespace-only value yields an empty set -> default."""
    monkeypatch.setenv("CVE_ENV_RECOVERY_ELIGIBLE_STAGES", " , , ")
    assert get_recovery_eligible_stages() == _DEFAULT_RECOVERY_ELIGIBLE_STAGES


def test_recovery_eligible_stages_valid_override(monkeypatch) -> None:
    """Comma list is split, trimmed, and upper-cased into a frozenset."""
    monkeypatch.setenv("CVE_ENV_RECOVERY_ELIGIBLE_STAGES", "acquire, launch ")
    assert get_recovery_eligible_stages() == frozenset({"ACQUIRE", "LAUNCH"})


# --- get_disallowed_tools (list accessor) -----------------------------------








# --- get_stage_budget (per-stage float with malformed fallback) -------------


def test_stage_budget_unset_returns_code_default(monkeypatch) -> None:
    monkeypatch.delenv("CVE_ENV_BUDGET_RESEARCH", raising=False)
    assert get_stage_budget("RESEARCH") == 0.50


def test_stage_budget_malformed_env_returns_code_default(monkeypatch) -> None:
    """A non-float env value falls back to the empirical stage default."""
    monkeypatch.setenv("CVE_ENV_BUDGET_RESEARCH", "abc")
    assert get_stage_budget("RESEARCH") == 0.50


def test_stage_budget_unknown_stage_malformed_returns_zero(monkeypatch) -> None:
    """An unknown stage with malformed env falls back to 0.0 (unbounded)."""
    monkeypatch.setenv("CVE_ENV_BUDGET_NOSUCHSTAGE", "abc")
    assert get_stage_budget("NOSUCHSTAGE") == 0.0


def test_stage_budget_valid_env_override(monkeypatch) -> None:
    monkeypatch.setenv("CVE_ENV_BUDGET_RESEARCH", "1.25")
    assert get_stage_budget("RESEARCH") == 1.25


# --- get_token_rates (two-var override with malformed fallback) -------------








