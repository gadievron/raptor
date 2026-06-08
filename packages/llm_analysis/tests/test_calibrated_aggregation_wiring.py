"""Integration tests for the Phase 3b orchestrator wire-up.

The orchestrator-level integration is small: a feature-flag helper, an
inline call to ``calibrate_results``, and an attach loop. These tests
exercise the helper directly and verify the attach loop's contract
(every result that had ``multi_model_analyses`` gains a sibling
``calibrated_aggregation`` field) by driving the same code path the
orchestrator runs, without booting the full orchestrate() machinery.

We don't run a real orchestrate() — that needs an LLM, a target
repo, a CodeQL database and several minutes per case. The wire-up
itself is a single block; isolating it is honest about what's
actually being tested.
"""
from __future__ import annotations

import os
from contextlib import contextmanager

import pytest

from packages.llm_analysis.orchestrator import _calibrated_aggregation_enabled


@contextmanager
def _env(key: str, value):
    """Context manager that sets / restores an env var."""
    original = os.environ.get(key)
    try:
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value
        yield
    finally:
        if original is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = original


# ---------------------------------------------------------------------------
# Feature-flag helper
# ---------------------------------------------------------------------------


def test_feature_flag_default_enabled():
    with _env("RAPTOR_CALIBRATED_AGGREGATION", None):
        assert _calibrated_aggregation_enabled() is True


@pytest.mark.parametrize("value", ["0", "false", "FALSE", "no", "NO", "off", ""])
def test_feature_flag_falsy_values_disable(value):
    with _env("RAPTOR_CALIBRATED_AGGREGATION", value):
        assert _calibrated_aggregation_enabled() is False


@pytest.mark.parametrize("value", ["1", "true", "TRUE", "yes", "on", "anything"])
def test_feature_flag_truthy_values_enable(value):
    with _env("RAPTOR_CALIBRATED_AGGREGATION", value):
        assert _calibrated_aggregation_enabled() is True


# ---------------------------------------------------------------------------
# Attach loop contract — simulate the orchestrator inline block
# ---------------------------------------------------------------------------


def _simulate_wire_up(results_by_id: dict) -> dict:
    """Drive the same code path the orchestrator runs at line ~826.
    Returns the mutated results_by_id so callers can assert on it."""
    from core.llm.multi_model.calibrated_aggregation import (
        calibrate_results, verdict_to_json,
    )
    verdicts = calibrate_results(results_by_id)
    for fid, verdict in verdicts.items():
        primary = results_by_id.get(fid)
        if primary is not None:
            primary["calibrated_aggregation"] = verdict_to_json(verdict)
    return results_by_id


def test_attach_loop_populates_calibrated_aggregation_on_multi_model_finding():
    results_by_id = {
        "F1": {
            "finding_id": "F1", "rule_id": "py/sql-inj",
            "is_exploitable": True,
            "multi_model_analyses": [
                {"model": "m1", "is_exploitable": True},
                {"model": "m2", "is_exploitable": True},
                {"model": "m3", "is_exploitable": False},
            ],
        },
    }
    out = _simulate_wire_up(results_by_id)
    assert "calibrated_aggregation" in out["F1"]
    ca = out["F1"]["calibrated_aggregation"]
    assert ca["aggregation_method"] == "dawid_skene"
    assert "posterior_true_positive" in ca
    assert "credible_interval" in ca
    assert isinstance(ca["credible_interval"], list)
    assert ca["n_models"] == 3


def test_attach_loop_falls_back_for_single_model_finding():
    results_by_id = {
        "F1": {
            "finding_id": "F1", "rule_id": "py/sql-inj",
            "is_exploitable": True,
            # No multi_model_analyses → vote fallback
        },
    }
    out = _simulate_wire_up(results_by_id)
    ca = out["F1"]["calibrated_aggregation"]
    assert ca["aggregation_method"] == "vote"
    assert ca["aggregation_fallback_reason"] == "no_panel"
    assert ca["posterior_true_positive"] == 1.0


def test_attach_loop_does_not_disturb_existing_fields():
    """Other fields on the primary must survive untouched."""
    results_by_id = {
        "F1": {
            "finding_id": "F1", "rule_id": "py/sql-inj",
            "is_exploitable": True, "exploitability_score": 0.8,
            "ruling": "exploitable",
            "file_path": "src/foo.py", "start_line": 42,
            "multi_model_analyses": [
                {"model": "m1", "is_exploitable": True},
                {"model": "m2", "is_exploitable": True},
            ],
        },
    }
    out = _simulate_wire_up(results_by_id)
    finding = out["F1"]
    assert finding["is_exploitable"] is True
    assert finding["exploitability_score"] == 0.8
    assert finding["ruling"] == "exploitable"
    assert finding["file_path"] == "src/foo.py"
    assert finding["start_line"] == 42
    # multi_model_analyses preserved
    assert len(finding["multi_model_analyses"]) == 2
    # New field present
    assert "calibrated_aggregation" in finding


def test_attach_loop_mixed_panel_and_no_panel():
    """A run with both multi-model and single-model findings should
    populate every finding with a verdict, distinguishable via
    ``aggregation_method``."""
    results_by_id = {
        "F1": {
            "finding_id": "F1", "rule_id": "x",
            "is_exploitable": True,
            "multi_model_analyses": [
                {"model": "m1", "is_exploitable": True},
                {"model": "m2", "is_exploitable": True},
            ],
        },
        "F2": {
            "finding_id": "F2", "rule_id": "x",
            "is_exploitable": False,
        },
    }
    out = _simulate_wire_up(results_by_id)
    assert "calibrated_aggregation" in out["F1"]
    assert "calibrated_aggregation" in out["F2"]
    assert out["F1"]["calibrated_aggregation"]["aggregation_method"] == "dawid_skene"
    assert out["F2"]["calibrated_aggregation"]["aggregation_method"] == "vote"
