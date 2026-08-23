"""Integration tests for the Phase 3 orchestrator wire-up.

The orchestrator-level integration is the ``_attach_calibrated_aggregation``
helper: it runs ``calibrate_results`` and attaches the additive
``calibrated_aggregation`` field to each finding, returning the run
summary surfaced in ``orchestrated_report.json``. These tests drive the
real helper directly, without booting the full orchestrate() machinery
(which needs an LLM, a target repo, a CodeQL database and several
minutes per case).

The step is unconditional (additive, no feature flag — review of
PR #793 removed RAPTOR_CALIBRATED_AGGREGATION).
"""
from __future__ import annotations

from packages.llm_analysis.orchestrator import _attach_calibrated_aggregation


# ---------------------------------------------------------------------------
# Attach loop contract — drive the real orchestrator helper
# ---------------------------------------------------------------------------


def _simulate_wire_up(results_by_id: dict) -> dict:
    """Drive the real orchestrator helper and return the mutated
    results_by_id so callers can assert on it."""
    _attach_calibrated_aggregation(results_by_id)
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


# ---------------------------------------------------------------------------
# Run summary + failure / atomicity contracts (review #4, #5 on PR #793)
# ---------------------------------------------------------------------------


def _two_multi_model_findings() -> dict:
    return {
        "F1": {
            "finding_id": "F1", "rule_id": "x", "is_exploitable": True,
            "multi_model_analyses": [
                {"model": "m1", "is_exploitable": True},
                {"model": "m2", "is_exploitable": True},
            ],
        },
        "F2": {
            "finding_id": "F2", "rule_id": "x", "is_exploitable": True,
            "multi_model_analyses": [
                {"model": "m1", "is_exploitable": True},
                {"model": "m2", "is_exploitable": False},
            ],
        },
    }


def test_summary_shape_on_success():
    rbi = _two_multi_model_findings()
    summary = _attach_calibrated_aggregation(rbi)
    assert summary["failed"] is False
    assert summary["total"] == 2
    assert "dawid_skene" in summary
    assert "vote_fallback" in summary
    assert isinstance(summary["fallback_by_reason"], dict)
    assert all("calibrated_aggregation" in f for f in rbi.values())


def test_failure_path_summary_and_no_partial_mutation(monkeypatch):
    """Review #5: when calibrate_results raises, the helper returns a
    failed summary (landing in orchestrated_report.json) and leaves NO
    finding carrying the field — never aborts the orchestrator."""
    import core.llm.multi_model.calibrated_aggregation as ca

    def _boom(_results):
        raise RuntimeError("D-S blew up")

    monkeypatch.setattr(ca, "calibrate_results", _boom)
    rbi = _two_multi_model_findings()
    summary = _attach_calibrated_aggregation(rbi)
    assert summary == {
        "failed": True,
        "error": "RuntimeError: D-S blew up",
    }
    assert all("calibrated_aggregation" not in f for f in rbi.values())


def test_conversion_is_atomic_on_partial_failure(monkeypatch):
    """Review #4: if verdict_to_json raises on the 2nd finding, the
    1st finding must NOT be left carrying the field — conversion is
    all-or-nothing."""
    import core.llm.multi_model.calibrated_aggregation as ca
    real = ca.verdict_to_json
    state = {"n": 0}

    def _flaky(verdict):
        state["n"] += 1
        if state["n"] == 2:
            raise ValueError("bad verdict")
        return real(verdict)

    monkeypatch.setattr(ca, "verdict_to_json", _flaky)
    rbi = _two_multi_model_findings()
    summary = _attach_calibrated_aggregation(rbi)
    assert summary["failed"] is True
    assert "ValueError" in summary["error"]
    # Atomic: even though the 1st conversion succeeded, no finding was
    # mutated because the comprehension aborts before the assignment loop.
    assert all("calibrated_aggregation" not in f for f in rbi.values())
