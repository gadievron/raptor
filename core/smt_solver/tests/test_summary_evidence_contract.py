"""Constraint-summary completeness requires recorded, decided evidence."""

import pytest

from core.smt_solver.path_feasibility import PathSMTResult


def result(**kwargs):
    fields = dict(feasible=True, satisfied=[], unsatisfied=[], unknown=[],
                  model={}, smt_available=True, reasoning="owned result")
    fields.update(kwargs)
    return PathSMTResult(**fields)


def test_absent_completeness_evidence_defaults_to_incomplete():
    assert result().wp_complete is False


@pytest.mark.parametrize("marker", [None, "false", "true", 0, 1, [], {}],
                         ids=["null", "string-false", "string-true", "zero", "one", "list", "dict"])
def test_non_boolean_completeness_markers_do_not_certify_a_summary(marker):
    assert result(wp_complete=marker).wp_complete is False


@pytest.mark.parametrize("feasible", [True, False])
def test_unencoded_inputs_prevent_a_complete_summary_even_with_a_refutation(feasible):
    value = result(wp_complete=True, unknown=["unencoded guard"], feasible=feasible)
    assert value.wp_complete is False
    assert value.feasible is feasible


def test_unavailable_native_solver_cannot_certify_a_summary():
    value = result(wp_complete=True, smt_available=False)
    assert value.wp_complete is False


def test_explicit_complete_native_evidence_is_retained():
    assert result(wp_complete=True).wp_complete is True
