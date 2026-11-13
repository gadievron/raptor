"""Incomplete SARIF runs cannot establish suppression measurements."""

import pytest

from core.dataflow.finding_diff import diff_sarif_data


def _document(invocation):
    return {"runs": [{"results": [], "invocations": [invocation]}]}


def test_diff_run_status_refuses_incomplete_analysis():
    legacy = {"runs": [{"results": []}]}
    for invocation in (
        {"executionSuccessful": True},
        {"executionSuccessful": True, "toolExecutionNotifications": [{"level": "warning"}]},
        {"toolExecutionNotifications": [{"properties": {"coverage_limitation": "review_candidates"}}]},
    ):
        assert diff_sarif_data(legacy, _document(invocation)).suppression_rate == 0
    for invocation in (
        {"executionSuccessful": False},
        {"executionSuccessful": "true"},
        {"toolConfigurationNotifications": [{"level": "error"}]},
        {"toolExecutionNotifications": [{"level": "warning", "properties": {"coverage_limitation": "partial"}}]},
    ):
        incomplete = _document(invocation)
        for baseline, augmented in ((legacy, incomplete), (incomplete, legacy)):
            with pytest.raises(ValueError, match="incomplete SARIF run"):
                diff_sarif_data(baseline, augmented)
