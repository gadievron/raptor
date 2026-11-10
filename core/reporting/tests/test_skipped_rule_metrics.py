"""Captured skipped-rule metrics retain the scan status helper's limitations."""
from copy import deepcopy

import pytest

from core.reporting.adapters import apply_scan_metrics
from core.reporting.document import ReportContext
from core.reporting.scan_coverage import scan_execution_status
from core.reporting.summary import build_operator_summary


def test_captured_skipped_rules_override_a_stale_ok_claim():
    captured = {"execution_status": "ok", "semgrep_skipped_rules": 2}
    original = deepcopy(captured)
    context = ReportContext("scan", "captured", state="completed")
    apply_scan_metrics(context, captured)
    summary = build_operator_summary(context)
    assert summary.metrics["Scan execution"] == scan_execution_status(captured) == "partial"
    assert summary.state == "partial"
    assert any("semgrep_skipped_rules" in note for note in summary.diagnostics)
    assert context.extensions["raptor.scan_metrics"] == original and captured == original


def test_legacy_skipped_rules_without_execution_status_remain_partial():
    context = ReportContext("scan", "captured", state="completed")
    captured = {"semgrep_skipped_rules": 1}
    apply_scan_metrics(context, captured)
    assert context.state == "partial"
    assert context.extensions["raptor.metrics"]["Scan execution"] == "partial"
    assert context.extensions["raptor.scan_metrics"] == captured


def test_explicit_zero_skip_count_does_not_invent_a_limitation():
    context = ReportContext("scan", "captured", state="completed")
    apply_scan_metrics(context, {"execution_status": "ok", "semgrep_skipped_rules": 0})
    assert context.state == "completed"
    assert context.extensions["raptor.metrics"]["Scan execution"] == "ok"
    assert not context.diagnostics


@pytest.mark.parametrize("state", ["failed", "cancelled"])
def test_skip_disclosure_does_not_replace_terminal_failure_state(state):
    context = ReportContext("scan", "captured", state=state)
    apply_scan_metrics(context, {"execution_status": "error", "semgrep_skipped_rules": 1})
    assert context.state == state
    assert context.extensions["raptor.metrics"]["Scan execution"] == "error"
