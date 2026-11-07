"""Compromise checks compare the populations declared by the shared report."""

from pathlib import Path
import runpy
import sys
from unittest.mock import patch

import pytest

from core.reporting.renderers import render_document
from packages.sca.reporting import build_sca_document


@pytest.fixture
def harness():
    script = Path(__file__).resolve().parents[1] / "scripts/raptor-sca-compromise-check"
    with patch.object(sys, "path", sys.path.copy()):
        return runpy.run_path(str(script))


def _report(rows, tmp_path):
    _, document = build_sca_document(rows=rows, target=tmp_path, output_dir=tmp_path,
                                     deps_analysed=2)
    return render_document(document, "markdown").content.decode("utf-8")


def _rows():
    return [
        {"id": "1", "vuln_type": "sca:supply_chain:install_hook", "severity": "critical"},
        {"id": "2", "vuln_type": "sca:hygiene:unpinned", "severity": "medium"},
        {"id": "3", "vuln_type": "sca:vulnerable_dependency", "severity": "high"},
        {"id": "4", "vuln_type": "sca:vulnerable_dependency", "severity": "critical", "suppressed": True},
        {"id": "5", "vuln_type": "sca:scan_health:parser", "severity": "info"},
    ]


def test_shared_report_counts_signals_and_suppressed_rows_separately(harness, tmp_path):
    rows = _rows()
    art = harness["_ScanArtifacts"](findings=rows, report_md=_report(rows, tmp_path))
    assert harness["_parity_check"](art) == (True, "")


@pytest.mark.parametrize("change", ["dropped_signal", "wrong_severity", "wrong_signal_severity"])
def test_shared_report_parity_still_detects_missing_or_miscounted_evidence(harness, tmp_path, change):
    rows = _rows()
    displayed = rows[1:] if change == "dropped_signal" else [
        row | {"severity": "low"} if row["id"] == ("1" if change == "wrong_signal_severity" else "3") else row for row in rows
    ]
    art = harness["_ScanArtifacts"](findings=rows, report_md=_report(displayed, tmp_path))
    ok, note = harness["_parity_check"](art)
    assert not ok, note


def test_legacy_severity_summary_remains_supported(harness):
    art = harness["_ScanArtifacts"](
        findings=[{"severity": "critical"}], report_md="| Critical | 1 |\n",
    )
    assert harness["_parity_check"](art) == (True, "")
