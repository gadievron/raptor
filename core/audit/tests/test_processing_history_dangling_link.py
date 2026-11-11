"""A dangling explicit history receipt must not become healthy absence."""
import json

from core.audit import report as reports
from core.audit.findings_export import export_findings
from core.audit.orchestrator import ReviewOutcome
from core.audit.tests.test_report_completeness import TestCompleteRunReport as _CompleteRun, _journal


def test_dangling_processing_receipt_is_invalid_and_legacy_absence_stays_healthy(tmp_path):
    out = _CompleteRun()._complete_run(tmp_path)
    _journal(out, "independent_finding", "finding")
    native = export_findings([ReviewOutcome(
        file="a.c", function="independent_finding", line=1, status="finding",
        body="Independent retained concern", hypothesis="Independent retained concern",
    )])["findings"]
    (out / "findings.json").write_text(json.dumps(native))
    baseline = reports.generate_report(out)
    assert baseline["stats"]["finding"] == 1 and baseline["findings"]
    assert baseline["completeness"]["missing"] == []
    receipt = out / "processing-completeness.json"
    receipt.symlink_to(out / "owned-missing-processing-receipt.json")
    assert receipt.is_symlink() and not receipt.exists()
    limited = reports.generate_report(out)
    assert limited["completeness"]["missing"] == [
        "processing completeness record (unreadable or invalid)",
    ]
    assert limited["completeness"]["partial"] is True
    assert limited["stats"] == baseline["stats"]
    assert limited["findings"] == baseline["findings"]
    receipt.unlink()
    label = "new dark verification pass results (persistence failed)"
    receipt.write_text(json.dumps({"schema_version": 1, "limitations": [label]}))
    assert reports.generate_report(out)["completeness"]["missing"] == [label]
