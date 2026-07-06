import json
from pathlib import Path

from packages.web.benchmark import ExpectedFinding, evaluate_manifest, evaluate_report


def test_evaluate_report_matches_expected_finding_and_forbidden_check():
    report = {
        "findings": [
            {"vuln_type": "injection", "check_id": "V5.2.1"},
            {"vuln_type": "missing_security_header", "check_id": "V14.4.1"},
        ]
    }

    result = evaluate_report(
        report,
        expected=[ExpectedFinding(vuln_type="injection")],
        forbidden_check_ids=["V14.4.9"],
    )

    assert result["passed"] is True
    assert result["expectations"][0]["observed_count"] == 1


def test_evaluate_manifest_fails_when_report_is_missing(tmp_path: Path):
    result = evaluate_manifest({
        "suite": "demo",
        "cases": [{"id": "missing", "report": "missing/report.json"}],
    }, tmp_path)

    assert result["passed"] is False
    assert result["cases"][0]["status"] == "missing_report"


def test_evaluate_manifest_reads_report_file(tmp_path: Path):
    report_path = tmp_path / "lab" / "web_scan_report.json"
    report_path.parent.mkdir()
    report_path.write_text(json.dumps({
        "findings": [{"vuln_type": "injection", "check_id": "V5.2.1"}],
    }), encoding="utf-8")

    result = evaluate_manifest({
        "suite": "demo",
        "cases": [{
            "id": "lab",
            "report": "lab/web_scan_report.json",
            "expected_findings": [{"check_id": "V5.2.1"}],
        }],
    }, tmp_path)

    assert result["passed"] is True
    assert result["cases"][0]["status"] == "evaluated"

