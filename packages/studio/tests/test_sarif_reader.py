"""Tests for SARIF reader."""

from __future__ import annotations

import json
from pathlib import Path

from packages.studio.services.sarif_reader import parse_run_sarif, parse_sarif_file, scan_metrics


def _minimal_sarif(results: list) -> dict:
    return {
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "semgrep", "rules": [
                {
                    "id": "python.lang.security.audit.os-system.os-system",
                    "name": "os-system",
                    "shortDescription": {"text": "Avoid os.system with tainted input"},
                    "properties": {"tags": ["security", "external/cwe/cwe-78"]},
                },
            ]}},
            "results": results,
        }],
    }


def test_parse_sarif_file_produces_normalized_findings(tmp_path: Path):
    path = tmp_path / "semgrep_security.sarif"
    path.write_text(json.dumps(_minimal_sarif([
        {
            "ruleId": "python.lang.security.audit.os-system.os-system",
            "level": "error",
            "message": {"text": "Untrusted input flows into os.system"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": "src/shell.py"},
                    "region": {"startLine": 42},
                }
            }],
        },
    ])))
    findings = parse_sarif_file(path, tool_hint="semgrep")
    assert len(findings) == 1
    f = findings[0]
    assert f["file"] == "src/shell.py"
    assert f["line"] == 42
    assert f["cwe_id"] == "CWE-78"
    assert f["tool"] == "semgrep"
    assert f["severity_assessment"] == "high"
    assert f["final_status"] == "pending"


def test_parse_sarif_handles_missing_location(tmp_path: Path):
    path = tmp_path / "x.sarif"
    path.write_text(json.dumps(_minimal_sarif([
        {"ruleId": "python.lang.security.audit.os-system.os-system", "level": "warning",
         "message": {"text": "unlocated issue"}, "locations": []},
    ])))
    findings = parse_sarif_file(path)
    assert findings[0]["file"] == ""
    assert findings[0]["line"] is None
    assert findings[0]["severity_assessment"] == "medium"


def test_parse_sarif_skips_malformed(tmp_path: Path):
    path = tmp_path / "broken.sarif"
    path.write_text("{not valid json")
    assert parse_sarif_file(path) == []


def test_parse_run_sarif_reads_all_sarif(tmp_path: Path):
    (tmp_path / "semgrep_a.sarif").write_text(json.dumps(_minimal_sarif([
        {"ruleId": "python.lang.security.audit.os-system.os-system", "level": "error",
         "message": {"text": "a"},
         "locations": [{"physicalLocation": {"artifactLocation": {"uri": "a.py"}, "region": {"startLine": 1}}}]},
    ])))
    (tmp_path / "codeql_b.sarif").write_text(json.dumps(_minimal_sarif([
        {"ruleId": "python.lang.security.audit.os-system.os-system", "level": "warning",
         "message": {"text": "b"},
         "locations": [{"physicalLocation": {"artifactLocation": {"uri": "b.py"}, "region": {"startLine": 2}}}]},
    ])))
    findings = parse_run_sarif(tmp_path)
    assert len(findings) == 2
    files = sorted(f["file"] for f in findings)
    assert files == ["a.py", "b.py"]


def test_scan_metrics_returns_dict_or_none(tmp_path: Path):
    assert scan_metrics(tmp_path) is None
    (tmp_path / "scan_metrics.json").write_text(json.dumps({"files": 10, "findings": 3}))
    assert scan_metrics(tmp_path) == {"files": 10, "findings": 3}


def test_scan_metrics_handles_malformed(tmp_path: Path):
    (tmp_path / "scan_metrics.json").write_text("{bad")
    assert scan_metrics(tmp_path) is None
