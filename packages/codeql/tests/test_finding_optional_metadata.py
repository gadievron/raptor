"""Optional CWE metadata cannot erase an otherwise usable selected finding."""
from __future__ import annotations

import json

import pytest

from packages.codeql.autonomous_analyzer import AutonomousCodeQLAnalyzer
from packages.codeql.finding_selection import select_findings_for_analysis


@pytest.mark.parametrize("properties,expected_cwe", [
    pytest.param(None, None, id="null-properties"),
    pytest.param([], None, id="list-properties"),
    pytest.param("unknown", None, id="text-properties"),
    pytest.param({}, None, id="empty-properties"),
    pytest.param({"tags": [None, {"name": "untrusted"}, 1, "external/cwe/cwe-078"]},
                 "CWE-078", id="mixed-tags-with-valid-cwe"),
])
def test_selected_finding_keeps_location_when_cwe_properties_are_unavailable(
    tmp_path, properties, expected_cwe,
):
    report = {"version": "2.1.0", "runs": [{
        "tool": {"driver": {"name": "CodeQL", "rules": [{
            "id": "owned/rule", "name": "Owned rule",
            "defaultConfiguration": {"level": "warning"}, "properties": properties,
        }]}},
        "results": [{
            "ruleId": "owned/rule", "message": {"text": "Owned finding"},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": "src/owned.py"},
                "region": {"startLine": 2, "endLine": 2},
            }}],
        }],
    }]}
    path = tmp_path / "findings.sarif"
    path.write_text(json.dumps(report))
    selected, count, duplicates = select_findings_for_analysis([path], 1)
    assert (len(selected), count, duplicates) == (1, 1, 0)

    # Exercise parsing only, without constructing clients or entering analysis.
    parser = object.__new__(AutonomousCodeQLAnalyzer)
    finding = parser.parse_sarif_finding(selected[0].result, selected[0].run)

    assert finding.rule_id == "owned/rule"
    assert finding.rule_name == "Owned rule"
    assert finding.message == "Owned finding"
    assert finding.file_path == "src/owned.py"
    assert (finding.start_line, finding.end_line) == (2, 2)
    assert finding.level == "warning"
    assert finding.cwe == expected_cwe
    assert not finding.has_dataflow
    assert json.loads(path.read_text()) == report
