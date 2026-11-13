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


@pytest.mark.parametrize("properties,target,expected,shared_expected", [
    pytest.param({}, {"id": "CWE-89", "toolComponent": {"name": "CWE"}},
                 "CWE-89", "CWE-89", id="prefixed-cwe"),
    pytest.param({}, {"id": "89", "toolComponent": {"name": "CWE"}},
                 "CWE-89", "CWE-89", id="numeric-cwe-catalogue"),
    pytest.param({}, {"id": "89", "toolComponent": {"name": "other"}},
                 None, None, id="foreign-catalogue"),
    pytest.param({"tags": ["external/cwe/cwe-078"]},
                 {"id": "CWE-89", "toolComponent": {"name": "CWE"}},
                 "CWE-078", "CWE-78", id="existing-tag-priority-and-spelling"),
])
def test_relationship_cwe_metadata_reaches_the_selected_finding(
    tmp_path, properties, target, expected, shared_expected,
):
    from core.sarif.parser import parse_sarif_findings
    from packages.codeql.tests.test_finding_selection import _located_result, _run, _write

    run = _run(_located_result(), default="warning")
    descriptor = run["tool"]["driver"]["rules"][0]
    descriptor["properties"] = properties
    descriptor["relationships"] = [{"target": target}]
    path = _write(tmp_path, "relationships.sarif", run)
    assert parse_sarif_findings(path)[0]["cwe_id"] == shared_expected
    selected, count, duplicates = select_findings_for_analysis([path], 1)
    assert (len(selected), count, duplicates) == (1, 1, 0)

    parser = object.__new__(AutonomousCodeQLAnalyzer)
    finding = parser.parse_sarif_finding(selected[0].result, selected[0].run)

    assert finding.cwe == expected
    assert finding.rule_id == selected[0].result["ruleId"]
    assert finding.level == "warning"
    assert json.loads(path.read_text())["runs"][0] == run


@pytest.mark.parametrize('flows', [None, 3, 'unavailable', {'unknown': True}])
def test_unavailable_flow_array_keeps_the_selected_report(tmp_path, flows):
    from packages.codeql.tests.test_finding_selection import _located_result, _run, _write

    result = _located_result()
    result['codeFlows'] = flows
    run = _run(result)
    path = _write(tmp_path, 'flow-shape.sarif', run)
    selected, count, duplicates = select_findings_for_analysis([path], 1)
    assert (len(selected), count, duplicates) == (1, 1, 0)

    parser = object.__new__(AutonomousCodeQLAnalyzer)
    finding = parser.parse_sarif_finding(selected[0].result, selected[0].run)

    assert finding.rule_id == result['ruleId']
    assert finding.message == result['message']['text']
    assert finding.file_path == result['locations'][0]['physicalLocation']['artifactLocation']['uri']
    assert not finding.has_dataflow
    assert finding.dataflow_path_count == 0
    assert json.loads(path.read_text())['runs'][0] == run


@pytest.mark.parametrize('flows', [[], [{'threadFlows': []}], [{'threadFlows': []}, {'threadFlows': []}]])
def test_flow_array_retains_existing_path_count(flows):
    from packages.codeql.tests.test_finding_selection import _located_result, _run

    result = _located_result()
    result['codeFlows'] = flows
    parser = object.__new__(AutonomousCodeQLAnalyzer)
    finding = parser.parse_sarif_finding(result, _run(result))
    assert finding.dataflow_path_count == len(flows)
    assert finding.has_dataflow is bool(flows)
