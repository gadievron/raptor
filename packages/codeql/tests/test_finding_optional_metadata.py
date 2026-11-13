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


@pytest.mark.parametrize('artifact,expected', [
    ({'index': 0}, 'src/owned%20file.py'),
    ({'uri': 'owned%20file.py', 'uriBaseId': 'ROOT'}, 'src/owned%20file.py'),
    ({'uri': 'plain.py'}, 'plain.py'),
    ({'index': True}, ''),
    ({'uri': 'file://remote-host/private.py'}, ''),
])
def test_selected_finding_resolves_source_in_its_own_run(tmp_path, artifact, expected):
    from packages.codeql.tests.test_finding_selection import _located_result, _run, _write

    result = _located_result()
    result['locations'][0]['physicalLocation']['artifactLocation'] = artifact
    run = _run(result)
    run['originalUriBaseIds'] = {'ROOT': {'uri': 'src/'}}
    run['artifacts'] = [{'location': {'uri': 'owned%20file.py', 'uriBaseId': 'ROOT'}}]
    path = _write(tmp_path, 'artifact-source.sarif', run)
    selected, count, duplicates = select_findings_for_analysis([path], 1)
    assert (len(selected), count, duplicates) == (1, 1, 0)
    parser = object.__new__(AutonomousCodeQLAnalyzer)

    finding = parser.parse_sarif_finding(selected[0].result, selected[0].run)

    assert finding.file_path == expected
    assert finding.rule_id == result['ruleId']
    assert finding.start_line == result['locations'][0]['physicalLocation']['region']['startLine']
    assert json.loads(path.read_text())['runs'][0] == run


@pytest.mark.parametrize('line', ['not/a/line', True, -1, []])
def test_unusable_start_coordinate_remains_unknown_in_finding_and_artifact(tmp_path, line):
    from packages.codeql.autonomous_analyzer import _artifact_safe_id
    from packages.codeql.tests.test_finding_selection import _located_result, _run, _write

    result = _located_result()
    region = result['locations'][0]['physicalLocation']['region']
    region.update(startLine=line, endLine=9)
    run = _run(result)
    path = _write(tmp_path, 'coordinate.sarif', run)
    selected, count, duplicates = select_findings_for_analysis([path], 1)
    assert (len(selected), count, duplicates) == (1, 1, 0)
    parser = object.__new__(AutonomousCodeQLAnalyzer)

    finding = parser.parse_sarif_finding(selected[0].result, selected[0].run)

    assert (finding.start_line, finding.end_line) == (0, 0)
    assert finding.file_path == result['locations'][0]['physicalLocation']['artifactLocation']['uri']
    stem = _artifact_safe_id(finding)
    assert stem.endswith('_0') and '/' not in stem and '\\' not in stem
    assert json.loads(path.read_text())['runs'][0] == run


@pytest.mark.parametrize('end,expected', [(None, 4), ([], 4), (3, 4), (9, 9)])
def test_optional_end_coordinate_never_precedes_known_start(end, expected):
    from packages.codeql.tests.test_finding_selection import _located_result, _run

    result = _located_result()
    result['locations'][0]['physicalLocation']['region'].update(startLine=4, endLine=end)
    parser = object.__new__(AutonomousCodeQLAnalyzer)
    finding = parser.parse_sarif_finding(result, _run(result))
    assert (finding.start_line, finding.end_line) == (4, expected)


@pytest.mark.parametrize('snippet,expected', [
    (['unavailable'], ''), ('unavailable', ''), ({'text': []}, ''), ({'text': 'owned snippet'}, 'owned snippet'),
], ids=['array-snippet', 'text-snippet', 'bad-text-field', 'valid-text'])
def test_optional_snippet_shape_does_not_erase_selected_source(tmp_path, snippet, expected):
    from packages.codeql.tests.test_finding_selection import _located_result, _run, _write

    result = _located_result()
    result['locations'][0]['physicalLocation']['region']['snippet'] = snippet
    run = _run(result)
    path = _write(tmp_path, 'snippet.sarif', run)
    selected, count, duplicates = select_findings_for_analysis([path], 1)
    assert (len(selected), count, duplicates) == (1, 1, 0)
    parser = object.__new__(AutonomousCodeQLAnalyzer)

    finding = parser.parse_sarif_finding(selected[0].result, selected[0].run)

    assert finding.snippet == expected
    assert finding.rule_id == result['ruleId']
    assert finding.file_path == result['locations'][0]['physicalLocation']['artifactLocation']['uri']
    assert finding.start_line == result['locations'][0]['physicalLocation']['region']['startLine']
    assert json.loads(path.read_text())['runs'][0] == run


@pytest.mark.parametrize('field', ['locations', 'primary', 'physicalLocation', 'region', 'artifactLocation'])
def test_unavailable_primary_location_wrapper_preserves_report_identity(field):
    from packages.codeql.tests.test_finding_selection import _located_result, _run

    result = _located_result()
    physical = result['locations'][0]['physicalLocation']
    file, line = physical['artifactLocation']['uri'], physical['region']['startLine']
    if field == 'locations':
        result['locations'] = {'unavailable': True}
    elif field == 'primary':
        result['locations'][0] = ['unavailable']
    elif field == 'physicalLocation':
        result['locations'][0]['physicalLocation'] = ['unavailable']
    else:
        physical[field] = ['unavailable']
    parser = object.__new__(AutonomousCodeQLAnalyzer)

    finding = parser.parse_sarif_finding(result, _run(result))

    assert finding.rule_id == result['ruleId']
    assert finding.message == result['message']['text']
    assert finding.file_path == (file if field == 'region' else '')
    assert finding.start_line == (line if field == 'artifactLocation' else 0)
    assert finding.snippet == ''


@pytest.mark.parametrize('name', [
    pytest.param(None, id='null-name'), pytest.param([], id='array-name'),
    pytest.param({}, id='object-name'), pytest.param(7, id='number-name'),
    pytest.param('', id='empty-name'), pytest.param('Owned display name', id='valid-name'),
])
def test_unavailable_descriptor_name_retains_readable_rule_identity(tmp_path, name):
    from core.security.prompt_defense_profiles import CONSERVATIVE
    from core.security.prompt_envelope import TaintedString, build_prompt
    from packages.codeql.tests.test_finding_selection import _located_result, _run, _write

    result = _located_result()
    run = _run(result)
    run['tool']['driver']['rules'][0]['name'] = name
    path = _write(tmp_path, 'descriptor-name.sarif', run)
    selected, count, duplicates = select_findings_for_analysis([path], 1)
    assert (len(selected), count, duplicates) == (1, 1, 0)
    parser = object.__new__(AutonomousCodeQLAnalyzer)
    finding = parser.parse_sarif_finding(selected[0].result, selected[0].run)

    expected = name if isinstance(name, str) and name else result['ruleId']
    assert finding.rule_name == expected
    bundle = build_prompt(system='Owned descriptor control', profile=CONSERVATIVE,
                          slots={'rule_name': TaintedString(value=finding.rule_name, trust='untrusted')})
    assert any(expected in message.content for message in bundle.messages)
    assert finding.rule_id == result['ruleId']
    assert json.loads(path.read_text())['runs'][0] == run


@pytest.mark.parametrize('message,expected', [
    pytest.param(['unavailable'], '', id='array-message'),
    pytest.param('unavailable', '', id='text-wrapper'),
    pytest.param({'text': []}, '', id='array-text-field'),
    pytest.param({'text': None}, '', id='null-text-field'),
    pytest.param({'id': 'unresolved-template'}, '', id='unresolved-id'),
    pytest.param({'text': 'Owned warning'}, 'Owned warning', id='valid-text'),
])
def test_unavailable_message_text_preserves_selected_identity_and_source(tmp_path, message, expected):
    from core.security.prompt_defense_profiles import CONSERVATIVE
    from core.security.prompt_envelope import UntrustedBlock, build_prompt
    from packages.codeql.tests.test_finding_selection import _located_result, _run, _write

    result = _located_result()
    result['message'] = message
    run = _run(result)
    path = _write(tmp_path, 'message-shape.sarif', run)
    selected, count, duplicates = select_findings_for_analysis([path], 1)
    assert (len(selected), count, duplicates) == (1, 1, 0)
    parser = object.__new__(AutonomousCodeQLAnalyzer)

    finding = parser.parse_sarif_finding(selected[0].result, selected[0].run)

    assert finding.message == expected
    bundle = build_prompt(system='Owned message control', profile=CONSERVATIVE,
                          untrusted_blocks=(UntrustedBlock(content=finding.message,
                                                           kind='scanner-message', origin='owned'),))
    assert bundle.messages
    assert finding.rule_id == result['ruleId']
    assert finding.file_path == result['locations'][0]['physicalLocation']['artifactLocation']['uri']
    assert finding.start_line == result['locations'][0]['physicalLocation']['region']['startLine']
    assert json.loads(path.read_text())['runs'][0] == run
