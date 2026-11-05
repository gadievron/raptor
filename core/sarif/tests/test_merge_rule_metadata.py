"""ID-only merges cannot rebind another report's rule metadata."""

import json
from copy import deepcopy

import pytest

from core.sarif import parser


def _run(rule, line, *, version=None, result_id='same'):
    driver = {'name': 'test', 'rules': [rule] if rule is not None else []}
    if version is not None:
        driver['version'] = version
    return {'tool': {'driver': driver}, 'results': [{
        'ruleId': result_id, 'message': {'text': 'Finding'}, 'locations': [{
            'physicalLocation': {'artifactLocation': {'uri': 'app.c'},
                                 'region': {'startLine': line}},
        }],
    }]}


def _merge(tmp_path, runs):
    paths = []
    for index, run in enumerate(runs):
        path = tmp_path / f'input-{index}.sarif'
        path.write_text(json.dumps({'version': '2.1.0', 'runs': [run]}))
        paths.append(str(path))
    merged = parser.merge_sarif(paths)
    output = tmp_path / 'combined.sarif'
    output.write_text(json.dumps(merged))
    return merged, parser.parse_sarif_findings(output)


def test_conflicting_classification_and_severity_remain_owned(tmp_path):
    first = {'id': 'same', 'properties': {'cwe': ['CWE-89']},
             'defaultConfiguration': {'level': 'error'}}
    second = {'id': 'same', 'properties': {'cwe': ['CWE-79']},
              'defaultConfiguration': {'level': 'note'}}
    merged, findings = _merge(tmp_path, [_run(first, 1), _run(second, 2)])
    assert len(merged['runs']) == 2
    assert [(row['cwe_id'], row['level']) for row in findings] == [
        ('CWE-89', 'error'), ('CWE-79', 'note')]


@pytest.mark.parametrize('missing_first', [False, True])
def test_missing_descriptor_cannot_borrow_a_later_or_earlier_binding(tmp_path, missing_first):
    known = _run({'id': 'same', 'properties': {'cwe': ['CWE-89']}}, 1)
    missing = _run(None, 2)
    _, findings = _merge(tmp_path, [missing, known] if missing_first else [known, missing])
    by_line = {row['startLine']: row for row in findings}
    assert by_line[1]['cwe_id'] == 'CWE-89'
    assert by_line[2]['cwe_id'] is None


def test_compatible_tables_still_union_and_deduplicate(tmp_path):
    first = _run({'id': 'first'}, 1, result_id='first')
    second = _run({'id': 'second'}, 2, result_id='second')
    merged, findings = _merge(tmp_path, [first, second, deepcopy(first)])
    assert len(merged['runs']) == 1
    assert {rule['id'] for rule in merged['runs'][0]['tool']['driver']['rules']} == {'first', 'second'}
    assert len(findings) == 2


def test_tool_versions_do_not_inherit_the_first_header(tmp_path):
    merged, findings = _merge(tmp_path, [
        _run({'id': 'same'}, 1, version='1'), _run({'id': 'same'}, 2, version='2'),
    ])
    assert [run['tool']['driver']['version'] for run in merged['runs']] == ['1', '2']
    assert len(findings) == 2


def test_id_only_extension_rule_keeps_its_component_namespace(tmp_path):
    run = _run(None, 1)
    run['tool']['extensions'] = [{'name': 'pack', 'rules': [
        {'id': 'same', 'properties': {'cwe': ['CWE-89']}},
    ]}]
    merged, findings = _merge(tmp_path, [run])
    assert merged['runs'][0] == run
    assert findings[0]['cwe_id'] == 'CWE-89'
    assert findings[0]['rule_scope']


def test_ambiguous_driver_ids_do_not_become_one_authoritative_rule(tmp_path):
    run = _run({'id': 'same', 'properties': {'cwe': ['CWE-89']}}, 1)
    run['tool']['driver']['rules'].append({'id': 'same', 'properties': {'cwe': ['CWE-79']}})
    merged, findings = _merge(tmp_path, [run])
    assert merged['runs'][0] == run
    assert findings[0]['cwe_id'] is None


def test_compatibility_search_is_bounded_without_losing_reports(monkeypatch):
    comparisons = []

    class Rule(dict):
        def __ne__(self, other):
            comparisons.append(1)
            return dict.__ne__(self, other)

    count = 40
    reports = {str(index): {'runs': [_run(Rule(id='same', name=str(index)), index + 1)]}
               for index in range(count)}
    monkeypatch.setattr(parser, 'load_sarif', lambda path: reports[str(path)])
    merged = parser.merge_sarif(list(reports))
    assert len(merged['runs']) == count
    assert len(comparisons) <= count * parser._MERGE_COMPATIBILITY_CHECKS
    assert sum(len(run['results']) for run in merged['runs']) == count


@pytest.mark.parametrize('change', ['severity', 'guid', 'scope'])
def test_equal_cwe_does_not_mask_other_descriptor_conflicts(tmp_path, change):
    first = {'id': 'same', 'properties': {'cwe': ['CWE-89']},
             'defaultConfiguration': {'level': 'warning'}}
    second = deepcopy(first)
    if change == 'severity':
        second['defaultConfiguration']['level'] = 'error'
    elif change == 'guid':
        second['guid'] = 'different-guid'
    else:
        first['properties']['raptor_rule_scope'] = 'a' * 64
        second['properties']['raptor_rule_scope'] = 'b' * 64
    merged, findings = _merge(tmp_path, [_run(first, 1), _run(second, 2)])
    assert len(merged['runs']) == 2
    assert [row['cwe_id'] for row in findings] == ['CWE-89', 'CWE-89']
    if change == 'severity':
        assert [row['level'] for row in findings] == ['warning', 'error']
    if change == 'scope':
        assert [row['rule_scope'] for row in findings] == ['a' * 64, 'b' * 64]
