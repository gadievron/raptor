"""Merging retains distinct spans and native scanner identities."""

import json
from copy import deepcopy

import pytest

from core.sarif.parser import _result_key, deduplicate_findings, merge_sarif, parse_sarif_findings


def _result():
    return {'ruleId': 'example', 'message': {'text': 'first'}, 'locations': [{
        'physicalLocation': {'artifactLocation': {'uri': 'app.c'},
                             'region': {'startLine': 7, 'startColumn': 3}},
    }]}


def _merged(tmp_path, results):
    inputs = []
    for index, result in enumerate(results):
        document = {'version': '2.1.0', 'runs': [{
            'tool': {'driver': {'name': 'test'}}, 'results': [result],
        }]}
        path = tmp_path / f'input-{index}.sarif'
        path.write_text(json.dumps(document))
        inputs.append(str(path))
    document = merge_sarif(inputs)
    output = tmp_path / 'merged.sarif'
    output.write_text(json.dumps(document))
    return document['runs'][0]['results'], deduplicate_findings(parse_sarif_findings(output))


def test_distinct_end_columns_survive_merge_and_parse(tmp_path):
    first = _result()
    second = deepcopy(first)
    first['locations'][0]['physicalLocation']['region']['endColumn'] = 8
    second['locations'][0]['physicalLocation']['region']['endColumn'] = 16
    results, findings = _merged(tmp_path, [first, second])
    assert len(results) == len(findings) == 2
    assert len({finding['finding_id'] for finding in findings}) == 2


def test_distinct_native_match_ids_survive_merge_and_parse(tmp_path):
    first = _result()
    second = deepcopy(first)
    first['fingerprints'] = {'matchBasedId/v1': 'native-a'}
    second['fingerprints'] = {'matchBasedId/v1': 'native-b'}
    results, findings = _merged(tmp_path, [first, second])
    assert len(results) == len(findings) == 2
    assert {finding['finding_id'] for finding in findings} == {'native-a', 'native-b'}


@pytest.mark.parametrize('metadata', ['legacy', 'end-column', 'native-id', 'both'])
def test_true_duplicates_keep_latest_report(tmp_path, metadata):
    first = _result()
    if metadata in ('end-column', 'both'):
        first['locations'][0]['physicalLocation']['region']['endColumn'] = 8
    if metadata in ('native-id', 'both'):
        first['fingerprints'] = {'matchBasedId/v1': 'native-a'}
    second = deepcopy(first)
    second['message']['text'] = 'updated explanation'
    results, findings = _merged(tmp_path, [first, second])
    assert len(results) == len(findings) == 1
    assert results[0]['message']['text'] == findings[0]['message'] == 'updated explanation'


@pytest.mark.parametrize('invalid', [None, True, -1, 0, 'invalid', [], {}, float('inf')])
def test_invalid_optional_end_column_keeps_legacy_identity(invalid):
    legacy = _result()
    changed = deepcopy(legacy)
    changed['locations'][0]['physicalLocation']['region']['endColumn'] = invalid
    assert _result_key(changed) == _result_key(legacy)


@pytest.mark.parametrize('invalid', [None, True, 7, '', [], {}, 'example'])
def test_invalid_or_bare_rule_native_id_keeps_legacy_identity(invalid):
    legacy = _result()
    changed = deepcopy(legacy)
    changed['fingerprints'] = {'matchBasedId/v1': invalid}
    assert _result_key(changed) == _result_key(legacy)


def test_legacy_key_remains_byte_compatible():
    assert _result_key(_result()) == ('example', 'app.c', 7, 7, 3, '')


def test_reused_native_id_does_not_collapse_distinct_spans(tmp_path):
    first = _result()
    first['fingerprints'] = {'matchBasedId/v1': 'reused-native'}
    second = deepcopy(first)
    first['locations'][0]['physicalLocation']['region']['endColumn'] = 8
    second['locations'][0]['physicalLocation']['region']['endColumn'] = 16
    results, findings = _merged(tmp_path, [first, second])
    assert len(results) == len(findings) == 2
    assert len({finding['finding_id'] for finding in findings}) == 2
    assert {finding['source_finding_id'] for finding in findings} == {'reused-native'}
    assert [finding['endColumn'] for finding in findings] == [8, 16]
    assert [finding['startColumn'] for finding in findings] == [3, 3]


@pytest.mark.parametrize('writer', ['normalized', 'enriched'])
def test_columns_and_colliding_ids_survive_export_round_trip(tmp_path, writer):
    from core.sarif.enriched_writer import build_enriched_sarif
    from core.sarif.import_normalizer import findings_to_sarif

    first = _result()
    second = deepcopy(first)
    first['locations'][0]['physicalLocation']['region']['endColumn'] = 8
    second['locations'][0]['physicalLocation']['region']['endColumn'] = 16
    first['fingerprints'] = second['fingerprints'] = {'matchBasedId/v1': 'reused-native'}
    _, findings = _merged(tmp_path, [first, second])
    document = findings_to_sarif(findings) if writer == 'normalized' else build_enriched_sarif(findings)
    path = tmp_path / 'export.sarif'
    path.write_text(json.dumps(document))
    actual = deduplicate_findings(parse_sarif_findings(path))
    assert len(actual) == 2
    assert [finding['endColumn'] for finding in actual] == [8, 16]
    assert [finding['startColumn'] for finding in actual] == [3, 3]
    assert [finding['finding_id'] for finding in actual] == [finding['finding_id'] for finding in findings]
