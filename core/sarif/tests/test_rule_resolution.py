"""Result descriptors must stay within the referenced SARIF component."""

import pytest

from core.sarif.parser import get_result_rule


@pytest.fixture
def run():
    return {"tool": {
        "driver": {"name": "driver", "rules": [{"id": "same", "name": "driver-rule"}]},
        "extensions": [{"name": "extension", "guid": "extension-guid", "rules": [
            {"id": "same", "guid": "rule-guid", "name": "extension-rule"},
        ]}],
    }}


@pytest.mark.parametrize("result,expected", [
    ({"ruleId": "same"}, "driver-rule"),
    ({"ruleIndex": 0}, "driver-rule"),
    ({"ruleId": "same", "ruleIndex": -1}, "driver-rule"),
    ({"rule": {"index": 0, "toolComponent": {"index": 0}}}, "extension-rule"),
    ({"rule": {"id": "same", "toolComponent": {"name": "extension"}}}, "extension-rule"),
    ({"rule": {"guid": "rule-guid", "toolComponent": {"guid": "extension-guid"}}}, "extension-rule"),
    ({"ruleId": "same", "rule": {"toolComponent": {"index": 5}}}, None),
    ({"ruleId": "same", "rule": {"toolComponent": {"index": True}}}, None),
    ({"ruleId": "same", "rule": {"toolComponent": {"index": -2}}}, None),
    ({"ruleId": "same", "rule": {"toolComponent": {"index": 0, "name": "wrong"}}}, None),
    ({"ruleId": "same", "rule": {"id": "different"}}, None),
    ({"ruleIndex": True}, None),
    ({"ruleIndex": -1}, None),
])
def test_component_resolution(run, result, expected):
    assert get_result_rule(run, result).get("name") == expected


def test_ambiguous_extension_reference_cannot_borrow_driver(run):
    run["tool"]["extensions"].append(run["tool"]["extensions"][0])
    result = {"ruleId": "same", "rule": {"toolComponent": {"name": "extension"}}}
    assert get_result_rule(run, result) == {}


def test_ambiguous_driver_cannot_fall_through_to_extension(run):
    run["tool"]["driver"]["rules"].append({"id": "same", "name": "duplicate"})
    assert get_result_rule(run, {"ruleId": "same"}) == {}


def test_explicit_index_disambiguates_duplicate_rule_ids(run):
    rules = run['tool']['driver']['rules']
    rules.append({'id': 'same', 'name': 'second-rule', 'defaultConfiguration': {'level': 'error'}})
    assert get_result_rule(run, {'ruleId': 'same', 'ruleIndex': 1}) is rules[1]


@pytest.mark.parametrize('result', [
    {'ruleId': 'same', 'ruleIndex': 1},
    {'ruleId': 'same', 'ruleIndex': True},
    {'ruleId': 'same', 'ruleIndex': -2},
    {'ruleId': 'same', 'ruleIndex': '0'},
    {'ruleId': 'same', 'ruleIndex': 0, 'rule': {'index': 1}},
    {'ruleId': 'same', 'ruleIndex': True, 'rule': {'index': 0}},
])
def test_invalid_or_conflicting_indexes_cannot_borrow_id_metadata(run, result):
    assert get_result_rule(run, result) == {}


@pytest.mark.parametrize('component', ['driver', 'extension'])
@pytest.mark.parametrize('identifier,expected', [
    ('same', True), ('same/subrule', True), ('same/subrule/deeper', False),
    ('same/', False), ('other', False),
])
def test_indexed_reference_validates_readable_rule_id(run, component, identifier, expected):
    reference = {'id': identifier, 'index': 0}
    if component == 'extension':
        reference['toolComponent'] = {'index': 0}
    result = {'rule': reference}
    assert bool(get_result_rule(run, result)) is expected


@pytest.mark.parametrize('guid,expected', [('rule-guid', True), ('different-guid', False)])
def test_index_and_guid_must_resolve_to_same_descriptor(run, guid, expected):
    reference = {'guid': guid, 'index': 0, 'toolComponent': {'index': 0}}
    assert bool(get_result_rule(run, {'rule': reference})) is expected


def test_indexed_reference_does_not_fall_through_to_extension(run):
    run['tool']['driver']['rules'] = [{'id': 'other'}]
    assert get_result_rule(run, {'ruleId': 'same', 'ruleIndex': 0}) == {}
    assert get_result_rule(run, {'ruleId': 'same'})['name'] == 'extension-rule'


@pytest.mark.parametrize('reference,level,cwe', [
    ({'ruleId': 'same', 'ruleIndex': 0}, 'note', 'CWE-79'),
    ({'ruleId': 'same', 'ruleIndex': 0, 'rule': {'toolComponent': {'index': 0}}}, 'error', 'CWE-78'),
    ({'rule': {'index': 0, 'toolComponent': {'index': 0}}}, 'error', 'CWE-78'),
    ({'ruleId': 'same', 'rule': {'toolComponent': {'index': 5}}}, 'warning', None),
    ({'ruleId': 'same', 'ruleIndex': 0, 'rule': {'index': 1}}, 'warning', None),
])
def test_import_and_metrics_use_the_owning_descriptor(tmp_path, run, reference, level, cwe):
    import json
    from core.sarif.parser import generate_scan_metrics, parse_sarif_findings

    driver = run['tool']['driver']['rules'][0]
    extension = run['tool']['extensions'][0]['rules'][0]
    for rule, severity, weakness in [(driver, 'note', 'CWE-79'), (extension, 'error', 'CWE-78')]:
        rule.update(defaultConfiguration={'level': severity}, properties={'cwe': weakness})
    run['results'] = [dict(reference, message={'text': 'finding'}, locations=[{
        'physicalLocation': {'artifactLocation': {'uri': 'source.c'}, 'region': {'startLine': 1}},
    }])]
    path = tmp_path / 'input.sarif'
    path.write_text(json.dumps({'version': '2.1.0', 'runs': [run]}))
    findings = parse_sarif_findings(path)
    assert len(findings) == 1
    assert (findings[0]['level'], findings[0]['cwe_id']) == (level, cwe)
    assert generate_scan_metrics([str(path)])['findings_by_severity'][level] == 1


@pytest.mark.parametrize('shape', ['normal', 'duplicate-driver', 'duplicate-extension',
                                 'two-extensions', 'no-driver', 'malformed'])
def test_run_owned_lookup_matches_shared_resolution_without_mutation(run, shape):
    import copy
    from core.sarif.parser import ResultRuleResolver

    if shape == 'duplicate-driver':
        run['tool']['driver']['rules'].append({'id': 'same', 'name': 'duplicate'})
    elif shape == 'duplicate-extension':
        run['tool']['extensions'][0]['rules'].append({'id': 'same', 'name': 'duplicate'})
    elif shape == 'two-extensions':
        run['tool']['extensions'].append(copy.deepcopy(run['tool']['extensions'][0]))
    elif shape == 'no-driver':
        run['tool'].pop('driver')
    elif shape == 'malformed':
        run['tool'] = {'driver': {'rules': [None, {}, {'id': []}]}, 'extensions': [None]}
    before = copy.deepcopy(run)
    resolver = ResultRuleResolver(run)
    for result in [
        {'ruleId': 'same'}, {'ruleId': 'same', 'ruleIndex': -1}, {'ruleIndex': 0},
        {'ruleId': 'same', 'ruleIndex': True}, {'ruleId': 'missing'},
        {'rule': {'id': 'same', 'toolComponent': {'index': 0}}},
        {'rule': {'index': 0, 'toolComponent': {'index': 0}}},
        {'ruleId': 'same', 'ruleIndex': 0, 'rule': {'index': 1}}, {},
    ]:
        expected = get_result_rule(run, result)
        actual = resolver.resolve(result)
        assert actual == expected
        if expected:
            assert actual is expected
    assert run == before


def test_run_owned_lookup_does_not_retain_finished_result_payloads(run):
    import gc
    import weakref
    from core.sarif.parser import ResultRuleResolver

    class Tracked(dict):
        pass

    result = Tracked(ruleId='same')
    raw_run = Tracked(run, results=[result])
    run_ref, result_ref = weakref.ref(raw_run), weakref.ref(result)
    resolver = ResultRuleResolver(raw_run)
    assert resolver.resolve(result)['name'] == 'driver-rule'
    del result, raw_run
    gc.collect(0)
    assert run_ref() is None and result_ref() is None
    assert resolver.resolve({'ruleId': 'same'})['name'] == 'driver-rule'


@pytest.mark.parametrize('extension', [False, True])
def test_metadata_cache_distinguishes_same_id_descriptors_in_one_run(tmp_path, run, extension):
    import copy
    import json
    from core.sarif.parser import generate_scan_metrics, parse_sarif_findings

    first = run['tool']['driver']['rules'][0]
    second = copy.deepcopy(first)
    first.update(defaultConfiguration={'level': 'note'}, properties={'cwe': 'CWE-79'})
    second.update(defaultConfiguration={'level': 'error'}, properties={'cwe': 'CWE-78'})
    if extension:
        run['tool']['extensions'][0]['rules'] = [second]
        refs = [{'ruleIndex': 0}, {'ruleIndex': 0, 'rule': {'toolComponent': {'index': 0}}}]
    else:
        run['tool']['driver']['rules'].append(second)
        refs = [{'ruleIndex': 0}, {'ruleIndex': 1}]
    run['results'] = [dict(ref, ruleId='same', message={'text': 'finding'}, locations=[{
        'physicalLocation': {'artifactLocation': {'uri': 'source.c'}, 'region': {'startLine': i+1}},
    }]) for i, ref in enumerate(refs)]
    path = tmp_path / 'cache.sarif'
    path.write_text(json.dumps({'version': '2.1.0', 'runs': [run]}))
    assert [(f['level'], f['cwe_id']) for f in parse_sarif_findings(path)] == [
        ('note', 'CWE-79'), ('error', 'CWE-78'),
    ]
    counts = generate_scan_metrics([str(path)])['findings_by_severity']
    assert (counts['note'], counts['error']) == (1, 1)


@pytest.mark.parametrize('extension', [False, True])
@pytest.mark.parametrize('shared_id', [False, True])
def test_merge_keeps_rule_reference_namespaces_valid(tmp_path, extension, shared_id):
    import json
    from core.sarif.parser import generate_scan_metrics, merge_sarif, parse_sarif_findings

    paths = []
    for index, (level, cwe) in enumerate([('note', 'CWE-79'), ('error', 'CWE-78')]):
        rule = {'id': 'same' if shared_id else f'rule-{index}',
                'defaultConfiguration': {'level': level}, 'properties': {'cwe': cwe}}
        tool = {'driver': {'name': 'CodeQL', 'rules': [] if extension else [rule]}}
        reference = {'ruleIndex': 0}
        if extension:
            tool['extensions'] = [{'name': 'extension', 'rules': [rule]}]
            reference['rule'] = {'toolComponent': {'index': 0}}
        result = dict(reference, message={'text': 'finding'}, locations=[{'physicalLocation': {
            'artifactLocation': {'uri': f'source-{index}.c'}, 'region': {'startLine': 1},
        }}])
        path = tmp_path / f'input-{index}.sarif'
        path.write_text(json.dumps({'version': '2.1.0', 'runs': [{'tool': tool, 'results': [result]}]}))
        paths.append(str(path))
    merged = merge_sarif(paths)
    assert len(merged['runs']) == 2
    output = tmp_path / 'merged.sarif'
    output.write_text(json.dumps(merged))
    assert [(f['level'], f['cwe_id']) for f in parse_sarif_findings(output)] == [
        ('note', 'CWE-79'), ('error', 'CWE-78'),
    ]
    counts = generate_scan_metrics([str(output)])['findings_by_severity']
    assert (counts['note'], counts['error']) == (1, 1)


def test_merge_exact_qualified_reports_deduplicate_without_reindexing(tmp_path, run):
    import copy
    import json
    from core.sarif.parser import merge_sarif

    result = {'ruleIndex': 0, 'rule': {'toolComponent': {'index': 0}},
              'message': {'text': 'finding'}, 'locations': [{'physicalLocation': {
                  'artifactLocation': {'uri': 'source.c'}, 'region': {'startLine': 1},
              }}]}
    run['results'] = [result, copy.deepcopy(result)]
    run['artifacts'] = [{'location': {'uri': 'source.c'}}]
    path = tmp_path / 'qualified.sarif'
    path.write_text(json.dumps({'version': '2.1.0', 'runs': [run]}))
    output = merge_sarif([str(path), str(path)])
    assert len(output['runs']) == 1
    assert output['runs'][0]['results'] == [result]
    assert output['runs'][0]['tool'] == run['tool']
    assert output['runs'][0]['artifacts'] == run['artifacts']
