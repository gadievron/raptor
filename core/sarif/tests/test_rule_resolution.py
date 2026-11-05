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


@pytest.mark.parametrize('reference_kind', ['driver-index', 'extension-index', 'qualified-id'])
def test_referenced_rule_identity_preserves_same_location_findings(tmp_path, reference_kind):
    import copy
    import json
    from core.sarif.parser import deduplicate_findings, parse_sarif_findings

    rules = [{'id': 'rule-a'}, {'id': 'rule-b'}]
    tool = {'driver': {'name': 'CodeQL', 'rules': rules}}
    if reference_kind != 'driver-index':
        tool = {'driver': {'name': 'CodeQL'}, 'extensions': [{'name': 'pack', 'rules': rules}]}
    results = []
    for index, rule in enumerate(rules):
        if reference_kind == 'driver-index':
            reference = {'ruleIndex': index}
        elif reference_kind == 'extension-index':
            reference = {'rule': {'index': index, 'toolComponent': {'index': 0}}}
        else:
            reference = {'rule': {'id': rule['id'], 'toolComponent': {'name': 'pack'}}}
        results.append(dict(reference, message={'text': 'same message'}, locations=[{
            'physicalLocation': {'artifactLocation': {'uri': 'source.c'}, 'region': {'startLine': 1}},
        }]))
    path = tmp_path / 'identity.sarif'
    report = {'version': '2.1.0', 'runs': [{'tool': tool, 'results': results}]}
    before = copy.deepcopy(report)
    path.write_text(json.dumps(report))
    findings = parse_sarif_findings(path)
    assert [finding['rule_id'] for finding in findings] == ['rule-a', 'rule-b']
    assert len({finding['finding_id'] for finding in findings}) == 2
    assert len(deduplicate_findings(findings)) == 2
    assert json.loads(path.read_text()) == before


@pytest.mark.parametrize('readable_id', ['same', 'same/child'])
def test_referenced_rule_identity_matches_explicit_readable_id(tmp_path, run, readable_id):
    import json
    from core.sarif.parser import parse_sarif_findings

    result = {'rule': {'id': readable_id, 'index': 0, 'toolComponent': {'index': 0}},
              'message': {'text': 'finding'}, 'locations': [{'physicalLocation': {
                  'artifactLocation': {'uri': 'source.c'}, 'region': {'startLine': 1},
              }}]}
    path = tmp_path / 'equivalent.sarif'

    def parse(row):
        path.write_text(json.dumps({'version': '2.1.0', 'runs': [dict(run, results=[row])]}))
        return parse_sarif_findings(path)[0]

    implicit = parse(result)
    explicit = parse(dict(result, ruleId=readable_id))
    assert implicit['rule_id'] == explicit['rule_id'] == readable_id
    assert implicit['finding_id'] == explicit['finding_id']
    fingerprinted = parse(dict(result, fingerprints={'matchBasedId/v1': 'tool-fingerprint'}))
    assert fingerprinted['finding_id'] == 'tool-fingerprint'


def test_invalid_reference_cannot_supply_missing_rule_identity(tmp_path, run):
    import json
    from core.sarif.parser import parse_sarif_findings

    result = {'rule': {'id': 'invented', 'index': 0}, 'message': {'text': 'finding'}}
    path = tmp_path / 'invalid.sarif'
    path.write_text(json.dumps({'version': '2.1.0', 'runs': [dict(run, results=[result])]}))
    assert parse_sarif_findings(path)[0]['rule_id'] is None


def test_distinct_subrules_survive_dedup_and_table_reordering(tmp_path, run):
    import json
    from core.sarif.parser import deduplicate_findings, parse_sarif_findings

    path = tmp_path / 'subrules.sarif'

    def parse(index):
        results = [{'rule': {'id': child, 'index': index, 'toolComponent': {'index': 0}},
                    'message': {'text': 'same message'}, 'locations': [{'physicalLocation': {
                        'artifactLocation': {'uri': 'source.c'}, 'region': {'startLine': 1},
                    }}]} for child in ['same/first', 'same/second']]
        path.write_text(json.dumps({'version': '2.1.0', 'runs': [dict(run, results=results)]}))
        return parse_sarif_findings(path)

    original = parse(0)
    assert len(deduplicate_findings(original)) == 2
    assert len({finding['finding_id'] for finding in original}) == 2
    run['tool']['extensions'][0]['rules'].insert(0, {'id': 'unrelated'})
    reordered = parse(1)
    assert [(f['rule_id'], f['finding_id']) for f in reordered] == [
        (f['rule_id'], f['finding_id']) for f in original
    ]


@pytest.mark.parametrize('level', [None, 'error'])
@pytest.mark.parametrize('reference,expected', [
    ({'ruleIndex': 0}, 'same'),
    ({'rule': {'index': 0, 'toolComponent': {'index': 0}}}, 'same'),
    ({'rule': {'id': 'same/child', 'index': 0, 'toolComponent': {'index': 0}}}, 'same/child'),
    ({'ruleId': 'explicit'}, 'explicit'),
    ({'rule': {'id': 'invented', 'index': 0}}, 'unknown'),
    ({'ruleIndex': True}, 'unknown'),
    ({'ruleId': ''}, 'unknown'),
])
def test_metrics_rule_counts_match_validated_import_identity(tmp_path, run, reference, expected, level):
    import json
    from core.sarif.parser import generate_scan_metrics, parse_sarif_findings

    result = dict(reference, message={'text': 'finding'}, locations=[{'physicalLocation': {
        'artifactLocation': {'uri': 'source.c'}, 'region': {'startLine': 1},
    }}])
    if level is not None:
        result['level'] = level
    path = tmp_path / 'metrics-identity.sarif'
    path.write_text(json.dumps({'version': '2.1.0', 'runs': [dict(run, results=[result])]}))
    metrics = generate_scan_metrics([str(path)])
    finding = parse_sarif_findings(path)[0]
    assert metrics['findings_by_rule'] == {expected: 1}
    assert (finding['rule_id'] or 'unknown') == expected
    assert metrics['findings_by_severity'][finding['level']] == 1


@pytest.mark.parametrize('identity', ['location', 'partial-fingerprint', 'tool-fingerprint'])
def test_established_identity_does_not_copy_unused_result_payload(monkeypatch, identity):
    import tracemalloc
    from pathlib import Path
    import core.sarif.parser as parser

    result = {'ruleId': 'rule-a', 'message': {'text': 'finding'},
              'properties': {'tool_details': 'x' * (2 * 1024 * 1024)}}
    if identity == 'location':
        result['locations'] = [{'physicalLocation': {
            'artifactLocation': {'uri': 'source.c'}, 'region': {'startLine': 1},
        }}]
    elif identity == 'partial-fingerprint':
        result['partialFingerprints'] = {'primaryLocationLineHash': 'line-hash'}
    else:
        result['fingerprints'] = {'matchBasedId/v1': 'tool-fingerprint'}
    report = {'runs': [{'tool': {'driver': {'name': 'tool'}}, 'results': [result]}]}
    # Isolate import work after the bounded loader; the caller-owned raw
    # document is already resident and must not be duplicated for identity.
    monkeypatch.setattr(parser, 'load_sarif', lambda path: report)
    parser.parse_sarif_findings(Path('unused.sarif'))  # Warm imports/caches.
    tracemalloc.start()
    try:
        findings = parser.parse_sarif_findings(Path('unused.sarif'))
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert len(findings) == 1
    assert findings[0]['message'] == 'finding'
    assert peak < 1024 * 1024, f'identity copied unused raw payload: {peak} bytes'


def test_content_identity_fallback_retains_exact_digest(tmp_path):
    import hashlib
    import json
    from core.sarif.parser import parse_sarif_findings

    result = {'ruleId': 'rule-a', 'message': {'text': 'locationless finding'},
              'properties': {'details': 'non-ASCII: λ'}}
    expected = hashlib.sha256(json.dumps(result, sort_keys=True, default=str).encode('utf-8')).hexdigest()
    path = tmp_path / 'content-identity.sarif'
    for row in [result, dict(reversed(list(result.items())))]:
        path.write_text(json.dumps({'runs': [{'tool': {'driver': {'name': 'tool'}}, 'results': [row]}]}))
        assert parse_sarif_findings(path)[0]['finding_id'] == expected


def test_metrics_can_count_original_artifacts_without_recounting_findings(tmp_path):
    import json
    from core.sarif.parser import generate_scan_metrics

    primary = tmp_path / 'combined.sarif'
    primary.write_text(json.dumps({'runs': [{'tool': {'driver': {'name': 'primary'}},
        'artifacts': [{'location': {'uri': 'discarded-fallback.c'}}],
        'results': [{'ruleId': 'kept', 'level': 'error'}]}]}))
    original = tmp_path / 'original.sarif'
    original.write_text(json.dumps({'runs': [{'tool': {'driver': {'name': 'original'}},
        'artifacts': [{'location': {'uri': 'a.c'}}, {'location': {'uri': 'b.c'}}],
        'results': [{'ruleId': 'raw', 'level': 'warning'}] * 3}]}))
    metrics = generate_scan_metrics([str(primary)], file_count_paths=[str(original)])
    assert metrics['total_files_scanned'] == 2
    assert metrics['total_findings'] == 1
    assert metrics['tools_used'] == ['primary']
    assert metrics['findings_by_tool'] == {'primary': 1}
    assert metrics['findings_by_rule'] == {'kept': 1}
    assert metrics['findings_by_severity']['error'] == 1
    assert metrics['findings_by_severity']['warning'] == 0
