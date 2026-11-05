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


@pytest.mark.parametrize('properties,expected', [
    (None, 0), ('malformed', 0), ({'nosemgrep': None}, 0),
    ({'nosemgrep': 'malformed'}, 0), ({'nosemgrep': {'suppressed': False}}, 0),
    ({'nosemgrep': {'suppressed': 'true'}}, 0), ({'nosemgrep': {'suppressed': 1}}, 0),
    ({'nosemgrep': {'suppressed': True}}, 1),
])
def test_metrics_count_only_literal_suppression_annotations(tmp_path, properties, expected):
    import json
    from core.sarif.parser import generate_scan_metrics

    path = tmp_path / 'suppressed.sarif'
    path.write_text(json.dumps({'runs': [{'tool': {'driver': {'name': 'Semgrep'}},
        'results': [{'ruleId': 'rule-a', 'level': 'warning', 'properties': properties}]}]}))
    metrics = generate_scan_metrics([str(path)])
    assert metrics['nosemgrep_suppressed_count'] == expected
    assert metrics['total_findings'] == 1


def test_artifact_count_inputs_cannot_inflate_suppression_count(tmp_path):
    import json
    from core.sarif.parser import generate_scan_metrics

    primary = tmp_path / 'empty.sarif'
    primary.write_text(json.dumps({'runs': [{'results': []}]}))
    original = tmp_path / 'original.sarif'
    original.write_text(json.dumps({'runs': [{'artifacts': [{'location': {'uri': 'a.py'}}],
        'results': [{'properties': {'nosemgrep': {'suppressed': True}}}]}]}))
    metrics = generate_scan_metrics([str(primary)], file_count_paths=[str(original)])
    assert metrics['total_files_scanned'] == 1
    assert metrics['total_findings'] == metrics['nosemgrep_suppressed_count'] == 0


@pytest.mark.parametrize('tool_fingerprint', [False, True])
def test_cross_tool_collisions_survive_dedup_without_artifact_id_overlap(tmp_path, tool_fingerprint):
    import copy
    import json
    from core.sarif.parser import deduplicate_findings, parse_sarif_findings

    result = {'ruleId': 'shared-rule', 'message': {'text': 'finding'}, 'locations': [{'physicalLocation': {
        'artifactLocation': {'uri': 'source.c'}, 'region': {'startLine': 1},
    }}]}
    if tool_fingerprint:
        result['fingerprints'] = {'matchBasedId/v1': 'shared-fingerprint'}
    path = tmp_path / 'tools.sarif'
    path.write_text(json.dumps({'runs': [
        {'tool': {'driver': {'name': name}}, 'results': [result, result]}
        for name in ['Semgrep', 'CodeQL']
    ]}))
    findings = parse_sarif_findings(path)
    before = copy.deepcopy(findings)
    assert len({finding['finding_id'] for finding in findings}) == 1
    retained = deduplicate_findings(findings)
    assert len(retained) == 2
    assert {finding['tool'] for finding in retained} == {'Semgrep', 'CodeQL'}
    # Consumers key analysis files and result maps on finding_id alone.
    assert len({finding['finding_id']: finding for finding in retained}) == 2
    assert {finding['source_finding_id'] for finding in retained} == {findings[0]['finding_id']}
    assert findings == before
    assert deduplicate_findings(retained) == retained
    reversed_result = deduplicate_findings(list(reversed(findings)))
    assert {f['tool']: f['finding_id'] for f in reversed_result} == {
        f['tool']: f['finding_id'] for f in retained
    }


def test_tool_scoped_ids_do_not_shadow_an_existing_finding_id():
    import copy
    from core.sarif.parser import deduplicate_findings

    rows = [dict(file='a.c', startLine=1, endLine=1, rule_id='shared',
                 finding_id='shared', tool=tool) for tool in ['Semgrep', 'CodeQL']]
    first = deduplicate_findings(rows)
    assert len(first) == 2
    existing = dict(rows[0], file='elsewhere.c', tool='other', finding_id=first[0]['finding_id'])
    original = copy.deepcopy([*rows, existing])
    retained = deduplicate_findings([*rows, existing])
    assert len(retained) == len({f['finding_id'] for f in retained}) == 3
    assert retained[-1] == existing
    assert [*rows, existing] == original
    reversed_result = deduplicate_findings(list(reversed([*rows, existing])))
    assert {f['tool']: f['finding_id'] for f in reversed_result} == {
        f['tool']: f['finding_id'] for f in retained
    }


def test_tool_aliases_and_uncollided_ids_keep_existing_identity():
    from core.sarif.parser import deduplicate_findings

    row = dict(file='a.c', startLine=1, endLine=1, rule_id='rule',
               finding_id='original-fingerprint', tool='Semgrep OSS')
    duplicate = dict(row, tool='semgrep')
    assert deduplicate_findings([row, duplicate]) == [row]
    assert deduplicate_findings([row])[0] is row


def test_legacy_findings_without_ids_remain_separate_across_tools():
    from core.sarif.parser import deduplicate_findings

    rows = [dict(file='a.c', startLine=1, rule_id='rule', tool=tool)
            for tool in ['Semgrep', 'CodeQL']]
    assert deduplicate_findings([*rows, dict(rows[0])]) == rows


@pytest.mark.parametrize('same_component', [False, True])
@pytest.mark.parametrize('tool_fingerprint', [False, True])
@pytest.mark.parametrize('use_guids', [False, True])
def test_same_tool_rule_namespaces_keep_independent_evidence(tmp_path, run, same_component, tool_fingerprint, use_guids):
    import copy
    import json
    from core.sarif.parser import deduplicate_findings, parse_sarif_findings

    driver = run['tool']['driver']['rules'][0]
    extension = run['tool']['extensions'][0]['rules'][0]
    driver.update(guid='driver-rule-guid', properties={'cwe': 'CWE-79'})
    extension.update(properties={'cwe': 'CWE-78'})
    if not use_guids:
        driver.pop('guid')
        extension.pop('guid')
        run['tool']['extensions'][0].pop('guid')
    references = [{'ruleId': 'same', 'ruleIndex': 0},
                  {'ruleId': 'same', 'ruleIndex': 0, 'rule': {'toolComponent': {'index': 0}}}]
    if same_component:
        run['tool']['driver']['rules'].append(copy.deepcopy(extension))
        references[1] = {'ruleId': 'same', 'ruleIndex': 1}
    rows = [dict(reference, message={'text': 'same message'}, locations=[{'physicalLocation': {
        'artifactLocation': {'uri': 'source.c'}, 'region': {'startLine': 1},
    }}]) for reference in references]
    if tool_fingerprint:
        for row in rows:
            row['fingerprints'] = {'matchBasedId/v1': 'shared-fingerprint'}
    path = tmp_path / 'rule-namespaces.sarif'
    run['results'] = rows + copy.deepcopy(rows)
    path.write_text(json.dumps({'runs': [run]}))
    findings = parse_sarif_findings(path)
    original = copy.deepcopy(findings)
    assert len({finding['finding_id'] for finding in findings}) == 1
    retained = deduplicate_findings(findings)
    assert len(retained) == len({finding['finding_id'] for finding in retained}) == 2
    assert {finding['cwe_id'] for finding in retained} == {'CWE-79', 'CWE-78'}
    assert findings == original
    assert deduplicate_findings(retained) == retained


@pytest.mark.parametrize('use_guids', [False, True])
def test_rule_scope_is_stable_across_reference_forms_and_table_reordering(tmp_path, run, use_guids):
    import json
    from core.sarif.parser import deduplicate_findings, parse_sarif_findings

    path = tmp_path / 'reordered-components.sarif'

    def parse(reference):
        row = dict(reference, message={'text': 'finding'}, locations=[{'physicalLocation': {
            'artifactLocation': {'uri': 'source.c'}, 'region': {'startLine': 1},
        }}])
        path.write_text(json.dumps({'runs': [dict(run, results=[row])]}))
        return parse_sarif_findings(path)[0]

    if not use_guids:
        run['tool']['extensions'][0].pop('guid')
        run['tool']['extensions'][0]['rules'][0].pop('guid')
    by_index = parse({'rule': {'index': 0, 'toolComponent': {'index': 0}}})
    readable = ({'guid': 'rule-guid', 'toolComponent': {'guid': 'extension-guid'}}
                if use_guids else {'id': 'same', 'toolComponent': {'name': 'extension'}})
    by_name = parse({'rule': readable})
    assert by_index['rule_scope'] == by_name['rule_scope']
    run['tool']['extensions'][0]['rules'].insert(0, {'id': 'unrelated'})
    run['tool']['extensions'].insert(0, {'name': 'unrelated', 'rules': []})
    reordered = parse({'rule': {'index': 1, 'toolComponent': {'index': 1}}})
    assert reordered['rule_scope'] == by_index['rule_scope']
    assert deduplicate_findings([by_index, by_name, reordered]) == [by_index]


def test_invalid_reference_cannot_borrow_rule_scope(tmp_path, run):
    import json
    from core.sarif.parser import parse_sarif_findings

    path = tmp_path / 'invalid-scope.sarif'
    row = {'ruleId': 'same', 'rule': {'toolComponent': {'index': 99}},
           'message': {'text': 'finding'}, 'properties': {'rule_scope': 'forged'}}
    path.write_text(json.dumps({'runs': [dict(run, results=[row])]}))
    assert 'rule_scope' not in parse_sarif_findings(path)[0]


@pytest.mark.parametrize('reference', [{'ruleId': 'same'}, {'ruleId': 'same', 'ruleIndex': 0}])
def test_unique_driver_keeps_legacy_identity_and_finding_shape(tmp_path, run, reference):
    import json
    from core.sarif.parser import deduplicate_findings, parse_sarif_findings

    path = tmp_path / 'ordinary-driver.sarif'
    row = dict(reference, message={'text': 'finding'}, fingerprints={'matchBasedId/v1': 'original'})
    path.write_text(json.dumps({'runs': [dict(run, results=[row])]}))
    finding = parse_sarif_findings(path)[0]
    assert finding['finding_id'] == 'original'
    assert 'rule_scope' not in finding
    assert deduplicate_findings([finding, dict(finding)]) == [finding]


@pytest.mark.parametrize('difference', ['cwe', 'severity'])
def test_anonymous_duplicate_descriptors_keep_distinct_inherited_evidence(tmp_path, difference):
    import json
    from core.sarif.parser import deduplicate_findings, parse_sarif_findings

    rules = [{'id': 'same', 'properties': {'cwe': cwe}, 'defaultConfiguration': {'level': level}}
             for cwe, level in [('CWE-79', 'note'),
                                ('CWE-78', 'note') if difference == 'cwe' else ('CWE-79', 'error')]]
    rows = [{'ruleId': 'same', 'ruleIndex': index, 'message': {'text': 'finding'},
             'locations': [{'physicalLocation': {'artifactLocation': {'uri': 'source.c'},
                                                'region': {'startLine': 1}}}]} for index in range(2)]
    path = tmp_path / 'anonymous-rules.sarif'
    path.write_text(json.dumps({'runs': [{'tool': {'driver': {'name': 'tool', 'rules': rules}},
                                         'results': rows}]}))
    retained = deduplicate_findings(parse_sarif_findings(path))
    assert len(retained) == len({finding['finding_id'] for finding in retained}) == 2
    assert len({(finding['cwe_id'], finding['level']) for finding in retained}) == 2


@pytest.mark.parametrize('change', [
    {'file': 'b.c'}, {'startLine': 2}, {'endLine': 3}, {'rule_id': 'other'},
    {'file': None}, {'endLine': None},
])
def test_reused_id_cannot_overwrite_distinct_retained_locations(change):
    import copy
    from core.sarif.parser import deduplicate_findings

    first = dict(tool='Semgrep', file='a.c', startLine=1, endLine=1,
                 rule_id='rule', finding_id='reused')
    second = dict(first, **change)
    rows = [first, second, dict(first), dict(second)]
    original = copy.deepcopy(rows)
    retained = deduplicate_findings(rows)
    assert len(retained) == len({row['finding_id']: row for row in retained}) == 2
    assert {row['source_finding_id'] for row in retained} == {'reused'}
    assert rows == original
    assert deduplicate_findings(retained) == retained
    fields = ('file', 'startLine', 'endLine', 'rule_id')
    assert {tuple(row.get(field) for field in fields): row['finding_id']
            for row in deduplicate_findings(list(reversed(rows)))} == {
                tuple(row.get(field) for field in fields): row['finding_id'] for row in retained
            }


def test_indexed_files_with_one_tool_fingerprint_keep_distinct_artifact_ids(tmp_path):
    import json
    from core.sarif.parser import deduplicate_findings, parse_sarif_findings

    rows = [{'ruleId': 'rule', 'fingerprints': {'matchBasedId/v1': 'shared'},
             'message': {'text': 'finding'}, 'locations': [{'physicalLocation': {
                 'artifactLocation': {'index': index}, 'region': {'startLine': 1},
             }}]} for index in range(2)]
    path = tmp_path / 'reused-indexed-fingerprint.sarif'
    path.write_text(json.dumps({'runs': [{'tool': {'driver': {'name': 'Semgrep'}},
        'artifacts': [{'location': {'uri': file}} for file in ['left.c', 'right.c']],
        'results': rows}]}))
    parsed = parse_sarif_findings(path)
    assert [row['finding_id'] for row in parsed] == ['shared', 'shared']
    retained = deduplicate_findings(parsed)
    assert len({row['finding_id']: row for row in retained}) == 2
    assert {row['file'] for row in retained} == {'left.c', 'right.c'}


def test_existing_cross_tool_qualified_ids_keep_their_byte_contract():
    from core.sarif.parser import deduplicate_findings

    rows = [dict(file='a.c', startLine=1, endLine=1, rule_id='shared',
                 finding_id='shared', tool=tool) for tool in ['Semgrep', 'CodeQL']]
    # Captured from the previous implementation before adding location
    # disambiguation; existing cross-tool artifact names must not drift.
    assert {row['tool']: row['finding_id'] for row in deduplicate_findings(rows)} == {
        'Semgrep': 'f14510e0548bdfd624999bb8ab5078c3a683a53042b317c5d688d9a08603e92f',
        'CodeQL': 'c75351778d4daf94ef68d11e40f5a590c0451e3dd5b343a89377ee24982ba773',
    }


def test_location_qualified_ids_avoid_existing_ids_and_keep_original_provenance():
    import copy
    from core.sarif.parser import deduplicate_findings

    rows = [dict(tool='Semgrep', file=file, startLine=1, endLine=1, rule_id='rule',
                 finding_id='reused', source_finding_id='original-upstream') for file in ['a.c', 'b.c']]
    initial = deduplicate_findings(rows)
    existing = dict(rows[0], file='existing.c', finding_id=initial[0]['finding_id'])
    original = copy.deepcopy([*rows, existing])
    retained = deduplicate_findings([*rows, existing])
    assert len(retained) == len({row['finding_id'] for row in retained}) == 3
    assert retained[-1] is existing
    assert {row['source_finding_id'] for row in retained[:2]} == {'original-upstream'}
    assert [*rows, existing] == original
    assert {row['file']: row['finding_id'] for row in retained} == {
        row['file']: row['finding_id'] for row in deduplicate_findings(list(reversed([*rows, existing])))
    }


def test_merge_identity_does_not_copy_a_whole_rule_table(monkeypatch):
    import tracemalloc
    import core.sarif.parser as parser

    rules = [{'id': f'rule-{index}', 'shortDescription': {'text': 'x' * 1024}}
             for index in range(4096)]
    result = {'ruleIndex': 0, 'ruleId': 'rule-0', 'message': {'text': 'finding'}}
    report = {'runs': [{'tool': {'driver': {'name': 'CodeQL', 'rules': rules}},
                        'results': [result, dict(result)]}]}
    monkeypatch.setattr(parser, 'load_sarif', lambda path: report)
    parser.merge_sarif(['unused.sarif'])
    tracemalloc.start()
    try:
        merged = parser.merge_sarif(['unused.sarif'])
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert merged['runs'][0]['tool'] is report['runs'][0]['tool']
    assert merged['runs'][0]['results'] == [result]
    assert peak < 1024 * 1024, f'merge identity copied the rule table: {peak} bytes'


def test_merge_restarts_identity_after_a_partial_stream_depth_failure(monkeypatch):
    import core.sarif.parser as parser

    report = {'runs': [{'tool': {'driver': {'name': 'CodeQL', 'rules': [{'id': 'rule'}]}},
                        'results': [{'ruleId': 'rule', 'ruleIndex': 0, 'message': {'text': 'finding'}}]}]}
    monkeypatch.setattr(parser, 'load_sarif', lambda path: report)
    real_stream = parser.iterencode_canonical
    failed = False

    def fail_once(value):
        nonlocal failed
        if not failed:
            failed = True
            yield b'{"tool":'
            raise RecursionError('synthetic streaming depth limit')
        yield from real_stream(value)

    monkeypatch.setattr(parser, 'iterencode_canonical', fail_once)
    merged = parser.merge_sarif(['first.sarif', 'second.sarif'])
    # A partial-prefix digest would differ from the successful retry and
    # retain two runs. Both complete identities must still coalesce.
    assert len(merged['runs']) == 1
    assert merged['runs'][0]['results'] == report['runs'][0]['results']
